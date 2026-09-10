package internal

import (
	"bytes"
	"crypto/tls"
	"os"
	"path/filepath"
	"testing"
)

func TestMatchResume(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "f.bin")

	content := bytes.Repeat([]byte("abcdefgh"), 300_000) // > 2 MiB
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatal(err)
	}
	fi, err := scanFile(path)
	if err != nil {
		t.Fatal(err)
	}

	if off, complete, err := matchResume(path, *fi); err != nil || !complete || off != fi.Size {
		t.Fatalf("full file: off=%d complete=%v err=%v", off, complete, err)
	}

	// Simulate an interrupted transfer: keep only a chunk-aligned prefix.
	partial := content[:ChunkSize+100]
	if err := os.WriteFile(path, partial, 0o644); err != nil {
		t.Fatal(err)
	}
	off, complete, err := matchResume(path, *fi)
	if err != nil || complete {
		t.Fatalf("partial file: off=%d complete=%v err=%v", off, complete, err)
	}
	if off != ChunkSize {
		t.Fatalf("expected resume at chunk boundary %d, got %d", ChunkSize, off)
	}
}

func TestTLSWrongSecretRejected(t *testing.T) {
	serverTLS, _, err := buildTLS([]byte("secret-a"))
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", serverTLS)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	_, wrongClient, err := buildTLS([]byte("secret-b"))
	if err != nil {
		t.Fatal(err)
	}

	// Accept and read to trigger the (lazy) handshake; both sides must fail.
	serverErr := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		buf := make([]byte, 1)
		_, err = c.Read(buf)
		serverErr <- err
	}()

	if _, err := tls.Dial("tcp", ln.Addr().String(), wrongClient); err == nil {
		t.Fatal("expected client handshake to fail with mismatched secret")
	}
	if err := <-serverErr; err == nil {
		t.Fatal("expected server handshake to fail with mismatched secret")
	}
}

func TestEndToEnd(t *testing.T) {
	secret := []byte("integration-secret")
	serverTLS, _, err := buildTLS(secret)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", serverTLS)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	src := t.TempDir()
	dst := t.TempDir()

	if err := os.WriteFile(filepath.Join(src, "a.txt"), []byte("hello world"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(src, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	big := bytes.Repeat([]byte("z"), int(2*ChunkSize)+123)
	if err := os.WriteFile(filepath.Join(src, "sub", "b.bin"), big, 0o644); err != nil {
		t.Fatal(err)
	}

	serveErr := make(chan error, 1)
	go func() {
		raw, err := ln.Accept()
		if err != nil {
			serveErr <- err
			return
		}
		serveErr <- handleConn(raw, dst)
	}()

	if err := Send(SendConfig{
		To:     ln.Addr().String(),
		Secret: secret,
		Paths:  []string{filepath.Join(src, "a.txt"), filepath.Join(src, "sub")},
	}); err != nil {
		t.Fatal(err)
	}
	if err := <-serveErr; err != nil {
		t.Fatal(err)
	}

	assertFile(t, filepath.Join(dst, "a.txt"), []byte("hello world"))
	assertFile(t, filepath.Join(dst, "sub", "b.bin"), big)

	// A second send must skip everything (files already complete).
	serveErr2 := make(chan error, 1)
	go func() {
		raw, err := ln.Accept()
		if err != nil {
			serveErr2 <- err
			return
		}
		serveErr2 <- handleConn(raw, dst)
	}()
	if err := Send(SendConfig{
		To:     ln.Addr().String(),
		Secret: secret,
		Paths:  []string{filepath.Join(src, "a.txt"), filepath.Join(src, "sub")},
	}); err != nil {
		t.Fatal(err)
	}
	if err := <-serveErr2; err != nil {
		t.Fatal(err)
	}
	assertFile(t, filepath.Join(dst, "sub", "b.bin"), big)
}

func TestResumeAfterTruncate(t *testing.T) {
	secret := []byte("resume-secret")
	serverTLS, _, err := buildTLS(secret)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", serverTLS)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	src := t.TempDir()
	dst := t.TempDir()
	big := bytes.Repeat([]byte("q"), int(3*ChunkSize)+500)
	srcPath := filepath.Join(src, "big.bin")
	if err := os.WriteFile(srcPath, big, 0o644); err != nil {
		t.Fatal(err)
	}

	serve := func() <-chan error {
		ch := make(chan error, 1)
		go func() {
			raw, err := ln.Accept()
			if err != nil {
				ch <- err
				return
			}
			ch <- handleConn(raw, dst)
		}()
		return ch
	}

	// First transfer completes fully.
	srv := serve()
	if err := Send(SendConfig{To: ln.Addr().String(), Secret: secret, Paths: []string{srcPath}}); err != nil {
		t.Fatal(err)
	}
	if err := <-srv; err != nil {
		t.Fatal(err)
	}
	assertFile(t, filepath.Join(dst, "big.bin"), big)

	// Truncate the destination to a chunk-aligned prefix + a few bytes.
	if err := os.Truncate(filepath.Join(dst, "big.bin"), ChunkSize+7); err != nil {
		t.Fatal(err)
	}
	srv = serve()
	if err := Send(SendConfig{To: ln.Addr().String(), Secret: secret, Paths: []string{srcPath}}); err != nil {
		t.Fatal(err)
	}
	if err := <-srv; err != nil {
		t.Fatal(err)
	}
	assertFile(t, filepath.Join(dst, "big.bin"), big)
}

func assertFile(t *testing.T, path string, want []byte) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s: content mismatch (got %d bytes, want %d)", path, len(got), len(want))
	}
}
