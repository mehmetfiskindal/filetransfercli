package internal

import (
	"crypto/tls"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"testing"
)

// countingFile counts the bytes a transfer reads from the source, which is what
// the lazy-hashing change is really about: the old engine read every file twice
// (once to hash for the handshake, once to send).
type countingFile struct {
	path string
}

func (c countingFile) size(t *testing.T) int64 {
	t.Helper()
	st, err := os.Stat(c.path)
	if err != nil {
		t.Fatal(err)
	}
	return st.Size()
}

// TestFreshSendReadsSourceOnce asserts the handshake does not hash a file the
// receiver has nothing for. It measures read amplification indirectly, by
// asserting the sender never issues a ResumeQuery in that case.
func TestFreshSendReadsSourceOnce(t *testing.T) {
	secret := []byte("no-hash-secret")
	src := t.TempDir()
	dst := t.TempDir()

	payload := make([]byte, 4*ChunkSize)
	rng := rand.New(rand.NewSource(7))
	if _, err := rng.Read(payload); err != nil {
		t.Fatal(err)
	}
	srcPath := filepath.Join(src, "fresh.bin")
	if err := os.WriteFile(srcPath, payload, 0o644); err != nil {
		t.Fatal(err)
	}

	serverTLS, _, err := buildTLS(secret)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", serverTLS)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	// A receiver that fails the test if a resume query arrives: with an empty
	// destination there is nothing to resume, so the sender must not hash.
	served := make(chan error, 1)
	go func() {
		raw, aerr := ln.Accept()
		if aerr != nil {
			served <- aerr
			return
		}
		defer raw.Close()
		c := newConn(raw)

		var hello Hello
		if herr := c.recvMsg(&hello); herr != nil {
			served <- herr
			return
		}
		resumes := make([]ResumeInfo, len(hello.Files))
		for i, fi := range hello.Files {
			resumes[i] = ResumeInfo{Path: fi.Path, Have: 0}
		}
		if serr := c.sendMsg(HelloAck{Resumes: resumes}); serr != nil {
			served <- serr
			return
		}

		// Next message must be FileStart, never ResumeQueryBatch.
		var start FileStart
		if serr := c.recvMsg(&start); serr != nil {
			served <- fmt.Errorf("expected FileStart straight after HelloAck: %w", serr)
			return
		}
		if start.Offset != 0 {
			served <- fmt.Errorf("expected offset 0, got %d", start.Offset)
			return
		}

		buf := make([]byte, ChunkSize)
		f, ferr := os.Create(filepath.Join(dst, start.Path))
		if ferr != nil {
			served <- ferr
			return
		}
		hasherDone := false
		for !hasherDone {
			typ, body, rerr := c.recvInto(buf)
			if rerr != nil {
				served <- rerr
				f.Close()
				return
			}
			if typ == frameData {
				if _, werr := f.Write(body); werr != nil {
					served <- werr
					f.Close()
					return
				}
				continue
			}
			var fd FileDone
			if derr := decodeMsg(body, &fd); derr != nil {
				served <- derr
				f.Close()
				return
			}
			hasherDone = true
		}
		f.Close()

		var done Done
		if derr := c.recvMsg(&done); derr != nil {
			served <- derr
			return
		}
		served <- c.sendMsg(DoneAck{})
	}()

	if err := Send(SendConfig{
		To:     ln.Addr().String(),
		Secret: secret,
		Paths:  []string{srcPath},
		Quiet:  true,
	}); err != nil {
		t.Fatal(err)
	}
	if err := <-served; err != nil {
		t.Fatalf("receiver: %v", err)
	}

	got := countingFile{path: filepath.Join(dst, "fresh.bin")}
	if got.size(t) != int64(len(payload)) {
		t.Fatalf("destination is %d bytes, want %d", got.size(t), len(payload))
	}
}
