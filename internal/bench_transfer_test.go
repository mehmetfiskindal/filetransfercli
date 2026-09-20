package internal

import (
	"crypto/tls"
	"math/rand"
	"os"
	"path/filepath"
	"testing"
)

// benchBytes is the payload size for the throughput benchmark. Large enough
// that per-chunk costs and the handshake's hashing pass dominate startup
// noise, small enough to run on a laptop.
const benchBytes = 192 << 20 // 192 MiB

// BenchmarkTransfer measures a fresh whole-file transfer over loopback TLS,
// handshake included. Run with:
//
//	go test ./internal/ -run '^$' -bench BenchmarkTransfer -benchtime 1x
//
// Written to compile against both the pre- and post-optimization engines so the
// two can be compared in a git worktree.
func BenchmarkTransfer(b *testing.B) {
	src := b.TempDir()
	srcPath := filepath.Join(src, "payload.bin")

	// Pseudo-random, fixed seed: reproducible, and incompressible so nothing
	// downstream can cheat the measurement.
	payload := make([]byte, benchBytes)
	rng := rand.New(rand.NewSource(1))
	if _, err := rng.Read(payload); err != nil {
		b.Fatal(err)
	}
	if err := os.WriteFile(srcPath, payload, 0o644); err != nil {
		b.Fatal(err)
	}

	secret := []byte("bench-secret")
	serverTLS, _, err := buildTLS(secret)
	if err != nil {
		b.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", serverTLS)
	if err != nil {
		b.Fatal(err)
	}
	defer ln.Close()

	b.SetBytes(benchBytes)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		b.StopTimer()
		// A fresh destination each iteration keeps this a first-transfer
		// measurement rather than an all-skipped resume.
		dst, err := os.MkdirTemp("", "ft-bench-dst")
		if err != nil {
			b.Fatal(err)
		}

		served := make(chan error, 1)
		go func() {
			raw, aerr := ln.Accept()
			if aerr != nil {
				served <- aerr
				return
			}
			served <- handleConn(raw, dst)
		}()
		b.StartTimer()

		if err := Send(SendConfig{
			To:     ln.Addr().String(),
			Secret: secret,
			Paths:  []string{srcPath},
		}); err != nil {
			b.Fatal(err)
		}
		if err := <-served; err != nil {
			b.Fatal(err)
		}

		b.StopTimer()
		if st, serr := os.Stat(filepath.Join(dst, "payload.bin")); serr != nil {
			b.Fatal(serr)
		} else if st.Size() != benchBytes {
			b.Fatalf("transferred %d bytes, want %d", st.Size(), benchBytes)
		}
		os.RemoveAll(dst)
		b.StartTimer()
	}
}
