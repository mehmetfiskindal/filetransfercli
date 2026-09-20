package internal

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"hash"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
)

// ReceiveConfig holds the receiver's runtime options.
type ReceiveConfig struct {
	Addr   string // listen address, e.g. ":8443"
	Secret []byte
	OutDir string
}

// Receive listens for a sender and writes incoming files under OutDir.
func Receive(cfg ReceiveConfig) error {
	serverTLS, _, err := buildTLS(cfg.Secret)
	if err != nil {
		return err
	}

	ln, err := tls.Listen("tcp", cfg.Addr, serverTLS)
	if err != nil {
		return err
	}
	defer ln.Close()
	fmt.Printf("listening on %s (out dir: %s)\n", ln.Addr(), cfg.OutDir)

	for {
		raw, err := ln.Accept()
		if err != nil {
			return err
		}
		go func() {
			if err := handleConn(raw, cfg.OutDir); err != nil {
				fmt.Fprintf(os.Stderr, "transfer error: %v\n", err)
			}
		}()
	}
}

func handleConn(raw net.Conn, outDir string) error {
	defer raw.Close()
	c := newConn(raw)

	var hello Hello
	if err := c.recvMsg(&hello); err != nil {
		return err
	}

	// Phase one is a stat per destination: report what is already on disk so
	// the sender only hashes the files that could actually resume.
	resumes := make([]ResumeInfo, len(hello.Files))
	needQuery := false
	for i, fi := range hello.Files {
		dest := filepath.Join(outDir, filepath.FromSlash(fi.Path))
		if !withinDir(outDir, dest) {
			return fmt.Errorf("refusing unsafe path %q", fi.Path)
		}
		have := int64(0)
		if st, err := os.Stat(dest); err == nil && !st.IsDir() {
			have = st.Size()
		}
		resumes[i] = ResumeInfo{Path: fi.Path, Have: have}
		if have > 0 {
			needQuery = true
		}
	}

	if err := c.sendMsg(HelloAck{Resumes: resumes}); err != nil {
		return err
	}

	// Phase two runs only when something might resume.
	offsets := make([]int64, len(hello.Files))
	if needQuery {
		var batch ResumeQueryBatch
		if err := c.recvMsg(&batch); err != nil {
			return err
		}
		answers := make([]ResumeAnswer, len(batch.Queries))
		resolved := make(map[string]int64, len(batch.Queries))
		for j, q := range batch.Queries {
			dest := filepath.Join(outDir, filepath.FromSlash(q.Path))
			if !withinDir(outDir, dest) {
				return fmt.Errorf("refusing unsafe path %q", q.Path)
			}
			off, complete, err := matchResume(dest, q)
			if err != nil {
				return err
			}
			if complete {
				off = -1
			}
			answers[j] = ResumeAnswer{Path: q.Path, Offset: off}
			resolved[q.Path] = off
		}
		if err := c.sendMsg(ResumeAnswerBatch{Answers: answers}); err != nil {
			return err
		}
		for i, fi := range hello.Files {
			if off, ok := resolved[fi.Path]; ok {
				offsets[i] = off
			}
		}
	}

	// One buffer serves every file on this connection, so a directory of
	// thousands of files does not churn chunk-sized allocations.
	buf := make([]byte, ChunkSize)
	for i, fi := range hello.Files {
		if offsets[i] < 0 {
			continue
		}
		if err := receiveFile(c, outDir, fi, offsets[i], buf); err != nil {
			return err
		}
	}

	var done Done
	if err := c.recvMsg(&done); err != nil {
		return err
	}
	return c.sendMsg(DoneAck{})
}

func receiveFile(c *conn, outDir string, fi FileInfo, offset int64, buf []byte) error {
	var start FileStart
	if err := c.recvMsg(&start); err != nil {
		return err
	}

	dest := filepath.Join(outDir, filepath.FromSlash(fi.Path))
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return err
	}

	f, err := os.OpenFile(dest, os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()

	if err := f.Truncate(offset); err != nil {
		return err
	}

	// Hash as the bytes land instead of re-reading the finished file. On a
	// resumed transfer the retained prefix is folded in first so the digest
	// still covers the whole file.
	hasher := sha256.New()
	if err := hashPrefixInto(f, offset, hasher); err != nil {
		return err
	}
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return err
	}

	received, err := drainFile(c, f, hasher, buf)
	if err != nil {
		return err
	}

	if err := f.Close(); err != nil {
		return err
	}
	if !bytes.Equal(hasher.Sum(nil), received.SHA256) {
		return fmt.Errorf("checksum mismatch for %s", dest)
	}
	fmt.Printf("received %s (%s)\n", fi.Path, humanBytes(received.Bytes))
	return nil
}

// drainFile writes incoming data frames to f until the sender's FileDone
// arrives, returning that message.
func drainFile(c *conn, f *os.File, hasher hash.Hash, buf []byte) (FileDone, error) {
	for {
		typ, payload, err := c.recvInto(buf)
		if err != nil {
			return FileDone{}, err
		}
		switch typ {
		case frameData:
			if _, err := f.Write(payload); err != nil {
				return FileDone{}, err
			}
			hasher.Write(payload)
		case frameControl:
			var fd FileDone
			if err := decodeMsg(payload, &fd); err != nil {
				return FileDone{}, err
			}
			return fd, nil
		default:
			return FileDone{}, fmt.Errorf("unexpected frame type %d", typ)
		}
	}
}

// withinDir reports whether path is inside root (guards against path traversal).
func withinDir(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}
