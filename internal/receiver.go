package internal

import (
	"bytes"
	"crypto/tls"
	"fmt"
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

	resumes := make([]ResumeInfo, len(hello.Files))
	for i, fi := range hello.Files {
		dest := filepath.Join(outDir, filepath.FromSlash(fi.Path))
		if !withinDir(outDir, dest) {
			return fmt.Errorf("refusing unsafe path %q", fi.Path)
		}
		off, complete, err := matchResume(dest, fi)
		if err != nil {
			return err
		}
		if complete {
			resumes[i] = ResumeInfo{Path: fi.Path, Offset: -1}
		} else {
			resumes[i] = ResumeInfo{Path: fi.Path, Offset: off}
		}
	}

	if err := c.sendMsg(HelloAck{Resumes: resumes}); err != nil {
		return err
	}

	for i, fi := range hello.Files {
		if resumes[i].Offset < 0 {
			continue
		}
		if err := receiveFile(c, outDir, fi, resumes[i].Offset); err != nil {
			return err
		}
	}

	var done Done
	if err := c.recvMsg(&done); err != nil {
		return err
	}
	return c.sendMsg(DoneAck{})
}

func receiveFile(c *conn, outDir string, fi FileInfo, offset int64) error {
	var start FileStart
	if err := c.recvMsg(&start); err != nil {
		return err
	}

	dest := filepath.Join(outDir, filepath.FromSlash(fi.Path))
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return err
	}

	f, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	if err := f.Truncate(offset); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		f.Close()
		return err
	}

	var received int64
	for {
		typ, payload, err := c.recv()
		if err != nil {
			f.Close()
			return err
		}
		if typ == frameData {
			if _, err := f.Write(payload); err != nil {
				f.Close()
				return err
			}
			received += int64(len(payload))
			continue
		}
		if typ != frameControl {
			f.Close()
			return fmt.Errorf("unexpected frame type %d", typ)
		}
		var fd FileDone
		if err := decodeMsg(payload, &fd); err != nil {
			f.Close()
			return err
		}
		if err := f.Close(); err != nil {
			return err
		}
		if err := verifyFile(dest, fi.SHA256); err != nil {
			return err
		}
		fmt.Printf("received %s (%s)\n", fi.Path, humanBytes(received))
		return nil
	}
}

func verifyFile(path string, want []byte) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	got, err := hashFile(f)
	if err != nil {
		return err
	}
	if !bytes.Equal(got, want) {
		return fmt.Errorf("checksum mismatch for %s", path)
	}
	return nil
}

// withinDir reports whether path is inside root (guards against path traversal).
func withinDir(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}
