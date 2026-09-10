package internal

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// SendConfig holds the sender's runtime options.
type SendConfig struct {
	To     string   // host:port of the receiver
	Secret []byte   // shared secret
	Paths  []string // local files or directories to send
}

type sendItem struct {
	info FileInfo // wire metadata (info.Path is the relative display name)
	src  string   // local filesystem path
}

// Send connects to the receiver and transfers the requested paths.
func Send(cfg SendConfig) error {
	items, err := collectFiles(cfg.Paths)
	if err != nil {
		return err
	}
	if len(items) == 0 {
		return errors.New("no files to send")
	}

	_, clientTLS, err := buildTLS(cfg.Secret)
	if err != nil {
		return err
	}

	raw, err := tls.Dial("tcp", cfg.To, clientTLS)
	if err != nil {
		return fmt.Errorf("connect to %s: %w", cfg.To, err)
	}
	defer raw.Close()
	c := newConn(raw)

	files := make([]FileInfo, len(items))
	for i, it := range items {
		files[i] = it.info
	}

	if err := c.sendMsg(Hello{Files: files, ChunkSize: ChunkSize}); err != nil {
		return err
	}

	var ack HelloAck
	if err := c.recvMsg(&ack); err != nil {
		return err
	}
	if len(ack.Resumes) != len(files) {
		return fmt.Errorf("receiver returned %d resume entries for %d files", len(ack.Resumes), len(files))
	}

	var total, transferred int64
	var skipped []string
	for i, r := range ack.Resumes {
		if r.Offset < 0 {
			skipped = append(skipped, files[i].Path)
			continue
		}
		total += files[i].Size - r.Offset
	}

	prog := newProgress(total, os.Stdout)
	for i := range files {
		r := ack.Resumes[i]
		if r.Offset < 0 {
			continue
		}
		if err := sendFile(c, items[i], r.Offset, prog, &transferred); err != nil {
			prog.finish()
			return err
		}
	}

	if err := c.sendMsg(Done{}); err != nil {
		return err
	}
	var doneAck DoneAck
	if err := c.recvMsg(&doneAck); err != nil {
		return err
	}

	prog.finish()
	for _, s := range skipped {
		fmt.Printf("skip   %s (already complete)\n", s)
	}
	fmt.Printf("sent %d file(s), %s\n", len(files)-len(skipped), humanBytes(transferred))
	return nil
}

func sendFile(c *conn, it sendItem, offset int64, prog *progress, transferred *int64) error {
	f, err := os.Open(it.src)
	if err != nil {
		return err
	}
	defer f.Close()

	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return err
	}

	prog.setCurrent(it.info.Path)

	if err := c.sendMsg(FileStart{Path: it.info.Path, Offset: offset}); err != nil {
		return err
	}

	buf := make([]byte, ChunkSize)
	var sent int64
	for {
		n, rerr := io.ReadFull(f, buf)
		if n > 0 {
			if err := c.sendChunk(buf[:n]); err != nil {
				return err
			}
			sent += int64(n)
			*transferred += int64(n)
			prog.add(int64(n))
		}
		if rerr == io.EOF || rerr == io.ErrUnexpectedEOF {
			break
		}
		if rerr != nil {
			return rerr
		}
	}

	if err := c.sendMsg(FileDone{Path: it.info.Path, SHA256: it.info.SHA256, Bytes: sent}); err != nil {
		return err
	}
	return nil
}

func collectFiles(paths []string) ([]sendItem, error) {
	var items []sendItem
	seen := map[string]bool{}

	add := func(src, name string) error {
		if seen[name] {
			return fmt.Errorf("duplicate target name %q; use a directory or rename to avoid collision", name)
		}
		seen[name] = true
		fi, err := scanFile(src)
		if err != nil {
			return err
		}
		fi.Path = name
		items = append(items, sendItem{info: *fi, src: src})
		return nil
	}

	for _, p := range paths {
		st, err := os.Stat(p)
		if err != nil {
			return nil, err
		}
		if st.IsDir() {
			err := filepath.Walk(p, func(wp string, info os.FileInfo, werr error) error {
				if werr != nil {
					return werr
				}
				if info.IsDir() {
					return nil
				}
				rel, err := filepath.Rel(p, wp)
				if err != nil {
					return err
				}
				name := filepath.ToSlash(filepath.Join(filepath.Base(p), rel))
				return add(wp, name)
			})
			if err != nil {
				return nil, err
			}
		} else {
			if err := add(p, filepath.Base(p)); err != nil {
				return nil, err
			}
		}
	}
	return items, nil
}
