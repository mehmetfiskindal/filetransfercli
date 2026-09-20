package internal

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"time"
)

// pipelineDepth is how many chunk buffers circulate between the disk reader
// and the socket writer. Two would be enough to overlap the two devices; three
// absorbs a slow read or a stalled write without draining the pipe. Each buffer
// costs ChunkSize, so this is also the sender's memory ceiling per file.
const pipelineDepth = 3

// PlanItem is one file's place in a transfer once resume has been resolved.
// Resume is the byte count the receiver already had; -1 marks a skipped file.
type PlanItem struct {
	Path   string
	Size   int64
	Resume int64
}

// Observer receives transfer lifecycle updates. The CLI leaves it nil and
// renders its own progress bar; the bridge implements it to feed the app.
type Observer interface {
	Plan(items []PlanItem)
	FileBegin(path string, offset, size int64)
	FileProgress(path string, sent int64)
	FileEnd(path string, err error)
	Finish(files int, bytes int64, elapsed time.Duration)
}

// SendConfig holds the sender's runtime options.
type SendConfig struct {
	To     string   // host:port of the receiver
	Secret []byte   // shared secret
	Paths  []string // local files or directories to send

	// Ctx cancels an in-flight transfer. Nil means context.Background().
	Ctx context.Context
	// Observer, when non-nil, receives lifecycle updates.
	Observer Observer
	// Quiet suppresses stdout progress rendering (used by the bridge).
	Quiet bool
}

type sendItem struct {
	info FileInfo // wire metadata (info.Path is the relative display name)
	src  string   // local filesystem path
}

// Send connects to the receiver and transfers the requested paths.
func Send(cfg SendConfig) error {
	ctx := cfg.Ctx
	if ctx == nil {
		ctx = context.Background()
	}

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

	dialer := &tls.Dialer{Config: clientTLS}
	rawConn, err := dialer.DialContext(ctx, "tcp", cfg.To)
	if err != nil {
		return fmt.Errorf("connect to %s: %w", cfg.To, err)
	}
	defer rawConn.Close()
	c := newConn(rawConn)

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

	offsets, err := resolveResume(c, items, ack.Resumes)
	if err != nil {
		return err
	}

	var total int64
	plan := make([]PlanItem, len(files))
	var skipped []string
	for i := range files {
		plan[i] = PlanItem{Path: files[i].Path, Size: files[i].Size, Resume: offsets[i]}
		if offsets[i] < 0 {
			skipped = append(skipped, files[i].Path)
			continue
		}
		total += files[i].Size - offsets[i]
	}
	if cfg.Observer != nil {
		cfg.Observer.Plan(plan)
	}

	started := time.Now()
	var transferred int64

	var prog *progress
	if !cfg.Quiet {
		prog = newProgress(total, os.Stdout)
	}

	for i := range files {
		if offsets[i] < 0 {
			continue
		}
		if err := ctx.Err(); err != nil {
			if prog != nil {
				prog.finish()
			}
			return err
		}
		ferr := sendFile(ctx, c, items[i], offsets[i], prog, &transferred, cfg.Observer)
		if cfg.Observer != nil {
			cfg.Observer.FileEnd(files[i].Path, ferr)
		}
		if ferr != nil {
			if prog != nil {
				prog.finish()
			}
			return ferr
		}
	}

	if err := c.sendMsg(Done{}); err != nil {
		return err
	}
	var doneAck DoneAck
	if err := c.recvMsg(&doneAck); err != nil {
		return err
	}

	if prog != nil {
		prog.finish()
		for _, s := range skipped {
			fmt.Printf("skip   %s (already complete)\n", s)
		}
		fmt.Printf("sent %d file(s), %s\n", len(files)-len(skipped), humanBytes(transferred))
	}
	if cfg.Observer != nil {
		cfg.Observer.Finish(len(files)-len(skipped), transferred, time.Since(started))
	}
	return nil
}

// resolveResume turns the receiver's "bytes I already have" report into a
// starting offset per file, where -1 means skip.
//
// Files the receiver has nothing for need no hashing at all, which is the
// common case for a first transfer. Only the remainder are hashed, and they go
// out as one batch so a directory of partial files costs a single round trip.
func resolveResume(c *conn, items []sendItem, resumes []ResumeInfo) ([]int64, error) {
	offsets := make([]int64, len(items))
	queryIndex := make([]int, 0, len(items))
	queries := make([]ResumeQuery, 0, len(items))

	for i := range items {
		if resumes[i].Have <= 0 {
			offsets[i] = 0
			continue
		}
		h, err := hashFileChunks(items[i].src)
		if err != nil {
			return nil, err
		}
		queries = append(queries, ResumeQuery{
			Path:   items[i].info.Path,
			Size:   items[i].info.Size,
			SHA256: h.Full,
			Chunks: h.Chunks,
		})
		queryIndex = append(queryIndex, i)
	}

	if len(queries) == 0 {
		return offsets, nil
	}

	if err := c.sendMsg(ResumeQueryBatch{Queries: queries}); err != nil {
		return nil, err
	}
	var answers ResumeAnswerBatch
	if err := c.recvMsg(&answers); err != nil {
		return nil, err
	}
	if len(answers.Answers) != len(queries) {
		return nil, fmt.Errorf("receiver answered %d of %d resume queries", len(answers.Answers), len(queries))
	}
	for j, ans := range answers.Answers {
		offsets[queryIndex[j]] = ans.Offset
	}
	return offsets, nil
}

// sendFile streams one file from offset to the receiver.
//
// A reader goroutine fills chunk buffers while this goroutine writes the
// previous one to the socket, so disk and network overlap instead of taking
// turns. The whole-file digest is accumulated on the reader side, which also
// keeps it off the socket's critical path.
func sendFile(
	ctx context.Context,
	c *conn,
	it sendItem,
	offset int64,
	prog *progress,
	transferred *int64,
	obs Observer,
) error {
	f, err := os.Open(it.src)
	if err != nil {
		return err
	}
	defer f.Close()

	hasher := sha256.New()
	if err := hashPrefixInto(f, offset, hasher); err != nil {
		return err
	}
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return err
	}

	if prog != nil {
		prog.setCurrent(it.info.Path)
	}
	if obs != nil {
		obs.FileBegin(it.info.Path, offset, it.info.Size)
	}

	if err := c.sendMsg(FileStart{Path: it.info.Path, Offset: offset}); err != nil {
		return err
	}

	// Reported per chunk rather than per file: a multi-gigabyte file must not
	// leave the progress bar and the app frozen until it completes.
	onChunk := func(n int64, fileSent int64) {
		*transferred += n
		if prog != nil {
			prog.add(n)
		}
		if obs != nil {
			obs.FileProgress(it.info.Path, offset+fileSent)
		}
	}

	sent, err := streamFile(ctx, c, f, hasher, onChunk)
	if err != nil {
		return err
	}

	return c.sendMsg(FileDone{
		Path:   it.info.Path,
		SHA256: hasher.Sum(nil),
		Bytes:  sent,
	})
}

// streamFile pumps f to the socket through a buffer pipeline and returns the
// number of bytes written. hasher receives every streamed byte, and onChunk is
// called after each frame with that frame's size and the running total.
func streamFile(
	ctx context.Context,
	c *conn,
	f *os.File,
	hasher hash.Hash,
	onChunk func(n int64, fileSent int64),
) (int64, error) {
	free := make(chan []byte, pipelineDepth)
	for i := 0; i < pipelineDepth; i++ {
		free <- make([]byte, frameHeaderSize+ChunkSize)
	}
	filled := make(chan []byte, pipelineDepth)
	readErr := make(chan error, 1)

	// done unblocks the reader if this goroutine bails out on a write error,
	// so a failed transfer never leaks the reader on a channel send.
	done := make(chan struct{})
	defer close(done)

	go func() {
		defer close(filled)
		for {
			var buf []byte
			select {
			case buf = <-free:
			case <-done:
				return
			}

			n, rerr := io.ReadFull(f, buf[frameHeaderSize:])
			if n > 0 {
				hasher.Write(buf[frameHeaderSize : frameHeaderSize+n])
				select {
				case filled <- buf[:frameHeaderSize+n]:
				case <-done:
					return
				}
			}
			if rerr != nil {
				if rerr == io.EOF || rerr == io.ErrUnexpectedEOF {
					readErr <- nil
				} else {
					readErr <- rerr
				}
				return
			}
		}
	}()

	var sent int64
	for frame := range filled {
		if err := ctx.Err(); err != nil {
			return sent, err
		}
		payload := int64(len(frame) - frameHeaderSize)
		if err := c.sendFramedChunk(frame); err != nil {
			return sent, err
		}
		sent += payload
		free <- frame[:cap(frame)]
		if onChunk != nil {
			onChunk(payload, sent)
		}
	}
	if err := <-readErr; err != nil {
		return sent, err
	}
	return sent, nil
}

func collectFiles(paths []string) ([]sendItem, error) {
	var items []sendItem
	seen := map[string]bool{}

	add := func(src, name string) error {
		if seen[name] {
			return fmt.Errorf("duplicate target name %q; use a directory or rename to avoid collision", name)
		}
		seen[name] = true
		fi, err := statFile(src)
		if err != nil {
			return err
		}
		fi.Path = name
		items = append(items, sendItem{info: fi, src: src})
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
