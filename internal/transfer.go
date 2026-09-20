package internal

import (
	"bytes"
	"crypto/sha256"
	"hash"
	"io"
	"os"
)

// ChunkSize is the transfer and hashing granularity. Files are split into
// fixed-size chunks so resume can restart at a chunk boundary.
const ChunkSize int64 = 1 << 20 // 1 MiB

// statFile collects the metadata the handshake needs. It deliberately does not
// hash: a fresh transfer never reads these bytes twice, and the walk over a
// large directory stays a stat walk.
func statFile(path string) (FileInfo, error) {
	st, err := os.Stat(path)
	if err != nil {
		return FileInfo{}, err
	}
	return FileInfo{
		Path:    path,
		Size:    st.Size(),
		ModTime: st.ModTime().Unix(),
	}, nil
}

// fileHashes holds one file's whole-file and per-chunk digests.
type fileHashes struct {
	Full   []byte
	Chunks [][]byte
}

// hashFileChunks reads path once and returns both digest forms. Only called
// for files the receiver already holds bytes for, so the cost is paid on
// resume rather than on every send.
func hashFileChunks(path string) (fileHashes, error) {
	f, err := os.Open(path)
	if err != nil {
		return fileHashes{}, err
	}
	defer f.Close()

	full := sha256.New()
	buf := make([]byte, ChunkSize)
	var out fileHashes
	for {
		n, rerr := io.ReadFull(f, buf)
		if n > 0 {
			full.Write(buf[:n])
			sum := sha256.Sum256(buf[:n])
			out.Chunks = append(out.Chunks, sum[:])
		}
		if rerr == io.EOF || rerr == io.ErrUnexpectedEOF {
			break
		}
		if rerr != nil {
			return fileHashes{}, rerr
		}
	}
	out.Full = full.Sum(nil)
	return out, nil
}

// matchResume inspects the file at path against a sender's hashes and returns
// the byte offset from which the transfer should resume. complete is true when
// the file is already fully present and correct.
func matchResume(path string, q ResumeQuery) (offset int64, complete bool, err error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, false, nil
		}
		return 0, false, err
	}
	defer f.Close()

	st, err := f.Stat()
	if err != nil {
		return 0, false, err
	}

	// Fast path: identical full file.
	if st.Size() == q.Size {
		if full, herr := hashFile(f); herr == nil && bytes.Equal(full, q.SHA256) {
			return q.Size, true, nil
		}
		if q.Size == 0 {
			return 0, true, nil
		}
	}

	// Otherwise match per-chunk hashes from the start.
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return 0, false, err
	}
	buf := make([]byte, ChunkSize)
	offset = 0
	for i := 0; i < len(q.Chunks); i++ {
		n, rerr := io.ReadFull(f, buf)
		if n == 0 {
			break
		}
		if rerr != nil && rerr != io.EOF && rerr != io.ErrUnexpectedEOF {
			return 0, false, rerr
		}
		got := sha256.Sum256(buf[:n])
		if !bytes.Equal(got[:], q.Chunks[i]) {
			break
		}
		offset += int64(n)
		if n < len(buf) {
			break
		}
	}

	if offset == q.Size {
		return offset, true, nil
	}
	return offset, false, nil
}

func hashFile(f *os.File) ([]byte, error) {
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

// hashPrefixInto feeds the first n bytes of f into h.
//
// Needed on both sides of a resumed transfer: FileDone's digest covers the
// whole file, but a resumed stream only carries the tail, so the already
// present prefix has to be folded in to reach the same value.
func hashPrefixInto(f *os.File, n int64, h hash.Hash) error {
	if n <= 0 {
		return nil
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return err
	}
	if _, err := io.CopyN(h, f, n); err != nil {
		return err
	}
	return nil
}
