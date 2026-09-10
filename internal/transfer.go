package internal

import (
	"bytes"
	"crypto/sha256"
	"io"
	"os"
)

// ChunkSize is the transfer and hashing granularity. Files are split into
// fixed-size chunks so resume can restart at a chunk boundary.
const ChunkSize int64 = 1 << 20 // 1 MiB

// scanFile computes the metadata (size, modtime, full and per-chunk SHA-256)
// used to drive transfer and resume.
func scanFile(path string) (*FileInfo, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	st, err := f.Stat()
	if err != nil {
		return nil, err
	}

	fi := &FileInfo{
		Path:    path,
		Size:    st.Size(),
		ModTime: st.ModTime().Unix(),
	}

	full := sha256.New()
	buf := make([]byte, ChunkSize)
	for {
		n, rerr := io.ReadFull(f, buf)
		if n > 0 {
			full.Write(buf[:n])
			sum := sha256.Sum256(buf[:n])
			fi.Chunks = append(fi.Chunks, sum[:])
		}
		if rerr == io.EOF || rerr == io.ErrUnexpectedEOF {
			break
		}
		if rerr != nil {
			return nil, rerr
		}
	}
	fi.SHA256 = full.Sum(nil)
	return fi, nil
}

// matchResume inspects an existing file at path and returns the byte offset
// from which the transfer should resume. complete is true when the file is
// already fully present and correct (the sender can skip it).
func matchResume(path string, fi FileInfo) (offset int64, complete bool, err error) {
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
	if st.Size() == fi.Size {
		if full, herr := hashFile(f); herr == nil && bytes.Equal(full, fi.SHA256) {
			return fi.Size, true, nil
		}
		if fi.Size == 0 {
			return 0, true, nil
		}
	}

	// Otherwise match per-chunk hashes from the start.
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return 0, false, err
	}
	buf := make([]byte, ChunkSize)
	offset = 0
	for i := 0; i < len(fi.Chunks); i++ {
		n, rerr := io.ReadFull(f, buf)
		if n == 0 {
			break
		}
		if rerr != nil && rerr != io.EOF && rerr != io.ErrUnexpectedEOF {
			return 0, false, rerr
		}
		got := sha256.Sum256(buf[:n])
		if !bytes.Equal(got[:], fi.Chunks[i]) {
			break
		}
		offset += int64(n)
		if n < len(buf) {
			break
		}
	}

	if offset == fi.Size {
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
