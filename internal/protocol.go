package internal

// FileInfo describes a single file to transfer. Path is slash-separated and
// relative to the transfer root.
//
// Deliberately hash-free: the sender only stats its files before the
// handshake, so a fresh transfer starts moving bytes immediately instead of
// reading the whole dataset once to hash it and again to send it. Hashes are
// exchanged later, and only for the files that actually need resume.
type FileInfo struct {
	Path    string
	Size    int64
	ModTime int64
}

// Hello is the sender's opening message listing every file to transfer.
type Hello struct {
	Files     []FileInfo
	ChunkSize int64
}

// ResumeInfo reports how many bytes the receiver already holds for a file.
// Have is 0 when the destination is absent or empty, which lets the sender
// skip hashing that file entirely.
type ResumeInfo struct {
	Path string
	Have int64
}

// HelloAck is the receiver's reply to Hello.
type HelloAck struct {
	Resumes []ResumeInfo
}

// ResumeQuery carries the per-chunk hashes for one file the receiver already
// has bytes for, so the receiver can find the last chunk that matches.
type ResumeQuery struct {
	Path   string
	Size   int64
	SHA256 []byte
	Chunks [][]byte
}

// ResumeQueryBatch sends every resume candidate in one round trip; a directory
// of thousands of partially-present files should not cost thousands of RTTs.
type ResumeQueryBatch struct {
	Queries []ResumeQuery
}

// ResumeAnswer is the resolved starting offset for a queried file. Offset -1
// means the file is already complete and can be skipped.
type ResumeAnswer struct {
	Path   string
	Offset int64
}

// ResumeAnswerBatch replies to ResumeQueryBatch, in the same order.
type ResumeAnswerBatch struct {
	Answers []ResumeAnswer
}

// FileStart announces the beginning of a file's data stream.
type FileStart struct {
	Path   string
	Offset int64
}

// FileDone ends a file's data stream. SHA256 covers the whole file, not just
// the transferred range, and is computed by the sender while streaming so
// neither side needs a separate verification pass.
type FileDone struct {
	Path   string
	SHA256 []byte
	Bytes  int64
}

// Done is sent by the sender after all files have been transferred.
type Done struct{}

// DoneAck is the receiver's confirmation that everything checks out.
type DoneAck struct{}

// ErrorMsg carries a fatal error across the wire.
type ErrorMsg struct {
	Message string
}
