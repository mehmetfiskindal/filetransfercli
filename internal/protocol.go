package internal

// FileInfo describes a single file to transfer. Path is slash-separated and
// relative to the transfer root. Chunks holds the SHA-256 of each fixed-size
// chunk, enabling offset-based resume.
type FileInfo struct {
	Path    string
	Size    int64
	ModTime int64
	SHA256  []byte
	Chunks  [][]byte
}

// Hello is the sender's opening message listing every file to transfer.
type Hello struct {
	Files     []FileInfo
	ChunkSize int64
}

// ResumeInfo tells the sender how much of a file the receiver already has.
// Offset -1 means the file is already complete and can be skipped.
type ResumeInfo struct {
	Path   string
	Offset int64
}

// HelloAck is the receiver's reply to Hello.
type HelloAck struct {
	Resumes []ResumeInfo
}

// FileStart announces the beginning of a file's data stream.
type FileStart struct {
	Path   string
	Offset int64
}

// FileDone ends a file's data stream with its final checksum and byte count.
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
