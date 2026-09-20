package internal

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"encoding/gob"
	"fmt"
	"io"
	"net"
)

// Frame types. Type 0 is a gob-encoded control message; type 1 is a raw data
// chunk whose meaning is implied by the surrounding protocol state.
const (
	frameControl byte = 0
	frameData    byte = 1
)

// frameHeaderSize is the per-frame prefix: one type byte plus a big-endian
// uint32 payload length.
const frameHeaderSize = 5

// conn wraps a TLS connection with length-prefixed framing.
type conn struct {
	c  net.Conn
	br *bufio.Reader
}

func newConn(c net.Conn) *conn {
	setNoDelay(c)
	// A read buffer a little over one chunk lets a full data frame land in one
	// bufio fill instead of several.
	return &conn{c: c, br: bufio.NewReaderSize(c, int(ChunkSize)+frameHeaderSize)}
}

// setNoDelay disables Nagle's algorithm on the underlying TCP connection.
// Without it, the small frame header written before each chunk payload
// triggers a Nagle/delayed-ACK stall that caps throughput to a few MiB/s.
func setNoDelay(c net.Conn) {
	var tc *net.TCPConn
	if tlsc, ok := c.(*tls.Conn); ok {
		tc, _ = tlsc.NetConn().(*net.TCPConn)
	} else {
		tc, _ = c.(*net.TCPConn)
	}
	if tc != nil {
		_ = tc.SetNoDelay(true)
	}
}

func (c *conn) Close() error { return c.c.Close() }

// sendMsg gob-encodes m and writes it as a control frame.
func (c *conn) sendMsg(m interface{}) error {
	var buf bytes.Buffer
	// Reserve the header inline so the control frame is also a single write.
	buf.Write(make([]byte, frameHeaderSize))
	if err := gob.NewEncoder(&buf).Encode(m); err != nil {
		return err
	}
	frame := buf.Bytes()
	putFrameHeader(frame, frameControl, len(frame)-frameHeaderSize)
	_, err := c.c.Write(frame)
	return err
}

// putFrameHeader writes the type/length prefix into the first frameHeaderSize
// bytes of frame.
func putFrameHeader(frame []byte, typ byte, payloadLen int) {
	frame[0] = typ
	binary.BigEndian.PutUint32(frame[1:frameHeaderSize], uint32(payloadLen))
}

// sendFramedChunk writes a data frame whose payload already sits in
// frame[frameHeaderSize:], filling the reserved header in place.
//
// The caller reads file bytes straight into that reserved layout, so a chunk
// reaches the socket as one write with no copy and no second syscall for the
// header. The previous shape (write header, then write payload) cost two TLS
// records per chunk.
func (c *conn) sendFramedChunk(frame []byte) error {
	putFrameHeader(frame, frameData, len(frame)-frameHeaderSize)
	_, err := c.c.Write(frame)
	return err
}

// recvInto reads the next frame into buf when it fits, returning a slice of
// buf. Reusing the caller's buffer keeps a multi-gigabyte transfer from
// allocating one chunk-sized slice per frame.
func (c *conn) recvInto(buf []byte) (typ byte, payload []byte, err error) {
	var hdr [frameHeaderSize]byte
	if _, err := io.ReadFull(c.br, hdr[:]); err != nil {
		return 0, nil, err
	}
	typ = hdr[0]
	n := int(binary.BigEndian.Uint32(hdr[1:]))

	if n > len(buf) {
		// Control messages are small but not bounded by ChunkSize, so fall
		// back to a fresh allocation rather than refusing the frame.
		payload = make([]byte, n)
	} else {
		payload = buf[:n]
	}
	if _, err := io.ReadFull(c.br, payload); err != nil {
		return 0, nil, err
	}
	return typ, payload, nil
}

// recvMsg reads the next control frame and gob-decodes it into m.
func (c *conn) recvMsg(m interface{}) error {
	typ, payload, err := c.recvInto(nil)
	if err != nil {
		return err
	}
	if typ != frameControl {
		return fmt.Errorf("expected control frame, got type %d", typ)
	}
	return decodeMsg(payload, m)
}

// decodeMsg gob-decodes a control frame payload into m.
func decodeMsg(payload []byte, m interface{}) error {
	return gob.NewDecoder(bytes.NewReader(payload)).Decode(m)
}
