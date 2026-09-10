package internal

import (
	"bufio"
	"bytes"
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

// conn wraps a TLS connection with length-prefixed framing.
type conn struct {
	c  net.Conn
	br *bufio.Reader
}

func newConn(c net.Conn) *conn {
	return &conn{c: c, br: bufio.NewReader(c)}
}

func (c *conn) Close() error { return c.c.Close() }

// sendMsg gob-encodes m and writes it as a control frame.
func (c *conn) sendMsg(m interface{}) error {
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(m); err != nil {
		return err
	}
	return c.writeFrame(frameControl, buf.Bytes())
}

// sendChunk writes a raw data frame.
func (c *conn) sendChunk(b []byte) error {
	return c.writeFrame(frameData, b)
}

func (c *conn) writeFrame(typ byte, payload []byte) error {
	var hdr [5]byte
	hdr[0] = typ
	binary.BigEndian.PutUint32(hdr[1:], uint32(len(payload)))
	if _, err := c.c.Write(hdr[:]); err != nil {
		return err
	}
	_, err := c.c.Write(payload)
	return err
}

// recv reads the next frame and returns its type and payload.
func (c *conn) recv() (byte, []byte, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(c.br, hdr[:]); err != nil {
		return 0, nil, err
	}
	typ := hdr[0]
	n := binary.BigEndian.Uint32(hdr[1:])
	payload := make([]byte, n)
	if _, err := io.ReadFull(c.br, payload); err != nil {
		return 0, nil, err
	}
	return typ, payload, nil
}

// recvMsg reads the next control frame and gob-decodes it into m.
func (c *conn) recvMsg(m interface{}) error {
	typ, payload, err := c.recv()
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

// recvChunk reads the next raw data frame.
func (c *conn) recvChunk() ([]byte, error) {
	typ, payload, err := c.recv()
	if err != nil {
		return nil, err
	}
	if typ != frameData {
		return nil, fmt.Errorf("expected data frame, got type %d", typ)
	}
	return payload, nil
}
