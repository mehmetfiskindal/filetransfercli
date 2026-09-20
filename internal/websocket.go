package internal

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
)

// RFC 6455's fixed handshake GUID, concatenated with the client's key to form
// the Sec-WebSocket-Accept response.
const wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

// WebSocket opcodes. Only text, close, ping and pong are needed: the control
// channel carries JSON, and file bytes never cross it.
const (
	wsOpContinuation byte = 0x0
	wsOpText         byte = 0x1
	wsOpBinary       byte = 0x2
	wsOpClose        byte = 0x8
	wsOpPing         byte = 0x9
	wsOpPong         byte = 0xA
)

// wsMaxPayload bounds a single inbound control frame. Commands are small JSON
// objects, so anything larger is a client bug or an attack rather than traffic
// worth buffering.
const wsMaxPayload = 1 << 20 // 1 MiB

// wsConn is a server-side WebSocket connection over a hijacked HTTP conn.
//
// Hand-rolled rather than pulled from a module: the control channel needs only
// text frames plus liveness, and AGENTS.md keeps this binary dependency-free.
type wsConn struct {
	c  net.Conn
	br *bufio.Reader

	// wmu serializes writes. The bridge fans progress events out from a
	// transfer goroutine while the read loop may answer a ping, and two
	// concurrent frame writes would interleave into a protocol error.
	wmu sync.Mutex

	closeOnce sync.Once
}

// wsUpgrade completes the RFC 6455 handshake and takes ownership of the
// connection. The caller must Close the returned conn.
func wsUpgrade(w http.ResponseWriter, r *http.Request) (*wsConn, error) {
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		return nil, errors.New("not a websocket upgrade")
	}
	if !headerContainsToken(r.Header.Get("Connection"), "upgrade") {
		return nil, errors.New("missing Connection: Upgrade")
	}
	if r.Header.Get("Sec-WebSocket-Version") != "13" {
		return nil, errors.New("unsupported websocket version")
	}
	key := r.Header.Get("Sec-WebSocket-Key")
	if key == "" {
		return nil, errors.New("missing Sec-WebSocket-Key")
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		return nil, errors.New("connection cannot be hijacked")
	}
	conn, rw, err := hj.Hijack()
	if err != nil {
		return nil, err
	}

	sum := sha1.Sum([]byte(key + wsGUID))
	accept := base64.StdEncoding.EncodeToString(sum[:])

	resp := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + accept + "\r\n\r\n"
	if _, err := io.WriteString(conn, resp); err != nil {
		conn.Close()
		return nil, err
	}

	setNoDelay(conn)
	return &wsConn{c: conn, br: rw.Reader}, nil
}

// headerContainsToken reports whether a comma-separated header lists token,
// case-insensitively. `Connection` may legitimately be "keep-alive, Upgrade".
func headerContainsToken(header, token string) bool {
	for _, part := range strings.Split(header, ",") {
		if strings.EqualFold(strings.TrimSpace(part), token) {
			return true
		}
	}
	return false
}

func (ws *wsConn) Close() error {
	var err error
	ws.closeOnce.Do(func() {
		// Best-effort courtesy close; the peer may already be gone.
		_ = ws.writeFrame(wsOpClose, nil)
		err = ws.c.Close()
	})
	return err
}

// ReadText returns the next text message, transparently answering pings and
// reassembling continuation frames. A close frame surfaces as io.EOF.
func (ws *wsConn) ReadText() (string, error) {
	var assembled []byte
	var assembling bool

	for {
		op, payload, final, err := ws.readFrame()
		if err != nil {
			return "", err
		}

		switch op {
		case wsOpPing:
			if err := ws.writeFrame(wsOpPong, payload); err != nil {
				return "", err
			}
		case wsOpPong:
			// Liveness only; nothing to do.
		case wsOpClose:
			return "", io.EOF
		case wsOpBinary:
			return "", errors.New("binary frames are not accepted on the control channel")
		case wsOpText:
			if final {
				return string(payload), nil
			}
			assembled = append(assembled, payload...)
			assembling = true
		case wsOpContinuation:
			if !assembling {
				return "", errors.New("continuation frame without a start frame")
			}
			assembled = append(assembled, payload...)
			if len(assembled) > wsMaxPayload {
				return "", errors.New("control message too large")
			}
			if final {
				return string(assembled), nil
			}
		default:
			return "", fmt.Errorf("unexpected websocket opcode 0x%x", op)
		}
	}
}

// WriteText sends s as a single unfragmented text frame.
func (ws *wsConn) WriteText(s string) error {
	return ws.writeFrame(wsOpText, []byte(s))
}

// WritePing sends an empty ping so an idle bridge notices a phone that dropped
// off WiFi without a close handshake.
func (ws *wsConn) WritePing() error {
	return ws.writeFrame(wsOpPing, nil)
}

// readFrame reads one frame, unmasking the payload in place.
func (ws *wsConn) readFrame() (op byte, payload []byte, final bool, err error) {
	var hdr [2]byte
	if _, err = io.ReadFull(ws.br, hdr[:]); err != nil {
		return 0, nil, false, err
	}

	final = hdr[0]&0x80 != 0
	if hdr[0]&0x70 != 0 {
		return 0, nil, false, errors.New("reserved websocket bits set")
	}
	op = hdr[0] & 0x0F

	masked := hdr[1]&0x80 != 0
	// RFC 6455 requires every client-to-server frame to be masked; an
	// unmasked one means a broken or hostile client.
	if !masked {
		return 0, nil, false, errors.New("client frame is not masked")
	}

	length := uint64(hdr[1] & 0x7F)
	switch length {
	case 126:
		var ext [2]byte
		if _, err = io.ReadFull(ws.br, ext[:]); err != nil {
			return 0, nil, false, err
		}
		length = uint64(binary.BigEndian.Uint16(ext[:]))
	case 127:
		var ext [8]byte
		if _, err = io.ReadFull(ws.br, ext[:]); err != nil {
			return 0, nil, false, err
		}
		length = binary.BigEndian.Uint64(ext[:])
	}
	if length > wsMaxPayload {
		return 0, nil, false, fmt.Errorf("control frame of %d bytes exceeds limit", length)
	}

	var mask [4]byte
	if _, err = io.ReadFull(ws.br, mask[:]); err != nil {
		return 0, nil, false, err
	}

	payload = make([]byte, length)
	if _, err = io.ReadFull(ws.br, payload); err != nil {
		return 0, nil, false, err
	}
	for i := range payload {
		payload[i] ^= mask[i&3]
	}
	return op, payload, final, nil
}

// writeFrame writes one unmasked server frame in a single Write so a frame
// never interleaves with another goroutine's.
func (ws *wsConn) writeFrame(op byte, payload []byte) error {
	n := len(payload)

	var hdr []byte
	switch {
	case n < 126:
		hdr = []byte{0x80 | op, byte(n)}
	case n <= 0xFFFF:
		hdr = []byte{0x80 | op, 126, 0, 0}
		binary.BigEndian.PutUint16(hdr[2:], uint16(n))
	default:
		hdr = []byte{0x80 | op, 127, 0, 0, 0, 0, 0, 0, 0, 0}
		binary.BigEndian.PutUint64(hdr[2:], uint64(n))
	}

	frame := make([]byte, 0, len(hdr)+n)
	frame = append(frame, hdr...)
	frame = append(frame, payload...)

	ws.wmu.Lock()
	defer ws.wmu.Unlock()
	_, err := ws.c.Write(frame)
	return err
}
