package internal

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// wsClient is a minimal client-side WebSocket, enough to drive the bridge the
// way the app does. Client frames must be masked, which the server enforces.
type wsClient struct {
	c  net.Conn
	br *bufio.Reader
}

func dialWS(t *testing.T, addr string) *wsClient {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial bridge: %v", err)
	}

	var keyBytes [16]byte
	if _, err := rand.Read(keyBytes[:]); err != nil {
		t.Fatal(err)
	}
	key := base64.StdEncoding.EncodeToString(keyBytes[:])

	req := "GET /api/ws HTTP/1.1\r\n" +
		"Host: " + addr + "\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: " + key + "\r\n" +
		"Sec-WebSocket-Version: 13\r\n\r\n"
	if _, err := io.WriteString(c, req); err != nil {
		t.Fatal(err)
	}

	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read handshake response: %v", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("expected 101, got %d", resp.StatusCode)
	}

	sum := sha1.Sum([]byte(key + wsGUID))
	want := base64.StdEncoding.EncodeToString(sum[:])
	if got := resp.Header.Get("Sec-WebSocket-Accept"); got != want {
		t.Fatalf("bad accept key: got %q want %q", got, want)
	}

	return &wsClient{c: c, br: br}
}

func (w *wsClient) Close() { w.c.Close() }

func (w *wsClient) writeText(t *testing.T, s string) {
	t.Helper()
	payload := []byte(s)

	var mask [4]byte
	if _, err := rand.Read(mask[:]); err != nil {
		t.Fatal(err)
	}

	var frame []byte
	switch n := len(payload); {
	case n < 126:
		frame = []byte{0x81, byte(0x80 | n)}
	case n <= 0xFFFF:
		frame = []byte{0x81, 0x80 | 126, 0, 0}
		binary.BigEndian.PutUint16(frame[2:], uint16(n))
	default:
		frame = []byte{0x81, 0x80 | 127, 0, 0, 0, 0, 0, 0, 0, 0}
		binary.BigEndian.PutUint64(frame[2:], uint64(n))
	}
	frame = append(frame, mask[:]...)

	masked := make([]byte, len(payload))
	for i := range payload {
		masked[i] = payload[i] ^ mask[i&3]
	}
	frame = append(frame, masked...)

	if _, err := w.c.Write(frame); err != nil {
		t.Fatalf("write frame: %v", err)
	}
}

// readEvent returns the next text message, skipping the server's pings.
func (w *wsClient) readEvent(t *testing.T) map[string]any {
	t.Helper()
	for {
		if err := w.c.SetReadDeadline(time.Now().Add(15 * time.Second)); err != nil {
			t.Fatal(err)
		}
		var hdr [2]byte
		if _, err := io.ReadFull(w.br, hdr[:]); err != nil {
			t.Fatalf("read frame header: %v", err)
		}
		op := hdr[0] & 0x0F
		if hdr[1]&0x80 != 0 {
			t.Fatal("server frames must not be masked")
		}

		length := uint64(hdr[1] & 0x7F)
		switch length {
		case 126:
			var ext [2]byte
			if _, err := io.ReadFull(w.br, ext[:]); err != nil {
				t.Fatal(err)
			}
			length = uint64(binary.BigEndian.Uint16(ext[:]))
		case 127:
			var ext [8]byte
			if _, err := io.ReadFull(w.br, ext[:]); err != nil {
				t.Fatal(err)
			}
			length = binary.BigEndian.Uint64(ext[:])
		}

		payload := make([]byte, length)
		if _, err := io.ReadFull(w.br, payload); err != nil {
			t.Fatal(err)
		}

		switch op {
		case wsOpText:
			var decoded map[string]any
			if err := json.Unmarshal(payload, &decoded); err != nil {
				t.Fatalf("decode event %q: %v", payload, err)
			}
			return decoded
		case wsOpPing, wsOpPong:
			continue
		case wsOpClose:
			t.Fatal("bridge closed the control channel")
		default:
			t.Fatalf("unexpected opcode 0x%x", op)
		}
	}
}

// waitFor reads events until one has the wanted type.
func (w *wsClient) waitFor(t *testing.T, eventType string) map[string]any {
	t.Helper()
	for i := 0; i < 400; i++ {
		event := w.readEvent(t)
		if event["type"] == eventType {
			return event
		}
		if event["type"] == "error" && eventType != "error" {
			t.Fatalf("bridge reported error while waiting for %q: %v", eventType, event["message"])
		}
	}
	t.Fatalf("never saw a %q event", eventType)
	return nil
}

// auth presents a secret and waits for the catalog the bridge sends on success.
func (w *wsClient) auth(t *testing.T, secret string) map[string]any {
	t.Helper()
	w.writeText(t, fmt.Sprintf(`{"type":"auth","secret":%q}`, secret))
	return w.waitFor(t, "catalog")
}

// startBridge runs a bridge on an ephemeral port and returns its address.
func startBridge(t *testing.T, cfg BridgeConfig) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	root, err := filepath.Abs(cfg.Root)
	if err != nil {
		t.Fatal(err)
	}
	srv := &bridgeServer{cfg: cfg, root: root}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/ws", srv.handleWS)

	httpSrv := &http.Server{Handler: mux}
	go func() { _ = httpSrv.Serve(ln) }()
	t.Cleanup(func() { _ = httpSrv.Close() })

	return ln.Addr().String()
}

func TestBridgeHandshakeAndCatalog(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "notes.txt"), []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	// A dotted directory must stay out of the catalog.
	if err := os.MkdirAll(filepath.Join(root, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".git", "HEAD"), []byte("ref"), 0o644); err != nil {
		t.Fatal(err)
	}

	addr := startBridge(t, BridgeConfig{Root: root, Peers: []string{"10.0.0.5:8443"}})
	client := dialWS(t, addr)
	defer client.Close()

	hello := client.waitFor(t, "hello")
	if hello["version"] != bridgeVersion {
		t.Fatalf("unexpected version %v", hello["version"])
	}
	// No -secret was given, so this bridge cannot demand one.
	if hello["authRequired"] != false {
		t.Fatalf("authRequired was %v for a secretless bridge", hello["authRequired"])
	}

	client.writeText(t, `{"type":"list"}`)
	catalog := client.waitFor(t, "catalog")

	files, ok := catalog["files"].([]any)
	if !ok {
		t.Fatalf("catalog files had type %T", catalog["files"])
	}
	if len(files) != 1 {
		t.Fatalf("expected exactly 1 catalog file, got %d: %v", len(files), files)
	}
	first := files[0].(map[string]any)
	if first["path"] != "notes.txt" {
		t.Fatalf("expected notes.txt, got %v", first["path"])
	}

	peers, ok := catalog["peers"].([]any)
	if !ok || len(peers) != 1 {
		t.Fatalf("expected 1 peer, got %v", catalog["peers"])
	}
}

// TestBridgeRequiresSecret covers the gate that keeps a bridge from handing its
// root to anyone who can reach the port.
func TestBridgeRequiresSecret(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "notes.txt"), []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	addr := startBridge(t, BridgeConfig{Root: root, Secret: []byte("right")})

	t.Run("list before auth is refused", func(t *testing.T) {
		client := dialWS(t, addr)
		defer client.Close()
		hello := client.waitFor(t, "hello")
		if hello["authRequired"] != true {
			t.Fatalf("authRequired was %v, want true", hello["authRequired"])
		}

		client.writeText(t, `{"type":"list"}`)
		event := client.waitFor(t, "error")
		if msg, _ := event["message"].(string); !strings.Contains(msg, "authenticate first") {
			t.Fatalf("expected an auth refusal, got %q", msg)
		}
	})

	t.Run("wrong secret is refused", func(t *testing.T) {
		client := dialWS(t, addr)
		defer client.Close()
		client.waitFor(t, "hello")

		client.writeText(t, `{"type":"auth","secret":"wrong"}`)
		event := client.waitFor(t, "error")
		if msg, _ := event["message"].(string); !strings.Contains(msg, "wrong secret") {
			t.Fatalf("expected a secret refusal, got %q", msg)
		}

		// A failed attempt must not leave the session usable.
		client.writeText(t, `{"type":"list"}`)
		event = client.waitFor(t, "error")
		if msg, _ := event["message"].(string); !strings.Contains(msg, "authenticate first") {
			t.Fatalf("session opened after a failed auth: %q", msg)
		}
	})

	t.Run("right secret returns the catalog", func(t *testing.T) {
		client := dialWS(t, addr)
		defer client.Close()
		client.waitFor(t, "hello")

		catalog := client.auth(t, "right")
		files, ok := catalog["files"].([]any)
		if !ok || len(files) != 1 {
			t.Fatalf("expected 1 file after auth, got %v", catalog["files"])
		}
	})
}

func TestBridgeRejectsPathEscape(t *testing.T) {
	root := t.TempDir()
	secretDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(secretDir, "private.txt"), []byte("no"), 0o644); err != nil {
		t.Fatal(err)
	}

	addr := startBridge(t, BridgeConfig{Root: root, Secret: []byte("s")})
	client := dialWS(t, addr)
	defer client.Close()
	client.waitFor(t, "hello")
	client.auth(t, "s")

	cmd := map[string]any{
		"type":   "send",
		"to":     "127.0.0.1:1",
		"secret": "s",
		"paths":  []string{"../" + filepath.Base(secretDir) + "/private.txt"},
	}
	encoded, err := json.Marshal(cmd)
	if err != nil {
		t.Fatal(err)
	}
	client.writeText(t, string(encoded))

	event := client.waitFor(t, "error")
	message, _ := event["message"].(string)
	if !strings.Contains(message, "outside the bridge root") {
		t.Fatalf("expected a path-escape refusal, got %q", message)
	}
}

// TestBridgeDrivesTransfer is the app's real path: the control channel starts a
// transfer, reports progress, and the bytes land via the TLS engine.
func TestBridgeDrivesTransfer(t *testing.T) {
	secret := []byte("bridge-secret")
	root := t.TempDir()
	dst := t.TempDir()

	payload := bytes.Repeat([]byte("k"), int(3*ChunkSize)+17)
	if err := os.WriteFile(filepath.Join(root, "big.bin"), payload, 0o644); err != nil {
		t.Fatal(err)
	}

	serverTLS, _, err := buildTLS(secret)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", serverTLS)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	recvErr := make(chan error, 1)
	go func() {
		raw, err := ln.Accept()
		if err != nil {
			recvErr <- err
			return
		}
		recvErr <- handleConn(raw, dst)
	}()

	addr := startBridge(t, BridgeConfig{Root: root, Secret: secret})
	client := dialWS(t, addr)
	defer client.Close()
	client.waitFor(t, "hello")
	client.auth(t, string(secret))

	cmd := fmt.Sprintf(`{"type":"send","to":%q,"secret":%q,"paths":["big.bin"]}`, ln.Addr().String(), secret)
	client.writeText(t, cmd)

	done := client.waitFor(t, "done")
	if err := <-recvErr; err != nil {
		t.Fatalf("receiver: %v", err)
	}

	if files, _ := done["files"].(float64); files != 1 {
		t.Fatalf("expected 1 file in done event, got %v", done["files"])
	}
	if bytesSent, _ := done["bytes"].(float64); int64(bytesSent) != int64(len(payload)) {
		t.Fatalf("done reported %v bytes, want %d", done["bytes"], len(payload))
	}

	assertFile(t, filepath.Join(dst, "big.bin"), payload)
}
