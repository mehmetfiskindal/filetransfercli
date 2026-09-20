package internal

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// bridgeVersion is reported in the hello event so a mismatched app can say so
// instead of failing in a confusing way.
const bridgeVersion = "0.2.0"

// progressInterval throttles progress events. The phone only needs a readable
// bar; emitting one frame per 1 MiB chunk would spend the LAN on JSON.
const progressInterval = 100 * time.Millisecond

// BridgeConfig holds the bridge server's options.
type BridgeConfig struct {
	Addr    string   // HTTP listen address, e.g. ":8080"
	Root    string   // directory whose files the app may send
	WebRoot string   // optional built web app to serve at /
	Peers   []string // suggested receiver addresses, as host:port
	Secret  []byte   // default shared secret when the app does not supply one
}

// Bridge serves the mobile app's control channel.
//
// It is a control plane only: file bytes never pass through it. A `send`
// command runs the ordinary TLS transfer engine between this machine and the
// peer, and the bridge relays byte counters back to the app.
func Bridge(cfg BridgeConfig) error {
	root, err := filepath.Abs(cfg.Root)
	if err != nil {
		return err
	}
	srv := &bridgeServer{cfg: cfg, root: root}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/ws", srv.handleWS)
	mux.HandleFunc("/api/health", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "ok %s\n", bridgeVersion)
	})
	if cfg.WebRoot != "" {
		mux.Handle("/", http.FileServer(http.Dir(cfg.WebRoot)))
	}

	fmt.Printf("bridge listening on %s (root: %s)\n", cfg.Addr, root)
	if cfg.WebRoot != "" {
		fmt.Printf("serving app from %s\n", cfg.WebRoot)
	}
	if len(cfg.Secret) == 0 {
		fmt.Fprintf(os.Stderr,
			"warning: no -secret, so anyone who can reach %s may list %s and send its files. "+
				"Pass -secret to require the app to authenticate.\n", cfg.Addr, root)
	}

	httpSrv := &http.Server{
		Addr:    cfg.Addr,
		Handler: mux,
		// No WriteTimeout: a hijacked WebSocket outlives any request deadline,
		// and a transfer can legitimately run for hours.
		ReadHeaderTimeout: 10 * time.Second,
	}
	return httpSrv.ListenAndServe()
}

type bridgeServer struct {
	cfg  BridgeConfig
	root string
}

func (s *bridgeServer) handleWS(w http.ResponseWriter, r *http.Request) {
	ws, err := wsUpgrade(w, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	defer ws.Close()

	sess := &session{srv: s, ws: ws}
	sess.run()
}

// session is one connected app.
type session struct {
	srv *bridgeServer
	ws  *wsConn

	mu       sync.Mutex
	cancel   context.CancelFunc
	busy     bool
	nextID   int64
	activeID int64

	// authed gates every command that touches the filesystem. A bridge started
	// without -secret has nothing to check, so those sessions start open.
	authed bool
}

func (sess *session) run() {
	host, _ := os.Hostname()
	sess.authed = len(sess.srv.cfg.Secret) == 0
	sess.emit(map[string]any{
		"type":         "hello",
		"host":         host,
		"version":      bridgeVersion,
		"root":         sess.srv.root,
		"chunkSize":    ChunkSize,
		"canStream":    false,
		"authRequired": !sess.authed,
	})

	// Ping so a phone that left WiFi without a close handshake is noticed and
	// its transfer context cancelled, rather than lingering forever.
	stopPing := make(chan struct{})
	defer close(stopPing)
	go func() {
		ticker := time.NewTicker(20 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if err := sess.ws.WritePing(); err != nil {
					return
				}
			case <-stopPing:
				return
			}
		}
	}()

	for {
		text, err := sess.ws.ReadText()
		if err != nil {
			// The client is gone, so cancel whatever it left running.
			sess.abort(0)
			return
		}
		sess.dispatch(text)
	}
}

// command is the decoded shape of every app->bridge message.
type command struct {
	Type   string   `json:"type"`
	To     string   `json:"to"`
	Secret string   `json:"secret"`
	Paths  []string `json:"paths"`
	ID     int64    `json:"id"`
}

func (sess *session) dispatch(text string) {
	var cmd command
	if err := json.Unmarshal([]byte(text), &cmd); err != nil {
		sess.fail(fmt.Sprintf("bad command: %v", err))
		return
	}

	// auth is the only command answered before the client proves it knows the
	// secret; otherwise reaching the port would be enough to read the root.
	if cmd.Type == "auth" {
		sess.authenticate(cmd.Secret)
		return
	}
	if !sess.authed {
		sess.fail("authenticate first")
		return
	}

	switch cmd.Type {
	case "list":
		sess.sendCatalog()
	case "send":
		sess.startSend(cmd)
	case "cancel":
		sess.abort(cmd.ID)
	default:
		sess.fail(fmt.Sprintf("unknown command %q", cmd.Type))
	}
}

// authenticate checks the app's secret against the bridge's and, on success,
// answers with the catalog so a connect costs one round trip.
func (sess *session) authenticate(secret string) {
	want := sess.srv.cfg.Secret
	if len(want) > 0 && subtle.ConstantTimeCompare([]byte(secret), want) != 1 {
		sess.fail("wrong secret for this bridge")
		return
	}
	sess.authed = true
	sess.sendCatalog()
}

func (sess *session) sendCatalog() {
	files, err := listRoot(sess.srv.root)
	if err != nil {
		sess.fail(err.Error())
		return
	}
	peers := make([]map[string]string, 0, len(sess.srv.cfg.Peers))
	for _, addr := range sess.srv.cfg.Peers {
		peers = append(peers, map[string]string{"addr": addr, "label": addr})
	}
	sess.emit(map[string]any{
		"type":  "catalog",
		"root":  sess.srv.root,
		"files": files,
		"peers": peers,
	})
}

func (sess *session) startSend(cmd command) {
	sess.mu.Lock()
	if sess.busy {
		sess.mu.Unlock()
		sess.fail("a transfer is already running")
		return
	}
	if len(cmd.Paths) == 0 {
		sess.mu.Unlock()
		sess.fail("no paths selected")
		return
	}

	secret := []byte(cmd.Secret)
	if len(secret) == 0 {
		secret = sess.srv.cfg.Secret
	}
	if len(secret) == 0 {
		sess.mu.Unlock()
		sess.fail("no shared secret: set one in the app or start the bridge with -secret")
		return
	}

	// Resolve every requested path against the bridge root and refuse anything
	// that escapes it, so a crafted command cannot read the whole filesystem.
	abs := make([]string, 0, len(cmd.Paths))
	for _, p := range cmd.Paths {
		full := filepath.Join(sess.srv.root, filepath.FromSlash(p))
		if !withinDir(sess.srv.root, full) {
			sess.mu.Unlock()
			sess.fail(fmt.Sprintf("refusing path outside the bridge root: %q", p))
			return
		}
		abs = append(abs, full)
	}

	ctx, cancel := context.WithCancel(context.Background())
	sess.cancel = cancel
	sess.busy = true
	sess.nextID++
	id := sess.nextID
	sess.activeID = id
	sess.mu.Unlock()

	obs := newWSObserver(sess, id)

	go func() {
		defer cancel()
		err := Send(SendConfig{
			To:       cmd.To,
			Secret:   secret,
			Paths:    abs,
			Ctx:      ctx,
			Observer: obs,
			Quiet:    true,
		})

		sess.mu.Lock()
		sess.busy = false
		sess.cancel = nil
		sess.activeID = 0
		sess.mu.Unlock()

		if err != nil {
			obs.flush()
			sess.fail(err.Error())
		}
	}()
}

// abort cancels the in-flight transfer, but only if the client is asking about
// that transfer. A cancel tap can be in flight while the current transfer
// finishes and the next one starts; without the id check that stale tap would
// kill the new transfer. id 0 means "whatever is running" for clients that do
// not track ids.
func (sess *session) abort(id int64) {
	sess.mu.Lock()
	cancel := sess.cancel
	if id != 0 && id != sess.activeID {
		cancel = nil
	}
	sess.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (sess *session) emit(payload map[string]any) {
	encoded, err := json.Marshal(payload)
	if err != nil {
		return
	}
	_ = sess.ws.WriteText(string(encoded))
}

func (sess *session) fail(message string) {
	sess.emit(map[string]any{"type": "error", "message": message})
}

// catalogFile is one entry in the app's file list.
type catalogFile struct {
	Path    string `json:"path"`
	Size    int64  `json:"size"`
	ModTime int64  `json:"modTime"`
}

// listRoot walks root and returns its regular files, newest first, with
// slash-separated paths relative to root.
func listRoot(root string) ([]catalogFile, error) {
	var files []catalogFile
	err := filepath.Walk(root, func(path string, info os.FileInfo, werr error) error {
		if werr != nil {
			// A single unreadable subtree should not fail the whole listing.
			if info != nil && info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if info.IsDir() {
			// Skip dotted directories: node_modules-style noise and VCS
			// metadata are never what someone taps to send from a phone.
			if path != root && filepath.Base(path)[0] == '.' {
				return filepath.SkipDir
			}
			return nil
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return nil
		}
		files = append(files, catalogFile{
			Path:    filepath.ToSlash(rel),
			Size:    info.Size(),
			ModTime: info.ModTime().Unix(),
		})
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(files, func(i, j int) bool {
		if files[i].ModTime != files[j].ModTime {
			return files[i].ModTime > files[j].ModTime
		}
		return files[i].Path < files[j].Path
	})
	return files, nil
}

// itemState tracks one file's counters for the progress event.
type itemState struct {
	Path    string
	State   string
	Sent    int64
	Total   int64
	Resumed int64
	Error   string
	rate    float64
	begun   time.Time
}

// wsObserver turns engine callbacks into throttled progress events.
type wsObserver struct {
	sess *session
	id   int64

	mu       sync.Mutex
	order    []string
	items    map[string]*itemState
	total    int64
	sent     int64
	start    time.Time
	lastEmit time.Time
}

func newWSObserver(sess *session, id int64) *wsObserver {
	return &wsObserver{
		sess:  sess,
		id:    id,
		items: map[string]*itemState{},
		start: time.Now(),
	}
}

func (o *wsObserver) Plan(items []PlanItem) {
	o.mu.Lock()
	for _, it := range items {
		state := "queued"
		sent := int64(0)
		resumed := int64(0)
		if it.Resume < 0 {
			state = "skipped"
			sent = it.Size
		} else {
			resumed = it.Resume
			sent = it.Resume
			o.total += it.Size - it.Resume
		}
		o.items[it.Path] = &itemState{
			Path:    it.Path,
			State:   state,
			Sent:    sent,
			Total:   it.Size,
			Resumed: resumed,
		}
		o.order = append(o.order, it.Path)
	}
	o.mu.Unlock()
	o.flush()
}

func (o *wsObserver) FileBegin(path string, offset, size int64) {
	o.mu.Lock()
	if it, ok := o.items[path]; ok {
		it.State = "running"
		it.begun = time.Now()
	}
	o.mu.Unlock()
	o.flush()
}

func (o *wsObserver) FileProgress(path string, sent int64) {
	o.mu.Lock()
	it, ok := o.items[path]
	if ok {
		delta := sent - it.Sent
		if delta > 0 {
			o.sent += delta
		}
		it.Sent = sent
		if elapsed := time.Since(it.begun).Seconds(); elapsed > 0 {
			it.rate = float64(sent-it.Resumed) / elapsed
		}
	}
	due := time.Since(o.lastEmit) >= progressInterval
	o.mu.Unlock()
	if due {
		o.flush()
	}
}

func (o *wsObserver) FileEnd(path string, err error) {
	o.mu.Lock()
	if it, ok := o.items[path]; ok {
		if err != nil {
			it.State = "failed"
			it.Error = err.Error()
		} else {
			it.State = "done"
			it.Sent = it.Total
		}
	}
	o.mu.Unlock()
	o.flush()
}

func (o *wsObserver) Finish(files int, bytes int64, elapsed time.Duration) {
	o.flush()
	o.sess.emit(map[string]any{
		"type":    "done",
		"id":      o.id,
		"files":   files,
		"bytes":   bytes,
		"seconds": elapsed.Seconds(),
	})
}

// flush emits the current counters as one progress event.
func (o *wsObserver) flush() {
	o.mu.Lock()
	o.lastEmit = time.Now()

	items := make([]map[string]any, 0, len(o.order))
	for _, path := range o.order {
		it := o.items[path]
		items = append(items, map[string]any{
			"id":             o.id,
			"path":           it.Path,
			"state":          it.State,
			"sent":           it.Sent,
			"total":          it.Total,
			"resumed":        it.Resumed,
			"bytesPerSecond": int64(it.rate),
			"error":          it.Error,
		})
	}

	overall := float64(0)
	if secs := time.Since(o.start).Seconds(); secs > 0 {
		overall = float64(o.sent) / secs
	}
	payload := map[string]any{
		"type":           "progress",
		"items":          items,
		"sent":           o.sent,
		"total":          o.total,
		"bytesPerSecond": int64(overall),
	}
	o.mu.Unlock()

	o.sess.emit(payload)
}

// ensure the bridge's observer satisfies the engine's interface.
var _ Observer = (*wsObserver)(nil)
