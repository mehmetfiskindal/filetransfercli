package internal

import (
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// progress renders a single-line progress indicator. When stdout is a
// terminal it updates in place with \r; otherwise it stays silent so that
// piped/redirected output is not polluted.
type progress struct {
	total   int64
	done    int64
	current string

	mu     sync.Mutex
	start  time.Time
	last   time.Time
	term   bool
	w      io.Writer
	active bool
}

func newProgress(total int64, w io.Writer) *progress {
	return &progress{
		total: total,
		start: time.Now(),
		term:  isTerminal(w),
		w:     w,
	}
}

func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

func (p *progress) setCurrent(name string) {
	p.mu.Lock()
	p.current = name
	p.mu.Unlock()
	p.render(true)
}

func (p *progress) add(n int64) {
	p.mu.Lock()
	p.done += n
	p.mu.Unlock()
	p.render(false)
}

func (p *progress) render(force bool) {
	if !p.term {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if !force && time.Since(p.last) < 100*time.Millisecond {
		return
	}
	p.last = time.Now()

	frac := 0.0
	if p.total > 0 {
		frac = float64(p.done) / float64(p.total)
	}
	rate := float64(p.done) / time.Since(p.start).Seconds()

	fmt.Fprintf(p.w, "\r\033[K%s  %s / %s  (%5.1f%%)  %s/s",
		p.current,
		humanBytes(p.done),
		humanBytes(p.total),
		frac*100,
		humanBytes(int64(rate)),
	)
}

// finish finalizes the progress line. On a terminal it leaves a newline;
// otherwise it reports a single summary line.
func (p *progress) finish() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.term {
		fmt.Fprint(p.w, "\n")
	} else {
		fmt.Fprintf(p.w, "transferred %s in %s\n", humanBytes(p.done), time.Since(p.start).Round(time.Millisecond))
	}
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGTPE"[exp])
}
