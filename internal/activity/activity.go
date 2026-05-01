// Package activity records human-readable timeline events for the web panel.
//
// The activity log answers "what's been happening to my firewall?" without
// asking the user to read syslog or a ruleset diff. Entries are short
// English sentences ("You opened SSH from 2 networks", "System auto-reverted
// a change") with a UTC timestamp.
//
// Storage is an append-only JSONL file (one event per line). No database.
// Rotation is naive: when the file grows past MaxBytes the oldest half is
// dropped on the next append. That's fine for a v0.3 panel — typical hosts
// emit a handful of events per week, and the timeline UI only renders the
// most recent ~50.
//
// Concurrency: a single *Logger is safe for concurrent Append/Recent.
package activity

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// MaxBytes is the soft cap before the log gets compacted. ~256 KiB ≈ 1500
// short events, more than enough for a single host's panel timeline.
const MaxBytes int64 = 256 * 1024

// Kind is a small enum of event categories. UI templates style each kind
// with its own icon + tone (info / success / warn).
type Kind string

const (
	KindStaged    Kind = "staged"
	KindConfirmed Kind = "confirmed"
	KindReverted  Kind = "reverted"      // explicit user revert
	KindAutoRevert Kind = "auto-revert"  // timer expired, system rolled back
	KindBoot      Kind = "boot"
)

// Event is a single timeline entry. Message is the rendered sentence; Detail
// is an optional one-liner (e.g. "SSH open from 2 networks").
type Event struct {
	Time    time.Time `json:"time"`
	Kind    Kind      `json:"kind"`
	Message string    `json:"message"`
	Detail  string    `json:"detail,omitempty"`
}

// Logger appends events to a JSONL file. The zero value is unusable; use New.
type Logger struct {
	path string
	mu   sync.Mutex
}

// New opens (or creates) the log at path. Parent directories are created.
// The file is created with 0640 permissions (owner+group read, no world).
func New(path string) (*Logger, error) {
	if path == "" {
		return nil, errors.New("activity: empty path")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, fmt.Errorf("activity: mkdir: %w", err)
	}
	// Touch the file so subsequent Recent() calls don't ENOENT.
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
	if err != nil {
		return nil, fmt.Errorf("activity: open: %w", err)
	}
	_ = f.Close()
	return &Logger{path: path}, nil
}

// Append writes one event. Errors are returned (caller usually logs &
// continues — losing a timeline entry must never break a stage/confirm).
func (l *Logger) Append(ev Event) error {
	if ev.Time.IsZero() {
		ev.Time = time.Now().UTC()
	} else {
		ev.Time = ev.Time.UTC()
	}
	if ev.Kind == "" {
		return errors.New("activity: empty kind")
	}
	line, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("activity: marshal: %w", err)
	}
	line = append(line, '\n')

	l.mu.Lock()
	defer l.mu.Unlock()

	if err := l.maybeCompactLocked(); err != nil {
		// Compaction failure is non-fatal — fall through and try to append.
		_ = err
	}

	f, err := os.OpenFile(l.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
	if err != nil {
		return fmt.Errorf("activity: open: %w", err)
	}
	defer f.Close()
	if _, err := f.Write(line); err != nil {
		return fmt.Errorf("activity: write: %w", err)
	}
	return nil
}

// Recent returns up to n most-recent events, newest first. Bad lines are
// skipped silently (the file is append-only and operator-readable; we don't
// want one corrupt line to nuke the whole timeline).
func (l *Logger) Recent(n int) ([]Event, error) {
	if n <= 0 {
		return nil, nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	f, err := os.Open(l.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("activity: open: %w", err)
	}
	defer f.Close()

	var all []Event
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 4096), 64*1024)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var ev Event
		if err := json.Unmarshal(line, &ev); err != nil {
			continue
		}
		all = append(all, ev)
	}
	if err := sc.Err(); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("activity: scan: %w", err)
	}

	// Reverse: newest first.
	out := make([]Event, 0, n)
	for i := len(all) - 1; i >= 0 && len(out) < n; i-- {
		out = append(out, all[i])
	}
	return out, nil
}

// maybeCompactLocked drops the oldest half of the file when it exceeds
// MaxBytes. Caller must hold l.mu.
func (l *Logger) maybeCompactLocked() error {
	st, err := os.Stat(l.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if st.Size() <= MaxBytes {
		return nil
	}

	src, err := os.Open(l.path)
	if err != nil {
		return err
	}
	defer src.Close()

	// Read all lines, then keep the newer half.
	var lines [][]byte
	sc := bufio.NewScanner(src)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		b := make([]byte, len(sc.Bytes()))
		copy(b, sc.Bytes())
		lines = append(lines, b)
	}
	if len(lines) < 2 {
		// Corrupt or single mega-line: cannot keep "the newer half"
		// sensibly. Truncate to recover bounded size.
		return os.Truncate(l.path, 0)
	}
	keep := lines[len(lines)/2:]

	tmp := l.path + ".tmp"
	w, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o640)
	if err != nil {
		return err
	}
	for _, ln := range keep {
		if _, err := w.Write(append(ln, '\n')); err != nil {
			_ = w.Close()
			_ = os.Remove(tmp)
			return err
		}
	}
	if err := w.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, l.path)
}
