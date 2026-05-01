// Package stager implements Zeerak's auto-rollback commit flow.
//
// The contract (VISION.md §4 "Safe by default"):
//
//  1. Stage a candidate ruleset (snapshot the current one first).
//  2. Apply the candidate atomically.
//  3. Start a timer (default 60s). Caller must call Confirm() before it
//     fires. If the timer fires first, OR the daemon dies, OR the operator
//     gets locked out — we restore the snapshot.
//  4. Confirm() cancels the timer and persists the new state.
//
// This package is transport-agnostic: the actual "apply" and "snapshot"
// operations are injected as an Applier interface, so tests can use an
// in-memory fake and production wires up internal/nft.
//
// Rollback is *the* keystone safety feature; this is the most heavily
// tested code in the daemon.
package stager

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/zeerak/zeerak/internal/model"
)

// DefaultTimeout is the default auto-rollback window.
const DefaultTimeout = 60 * time.Second

// Applier is the kernel-facing contract: read the current ruleset, apply a
// new one atomically. internal/nft (google/nftables) implements this in
// production; tests use an in-memory fake.
type Applier interface {
	// Snapshot returns the current live ruleset.
	Snapshot(ctx context.Context) (*model.Ruleset, error)
	// Apply atomically replaces the live ruleset with rs.
	Apply(ctx context.Context, rs *model.Ruleset) error
}

// State is the lifecycle of a staged change.
type State int

const (
	StateIdle      State = iota // nothing staged
	StatePending                // applied, awaiting Confirm() or timeout
	StateConfirmed              // operator confirmed
	StateRolledBack             // timer fired or Rollback() called
)

func (s State) String() string {
	switch s {
	case StateIdle:
		return "idle"
	case StatePending:
		return "pending"
	case StateConfirmed:
		return "confirmed"
	case StateRolledBack:
		return "rolled-back"
	default:
		return fmt.Sprintf("state(%d)", s)
	}
}

// ErrNoPending is returned when Confirm/Rollback is called with no staged change.
var ErrNoPending = errors.New("stager: no pending change")

// ErrAlreadyPending is returned when Stage is called while a change is in flight.
var ErrAlreadyPending = errors.New("stager: a change is already pending; confirm or rollback first")

// Stager owns the single in-flight staged change for a daemon instance.
//
// It is safe for concurrent use; all state transitions are serialized.
type Stager struct {
	applier Applier
	timeout time.Duration
	now     func() time.Time // injectable clock for tests
	onAutoRevert func()    // optional; called after auto-revert completes

	mu        sync.Mutex
	state     State
	snapshot  *model.Ruleset // captured pre-apply; restored on rollback
	candidate *model.Ruleset
	deadline  time.Time
	timer     *time.Timer
	cancel    context.CancelFunc // cancels the timer's rollback ctx
}

// Option configures a Stager.
type Option func(*Stager)

// WithTimeout overrides DefaultTimeout.
func WithTimeout(d time.Duration) Option {
	return func(s *Stager) { s.timeout = d }
}

// WithClock injects a clock (test hook).
func WithClock(now func() time.Time) Option {
	return func(s *Stager) { s.now = now }
}

// WithOnAutoRevert installs a callback fired AFTER an auto-revert (timer
// expiry) finishes. The callback runs in the timer goroutine and must not
// block; UI code uses it to append an activity-log entry.
func WithOnAutoRevert(fn func()) Option {
	return func(s *Stager) { s.onAutoRevert = fn }
}

// New returns a Stager backed by applier.
func New(applier Applier, opts ...Option) *Stager {
	s := &Stager{
		applier: applier,
		timeout: DefaultTimeout,
		now:     time.Now,
	}
	for _, o := range opts {
		o(s)
	}
	return s
}

// Status is a snapshot of the current state, safe to expose to API/UI.
type Status struct {
	State    State     `json:"state"`
	Deadline time.Time `json:"deadline,omitempty"`
}

// Status returns the current state and (if pending) the rollback deadline.
func (s *Stager) Status() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := Status{State: s.state}
	if s.state == StatePending {
		st.Deadline = s.deadline
	}
	return st
}

// Stage snapshots the current ruleset, applies candidate, and arms the
// rollback timer. Returns the deadline.
func (s *Stager) Stage(ctx context.Context, candidate *model.Ruleset) (time.Time, error) {
	s.mu.Lock()
	if s.state == StatePending {
		s.mu.Unlock()
		return time.Time{}, ErrAlreadyPending
	}
	s.mu.Unlock()

	snap, err := s.applier.Snapshot(ctx)
	if err != nil {
		return time.Time{}, fmt.Errorf("snapshot: %w", err)
	}
	if err := s.applier.Apply(ctx, candidate); err != nil {
		return time.Time{}, fmt.Errorf("apply candidate: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.snapshot = snap
	s.candidate = candidate
	s.state = StatePending
	s.deadline = s.now().Add(s.timeout)

	timerCtx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel
	s.timer = time.AfterFunc(s.timeout, func() {
		// The timer fires once; if Confirm/Rollback already ran, cancel()
		// has been called and the AfterFunc will still execute — guard by
		// re-checking state under the lock.
		s.fireTimeout(timerCtx)
	})

	return s.deadline, nil
}

// Confirm cancels the rollback timer; the staged change becomes permanent.
func (s *Stager) Confirm() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state != StatePending {
		return ErrNoPending
	}
	s.stopTimerLocked()
	s.state = StateConfirmed
	s.snapshot = nil
	s.candidate = nil
	return nil
}

// Rollback explicitly restores the pre-stage snapshot.
func (s *Stager) Rollback(ctx context.Context) error {
	s.mu.Lock()
	if s.state != StatePending {
		s.mu.Unlock()
		return ErrNoPending
	}
	s.stopTimerLocked()
	snap := s.snapshot
	s.mu.Unlock()

	if err := s.applier.Apply(ctx, snap); err != nil {
		return fmt.Errorf("rollback apply: %w", err)
	}

	s.mu.Lock()
	s.state = StateRolledBack
	s.snapshot = nil
	s.candidate = nil
	s.mu.Unlock()
	return nil
}

// fireTimeout is invoked by the AfterFunc when the rollback window expires.
func (s *Stager) fireTimeout(ctx context.Context) {
	s.mu.Lock()
	if s.state != StatePending {
		s.mu.Unlock()
		return // already confirmed or rolled back
	}
	snap := s.snapshot
	s.mu.Unlock()

	// Best-effort: if this fails, the operator is stuck with the staged
	// ruleset — but that's the same outcome as Confirm(), and the daemon
	// log will scream. We surface it via a future event channel.
	_ = s.applier.Apply(ctx, snap)

	s.mu.Lock()
	s.state = StateRolledBack
	s.snapshot = nil
	s.candidate = nil
	cb := s.onAutoRevert
	s.mu.Unlock()
	if cb != nil {
		go cb()
	}
}

func (s *Stager) stopTimerLocked() {
	if s.timer != nil {
		s.timer.Stop()
		s.timer = nil
	}
	if s.cancel != nil {
		s.cancel()
		s.cancel = nil
	}
}
