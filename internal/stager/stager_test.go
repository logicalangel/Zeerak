package stager

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zeerak/zeerak/internal/model"
)

// fakeApplier is an in-memory Applier for tests.
type fakeApplier struct {
	mu      sync.Mutex
	current *model.Ruleset
	applies int32
	failApply error
}

func (f *fakeApplier) Snapshot(ctx context.Context) (*model.Ruleset, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.current == nil {
		return &model.Ruleset{}, nil
	}
	cp := *f.current
	return &cp, nil
}

func (f *fakeApplier) Apply(ctx context.Context, rs *model.Ruleset) error {
	atomic.AddInt32(&f.applies, 1)
	if f.failApply != nil {
		return f.failApply
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := *rs
	f.current = &cp
	return nil
}

func tableNamed(name string) *model.Ruleset {
	return &model.Ruleset{Tables: []model.Table{{Family: model.FamilyINet, Name: name, Owned: true}}}
}

func TestStager_ConfirmKeepsCandidate(t *testing.T) {
	app := &fakeApplier{current: tableNamed("before")}
	s := New(app, WithTimeout(50*time.Millisecond))

	if _, err := s.Stage(context.Background(), tableNamed("after")); err != nil {
		t.Fatalf("stage: %v", err)
	}
	if got := s.Status().State; got != StatePending {
		t.Fatalf("state=%s, want pending", got)
	}
	if err := s.Confirm(); err != nil {
		t.Fatalf("confirm: %v", err)
	}
	if got := s.Status().State; got != StateConfirmed {
		t.Fatalf("state=%s, want confirmed", got)
	}
	// Wait past the would-be deadline; no extra Apply should fire.
	time.Sleep(120 * time.Millisecond)
	if got := atomic.LoadInt32(&app.applies); got != 1 {
		t.Errorf("applies=%d, want 1 (confirm should cancel timer)", got)
	}
	if app.current.Tables[0].Name != "after" {
		t.Errorf("current=%q, want after", app.current.Tables[0].Name)
	}
}

func TestStager_TimeoutRollsBack(t *testing.T) {
	app := &fakeApplier{current: tableNamed("before")}
	s := New(app, WithTimeout(20*time.Millisecond))

	if _, err := s.Stage(context.Background(), tableNamed("after")); err != nil {
		t.Fatalf("stage: %v", err)
	}
	// Wait for the timer to fire and rollback to apply.
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if s.Status().State == StateRolledBack {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if got := s.Status().State; got != StateRolledBack {
		t.Fatalf("state=%s, want rolled-back", got)
	}
	if app.current.Tables[0].Name != "before" {
		t.Errorf("current=%q, want before (rollback restores snapshot)", app.current.Tables[0].Name)
	}
	// Apply count: 1 stage + 1 rollback.
	if got := atomic.LoadInt32(&app.applies); got != 2 {
		t.Errorf("applies=%d, want 2", got)
	}
}

func TestStager_ExplicitRollback(t *testing.T) {
	app := &fakeApplier{current: tableNamed("before")}
	s := New(app, WithTimeout(time.Hour)) // long timeout; we cancel manually

	if _, err := s.Stage(context.Background(), tableNamed("after")); err != nil {
		t.Fatalf("stage: %v", err)
	}
	if err := s.Rollback(context.Background()); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if got := s.Status().State; got != StateRolledBack {
		t.Fatalf("state=%s, want rolled-back", got)
	}
	if app.current.Tables[0].Name != "before" {
		t.Errorf("current=%q, want before", app.current.Tables[0].Name)
	}
}

func TestStager_DoubleStageRejected(t *testing.T) {
	app := &fakeApplier{current: tableNamed("before")}
	s := New(app, WithTimeout(time.Hour))

	if _, err := s.Stage(context.Background(), tableNamed("a")); err != nil {
		t.Fatalf("stage 1: %v", err)
	}
	_, err := s.Stage(context.Background(), tableNamed("b"))
	if !errors.Is(err, ErrAlreadyPending) {
		t.Fatalf("stage 2 err=%v, want ErrAlreadyPending", err)
	}
}

func TestStager_ConfirmWithoutPending(t *testing.T) {
	s := New(&fakeApplier{})
	if err := s.Confirm(); !errors.Is(err, ErrNoPending) {
		t.Fatalf("confirm err=%v, want ErrNoPending", err)
	}
	if err := s.Rollback(context.Background()); !errors.Is(err, ErrNoPending) {
		t.Fatalf("rollback err=%v, want ErrNoPending", err)
	}
}
