package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zeerak/zeerak/internal/model"
	"github.com/zeerak/zeerak/internal/stager"
)

// fakeApplier is a deterministic in-memory Applier+Reader for tests.
type fakeApplier struct {
	mu      sync.Mutex
	current *model.Ruleset
	applies int

	// Pre-canned live text for /ruleset/live and /preview.
	liveText  string
	liveTable map[string]string // key = "family name"
}

func (f *fakeApplier) Snapshot(_ context.Context) (*model.Ruleset, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.current == nil {
		return &model.Ruleset{}, nil
	}
	cp := *f.current
	return &cp, nil
}

func (f *fakeApplier) Apply(_ context.Context, rs *model.Ruleset) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.applies++
	f.current = rs
	return nil
}

func (f *fakeApplier) LiveText(_ context.Context) (string, error) {
	return f.liveText, nil
}

func (f *fakeApplier) LiveTable(_ context.Context, family model.Family, name string) (string, error) {
	return f.liveTable[string(family)+" "+name], nil
}

func newTestServer(t *testing.T, opts ...stager.Option) (*Server, *fakeApplier) {
	t.Helper()
	a := &fakeApplier{liveTable: map[string]string{}}
	s := New(stager.New(a, opts...), a, nil, "test")
	return s, a
}

func do(t *testing.T, h http.Handler, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

const stageYAML = `
version: 1
tables:
  - family: inet
    name: zeerak-test
    chains:
      - name: input
        type: filter
        hook: input
        priority: 0
        policy: drop
`

func TestHealthz(t *testing.T) {
	s, _ := newTestServer(t)
	rec := do(t, s.Handler(), "GET", "/healthz", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("healthz: got %d, want 200", rec.Code)
	}
}

func TestStatus_Idle(t *testing.T) {
	s, _ := newTestServer(t)
	rec := do(t, s.Handler(), "GET", "/status", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d", rec.Code)
	}
	var got statusDTO
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.State != "idle" {
		t.Fatalf("state=%q, want idle", got.State)
	}
}

func TestStageConfirmFlow(t *testing.T) {
	s, applier := newTestServer(t, stager.WithTimeout(time.Hour))
	h := s.Handler()

	rec := do(t, h, "POST", "/stage", stageYAML)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("stage: got %d, body=%s", rec.Code, rec.Body.String())
	}
	if applier.applies != 1 {
		t.Fatalf("applies after stage: %d, want 1", applier.applies)
	}

	rec = do(t, h, "GET", "/status", "")
	if !bytes.Contains(rec.Body.Bytes(), []byte(`"pending"`)) {
		t.Fatalf("status not pending: %s", rec.Body.String())
	}

	rec = do(t, h, "POST", "/confirm", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("confirm: got %d", rec.Code)
	}

	// Confirm without a pending change is 409.
	rec = do(t, h, "POST", "/confirm", "")
	if rec.Code != http.StatusConflict {
		t.Fatalf("second confirm: got %d, want 409", rec.Code)
	}
}

func TestStageRollback(t *testing.T) {
	s, applier := newTestServer(t, stager.WithTimeout(time.Hour))
	h := s.Handler()

	if rec := do(t, h, "POST", "/stage", stageYAML); rec.Code != http.StatusAccepted {
		t.Fatalf("stage: %d", rec.Code)
	}
	if rec := do(t, h, "POST", "/rollback", ""); rec.Code != http.StatusOK {
		t.Fatalf("rollback: %d", rec.Code)
	}
	// Apply runs twice: once for stage, once to restore the snapshot.
	if applier.applies != 2 {
		t.Fatalf("applies: %d, want 2", applier.applies)
	}
}

func TestStageInvalidYAML(t *testing.T) {
	s, _ := newTestServer(t)
	rec := do(t, s.Handler(), "POST", "/stage", "version: 99\n")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("got %d, want 400", rec.Code)
	}
}

func TestStageDoubleStageConflict(t *testing.T) {
	s, _ := newTestServer(t, stager.WithTimeout(time.Hour))
	h := s.Handler()
	if rec := do(t, h, "POST", "/stage", stageYAML); rec.Code != http.StatusAccepted {
		t.Fatalf("first stage: %d", rec.Code)
	}
	rec := do(t, h, "POST", "/stage", stageYAML)
	if rec.Code != http.StatusConflict {
		t.Fatalf("second stage: got %d, want 409", rec.Code)
	}
}

func TestMethodNotAllowed(t *testing.T) {
	s, _ := newTestServer(t)
	rec := do(t, s.Handler(), "GET", "/stage", "")
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("got %d, want 405", rec.Code)
	}
}

func TestRulesetLive(t *testing.T) {
	s, a := newTestServer(t)
	a.liveText = "table inet filter { }\n"
	rec := do(t, s.Handler(), "GET", "/ruleset/live", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d", rec.Code)
	}
	var got map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got["text"] != a.liveText {
		t.Fatalf("text=%q, want %q", got["text"], a.liveText)
	}
}

func TestPreview_DiffAgainstLive(t *testing.T) {
	s, a := newTestServer(t)
	// Pretend the kernel has an older version of zeerak-presets without ssh.
	a.liveTable["inet zeerak-presets"] = "table inet zeerak-presets {\n\tchain input {\n\t\ttype filter hook input priority 0; policy drop;\n\t}\n}\n"

	rec := do(t, s.Handler(), "POST", "/preview", stageYAML)
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d, body=%s", rec.Code, rec.Body.String())
	}
	var got map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got["rendered"] == "" {
		t.Fatal("rendered missing")
	}
	if got["diff"] == "" {
		t.Fatalf("diff missing; live=%q rendered=%q", got["live"], got["rendered"])
	}
	if !bytes.Contains([]byte(got["diff"]), []byte("--- live\n+++ candidate")) {
		t.Fatalf("diff header wrong: %q", got["diff"])
	}
}

func TestPreview_NoMutation(t *testing.T) {
	s, a := newTestServer(t)
	if rec := do(t, s.Handler(), "POST", "/preview", stageYAML); rec.Code != http.StatusOK {
		t.Fatalf("preview: %d", rec.Code)
	}
	if a.applies != 0 {
		t.Fatalf("preview applied %d times, want 0", a.applies)
	}
	if got := s.stg.Status().State.String(); got != "idle" {
		t.Fatalf("state=%q, want idle", got)
	}
}

func TestPreview_InvalidYAML(t *testing.T) {
	s, _ := newTestServer(t)
	rec := do(t, s.Handler(), "POST", "/preview", "version: 99\n")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("got %d, want 400", rec.Code)
	}
}
