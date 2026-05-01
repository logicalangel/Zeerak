package ui

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/zeerak/zeerak/internal/model"
	"github.com/zeerak/zeerak/internal/stager"
)

// fakeBackend implements stager.Applier + ui.Reader for tests.
type fakeBackend struct {
	mu        sync.Mutex
	current   *model.Ruleset
	liveText  string
	liveTable map[string]string
}

func (f *fakeBackend) Snapshot(_ context.Context) (*model.Ruleset, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.current == nil {
		return &model.Ruleset{}, nil
	}
	cp := *f.current
	return &cp, nil
}
func (f *fakeBackend) Apply(_ context.Context, rs *model.Ruleset) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.current = rs
	return nil
}
func (f *fakeBackend) LiveText(_ context.Context) (string, error) { return f.liveText, nil }
func (f *fakeBackend) LiveTable(_ context.Context, fam model.Family, n string) (string, error) {
	return f.liveTable[string(fam)+" "+n], nil
}

func newTestHandler(t *testing.T) (*Handler, *http.ServeMux, *fakeBackend) {
	t.Helper()
	be := &fakeBackend{liveTable: map[string]string{}}
	stg := stager.New(be)
	h, err := New(stg, be, nil, "test")
	if err != nil {
		t.Fatalf("ui.New: %v", err)
	}
	mux := http.NewServeMux()
	h.Register(mux)
	return h, mux, be
}

func do(t *testing.T, mux http.Handler, method, target string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	var req *http.Request
	if form != nil {
		req = httptest.NewRequest(method, target, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		req = httptest.NewRequest(method, target, nil)
	}
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	return rr
}

func TestDashboard(t *testing.T) {
	_, mux, _ := newTestHandler(t)
	rr := do(t, mux, "GET", "/", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d, body=%s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	for _, want := range []string{"<title>", "Status", "Apply a preset", "live ruleset"} {
		if !strings.Contains(body, want) {
			t.Errorf("dashboard missing %q", want)
		}
	}
}

func TestRulesetPage(t *testing.T) {
	_, mux, be := newTestHandler(t)
	be.liveText = "table inet filter { }\n"
	rr := do(t, mux, "GET", "/ruleset", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "table inet filter") {
		t.Errorf("ruleset text not rendered")
	}
}

func TestPresetsForm(t *testing.T) {
	_, mux, _ := newTestHandler(t)
	rr := do(t, mux, "GET", "/presets", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d", rr.Code)
	}
	body := rr.Body.String()
	for _, want := range []string{"Preset wizard", "default_deny_inbound", "ssh_enabled", "caddy_box", "Preview diff"} {
		if !strings.Contains(body, want) {
			t.Errorf("presets form missing %q", want)
		}
	}
}

func TestPresetsPreview_RendersDiff(t *testing.T) {
	_, mux, _ := newTestHandler(t)
	form := url.Values{
		"default_deny_inbound": {"on"},
		"ssh_enabled":          {"on"},
		"ssh_port":             {"22"},
		"caddy_box":            {"on"},
	}
	rr := do(t, mux, "POST", "/ui/presets/preview", form)
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d, body=%s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	for _, want := range []string{"Preview", "Diff vs live", "zeerak-presets", "Stage with auto-rollback"} {
		if !strings.Contains(body, want) {
			t.Errorf("preview missing %q", want)
		}
	}
}

func TestPresetsPreview_BadCIDR(t *testing.T) {
	_, mux, _ := newTestHandler(t)
	form := url.Values{
		"ssh_enabled": {"on"},
		"ssh_from":    {"not-a-cidr"},
	}
	rr := do(t, mux, "POST", "/ui/presets/preview", form)
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "is not a CIDR") {
		t.Errorf("expected validation error in body, got: %s", rr.Body.String())
	}
}

func TestPresetsStage_RedirectsAndArmsTimer(t *testing.T) {
	h, mux, _ := newTestHandler(t)
	form := url.Values{
		"caddy_box": {"on"},
	}
	rr := do(t, mux, "POST", "/ui/presets/stage", form)
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("expected 303, got %d body=%s", rr.Code, rr.Body.String())
	}
	if got := rr.Header().Get("Location"); !strings.Contains(got, "flash=staged") {
		t.Errorf("redirect location = %q", got)
	}
	if h.stg.Status().State != stager.StatePending {
		t.Errorf("stager not pending: %s", h.stg.Status().State)
	}
}

func TestConfirmAndRollback_Redirect(t *testing.T) {
	h, mux, _ := newTestHandler(t)
	// Stage first.
	if _, err := h.stg.Stage(context.Background(), &model.Ruleset{}); err != nil {
		t.Fatalf("stage: %v", err)
	}
	rr := do(t, mux, "POST", "/ui/confirm", url.Values{})
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("confirm status %d", rr.Code)
	}
	if h.stg.Status().State != stager.StateConfirmed {
		t.Errorf("not confirmed: %s", h.stg.Status().State)
	}

	// Stage + rollback.
	if _, err := h.stg.Stage(context.Background(), &model.Ruleset{}); err != nil {
		t.Fatalf("stage: %v", err)
	}
	rr = do(t, mux, "POST", "/ui/rollback", url.Values{})
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("rollback status %d", rr.Code)
	}
	if h.stg.Status().State != stager.StateRolledBack {
		t.Errorf("not rolledback: %s", h.stg.Status().State)
	}
}

func TestConfirm_NoPending_RedirectsWithError(t *testing.T) {
	_, mux, _ := newTestHandler(t)
	rr := do(t, mux, "POST", "/ui/confirm", url.Values{})
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("status %d", rr.Code)
	}
	if !strings.Contains(rr.Header().Get("Location"), "error=") {
		t.Errorf("expected error in redirect, got %q", rr.Header().Get("Location"))
	}
}

func TestStaticServed(t *testing.T) {
	_, mux, _ := newTestHandler(t)
	rr := do(t, mux, "GET", "/static/style.css", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "--bg") {
		t.Errorf("style.css not served")
	}
}
