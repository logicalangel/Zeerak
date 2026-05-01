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
	for _, want := range []string{"<title>", "Incoming traffic", "Show technical view", "Add or change"} {
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

	// /presets is now a picker page that links to per-service editors.
	rr := do(t, mux, "GET", "/presets", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d", rr.Code)
	}
	body := rr.Body.String()
	for _, want := range []string{"Add or change a service", "/edit/ssh", "/edit/web", "/edit/db", "/edit/mail", "/edit/protection"} {
		if !strings.Contains(body, want) {
			t.Errorf("presets picker missing %q", want)
		}
	}

	// The SSH editor renders the audience radios + Review changes button.
	rr = do(t, mux, "GET", "/edit/ssh", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("edit/ssh status %d", rr.Code)
	}
	body = rr.Body.String()
	for _, want := range []string{"ssh_audience", "Review changes"} {
		if !strings.Contains(body, want) {
			t.Errorf("edit/ssh missing %q", want)
		}
	}
	// Other services should NOT appear as visible inputs on the SSH editor.
	if strings.Contains(body, `name="web_audience"`) {
		t.Errorf("edit/ssh should not contain web_audience input")
	}
	// But should round-trip the other services as hidden inputs.
	if !strings.Contains(body, `name="caddy_box"`) {
		t.Errorf("edit/ssh missing hidden caddy_box round-trip")
	}

	// Unknown kind → 404.
	rr = do(t, mux, "GET", "/edit/nope", nil)
	if rr.Code != http.StatusNotFound {
		t.Errorf("edit/nope status %d, want 404", rr.Code)
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
	for _, want := range []string{"Review changes", "service-grid", "zeerak-presets", "Apply with auto-rollback"} {
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

func TestEditService_NewFieldsRoundTrip(t *testing.T) {
	// SSH editor must surface the v0.3 advanced inputs.
	_, mux, _ := newTestHandler(t)
	rr := do(t, mux, "GET", "/edit/ssh", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("edit/ssh status %d", rr.Code)
	}
	body := rr.Body.String()
	for _, want := range []string{
		`name="ssh_interfaces"`,
		`name="ssh_rate_limit"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("edit/ssh missing %q", want)
		}
	}
	// Outbound editor must surface block-set fields.
	rr = do(t, mux, "GET", "/edit/outbound", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("edit/outbound status %d", rr.Code)
	}
	body = rr.Body.String()
	for _, want := range []string{
		`name="block_sets_raw"`,
		`name="out_block_refs"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("edit/outbound missing %q", want)
		}
	}
	// SSH editor must round-trip outbound block-set fields as hidden inputs.
	rr = do(t, mux, "GET", "/edit/ssh", nil)
	body = rr.Body.String()
	for _, want := range []string{
		`type="hidden" name="block_sets_raw"`,
		`type="hidden" name="out_block_refs"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("edit/ssh missing hidden round-trip %q", want)
		}
	}
}

func TestParseBlockSets(t *testing.T) {
	got := parseBlockSets("# header\n\ntor 1.2.3.0/24\ntor 5.6.7.0/24\nspam6 2001:db8::/32\n")
	if len(got) != 2 {
		t.Fatalf("got %d sets, want 2: %+v", len(got), got)
	}
	if got[0].Name != "tor" || got[0].Family != "v4" || len(got[0].CIDRs) != 2 {
		t.Errorf("tor set wrong: %+v", got[0])
	}
	if got[1].Name != "spam6" || got[1].Family != "v6" {
		t.Errorf("spam6 set wrong: %+v", got[1])
	}
}
