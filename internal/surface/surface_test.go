// Package surface_test exercises the complete stack — API, CLI, and UI —
// through real HTTP calls against an in-process test server. Each test
// scenario starts from a request over the wire and asserts on the response,
// deliberately crossing package boundaries that unit tests cannot see.
//
// The fake backend (fakeBackend) stands in for the kernel nftables adapter so
// the suite runs on any OS without root or nftables.
package surface_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/zeerak/zeerak/internal/api"
	"github.com/zeerak/zeerak/internal/cliclient"
	"github.com/zeerak/zeerak/internal/model"
	"github.com/zeerak/zeerak/internal/stager"
	"github.com/zeerak/zeerak/internal/ui"
)

// ---------------------------------------------------------------------------
// Shared fake backend
// ---------------------------------------------------------------------------

type fakeBackend struct {
	mu        sync.Mutex
	current   *model.Ruleset
	applies   int
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
	f.applies++
	cp := *rs
	f.current = &cp
	return nil
}

func (f *fakeBackend) LiveText(_ context.Context) (string, error) { return f.liveText, nil }
func (f *fakeBackend) LiveTable(_ context.Context, fam model.Family, name string) (string, error) {
	return f.liveTable[string(fam)+" "+name], nil
}

// ---------------------------------------------------------------------------
// Test server factory
// ---------------------------------------------------------------------------

// testServer bundles a running httptest.Server that has both the API and UI
// mounted on the same mux, plus a cliclient pointed at it.
type testServer struct {
	srv     *httptest.Server
	be      *fakeBackend
	stg     *stager.Stager
	client  *cliclient.Client
}

func newTestServer(t *testing.T, opts ...stager.Option) *testServer {
	t.Helper()
	be := &fakeBackend{
		liveText:  "# empty\n",
		liveTable: map[string]string{},
	}
	stg := stager.New(be, opts...)
	mux := http.NewServeMux()

	// Mount API routes.
	apiSrv := api.New(stg, be, nil, "test-surface")
	mux.Handle("/healthz", apiSrv.Handler())
	mux.Handle("/version", apiSrv.Handler())
	mux.Handle("/status", apiSrv.Handler())
	mux.Handle("/stage", apiSrv.Handler())
	mux.Handle("/confirm", apiSrv.Handler())
	mux.Handle("/rollback", apiSrv.Handler())
	mux.Handle("/preview", apiSrv.Handler())
	mux.Handle("/ruleset/", apiSrv.Handler())
	mux.Handle("/openapi.yaml", apiSrv.Handler())

	// Mount UI routes.
	uiHandler, err := ui.New(stg, be, nil, "test-surface")
	if err != nil {
		t.Fatalf("ui.New: %v", err)
	}
	uiHandler.Register(mux)

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	return &testServer{
		srv:    srv,
		be:     be,
		stg:    stg,
		client: cliclient.New(srv.URL),
	}
}

// Convenience wrappers that talk to the raw HTTP server.

func (ts *testServer) get(t *testing.T, path string) *http.Response {
	t.Helper()
	resp, err := http.Get(ts.srv.URL + path)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	return resp
}

func (ts *testServer) post(t *testing.T, path, contentType, body string) *http.Response {
	t.Helper()
	resp, err := http.Post(ts.srv.URL+path, contentType, strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	return resp
}

func (ts *testServer) postForm(t *testing.T, path string, form url.Values) *http.Response {
	t.Helper()
	req, err := http.NewRequest("POST", ts.srv.URL+path, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST form %s: %v", path, err)
	}
	return resp
}

func readBody(t *testing.T, r *http.Response) string {
	t.Helper()
	b, err := io.ReadAll(r.Body)
	_ = r.Body.Close()
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return string(b)
}

func decodeJSON(t *testing.T, r *http.Response) map[string]any {
	t.Helper()
	b := readBody(t, r)
	var out map[string]any
	if err := json.Unmarshal([]byte(b), &out); err != nil {
		t.Fatalf("decode JSON: %v\nbody: %s", err, b)
	}
	return out
}

// ---------------------------------------------------------------------------
// YAML fixture
// ---------------------------------------------------------------------------

const minimalYAML = `
version: 1
tables:
  - family: inet
    name: zeerak-presets
    owned: true
    chains:
      - name: input
        type: filter
        hook: input
        priority: 0
        policy: drop
`

const invalidVersionYAML = "version: 99\n"
const malformedYAML = ":::: not yaml\n"

// ---------------------------------------------------------------------------
// API surface tests
// ---------------------------------------------------------------------------

func TestAPI_Healthz(t *testing.T) {
	ts := newTestServer(t)
	r := ts.get(t, "/healthz")
	if r.StatusCode != http.StatusOK {
		t.Fatalf("healthz: got %d, want 200", r.StatusCode)
	}
}

func TestAPI_Version(t *testing.T) {
	ts := newTestServer(t)
	r := ts.get(t, "/version")
	if r.StatusCode != http.StatusOK {
		t.Fatalf("version: got %d", r.StatusCode)
	}
	body := decodeJSON(t, r)
	if body["version"] == "" || body["version"] == nil {
		t.Fatalf("version field missing or empty: %v", body)
	}
}

func TestAPI_Status_Idle(t *testing.T) {
	ts := newTestServer(t)
	r := ts.get(t, "/status")
	body := decodeJSON(t, r)
	if r.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d", r.StatusCode)
	}
	if body["state"] != "idle" {
		t.Fatalf("state=%v, want idle", body["state"])
	}
}

func TestAPI_StageConfirmFlow(t *testing.T) {
	ts := newTestServer(t, stager.WithTimeout(time.Hour))

	// Stage → 202, state becomes pending.
	r := ts.post(t, "/stage", "application/yaml", minimalYAML)
	if r.StatusCode != http.StatusAccepted {
		t.Fatalf("stage: got %d body=%s", r.StatusCode, readBody(t, r))
	}
	if ts.be.applies != 1 {
		t.Fatalf("expected 1 apply after stage, got %d", ts.be.applies)
	}

	// Status must report pending with a deadline.
	r = ts.get(t, "/status")
	body := decodeJSON(t, r)
	if body["state"] != "pending" {
		t.Fatalf("state=%v, want pending", body["state"])
	}
	if body["deadline"] == nil {
		t.Fatal("deadline must be set while pending")
	}

	// Confirm → 200.
	r = ts.post(t, "/confirm", "application/json", "")
	if r.StatusCode != http.StatusOK {
		t.Fatalf("confirm: got %d", r.StatusCode)
	}

	// Status must report confirmed.
	r = ts.get(t, "/status")
	body = decodeJSON(t, r)
	if body["state"] != "confirmed" {
		t.Fatalf("state=%v after confirm, want confirmed", body["state"])
	}
}

func TestAPI_StageRollbackFlow(t *testing.T) {
	ts := newTestServer(t, stager.WithTimeout(time.Hour))

	r := ts.post(t, "/stage", "application/yaml", minimalYAML)
	if r.StatusCode != http.StatusAccepted {
		t.Fatalf("stage: %d", r.StatusCode)
	}

	r = ts.post(t, "/rollback", "", "")
	if r.StatusCode != http.StatusOK {
		t.Fatalf("rollback: got %d body=%s", r.StatusCode, readBody(t, r))
	}
	// Apply runs twice: once for stage, once to restore snapshot.
	if ts.be.applies != 2 {
		t.Fatalf("applies=%d, want 2", ts.be.applies)
	}

	r = ts.get(t, "/status")
	body := decodeJSON(t, r)
	if body["state"] != "rolled-back" {
		t.Fatalf("state=%v, want rolled-back", body["state"])
	}
}

func TestAPI_Stage_InvalidVersion(t *testing.T) {
	ts := newTestServer(t)
	r := ts.post(t, "/stage", "application/yaml", invalidVersionYAML)
	if r.StatusCode != http.StatusBadRequest {
		t.Fatalf("got %d, want 400", r.StatusCode)
	}
	body := readBody(t, r)
	if !strings.Contains(body, "error") {
		t.Fatalf("expected error field in response, got: %s", body)
	}
}

func TestAPI_Stage_MalformedYAML(t *testing.T) {
	ts := newTestServer(t)
	r := ts.post(t, "/stage", "application/yaml", malformedYAML)
	if r.StatusCode != http.StatusBadRequest {
		t.Fatalf("got %d, want 400", r.StatusCode)
	}
}

func TestAPI_Stage_ConflictWhenPending(t *testing.T) {
	ts := newTestServer(t, stager.WithTimeout(time.Hour))
	if r := ts.post(t, "/stage", "application/yaml", minimalYAML); r.StatusCode != http.StatusAccepted {
		t.Fatalf("first stage: %d", r.StatusCode)
	}
	r := ts.post(t, "/stage", "application/yaml", minimalYAML)
	if r.StatusCode != http.StatusConflict {
		t.Fatalf("second stage: got %d, want 409", r.StatusCode)
	}
}

func TestAPI_Confirm_NoPending(t *testing.T) {
	ts := newTestServer(t)
	r := ts.post(t, "/confirm", "", "")
	if r.StatusCode != http.StatusConflict {
		t.Fatalf("confirm without pending: got %d, want 409", r.StatusCode)
	}
}

func TestAPI_Rollback_NoPending(t *testing.T) {
	ts := newTestServer(t)
	r := ts.post(t, "/rollback", "", "")
	if r.StatusCode != http.StatusConflict {
		t.Fatalf("rollback without pending: got %d, want 409", r.StatusCode)
	}
}

func TestAPI_WrongMethod(t *testing.T) {
	ts := newTestServer(t)
	r := ts.get(t, "/stage")
	if r.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("GET /stage: got %d, want 405", r.StatusCode)
	}
}

func TestAPI_RulesetLive(t *testing.T) {
	ts := newTestServer(t)
	ts.be.liveText = "table inet zeerak-presets { }\n"
	r := ts.get(t, "/ruleset/live")
	if r.StatusCode != http.StatusOK {
		t.Fatalf("ruleset/live: got %d", r.StatusCode)
	}
	body := decodeJSON(t, r)
	if body["text"] != ts.be.liveText {
		t.Fatalf("text=%q, want %q", body["text"], ts.be.liveText)
	}
}

func TestAPI_Preview_ReturnsDiff(t *testing.T) {
	ts := newTestServer(t)
	ts.be.liveTable["inet zeerak-presets"] = "table inet zeerak-presets {\n}\n"

	r := ts.post(t, "/preview", "application/yaml", minimalYAML)
	if r.StatusCode != http.StatusOK {
		t.Fatalf("preview: got %d body=%s", r.StatusCode, readBody(t, r))
	}
	body := decodeJSON(t, r)
	if body["rendered"] == "" {
		t.Fatal("rendered field missing")
	}
	if body["diff"] == "" {
		t.Fatalf("diff missing; rendered=%q", body["rendered"])
	}
	diff, _ := body["diff"].(string)
	if !strings.Contains(diff, "--- live") {
		t.Fatalf("diff header wrong: %q", diff)
	}
}

func TestAPI_Preview_NoMutation(t *testing.T) {
	ts := newTestServer(t)
	ts.post(t, "/preview", "application/yaml", minimalYAML)
	if ts.be.applies != 0 {
		t.Fatalf("preview must not apply: %d applies", ts.be.applies)
	}
	if ts.stg.Status().State != stager.StateIdle {
		t.Fatalf("stager state after preview: %v", ts.stg.Status().State)
	}
}

func TestAPI_Preview_Invalid(t *testing.T) {
	ts := newTestServer(t)
	r := ts.post(t, "/preview", "application/yaml", invalidVersionYAML)
	if r.StatusCode != http.StatusBadRequest {
		t.Fatalf("preview invalid: got %d, want 400", r.StatusCode)
	}
}

func TestAPI_OpenAPI(t *testing.T) {
	ts := newTestServer(t)
	r := ts.get(t, "/openapi.yaml")
	if r.StatusCode != http.StatusOK {
		t.Fatalf("openapi: got %d", r.StatusCode)
	}
	ct := r.Header.Get("Content-Type")
	if !strings.HasPrefix(ct, "application/yaml") {
		t.Fatalf("content-type=%q", ct)
	}
	body := readBody(t, r)
	for _, want := range []string{"openapi: 3.1.0", "/healthz", "/stage", "/confirm", "/rollback"} {
		if !strings.Contains(body, want) {
			t.Fatalf("openapi missing %q", want)
		}
	}
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(body), &doc); err != nil {
		t.Fatalf("openapi not valid YAML: %v", err)
	}
}

// ---------------------------------------------------------------------------
// CLI surface tests (cliclient wired to the test httptest.Server)
// ---------------------------------------------------------------------------

func TestCLI_Healthz(t *testing.T) {
	ts := newTestServer(t)
	if err := ts.client.Healthz(context.Background()); err != nil {
		t.Fatalf("CLI healthz: %v", err)
	}
}

func TestCLI_Version(t *testing.T) {
	ts := newTestServer(t)
	v, err := ts.client.Version(context.Background())
	if err != nil {
		t.Fatalf("CLI version: %v", err)
	}
	if v == "" {
		t.Fatal("version is empty")
	}
}

func TestCLI_Status_Idle(t *testing.T) {
	ts := newTestServer(t)
	st, err := ts.client.Status(context.Background())
	if err != nil {
		t.Fatalf("CLI status: %v", err)
	}
	if st["state"] != "idle" {
		t.Fatalf("state=%v, want idle", st["state"])
	}
}

func TestCLI_LiveRuleset(t *testing.T) {
	ts := newTestServer(t)
	ts.be.liveText = "table inet zeerak-presets { }\n"
	text, err := ts.client.LiveRuleset(context.Background())
	if err != nil {
		t.Fatalf("CLI LiveRuleset: %v", err)
	}
	if !strings.Contains(text, "zeerak-presets") {
		t.Fatalf("live text missing expected content: %q", text)
	}
}

func TestCLI_Preview(t *testing.T) {
	ts := newTestServer(t)
	ts.be.liveTable["inet zeerak-presets"] = "table inet zeerak-presets {\n}\n"
	rendered, live, diff, err := ts.client.Preview(context.Background(), []byte(minimalYAML))
	if err != nil {
		t.Fatalf("CLI preview: %v", err)
	}
	if rendered == "" {
		t.Fatal("rendered empty")
	}
	_ = live
	if diff == "" {
		t.Fatal("diff empty")
	}
}

func TestCLI_StageAndConfirm(t *testing.T) {
	ts := newTestServer(t, stager.WithTimeout(time.Hour))
	st, err := ts.client.Stage(context.Background(), []byte(minimalYAML))
	if err != nil {
		t.Fatalf("CLI stage: %v", err)
	}
	if st["state"] != "pending" {
		t.Fatalf("state after stage=%v, want pending", st["state"])
	}

	if err := ts.client.Confirm(context.Background()); err != nil {
		t.Fatalf("CLI confirm: %v", err)
	}
	status, _ := ts.client.Status(context.Background())
	if status["state"] != "confirmed" {
		t.Fatalf("state after confirm=%v, want confirmed", status["state"])
	}
}

func TestCLI_StageAndRollback(t *testing.T) {
	ts := newTestServer(t, stager.WithTimeout(time.Hour))
	if _, err := ts.client.Stage(context.Background(), []byte(minimalYAML)); err != nil {
		t.Fatalf("CLI stage: %v", err)
	}
	if err := ts.client.Rollback(context.Background()); err != nil {
		t.Fatalf("CLI rollback: %v", err)
	}
	if ts.be.applies != 2 {
		t.Fatalf("applies=%d, want 2 (stage+restore)", ts.be.applies)
	}
}

func TestCLI_Rollback_NoPending_ReturnsAPIError(t *testing.T) {
	ts := newTestServer(t)
	err := ts.client.Rollback(context.Background())
	var apiErr *cliclient.APIError
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	// Should surface a 409.
	_ = apiErr
	if !strings.Contains(err.Error(), "409") && !strings.Contains(err.Error(), "conflict") && !strings.Contains(err.Error(), "no pending") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// UI surface tests
// ---------------------------------------------------------------------------

func TestUI_Dashboard(t *testing.T) {
	ts := newTestServer(t)
	r := ts.get(t, "/")
	if r.StatusCode != http.StatusOK {
		t.Fatalf("dashboard: got %d", r.StatusCode)
	}
	body := readBody(t, r)
	for _, want := range []string{"<title>", "Incoming traffic", "Add or change", "NAT", `href="/apps"`} {
		if !strings.Contains(body, want) {
			t.Errorf("dashboard missing %q", want)
		}
	}
	// Integrations section must have moved to /apps.
	if strings.Contains(body, "Detected on this host") {
		t.Error("dashboard must not contain 'Detected on this host' (moved to /apps)")
	}
}

func TestUI_AppsPage(t *testing.T) {
	ts := newTestServer(t)
	r := ts.get(t, "/apps")
	if r.StatusCode != http.StatusOK {
		t.Fatalf("/apps: got %d", r.StatusCode)
	}
	body := readBody(t, r)
	for _, want := range []string{
		"Apps on this host",
		"Tailscale",
		"WireGuard",
		"Docker",
		"Caddy",
		`class="service-card`,
		"flow-arrowhead",
		"▶",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("/apps missing %q", want)
		}
	}
}

func TestUI_RulesetPage(t *testing.T) {
	ts := newTestServer(t)
	ts.be.liveText = "table inet zeerak-presets { }\n"
	r := ts.get(t, "/ruleset")
	if r.StatusCode != http.StatusOK {
		t.Fatalf("ruleset: got %d", r.StatusCode)
	}
	if !strings.Contains(readBody(t, r), "zeerak-presets") {
		t.Error("ruleset page does not show live text")
	}
}

func TestUI_ActivityPage(t *testing.T) {
	ts := newTestServer(t)
	r := ts.get(t, "/activity")
	if r.StatusCode != http.StatusOK {
		t.Fatalf("activity: got %d", r.StatusCode)
	}
}

func TestUI_PresetsPicker(t *testing.T) {
	ts := newTestServer(t)
	r := ts.get(t, "/presets")
	if r.StatusCode != http.StatusOK {
		t.Fatalf("presets picker: got %d", r.StatusCode)
	}
	body := readBody(t, r)
	for _, want := range []string{"/edit/ssh", "/edit/web", "/edit/db", "/edit/mail", "/edit/nat", "/edit/marks", "/edit/ct"} {
		if !strings.Contains(body, want) {
			t.Errorf("presets picker missing link to %q", want)
		}
	}
}

func TestUI_EditPages_AllKinds(t *testing.T) {
	ts := newTestServer(t)
	kinds := []struct {
		kind     string
		mustHave []string
	}{
		{"ssh", []string{"ssh_audience", "Review changes"}},
		{"web", []string{"web_audience", "Review changes"}},
		{"db", []string{"db_audience", "Review changes"}},
		{"mail", []string{"mail_smtp", "Review changes"}}, // mail uses individual toggles, not audience radio
		{"protection", []string{"default_deny_inbound", "Review changes"}},
		{"outbound", []string{"block_sets_raw", "Review changes"}},
		{"nat", []string{"pf_proto", "mq_oif", "Review changes"}},
		{"marks", []string{"mk_name", "mk_set", "Traffic routing rules", "Review changes"}},
		{"ct", []string{"ct_helper_ftp", "ct_helper_sip", "Protocol helpers", "Review changes"}},
	}
	for _, tc := range kinds {
		r := ts.get(t, "/edit/"+tc.kind)
		if r.StatusCode != http.StatusOK {
			t.Errorf("/edit/%s: got %d", tc.kind, r.StatusCode)
			continue
		}
		body := readBody(t, r)
		for _, want := range tc.mustHave {
			if !strings.Contains(body, want) {
				t.Errorf("/edit/%s missing %q", tc.kind, want)
			}
		}
	}
}

func TestUI_EditPages_UnknownKind_404(t *testing.T) {
	ts := newTestServer(t)
	r := ts.get(t, "/edit/nope")
	if r.StatusCode != http.StatusNotFound {
		t.Fatalf("/edit/nope: got %d, want 404", r.StatusCode)
	}
}

func TestUI_EditNAT_HasIfaceDatalist(t *testing.T) {
	ts := newTestServer(t)
	r := ts.get(t, "/edit/nat")
	body := readBody(t, r)
	// datalist is rendered when the server has interfaces (it always does in practice)
	// — but even if empty, the list= attribute must be wired.
	if !strings.Contains(body, `list="iface-list"`) {
		t.Error("/edit/nat: pf_iif missing list=iface-list")
	}
}

func TestUI_EditMarks_HasIfaceDatalist(t *testing.T) {
	ts := newTestServer(t)
	r := ts.get(t, "/edit/marks")
	body := readBody(t, r)
	if !strings.Contains(body, `list="iface-list"`) {
		t.Error("/edit/marks: mk_oif missing list=iface-list")
	}
}

func TestUI_StaticCSS(t *testing.T) {
	ts := newTestServer(t)
	r := ts.get(t, "/static/style.css")
	if r.StatusCode != http.StatusOK {
		t.Fatalf("style.css: got %d", r.StatusCode)
	}
	if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/css") {
		t.Errorf("content-type=%q, want text/css", ct)
	}
	if !strings.Contains(readBody(t, r), "--bg") {
		t.Error("style.css body missing CSS variable --bg")
	}
}

// ---------------------------------------------------------------------------
// UI form → preview round-trips
// ---------------------------------------------------------------------------

func TestUI_Preview_SSH(t *testing.T) {
	ts := newTestServer(t)
	form := url.Values{
		"default_deny_inbound": {"on"},
		"ssh_enabled":          {"on"},
		"ssh_port":             {"22"},
	}
	r := ts.postForm(t, "/ui/presets/preview", form)
	if r.StatusCode != http.StatusOK {
		t.Fatalf("preview SSH: got %d body=%s", r.StatusCode, readBody(t, r))
	}
	body := readBody(t, r)
	for _, want := range []string{"zeerak-presets", "tcp dport 22 accept", "Review changes"} {
		if !strings.Contains(body, want) {
			t.Errorf("preview SSH missing %q in rendered output", want)
		}
	}
}

func TestUI_Preview_NATPortForward(t *testing.T) {
	ts := newTestServer(t)
	form := url.Values{
		"default_deny_inbound": {"on"},
		"pf_proto":             {"tcp"},
		"pf_ext_port":          {"8080"},
		"pf_to":                {"10.0.0.5"},
		"pf_to_port":           {"80"},
		"pf_iif":               {"eth0"},
		"pf_from":              {""},
		"pf_comment":           {"web"},
	}
	r := ts.postForm(t, "/ui/presets/preview", form)
	if r.StatusCode != http.StatusOK {
		t.Fatalf("preview NAT: got %d body=%s", r.StatusCode, readBody(t, r))
	}
	body := readBody(t, r)
	for _, want := range []string{"zeerak-nat", "dnat to 10.0.0.5:80", "Review changes"} {
		if !strings.Contains(body, want) {
			t.Errorf("preview NAT missing %q", want)
		}
	}
}

func TestUI_Preview_Masquerade(t *testing.T) {
	ts := newTestServer(t)
	form := url.Values{
		"default_deny_inbound": {"on"},
		"mq_oif":               {"eth0"},
		"mq_source":            {"10.0.0.0/24"},
		"mq_comment":           {"lan"},
	}
	r := ts.postForm(t, "/ui/presets/preview", form)
	if r.StatusCode != http.StatusOK {
		t.Fatalf("preview masquerade: got %d body=%s", r.StatusCode, readBody(t, r))
	}
	body := readBody(t, r)
	for _, want := range []string{"zeerak-nat", "masquerade", "Review changes"} {
		if !strings.Contains(body, want) {
			t.Errorf("preview masquerade missing %q", want)
		}
	}
}

func TestUI_Preview_TrafficRoutingMarks(t *testing.T) {
	ts := newTestServer(t)
	form := url.Values{
		"mk_name":    {"vpn-split", "voip"},
		"mk_set":     {"0x100", "0x200"},
		"mk_proto":   {"", "udp"},
		"mk_dport":   {"", "5060"},
		"mk_oif":     {"", ""},
		"mk_daddr":   {"10.50.0.0/16", ""},
		"mk_comment": {"split-tunnel", ""},
	}
	r := ts.postForm(t, "/ui/presets/preview", form)
	if r.StatusCode != http.StatusOK {
		t.Fatalf("preview marks: got %d body=%s", r.StatusCode, readBody(t, r))
	}
	body := readBody(t, r)
	for _, want := range []string{"zeerak-marks", "meta mark set 0x100", "meta mark set 0x200", "Review changes"} {
		if !strings.Contains(body, want) {
			t.Errorf("preview marks missing %q", want)
		}
	}
}

func TestUI_Preview_CTHelpers(t *testing.T) {
	ts := newTestServer(t)
	form := url.Values{
		"ct_helper_ftp": {"on"},
		"ct_helper_sip": {"on"},
	}
	r := ts.postForm(t, "/ui/presets/preview", form)
	if r.StatusCode != http.StatusOK {
		t.Fatalf("preview CT: got %d body=%s", r.StatusCode, readBody(t, r))
	}
	body := readBody(t, r)
	// html/template encodes " as &#34; in the rendered nft output.
	for _, want := range []string{"zeerak-ct", "ftp-standard", "sip-standard", "Review changes"} {
		if !strings.Contains(body, want) {
			t.Errorf("preview CT helpers missing %q", want)
		}
	}
}

func TestUI_Preview_AllFeaturesAtOnce(t *testing.T) {
	ts := newTestServer(t)
	form := url.Values{
		// base
		"default_deny_inbound": {"on"},
		"ssh_enabled":          {"on"},
		"ssh_port":             {"22"},
		// NAT port forward
		"pf_proto":    {"tcp"},
		"pf_ext_port": {"443"},
		"pf_to":       {"10.0.0.5"},
		"pf_to_port":  {"8443"},
		"pf_iif":      {"eth0"},
		"pf_from":     {""},
		"pf_comment":  {"https"},
		// masquerade
		"mq_oif":     {"eth0"},
		"mq_source":  {"10.0.0.0/24"},
		"mq_comment": {"lan"},
		// marks
		"mk_name":    {"vpn-split"},
		"mk_set":     {"0x100"},
		"mk_proto":   {""},
		"mk_dport":   {""},
		"mk_oif":     {""},
		"mk_daddr":   {"10.50.0.0/16"},
		"mk_comment": {"vpn"},
		// CT helpers
		"ct_helper_ftp": {"on"},
	}
	r := ts.postForm(t, "/ui/presets/preview", form)
	if r.StatusCode != http.StatusOK {
		t.Fatalf("preview all features: got %d body=%s", r.StatusCode, readBody(t, r))
	}
	body := readBody(t, r)
	for _, want := range []string{
		"zeerak-presets",
		"zeerak-nat",
		"zeerak-marks",
		"zeerak-ct",
		"tcp dport 22 accept",
		"dnat to 10.0.0.5:8443",
		"masquerade",
		"meta mark set 0x100",
		"ftp-standard", // quotes are HTML-encoded in preview body
	} {
		if !strings.Contains(body, want) {
			t.Errorf("preview all-features missing %q", want)
		}
	}
}

func TestUI_Preview_BadCIDR_ShowsError(t *testing.T) {
	ts := newTestServer(t)
	form := url.Values{
		"ssh_enabled": {"on"},
		"ssh_from":    {"not-a-cidr"},
	}
	r := ts.postForm(t, "/ui/presets/preview", form)
	if r.StatusCode != http.StatusOK {
		t.Fatalf("bad cidr: got %d", r.StatusCode)
	}
	if !strings.Contains(readBody(t, r), "is not a CIDR") {
		t.Error("expected CIDR validation error in response")
	}
}

func TestUI_Preview_BadPortForward_ShowsError(t *testing.T) {
	ts := newTestServer(t)
	form := url.Values{
		"pf_proto":    {"tcp"},
		"pf_ext_port": {"not-a-number"},
		"pf_to":       {"10.0.0.5"},
		"pf_from":     {""},
		"pf_iif":      {""},
		"pf_to_port":  {""},
		"pf_comment":  {""},
	}
	r := ts.postForm(t, "/ui/presets/preview", form)
	if r.StatusCode != http.StatusOK {
		t.Fatalf("bad pf port: got %d", r.StatusCode)
	}
	body := readBody(t, r)
	if !strings.Contains(body, "port") && !strings.Contains(body, "error") && !strings.Contains(body, "Error") {
		t.Errorf("expected port error in response, got: %.200s", body)
	}
}

// ---------------------------------------------------------------------------
// UI stage/confirm/rollback flows
// ---------------------------------------------------------------------------

func TestUI_Stage_RedirectsWithFlash(t *testing.T) {
	ts := newTestServer(t)
	// Disable redirect following so we can inspect the 303.
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	req, _ := http.NewRequest("POST", ts.srv.URL+"/ui/presets/stage", strings.NewReader(url.Values{
		"default_deny_inbound": {"on"},
		"ssh_enabled":          {"on"},
		"ssh_port":             {"22"},
	}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r, err := client.Do(req)
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
	if r.StatusCode != http.StatusSeeOther {
		t.Fatalf("stage: got %d, want 303", r.StatusCode)
	}
	if loc := r.Header.Get("Location"); !strings.Contains(loc, "flash=staged") {
		t.Errorf("redirect location=%q, want flash=staged", loc)
	}
	if ts.stg.Status().State != stager.StatePending {
		t.Errorf("stager not pending: %v", ts.stg.Status().State)
	}
}

func TestUI_Confirm_Redirect(t *testing.T) {
	ts := newTestServer(t)
	// Stage first via the API to set up a pending change.
	if _, err := ts.stg.Stage(context.Background(), &model.Ruleset{}); err != nil {
		t.Fatalf("stage: %v", err)
	}
	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	req, _ := http.NewRequest("POST", ts.srv.URL+"/ui/confirm", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r, err := noRedirect.Do(req)
	if err != nil {
		t.Fatalf("confirm: %v", err)
	}
	if r.StatusCode != http.StatusSeeOther {
		t.Fatalf("confirm: got %d, want 303", r.StatusCode)
	}
	if ts.stg.Status().State != stager.StateConfirmed {
		t.Errorf("not confirmed: %v", ts.stg.Status().State)
	}
}

func TestUI_Rollback_Redirect(t *testing.T) {
	ts := newTestServer(t)
	if _, err := ts.stg.Stage(context.Background(), &model.Ruleset{}); err != nil {
		t.Fatalf("stage: %v", err)
	}
	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	req, _ := http.NewRequest("POST", ts.srv.URL+"/ui/rollback", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r, err := noRedirect.Do(req)
	if err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if r.StatusCode != http.StatusSeeOther {
		t.Fatalf("rollback: got %d, want 303", r.StatusCode)
	}
	if ts.stg.Status().State != stager.StateRolledBack {
		t.Errorf("not rolled back: %v", ts.stg.Status().State)
	}
}

func TestUI_Confirm_NoPending_RedirectsWithError(t *testing.T) {
	ts := newTestServer(t)
	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	req, _ := http.NewRequest("POST", ts.srv.URL+"/ui/confirm", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r, _ := noRedirect.Do(req)
	if r.StatusCode != http.StatusSeeOther {
		t.Fatalf("got %d, want 303", r.StatusCode)
	}
	if !strings.Contains(r.Header.Get("Location"), "error=") {
		t.Errorf("expected error= in redirect, got %q", r.Header.Get("Location"))
	}
}

// ---------------------------------------------------------------------------
// E2E: UI form → preview shows nft output → stage → CLI confirm
// ---------------------------------------------------------------------------

func TestE2E_UIFormToStageToCliConfirm(t *testing.T) {
	ts := newTestServer(t, stager.WithTimeout(time.Hour))

	// 1. User fills the SSH form and POSTs /ui/presets/preview.
	form := url.Values{
		"default_deny_inbound": {"on"},
		"ssh_enabled":          {"on"},
		"ssh_port":             {"22"},
	}
	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}

	req, _ := http.NewRequest("POST", ts.srv.URL+"/ui/presets/stage", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r, err := noRedirect.Do(req)
	if err != nil || r.StatusCode != http.StatusSeeOther {
		t.Fatalf("UI stage: got %d", r.StatusCode)
	}

	// Stager is now pending.
	if ts.stg.Status().State != stager.StatePending {
		t.Fatalf("expected pending, got %v", ts.stg.Status().State)
	}

	// 2. CLI operator confirms.
	if err := ts.client.Confirm(context.Background()); err != nil {
		t.Fatalf("CLI confirm: %v", err)
	}

	// 3. System is confirmed.
	if ts.stg.Status().State != stager.StateConfirmed {
		t.Fatalf("expected confirmed, got %v", ts.stg.Status().State)
	}
}

func TestE2E_CLIApplyThenUIRollback(t *testing.T) {
	ts := newTestServer(t, stager.WithTimeout(time.Hour))

	// CLI stages a config.
	if _, err := ts.client.Stage(context.Background(), []byte(minimalYAML)); err != nil {
		t.Fatalf("CLI stage: %v", err)
	}

	// UI operator rolls back.
	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	req, _ := http.NewRequest("POST", ts.srv.URL+"/ui/rollback", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r, err := noRedirect.Do(req)
	if err != nil || r.StatusCode != http.StatusSeeOther {
		t.Fatalf("UI rollback: got %d", r.StatusCode)
	}
	if ts.stg.Status().State != stager.StateRolledBack {
		t.Fatalf("expected rolled_back, got %v", ts.stg.Status().State)
	}
	// Both stage and rollback applied to backend.
	if ts.be.applies != 2 {
		t.Fatalf("applies=%d, want 2", ts.be.applies)
	}
}

// ---------------------------------------------------------------------------
// Topbar routing VM — nav badges reflect live preset counts
// ---------------------------------------------------------------------------

func TestUI_Topbar_ShowsNATBadge_WhenPortForwardExists(t *testing.T) {
	ts := newTestServer(t, stager.WithTimeout(time.Hour))

	// Stage a preset with a port forward so the UI has something to show.
	form := url.Values{
		"default_deny_inbound": {"on"},
		"pf_proto":             {"tcp"},
		"pf_ext_port":          {"8080"},
		"pf_to":                {"10.0.0.5"},
		"pf_to_port":           {"80"},
		"pf_iif":               {"eth0"},
		"pf_from":              {""},
		"pf_comment":           {""},
	}
	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	req, _ := http.NewRequest("POST", ts.srv.URL+"/ui/presets/stage", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if _, err := noRedirect.Do(req); err != nil {
		t.Fatalf("stage: %v", err)
	}
	// Confirm via UI so h.current is updated (CLI confirm does not call SetCurrent).
	reqConfirm, _ := http.NewRequest("POST", ts.srv.URL+"/ui/confirm", strings.NewReader(""))
	reqConfirm.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if _, err := noRedirect.Do(reqConfirm); err != nil {
		t.Fatalf("ui confirm: %v", err)
	}

	// The dashboard (and every page) must now show a NAT badge.
	r := ts.get(t, "/")
	body := readBody(t, r)
	if !strings.Contains(body, `href="/edit/nat"`) {
		t.Error("dashboard topbar missing NAT link")
	}
	// nav-badge should show "1" for the one port forward.
	if !strings.Contains(body, `class="nav-badge"`) {
		t.Error("dashboard topbar missing nav-badge for NAT")
	}
}

// bufClose wraps a bytes.Buffer to satisfy io.ReadCloser.
var _ = (*bytes.Buffer)(nil)
