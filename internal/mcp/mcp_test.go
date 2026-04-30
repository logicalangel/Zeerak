package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type fakeDaemon struct {
	status  map[string]any
	live    string
	err     error
}

func (f *fakeDaemon) Status(_ context.Context) (map[string]any, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.status, nil
}
func (f *fakeDaemon) LiveRuleset(_ context.Context) (string, error) {
	if f.err != nil {
		return "", f.err
	}
	return f.live, nil
}

func newTestServer() *Server {
	return New(&fakeDaemon{
		status: map[string]any{"state": "idle", "deadline": nil},
		live: `table inet zeerak-policy {
	chain input {
		type filter hook input priority 0; policy drop;
		ct state established,related accept
		iif "lo" accept
		ip saddr 10.0.0.0/8 tcp dport 22 accept
		tcp dport 80 accept
		tcp dport 443 accept
	}
}
`,
	}, "test")
}

func roundtrip(t *testing.T, s *Server, req string) map[string]any {
	t.Helper()
	resp, _ := s.Handle(context.Background(), []byte(req))
	if resp == nil {
		t.Fatalf("expected response, got notification")
	}
	var out map[string]any
	if err := json.Unmarshal(resp, &out); err != nil {
		t.Fatalf("unmarshal response: %v\n%s", err, resp)
	}
	if e, ok := out["error"]; ok && e != nil {
		t.Fatalf("rpc error: %v", e)
	}
	return out
}

func TestInitializeAndLists(t *testing.T) {
	s := newTestServer()

	out := roundtrip(t, s, `{"jsonrpc":"2.0","id":1,"method":"initialize"}`)
	r := out["result"].(map[string]any)
	if r["protocolVersion"] != ProtocolVersion {
		t.Errorf("protocolVersion=%v", r["protocolVersion"])
	}

	out = roundtrip(t, s, `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	tools := out["result"].(map[string]any)["tools"].([]any)
	if len(tools) != 2 {
		t.Errorf("want 2 tools, got %d", len(tools))
	}

	out = roundtrip(t, s, `{"jsonrpc":"2.0","id":3,"method":"resources/list"}`)
	res := out["result"].(map[string]any)["resources"].([]any)
	if len(res) != 2 {
		t.Errorf("want 2 resources, got %d", len(res))
	}
}

func TestNotificationProducesNoResponse(t *testing.T) {
	s := newTestServer()
	resp, isNotif := s.Handle(context.Background(), []byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}`))
	if !isNotif || resp != nil {
		t.Fatalf("notification should produce no response, got %s", resp)
	}
}

func TestUnknownMethod(t *testing.T) {
	s := newTestServer()
	resp, _ := s.Handle(context.Background(), []byte(`{"jsonrpc":"2.0","id":99,"method":"bogus"}`))
	var out map[string]any
	_ = json.Unmarshal(resp, &out)
	if out["error"] == nil {
		t.Fatal("want error for unknown method")
	}
}

func TestResourceRead_Status(t *testing.T) {
	s := newTestServer()
	out := roundtrip(t, s, `{"jsonrpc":"2.0","id":4,"method":"resources/read","params":{"uri":"zeerak://status"}}`)
	contents := out["result"].(map[string]any)["contents"].([]any)
	first := contents[0].(map[string]any)
	if !strings.Contains(first["text"].(string), `"state":"idle"`) {
		t.Errorf("body=%v", first["text"])
	}
}

func TestResourceRead_LiveRuleset(t *testing.T) {
	s := newTestServer()
	out := roundtrip(t, s, `{"jsonrpc":"2.0","id":5,"method":"resources/read","params":{"uri":"zeerak://ruleset/live"}}`)
	contents := out["result"].(map[string]any)["contents"].([]any)
	first := contents[0].(map[string]any)
	if !strings.Contains(first["text"].(string), "zeerak-policy") {
		t.Errorf("body=%v", first["text"])
	}
}

func TestToolsCall_ExplainRule(t *testing.T) {
	s := newTestServer()
	req := `{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"explain_rule","arguments":{"expr":"ip saddr 10.0.0.0/8 tcp dport 22 accept"}}}`
	out := roundtrip(t, s, req)
	content := out["result"].(map[string]any)["content"].([]any)[0].(map[string]any)
	text := content["text"].(string)
	if !strings.Contains(text, "source address is 10.0.0.0/8") || !strings.Contains(text, "tcp destination port is 22") || !strings.Contains(text, "accept") {
		t.Errorf("explanation=%q", text)
	}
}

func TestToolsCall_SimulatePacket_Hit(t *testing.T) {
	s := newTestServer()
	req := `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"simulate_packet","arguments":{"protocol":"tcp","dport":443}}}`
	out := roundtrip(t, s, req)
	content := out["result"].(map[string]any)["content"].([]any)[0].(map[string]any)
	var sim SimResult
	if err := json.Unmarshal([]byte(content["text"].(string)), &sim); err != nil {
		t.Fatalf("decode sim result: %v", err)
	}
	if sim.Verdict != "accept" || !sim.Matched {
		t.Errorf("want accept (matched), got %+v", sim)
	}
}

func TestToolsCall_SimulatePacket_PolicyDrop(t *testing.T) {
	s := newTestServer()
	// Some random port that's not allowed → should fall through to policy drop.
	req := `{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"simulate_packet","arguments":{"protocol":"tcp","dport":9999}}}`
	out := roundtrip(t, s, req)
	content := out["result"].(map[string]any)["content"].([]any)[0].(map[string]any)
	var sim SimResult
	_ = json.Unmarshal([]byte(content["text"].(string)), &sim)
	if sim.Verdict != "drop" {
		t.Errorf("want drop, got %+v", sim)
	}
}

func TestToolsCall_BadInput(t *testing.T) {
	s := newTestServer()
	req := `{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"explain_rule","arguments":{}}}`
	out := roundtrip(t, s, req)
	r := out["result"].(map[string]any)
	if r["isError"] != true {
		t.Errorf("want isError=true, got %v", r)
	}
}

func TestExplainRule_Variants(t *testing.T) {
	cases := []struct {
		expr string
		want string
	}{
		{"ct state established,related accept", "connection state is established,related"},
		{"iif \"lo\" accept", "input interface is \"lo\""},
		{"udp dport 53 accept", "udp destination port is 53"},
		{"drop", "verdict: drop"},
		{"meta l4proto tcp accept", "L4 protocol is tcp"},
	}
	for _, c := range cases {
		got := ExplainRule(c.expr)
		if !strings.Contains(got, c.want) {
			t.Errorf("ExplainRule(%q) = %q; want substring %q", c.expr, got, c.want)
		}
	}
}

func TestStdioRoundtrip(t *testing.T) {
	s := newTestServer()
	in := bytes.NewBufferString(`{"jsonrpc":"2.0","id":1,"method":"ping"}` + "\n" + `{"jsonrpc":"2.0","method":"notifications/initialized"}` + "\n")
	var out bytes.Buffer
	if err := s.ServeStdio(context.Background(), in, &out); err != nil {
		t.Fatalf("stdio: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 1 {
		t.Fatalf("expected exactly 1 response line (notification swallowed), got %d:\n%s", len(lines), out.String())
	}
}

func TestHTTPTransport(t *testing.T) {
	s := newTestServer()
	srv := httptest.NewServer(s.HTTPHandler())
	defer srv.Close()

	resp, err := http.Post(srv.URL, "application/json", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if !bytes.Contains(body, []byte(`"protocolVersion"`)) {
		t.Errorf("body=%s", body)
	}

	// Notification → 204
	resp, err = http.Post(srv.URL, "application/json", strings.NewReader(`{"jsonrpc":"2.0","method":"notifications/initialized"}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("want 204, got %d", resp.StatusCode)
	}

	// GET → info text
	r2, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	b, _ := io.ReadAll(r2.Body)
	r2.Body.Close()
	if !bytes.Contains(b, []byte("zeerak-mcp")) {
		t.Errorf("info=%s", b)
	}
}
