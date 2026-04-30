package cliclient

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestClient_RoutesAndErrors(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /status", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"state":"idle","deadline":null}`))
	})
	mux.HandleFunc("GET /version", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"version":"0.2.0"}`))
	})
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	mux.HandleFunc("GET /ruleset/live", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"text":"table inet zeerak {}\n"}`))
	})
	mux.HandleFunc("POST /preview", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"rendered":"R","live":"L","diff":"D"}`))
	})
	mux.HandleFunc("POST /stage", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"state":"pending","deadline":"2030-01-01T00:00:00Z"}`))
	})
	mux.HandleFunc("POST /confirm", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"state":"confirmed"}`))
	})
	mux.HandleFunc("POST /rollback", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"error":"no pending change"}`))
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := New(srv.URL)
	ctx := context.Background()

	if err := c.Healthz(ctx); err != nil {
		t.Fatalf("healthz: %v", err)
	}

	v, err := c.Version(ctx)
	if err != nil || v != "0.2.0" {
		t.Fatalf("version=%q err=%v", v, err)
	}

	st, err := c.Status(ctx)
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if st["state"] != "idle" {
		t.Fatalf("status state=%v", st["state"])
	}

	text, err := c.LiveRuleset(ctx)
	if err != nil || !strings.Contains(text, "zeerak") {
		t.Fatalf("live: %q err=%v", text, err)
	}

	rendered, live, diff, err := c.Preview(ctx, []byte("version: 1\n"))
	if err != nil || rendered != "R" || live != "L" || diff != "D" {
		t.Fatalf("preview: r=%q l=%q d=%q err=%v", rendered, live, diff, err)
	}

	if _, err := c.Stage(ctx, []byte("version: 1\n")); err != nil {
		t.Fatalf("stage: %v", err)
	}
	if err := c.Confirm(ctx); err != nil {
		t.Fatalf("confirm: %v", err)
	}

	err = c.Rollback(ctx)
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Status != http.StatusConflict {
		t.Fatalf("rollback should have surfaced APIError 409, got %v", err)
	}
	if !strings.Contains(apiErr.Msg, "no pending") {
		t.Fatalf("APIError msg=%q", apiErr.Msg)
	}
}

func TestClient_UnixSocketDefault(t *testing.T) {
	c := New("")
	if c.Addr != DefaultSocket {
		t.Fatalf("default addr=%q want %q", c.Addr, DefaultSocket)
	}
	if c.HTTP == nil {
		t.Fatal("http client nil")
	}
}
