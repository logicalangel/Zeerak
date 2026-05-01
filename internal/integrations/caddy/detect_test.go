package caddy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

func TestDetectAt_NoServer(t *testing.T) {
	got := DetectAt(context.Background(), "http://127.0.0.1:1") // unreachable
	if got.Detected {
		t.Fatalf("expected Detected=false, got %+v", got)
	}
}

func TestDetectAt_HTTPApp(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/config/apps/http/servers" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{
			"srv0": {
				"listen": [":443", ":80"],
				"routes": [
					{"match":[{"host":["example.com","www.example.com"]}]},
					{"match":[{"host":["api.example.com"]}]}
				]
			}
		}`))
	}))
	defer srv.Close()

	got := DetectAt(context.Background(), srv.URL)
	if !got.Detected {
		t.Fatal("expected Detected=true")
	}
	if len(got.Sites) != 2 {
		t.Fatalf("expected 2 sites, got %d: %+v", len(got.Sites), got.Sites)
	}
	if got.Sites[0].Port != 80 || got.Sites[1].Port != 443 {
		t.Fatalf("ports mis-sorted: %+v", got.Sites)
	}
	wantHosts := []string{"api.example.com", "example.com", "www.example.com"}
	if !reflect.DeepEqual(got.Sites[0].Hosts, wantHosts) {
		t.Fatalf("hosts: want %v, got %v", wantHosts, got.Sites[0].Hosts)
	}
	if ports := got.Ports(); !reflect.DeepEqual(ports, []int{80, 443}) {
		t.Fatalf("ports: %v", ports)
	}
}

func TestDetectAt_NullServers(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/config/apps/http/servers" {
			w.Write([]byte(`null`))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	got := DetectAt(context.Background(), srv.URL)
	if !got.Detected {
		t.Fatal("expected Detected=true even when http app is empty")
	}
	if len(got.Sites) != 0 {
		t.Fatalf("expected no sites, got %+v", got.Sites)
	}
}

func TestDetectAt_RootFallback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/config/apps/http/servers":
			http.NotFound(w, r)
		case "/config/":
			w.Write([]byte(`null`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	got := DetectAt(context.Background(), srv.URL)
	if !got.Detected {
		t.Fatalf("expected Detected=true via root fallback, got %+v", got)
	}
}

func TestDetectAt_TrimsTrailingSlash(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "//") {
			t.Fatalf("double slash in path: %q", r.URL.Path)
		}
		if r.URL.Path == "/config/apps/http/servers" {
			w.Write([]byte(`{}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	got := DetectAt(context.Background(), srv.URL+"/")
	if !got.Detected {
		t.Fatal("expected Detected=true")
	}
}

func TestParsePort(t *testing.T) {
	cases := map[string]int{
		":443":             443,
		"127.0.0.1:8080":   8080,
		"[::1]:8080":       8080,
		"tcp/:443":         443,
		"udp/:53":          53,
		"unix//run/x.sock": 0,
		"":                 0,
		":bogus":           0,
	}
	for in, want := range cases {
		if got := parsePort(in); got != want {
			t.Errorf("parsePort(%q) = %d, want %d", in, got, want)
		}
	}
}
