// Package caddy provides best-effort Caddy admin-API awareness for Zeerak.
//
// VISION.md §4 ("Caddy Integration") describes two complementary modes:
//
//   A. Caddy in front of Zeerak — pure deploy concern, see deploy/caddy/
//      Caddyfile.example. No code involvement.
//   B. Zeerak shows what Caddy is doing — read Caddy's admin API at
//      127.0.0.1:2019, surface bound listeners + host names on the
//      dashboard, and let the operator spot the classic footgun ("Caddy
//      is bound to :443 but the firewall blocks 443").
//
// This package implements the read half of mode B. We intentionally only
// *read* from the admin API; one-click rule creation and Caddyfile editing
// from inside Zeerak are deferred until v0.4.
//
// Detection is pure-HTTP, never requires root, and times out fast (so it's
// safe to call on every dashboard render even when Caddy isn't installed).
package caddy

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

// DefaultAdminURL is Caddy's default admin endpoint. Caddy itself reads
// CADDY_ADMIN to override it; we honour the same convention.
const DefaultAdminURL = "http://127.0.0.1:2019"

// Result is what the dashboard sees.
type Result struct {
	// Detected is true when the admin API responded.
	Detected bool
	// AdminURL we used (handy for the UI to print "checked http://...").
	AdminURL string
	// Sites is the deduplicated list of (port, hosts) bindings parsed from
	// /config/apps/http/servers. Empty when Caddy is up but has no http app.
	Sites []Site
}

// Site is one Caddy listener as Zeerak cares about it: a port plus the
// host names that match it.
type Site struct {
	// Port is the TCP port Caddy is bound to (443, 80, 8080, ...).
	// Zero means we couldn't parse the listen string.
	Port int
	// Listen is the raw listen address (":443", "127.0.0.1:8080", ...).
	Listen string
	// Hosts is the union of "host" matchers across routes on this server.
	// Empty when Caddy uses catch-all routes.
	Hosts []string
}

// Detect calls Caddy's admin API and returns what we can see. Best-effort:
// any error (admin not running, wrong URL, timeout) yields Detected=false
// with no error returned to the caller.
func Detect(ctx context.Context) Result {
	url := os.Getenv("CADDY_ADMIN")
	if url == "" {
		url = DefaultAdminURL
	}
	return DetectAt(ctx, url)
}

// DetectAt is Detect with an explicit admin URL — used by tests.
func DetectAt(ctx context.Context, adminURL string) Result {
	out := Result{AdminURL: adminURL}
	client := &http.Client{Timeout: 1500 * time.Millisecond}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(adminURL, "/")+"/config/apps/http/servers", nil)
	if err != nil {
		return out
	}
	resp, err := client.Do(req)
	if err != nil {
		return out
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		// Admin reachable but the http app may not be configured. Try the
		// root config to confirm Caddy is actually answering.
		if resp.StatusCode == http.StatusNotFound {
			out.Detected = pingRoot(ctx, client, adminURL)
		}
		return out
	}
	out.Detected = true

	// Caddy returns either `null` (no http app) or a map keyed by server
	// name. We only need the listen addresses + route host matchers.
	var servers map[string]struct {
		Listen []string `json:"listen"`
		Routes []struct {
			Match []struct {
				Host []string `json:"host"`
			} `json:"match"`
		} `json:"routes"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&servers); err != nil {
		return out
	}
	for _, s := range servers {
		hosts := collectHosts(s.Routes)
		for _, l := range s.Listen {
			out.Sites = append(out.Sites, Site{
				Port:   parsePort(l),
				Listen: l,
				Hosts:  hosts,
			})
		}
	}
	sort.Slice(out.Sites, func(i, j int) bool {
		if out.Sites[i].Port != out.Sites[j].Port {
			return out.Sites[i].Port < out.Sites[j].Port
		}
		return out.Sites[i].Listen < out.Sites[j].Listen
	})
	return out
}

// Ports returns the sorted, deduplicated set of TCP ports Caddy is bound
// to. The dashboard cross-references these against the inbound allowlist.
func (r Result) Ports() []int {
	seen := map[int]bool{}
	for _, s := range r.Sites {
		if s.Port > 0 && !seen[s.Port] {
			seen[s.Port] = true
		}
	}
	out := make([]int, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	sort.Ints(out)
	return out
}

// pingRoot is the fallback when /config/apps/http/servers 404s — Caddy is
// running but the http app isn't loaded. We GET /config/ which always
// answers (returns "null" when no config is loaded).
func pingRoot(ctx context.Context, client *http.Client, adminURL string) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(adminURL, "/")+"/config/", nil)
	if err != nil {
		return false
	}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

func collectHosts(routes []struct {
	Match []struct {
		Host []string `json:"host"`
	} `json:"match"`
}) []string {
	seen := map[string]bool{}
	for _, r := range routes {
		for _, m := range r.Match {
			for _, h := range m.Host {
				if h != "" && !seen[h] {
					seen[h] = true
				}
			}
		}
	}
	out := make([]string, 0, len(seen))
	for h := range seen {
		out = append(out, h)
	}
	sort.Strings(out)
	return out
}

// parsePort extracts the port from a Caddy listen string. Caddy accepts
// ":443", "127.0.0.1:8080", "[::1]:8080", and "tcp/:443"; we handle the
// common shapes and return 0 when nothing parses (e.g. unix sockets).
func parsePort(listen string) int {
	if listen == "" {
		return 0
	}
	// Strip an optional "tcp/" or "udp/" prefix.
	if i := strings.Index(listen, "/"); i >= 0 && i < len(listen)-1 {
		listen = listen[i+1:]
	}
	// Find the last colon that isn't inside [::]. Walk from the right.
	idx := strings.LastIndex(listen, ":")
	if idx < 0 {
		return 0
	}
	port, err := strconv.Atoi(listen[idx+1:])
	if err != nil {
		return 0
	}
	return port
}
