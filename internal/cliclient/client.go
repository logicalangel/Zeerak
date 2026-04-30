// Package cliclient is a tiny HTTP client for the Zeerak daemon.
//
// It speaks to zeerak-server over its unix socket by default (no TLS, no
// auth — that's the reverse proxy's job, see VISION.md §11 Q2). Operators
// can also point it at the loopback TCP listener via ZEERAK_ADDR.
package cliclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// DefaultSocket matches zeerak-server's --socket default.
const DefaultSocket = "/run/zeerak/zeerak.sock"

// Client talks to zeerak-server.
//
// Addr is either a unix-socket path (default) or an "http://host:port"
// URL when ZEERAK_ADDR is set.
type Client struct {
	Addr string
	HTTP *http.Client
}

// New returns a Client that talks to addr. If addr looks like a URL
// ("http://..." or "https://...") an ordinary HTTP transport is used;
// otherwise addr is treated as a unix-socket path.
func New(addr string) *Client {
	if addr == "" {
		addr = DefaultSocket
	}
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: 3 * time.Second}
			return d.DialContext(ctx, "unix", addr)
		},
	}
	if isURL(addr) {
		tr = &http.Transport{}
	}
	return &Client{
		Addr: addr,
		HTTP: &http.Client{Transport: tr, Timeout: 30 * time.Second},
	}
}

func isURL(s string) bool {
	return strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://")
}

func (c *Client) base() string {
	if isURL(c.Addr) {
		return strings.TrimRight(c.Addr, "/")
	}
	// Host is ignored by the unix dialer, but http.Client requires a valid URL.
	return "http://zeerak"
}

// Do performs an HTTP request and decodes a JSON response into out (when
// non-nil). Non-2xx responses produce a typed error built from the API's
// {"error": "..."} body.
func (c *Client) Do(ctx context.Context, method, path string, body io.Reader, out any) error {
	req, err := http.NewRequestWithContext(ctx, method, c.base()+path, body)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/x-yaml")
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("%s %s: %w", method, path, err)
	}
	defer resp.Body.Close()

	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(b, &e)
		msg := e.Error
		if msg == "" {
			msg = strings.TrimSpace(string(b))
			if msg == "" {
				msg = resp.Status
			}
		}
		return &APIError{Status: resp.StatusCode, Msg: msg}
	}
	if out != nil && len(b) > 0 {
		if err := json.Unmarshal(b, out); err != nil {
			return fmt.Errorf("decode %s %s: %w", method, path, err)
		}
	}
	return nil
}

// APIError is the typed form of a non-2xx response.
type APIError struct {
	Status int
	Msg    string
}

func (e *APIError) Error() string { return fmt.Sprintf("server: %s (HTTP %d)", e.Msg, e.Status) }

// Status returns /status.
func (c *Client) Status(ctx context.Context) (map[string]any, error) {
	var out map[string]any
	return out, c.Do(ctx, http.MethodGet, "/status", nil, &out)
}

// Version returns /version.
func (c *Client) Version(ctx context.Context) (string, error) {
	var out struct {
		Version string `json:"version"`
	}
	if err := c.Do(ctx, http.MethodGet, "/version", nil, &out); err != nil {
		return "", err
	}
	return out.Version, nil
}

// Healthz returns /healthz.
func (c *Client) Healthz(ctx context.Context) error {
	return c.Do(ctx, http.MethodGet, "/healthz", nil, nil)
}

// LiveRuleset returns the live `nft list ruleset` text.
func (c *Client) LiveRuleset(ctx context.Context) (string, error) {
	var out struct {
		Text string `json:"text"`
	}
	if err := c.Do(ctx, http.MethodGet, "/ruleset/live", nil, &out); err != nil {
		return "", err
	}
	return out.Text, nil
}

// Preview returns rendered/live/diff for a candidate YAML config.
func (c *Client) Preview(ctx context.Context, configYAML []byte) (rendered, live, diff string, err error) {
	var out struct {
		Rendered string `json:"rendered"`
		Live     string `json:"live"`
		Diff     string `json:"diff"`
	}
	if err = c.Do(ctx, http.MethodPost, "/preview", bytes.NewReader(configYAML), &out); err != nil {
		return
	}
	return out.Rendered, out.Live, out.Diff, nil
}

// Stage applies a YAML config and arms the rollback timer.
func (c *Client) Stage(ctx context.Context, configYAML []byte) (map[string]any, error) {
	var out map[string]any
	return out, c.Do(ctx, http.MethodPost, "/stage", bytes.NewReader(configYAML), &out)
}

// Confirm confirms the pending change.
func (c *Client) Confirm(ctx context.Context) error {
	return c.Do(ctx, http.MethodPost, "/confirm", nil, nil)
}

// Rollback rolls back the pending change.
func (c *Client) Rollback(ctx context.Context) error {
	return c.Do(ctx, http.MethodPost, "/rollback", nil, nil)
}
