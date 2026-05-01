// Package api implements Zeerak's HTTP control plane.
//
// The API is intentionally tiny and unauthenticated (VISION.md §11 Q2):
// it binds to loopback and a unix socket, and any auth/ACLs are the
// reverse proxy's job.
//
// Endpoints (v0.1):
//
//	GET  /healthz   — liveness, always 200
//	GET  /version   — build version
//	GET  /status    — stager state + rollback deadline
//	POST /stage     — body: zeerak.yaml; snapshots+applies, arms rollback timer
//	POST /confirm   — confirm pending change
//	POST /rollback  — explicit rollback of pending change
//
// All responses are JSON. Errors use {"error": "..."} with appropriate
// 4xx/5xx codes.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/zeerak/zeerak/internal/config"
	"github.com/zeerak/zeerak/internal/diff"
	"github.com/zeerak/zeerak/internal/model"
	"github.com/zeerak/zeerak/internal/render"
	"github.com/zeerak/zeerak/internal/stager"
)

// Reader is the read-only kernel view used by /ruleset/live and /preview.
// internal/nft.Adapter satisfies it; tests provide a fake.
type Reader interface {
	LiveText(ctx context.Context) (string, error)
	LiveTable(ctx context.Context, family model.Family, name string) (string, error)
}

// Server is the HTTP control plane.
type Server struct {
	stg     *stager.Stager
	reader  Reader
	logger  *slog.Logger
	version string

	// extraRoutes lets callers (e.g. the web panel) register additional
	// handlers on the same mux. Optional; nil is fine.
	extraRoutes func(*http.ServeMux)
}

// Option configures a Server.
type Option func(*Server)

// WithExtraRoutes registers additional routes on the mux returned by
// Handler(). Used by cmd/zeerak-server to mount the v0.2.5 web panel.
func WithExtraRoutes(register func(*http.ServeMux)) Option {
	return func(s *Server) { s.extraRoutes = register }
}

// New returns a Server backed by stg + reader.
func New(stg *stager.Stager, reader Reader, logger *slog.Logger, version string, opts ...Option) *Server {
	if logger == nil {
		logger = slog.Default()
	}
	s := &Server{stg: stg, reader: reader, logger: logger, version: version}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Handler returns the http.Handler exposing all API routes.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealthz)
	mux.HandleFunc("GET /version", s.handleVersion)
	mux.HandleFunc("GET /status", s.handleStatus)
	mux.HandleFunc("GET /ruleset/live", s.handleRulesetLive)
	mux.HandleFunc("POST /preview", s.handlePreview)
	mux.HandleFunc("POST /stage", s.handleStage)
	mux.HandleFunc("POST /confirm", s.handleConfirm)
	mux.HandleFunc("POST /rollback", s.handleRollback)
	if s.extraRoutes != nil {
		s.extraRoutes(mux)
	}
	return mux
}

// Serve runs the API on a TCP listen address and a unix socket until ctx
// is cancelled. Both listeners share the same handler. Either address may
// be empty to disable that listener.
func (s *Server) Serve(ctx context.Context, listen, socketPath string) error {
	h := s.Handler()

	var listeners []net.Listener
	var addrs []string

	if listen != "" {
		l, err := net.Listen("tcp", listen)
		if err != nil {
			return fmt.Errorf("listen tcp %s: %w", listen, err)
		}
		listeners = append(listeners, l)
		addrs = append(addrs, "tcp://"+l.Addr().String())
	}

	if socketPath != "" {
		// Ensure parent dir exists; remove any stale socket from a previous run.
		if err := os.MkdirAll(filepath.Dir(socketPath), 0o755); err != nil {
			return fmt.Errorf("mkdir socket dir: %w", err)
		}
		_ = os.Remove(socketPath)
		l, err := net.Listen("unix", socketPath)
		if err != nil {
			return fmt.Errorf("listen unix %s: %w", socketPath, err)
		}
		// 0660 so only the daemon user + group can poke it.
		if err := os.Chmod(socketPath, 0o660); err != nil {
			_ = l.Close()
			return fmt.Errorf("chmod socket: %w", err)
		}
		listeners = append(listeners, l)
		addrs = append(addrs, "unix://"+socketPath)
	}

	if len(listeners) == 0 {
		return errors.New("api: no listeners configured")
	}

	srv := &http.Server{
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
	}

	errCh := make(chan error, len(listeners))
	for i, l := range listeners {
		l := l
		s.logger.Info("api listening", "addr", addrs[i])
		go func() { errCh <- srv.Serve(l) }()
	}

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	case err := <-errCh:
		// http.ErrServerClosed only fires after Shutdown; here it means a
		// listener died unexpectedly.
		_ = srv.Close()
		return err
	}
}

// --- handlers ---------------------------------------------------------------

func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleVersion(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"version": s.version})
}

func (s *Server) handleStatus(w http.ResponseWriter, _ *http.Request) {
	st := s.stg.Status()
	writeJSON(w, http.StatusOK, statusDTO{
		State:    st.State.String(),
		Deadline: jsonTime(st.Deadline),
	})
}

// handleRulesetLive returns `nft list ruleset` text. Read-only view of the
// kernel; includes unowned tables (Docker, fail2ban, hand-written rules).
func (s *Server) handleRulesetLive(w http.ResponseWriter, r *http.Request) {
	text, err := s.reader.LiveText(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"text": text})
}

// handlePreview parses a candidate config, renders it, and diffs it
// against the live ruleset (restricted to the tables the candidate would
// touch). NO state is mutated; this is what the UI calls before /stage.
func (s *Server) handlePreview(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	if err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("read body: %w", err))
		return
	}
	var cfg config.Config
	if err := yaml.Unmarshal(body, &cfg); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("parse yaml: %w", err))
		return
	}
	if err := cfg.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	rs := cfg.ToRuleset()
	rendered, err := render.String(rs, false)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Errorf("render: %w", err))
		return
	}

	// Concatenate live text for each table the candidate owns. A table that
	// doesn't exist live yet contributes the empty string.
	var liveSb []byte
	for _, t := range rs.Tables {
		if !t.Owned {
			continue
		}
		text, err := s.reader.LiveTable(r.Context(), t.Family, t.Name)
		if err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Errorf("live table %s %s: %w", t.Family, t.Name, err))
			return
		}
		liveSb = append(liveSb, text...)
	}
	live := string(liveSb)

	writeJSON(w, http.StatusOK, map[string]string{
		"rendered": rendered,
		"live":     live,
		"diff":     diff.Unified(live, rendered, "live", "candidate"),
	})
}

func (s *Server) handleStage(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20)) // 1 MiB cap
	if err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("read body: %w", err))
		return
	}
	var cfg config.Config
	if err := yaml.Unmarshal(body, &cfg); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("parse yaml: %w", err))
		return
	}
	if err := cfg.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	deadline, err := s.stg.Stage(r.Context(), cfg.ToRuleset())
	if err != nil {
		switch {
		case errors.Is(err, stager.ErrAlreadyPending):
			writeError(w, http.StatusConflict, err)
		default:
			writeError(w, http.StatusInternalServerError, err)
		}
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{
		"state":    stager.StatePending.String(),
		"deadline": deadline,
	})
}

func (s *Server) handleConfirm(w http.ResponseWriter, _ *http.Request) {
	if err := s.stg.Confirm(); err != nil {
		s.writeStagerError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"state": stager.StateConfirmed.String()})
}

func (s *Server) handleRollback(w http.ResponseWriter, r *http.Request) {
	if err := s.stg.Rollback(r.Context()); err != nil {
		s.writeStagerError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"state": stager.StateRolledBack.String()})
}

func (s *Server) writeStagerError(w http.ResponseWriter, err error) {
	if errors.Is(err, stager.ErrNoPending) {
		writeError(w, http.StatusConflict, err)
		return
	}
	writeError(w, http.StatusInternalServerError, err)
}

// --- helpers ----------------------------------------------------------------

type statusDTO struct {
	State    string   `json:"state"`
	Deadline jsonTime `json:"deadline,omitempty"`
}

// jsonTime serialises as RFC3339, or omits when zero.
type jsonTime time.Time

func (t jsonTime) MarshalJSON() ([]byte, error) {
	tt := time.Time(t)
	if tt.IsZero() {
		return []byte("null"), nil
	}
	return json.Marshal(tt.Format(time.RFC3339Nano))
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, code int, err error) {
	writeJSON(w, code, map[string]string{"error": err.Error()})
}
