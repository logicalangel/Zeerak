// Package ui implements Zeerak's web panel — v0.2.5 minimum-viable.
//
// Per VISION.md §3 the long-term stack is HTMX + Svelte islands +
// shadcn-svelte. v0.2.5 ships a deliberately small subset: server-rendered
// HTML forms only, no JS framework. The shadcn-svelte rule designer,
// HTMX fragment swapping, and live diff islands arrive in v0.3 alongside
// the named-sets editor.
//
// Pages
//
//	GET  /            dashboard: status, pending-change banner, quick links
//	GET  /ruleset     live `nft list ruleset` (read-only)
//	GET  /presets     preset wizard (caddy_box / ssh / default_deny_inbound)
//
// Form actions (all POST, plain form submits; success → redirect; failure →
// re-render the form with an inline error)
//
//	POST /ui/presets/preview    show rendered diff vs live, with Stage button
//	POST /ui/presets/stage      stage the preset config (arms rollback timer)
//	POST /ui/confirm            confirm pending change
//	POST /ui/rollback           rollback pending change
//
// Static assets
//
//	GET  /static/style.css      hand-rolled CSS using shadcn-style tokens
//
// The UI never bypasses the safety bar: every change goes through the same
// stager.Stage → confirm-or-auto-rollback flow as the API and CLI.
package ui

import (
	"bytes"
	"context"
	"embed"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/zeerak/zeerak/internal/config"
	"github.com/zeerak/zeerak/internal/diff"
	"github.com/zeerak/zeerak/internal/model"
	"github.com/zeerak/zeerak/internal/policy"
	"github.com/zeerak/zeerak/internal/render"
	"github.com/zeerak/zeerak/internal/stager"
)

//go:embed templates/*.html
var templatesFS embed.FS

//go:embed static
var staticFS embed.FS

// Reader mirrors api.Reader so we can render the live ruleset without an
// import cycle.
type Reader interface {
	LiveText(ctx context.Context) (string, error)
	LiveTable(ctx context.Context, family model.Family, name string) (string, error)
}

// Handler renders the v0.2.5 web panel.
type Handler struct {
	stg     *stager.Stager
	reader  Reader
	logger  *slog.Logger
	version string

	tmpl   map[string]*template.Template
	static http.Handler
}

// New builds a Handler.
func New(stg *stager.Stager, reader Reader, logger *slog.Logger, version string) (*Handler, error) {
	if logger == nil {
		logger = slog.Default()
	}
	funcs := template.FuncMap{
		"untilSeconds": func(t time.Time) int {
			if t.IsZero() {
				return 0
			}
			d := time.Until(t)
			if d < 0 {
				return 0
			}
			return int(d.Round(time.Second).Seconds())
		},
		"diffLineClass": diffLineClass,
		"splitLines": func(s string) []string {
			s = strings.TrimRight(s, "\n")
			if s == "" {
				return nil
			}
			return strings.Split(s, "\n")
		},
	}
	pages := []string{"dashboard", "ruleset", "presets", "preview", "error"}
	tmpls := make(map[string]*template.Template, len(pages))
	for _, p := range pages {
		t, err := template.New("").Funcs(funcs).ParseFS(templatesFS, "templates/base.html", "templates/"+p+".html")
		if err != nil {
			return nil, fmt.Errorf("ui: parse %s: %w", p, err)
		}
		tmpls[p+".html"] = t
	}
	sub, err := fs.Sub(staticFS, "static")
	if err != nil {
		return nil, fmt.Errorf("ui: static fs: %w", err)
	}
	return &Handler{
		stg:     stg,
		reader:  reader,
		logger:  logger,
		version: version,
		tmpl:    tmpls,
		static:  http.FileServer(http.FS(sub)),
	}, nil
}

// Register installs the UI routes onto mux. Safe to call once per mux.
func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /{$}", h.dashboard)
	mux.HandleFunc("GET /ruleset", h.ruleset)
	mux.HandleFunc("GET /presets", h.presetsForm)
	mux.HandleFunc("POST /ui/presets/preview", h.presetsPreview)
	mux.HandleFunc("POST /ui/presets/stage", h.presetsStage)
	mux.HandleFunc("POST /ui/confirm", h.confirm)
	mux.HandleFunc("POST /ui/rollback", h.rollback)
	mux.Handle("GET /static/", http.StripPrefix("/static/", h.static))
}

// --- page handlers ----------------------------------------------------------

type baseData struct {
	Title   string
	Version string
	Status  statusVM
	Flash   string  // info banner (success message after redirect)
	Error   string  // error banner
	Page    any     // page-specific payload
}

type statusVM struct {
	State    string
	Deadline time.Time
	Pending  bool
}

func (h *Handler) status() statusVM {
	st := h.stg.Status()
	return statusVM{
		State:    st.State.String(),
		Deadline: st.Deadline,
		Pending:  st.State == stager.StatePending,
	}
}

func (h *Handler) dashboard(w http.ResponseWriter, r *http.Request) {
	h.render(w, r, "dashboard.html", baseData{
		Title: "Zeerak",
	})
}

func (h *Handler) ruleset(w http.ResponseWriter, r *http.Request) {
	text, err := h.reader.LiveText(r.Context())
	if err != nil {
		h.renderError(w, r, "Ruleset", fmt.Errorf("read live ruleset: %w", err))
		return
	}
	h.render(w, r, "ruleset.html", baseData{
		Title: "Live ruleset",
		Page:  map[string]string{"Text": text},
	})
}

// --- preset wizard ----------------------------------------------------------

type presetForm struct {
	DefaultDenyInbound bool
	SSHEnabled         bool
	SSHPort            int
	SSHFrom            string // newline- or comma-separated CIDRs
	CaddyBox           bool
}

func (f presetForm) toPresets() (policy.Presets, error) {
	p := policy.Presets{
		DefaultDenyInbound: f.DefaultDenyInbound,
		CaddyBox:           f.CaddyBox,
	}
	if f.SSHEnabled {
		port := f.SSHPort
		if port == 0 {
			port = 22
		}
		var from []string
		for _, raw := range strings.FieldsFunc(f.SSHFrom, func(r rune) bool {
			return r == '\n' || r == ',' || r == ' ' || r == '\t' || r == '\r'
		}) {
			if raw != "" {
				from = append(from, raw)
			}
		}
		p.SSH = &policy.SSHPreset{Port: port, From: from}
	}
	if err := p.Validate(); err != nil {
		return policy.Presets{}, err
	}
	return p, nil
}

// asConfig wraps the presets in a minimal Config so we can reuse
// config.ToRuleset / Validate.
func (f presetForm) toConfig() (*config.Config, error) {
	p, err := f.toPresets()
	if err != nil {
		return nil, err
	}
	c := &config.Config{Version: 1, Presets: p}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}

func parsePresetForm(r *http.Request) (presetForm, error) {
	if err := r.ParseForm(); err != nil {
		return presetForm{}, err
	}
	port := 0
	if s := strings.TrimSpace(r.PostFormValue("ssh_port")); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil {
			return presetForm{}, fmt.Errorf("ssh port: %w", err)
		}
		port = n
	}
	return presetForm{
		DefaultDenyInbound: r.PostFormValue("default_deny_inbound") == "on",
		SSHEnabled:         r.PostFormValue("ssh_enabled") == "on",
		SSHPort:            port,
		SSHFrom:            r.PostFormValue("ssh_from"),
		CaddyBox:           r.PostFormValue("caddy_box") == "on",
	}, nil
}

func (h *Handler) presetsForm(w http.ResponseWriter, r *http.Request) {
	h.render(w, r, "presets.html", baseData{
		Title: "Presets",
		Flash: r.URL.Query().Get("flash"),
		Page: map[string]any{
			"Form": presetForm{SSHPort: 22},
		},
	})
}

func (h *Handler) presetsPreview(w http.ResponseWriter, r *http.Request) {
	form, err := parsePresetForm(r)
	if err != nil {
		h.render(w, r, "presets.html", baseData{
			Title: "Presets",
			Error: err.Error(),
			Page:  map[string]any{"Form": form},
		})
		return
	}
	cfg, err := form.toConfig()
	if err != nil {
		h.render(w, r, "presets.html", baseData{
			Title: "Presets",
			Error: err.Error(),
			Page:  map[string]any{"Form": form},
		})
		return
	}

	rs := cfg.ToRuleset()
	rendered, err := render.String(rs, false)
	if err != nil {
		h.renderError(w, r, "Presets", fmt.Errorf("render: %w", err))
		return
	}

	var liveSb []byte
	for _, t := range rs.Tables {
		if !t.Owned {
			continue
		}
		text, err := h.reader.LiveTable(r.Context(), t.Family, t.Name)
		if err != nil {
			h.renderError(w, r, "Presets", fmt.Errorf("live table: %w", err))
			return
		}
		liveSb = append(liveSb, text...)
	}
	live := string(liveSb)

	yamlBytes, err := yaml.Marshal(cfg)
	if err != nil {
		h.renderError(w, r, "Presets", fmt.Errorf("marshal yaml: %w", err))
		return
	}

	h.render(w, r, "preview.html", baseData{
		Title: "Preview",
		Page: map[string]any{
			"Form":     form,
			"YAML":     string(yamlBytes),
			"Rendered": rendered,
			"Live":     live,
			"Diff":     diff.Unified(live, rendered, "live", "candidate"),
		},
	})
}

func (h *Handler) presetsStage(w http.ResponseWriter, r *http.Request) {
	form, err := parsePresetForm(r)
	if err != nil {
		h.render(w, r, "presets.html", baseData{
			Title: "Presets",
			Error: err.Error(),
			Page:  map[string]any{"Form": form},
		})
		return
	}
	cfg, err := form.toConfig()
	if err != nil {
		h.render(w, r, "presets.html", baseData{
			Title: "Presets",
			Error: err.Error(),
			Page:  map[string]any{"Form": form},
		})
		return
	}
	if _, err := h.stg.Stage(r.Context(), cfg.ToRuleset()); err != nil {
		msg := err.Error()
		if errors.Is(err, stager.ErrAlreadyPending) {
			msg = "a change is already pending — confirm or rollback first"
		}
		h.render(w, r, "presets.html", baseData{
			Title: "Presets",
			Error: msg,
			Page:  map[string]any{"Form": form},
		})
		return
	}
	http.Redirect(w, r, "/?flash=staged", http.StatusSeeOther)
}

// --- confirm / rollback -----------------------------------------------------

func (h *Handler) confirm(w http.ResponseWriter, r *http.Request) {
	if err := h.stg.Confirm(); err != nil {
		http.Redirect(w, r, "/?error="+urlSafe(err.Error()), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/?flash=confirmed", http.StatusSeeOther)
}

func (h *Handler) rollback(w http.ResponseWriter, r *http.Request) {
	if err := h.stg.Rollback(r.Context()); err != nil {
		http.Redirect(w, r, "/?error="+urlSafe(err.Error()), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/?flash=rolledback", http.StatusSeeOther)
}

// --- helpers ----------------------------------------------------------------

func (h *Handler) render(w http.ResponseWriter, r *http.Request, tmpl string, data baseData) {
	if data.Version == "" {
		data.Version = h.version
	}
	data.Status = h.status()
	if data.Flash == "" {
		data.Flash = flashLabel(r.URL.Query().Get("flash"))
	}
	if data.Error == "" {
		data.Error = r.URL.Query().Get("error")
	}

	var buf bytes.Buffer
	t, ok := h.tmpl[tmpl]
	if !ok {
		h.logger.Error("ui render: unknown template", "template", tmpl)
		http.Error(w, "render error", http.StatusInternalServerError)
		return
	}
	if err := t.ExecuteTemplate(&buf, "base.html", data); err != nil {
		h.logger.Error("ui render", "template", tmpl, "err", err)
		http.Error(w, "render error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(buf.Bytes())
}

func (h *Handler) renderError(w http.ResponseWriter, r *http.Request, title string, err error) {
	h.logger.Warn("ui error", "title", title, "err", err)
	h.render(w, r, "error.html", baseData{
		Title: title,
		Error: err.Error(),
	})
}

func flashLabel(code string) string {
	switch code {
	case "staged":
		return "Change staged. Confirm within the rollback window or it will revert automatically."
	case "confirmed":
		return "Change confirmed."
	case "rolledback":
		return "Change rolled back."
	default:
		return ""
	}
}

func diffLineClass(line string) string {
	switch {
	case strings.HasPrefix(line, "+++") || strings.HasPrefix(line, "---"):
		return "diff-meta"
	case strings.HasPrefix(line, "+"):
		return "diff-add"
	case strings.HasPrefix(line, "-"):
		return "diff-del"
	case strings.HasPrefix(line, "@@"):
		return "diff-hunk"
	default:
		return ""
	}
}

// urlSafe is a deliberately tiny escaper for redirect query values. We only
// pass our own error strings through here, so a small allowlist is fine.
func urlSafe(s string) string {
	r := strings.NewReplacer(" ", "+", "\n", " ", "&", "%26", "?", "%3F", "#", "%23")
	return r.Replace(s)
}
