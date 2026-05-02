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
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/zeerak/zeerak/internal/activity"
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

	activity *activity.Logger // optional; nil disables timeline

	mu                sync.RWMutex
	current           policy.Presets // last applied presets (boot config or UI-confirmed)
	pendingPresets    policy.Presets // presets staged via UI, promoted to current on confirm
	pendingPresetsSet bool
}

// SetCurrent records the most recently applied presets so the dashboard can
// render service cards. Callers (boot, post-confirm) update this; concurrent
// reads on dashboard render are safe.
func (h *Handler) SetCurrent(p policy.Presets) {
	h.mu.Lock()
	h.current = p
	h.mu.Unlock()
}

func (h *Handler) currentPresets() policy.Presets {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.current
}

// SetActivityLog wires an optional activity logger. Pass nil to disable the
// timeline (the Activity nav link hides itself when no logger is set).
func (h *Handler) SetActivityLog(a *activity.Logger) {
	h.mu.Lock()
	h.activity = a
	h.mu.Unlock()
}

func (h *Handler) logEvent(ev activity.Event) {
	h.mu.RLock()
	a := h.activity
	h.mu.RUnlock()
	if a == nil {
		return
	}
	if err := a.Append(ev); err != nil {
		h.logger.Warn("activity append", "err", err)
	}
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
		"relTime": func(t time.Time) string {
			if t.IsZero() {
				return ""
			}
			d := time.Since(t)
			switch {
			case d < time.Minute:
				return "just now"
			case d < time.Hour:
				m := int(d / time.Minute)
				if m == 1 {
					return "1 minute ago"
				}
				return fmt.Sprintf("%d minutes ago", m)
			case d < 24*time.Hour:
				h := int(d / time.Hour)
				if h == 1 {
					return "1 hour ago"
				}
				return fmt.Sprintf("%d hours ago", h)
			case d < 7*24*time.Hour:
				dd := int(d / (24 * time.Hour))
				if dd == 1 {
					return "yesterday"
				}
				return fmt.Sprintf("%d days ago", dd)
			default:
				return t.Local().Format("2006-01-02 15:04")
			}
		},
		"absTime": func(t time.Time) string {
			if t.IsZero() {
				return ""
			}
			return t.Local().Format("2006-01-02 15:04")
		},
	}
	pages := []string{"dashboard", "ruleset", "presets", "preview", "error", "activity", "edit-service"}
	tmpls := make(map[string]*template.Template, len(pages))
	for _, p := range pages {
		t, err := template.New("").Funcs(funcs).ParseFS(templatesFS, "templates/base.html", "templates/_icons.html", "templates/"+p+".html")
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
	mux.HandleFunc("GET /activity", h.activityPage)
	mux.HandleFunc("GET /ruleset", h.ruleset)
	mux.HandleFunc("GET /presets", h.presetsPicker)
	mux.HandleFunc("GET /edit/{kind}", h.editService)
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
	Routing RoutingVM // nftables-native scope rendered in the topbar nav (NAT/marks/ct)
	Flash   string    // info banner (success message after redirect)
	Error   string    // error banner
	Page    any       // page-specific payload
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
	cards := serviceCards(h.currentPresets())
	live, err := h.reader.LiveText(r.Context())
	if err != nil {
		// Don't fail the page on this — show the rest, log the error.
		h.logger.Warn("dashboard: live ruleset read failed", "err", err)
		live = ""
	}
	var counts struct{ Open, Restricted, Blocked int }
	for _, c := range cards {
		switch c.Status {
		case "open":
			counts.Open++
		case "restricted":
			counts.Restricted++
		default:
			counts.Blocked++
		}
	}
	h.render(w, r, "dashboard.html", baseData{
		Title: "Zeerak",
		Page: map[string]any{
			"Cards":        cards,
			"Live":         live,
			"Defense":      defenseSummary(h.currentPresets()),
			"Counts":       counts,
			"Integrations": detectIntegrations(r.Context(), h.reader, h.currentPresets()),
		},
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

func (h *Handler) activityPage(w http.ResponseWriter, r *http.Request) {
	h.mu.RLock()
	a := h.activity
	h.mu.RUnlock()
	var events []activity.Event
	if a != nil {
		evs, err := a.Recent(50)
		if err != nil {
			h.logger.Warn("activity recent", "err", err)
		}
		events = evs
	}
	h.render(w, r, "activity.html", baseData{
		Title: "Activity",
		Page:  map[string]any{"Events": events, "HasLog": a != nil},
	})
}

// --- preset wizard ----------------------------------------------------------

type presetForm struct {
	DefaultDenyInbound bool
	SSHEnabled         bool
	SSHPort            int
	SSHFrom            string // newline- or comma-separated CIDRs
	SSHInterfaces     string // newline/space/comma list, e.g. "tailscale0 wg0"
	SSHRateLimit      int    // per-minute, 0 = off (v0.3 §10 #8)
	CaddyBox           bool

	DBEnabled bool
	DBPort    int
	DBFrom    string

	MailSMTP       bool
	MailSubmission bool
	MailIMAPS      bool
	MailPOP3S      bool

	OutRestrict   bool
	OutAllowDNS   bool
	OutAllowHTTP  bool
	OutAllowHTTPS bool
	OutAllowNTP   bool
	OutAllowSMTP  bool
	OutAllowPing  bool
	OutCustomTCP  string // newline/comma-separated ints
	OutBlock      string // newline/comma-separated CIDRs
	OutBlockRefs  string // newline/comma-separated NamedBlockSet names (v0.3 §10 #7)
	BlockSetsRaw  string // each line "setname cidr"; repeated names accumulate (v0.3 §10 #7)

	// v0.4 nftables-native scope (NAT, policy-routing marks, conntrack
	// helpers). Each list is rendered as a structured row table in the panel
	// — one HTML row per slice element — and round-tripped via repeated
	// indexed POST fields. See parsePresetForm below for the field names.
	PortForwards []policy.PortForward
	Masquerades  []policy.Masquerade
	Marks        []policy.Mark
	CTHelperFTP  bool
	CTHelperSIP  bool
	CTHelperTFTP bool
	CTHelperPPTP bool
	CTHelperIRC  bool
	CTHelperH323 bool
}

func splitCIDRs(s string) []string {
	var out []string
	for _, raw := range strings.FieldsFunc(s, func(r rune) bool {
		return r == '\n' || r == ',' || r == ' ' || r == '\t' || r == '\r'
	}) {
		if raw != "" {
			out = append(out, raw)
		}
	}
	return out
}

// splitTokens splits a free-form string into non-empty tokens on whitespace
// or commas. Used for interface names, set-name lists, etc.
func splitTokens(s string) []string {
	var out []string
	for _, raw := range strings.FieldsFunc(s, func(r rune) bool {
		return r == '\n' || r == ',' || r == ' ' || r == '\t' || r == '\r'
	}) {
		if raw != "" {
			out = append(out, raw)
		}
	}
	return out
}

// parseBlockSets parses the panel's block_sets_raw textarea, where each
// non-empty, non-comment line is "<setname> <cidr>". Repeated names
// accumulate CIDRs into a single set; family is inferred from the CIDR
// (":" → v6, else v4). Order is preserved by first appearance of the name.
func parseBlockSets(s string) []policy.NamedBlockSet {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	type bucket struct {
		idx    int
		set    policy.NamedBlockSet
	}
	buckets := map[string]*bucket{}
	var order []string
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// split off leading whitespace-separated name; the rest is one CIDR
		// (commas and extra spaces handled too).
		fields := strings.FieldsFunc(line, func(r rune) bool {
			return r == ' ' || r == '\t' || r == ','
		})
		if len(fields) < 2 {
			continue
		}
		name := fields[0]
		for _, c := range fields[1:] {
			b, ok := buckets[name]
			if !ok {
				fam := "v4"
				if strings.Contains(c, ":") {
					fam = "v6"
				}
				b = &bucket{idx: len(order), set: policy.NamedBlockSet{Name: name, Family: fam}}
				buckets[name] = b
				order = append(order, name)
			}
			b.set.CIDRs = append(b.set.CIDRs, c)
		}
	}
	out := make([]policy.NamedBlockSet, 0, len(order))
	for _, name := range order {
		out = append(out, buckets[name].set)
	}
	return out
}

// readRowColumns extracts aligned column slices from a posted form. Every
// row in the structured-row UIs (NAT, marks, …) is rendered as a parallel
// set of repeated inputs sharing the same row index, e.g.
//
//	pf_proto=tcp&pf_ext_port=8080&pf_to=10.0.0.5&pf_to_port=80
//	pf_proto=udp&pf_ext_port=53 &pf_to=10.0.0.10&pf_to_port=
//
// readRowColumns returns one string slice per requested key, all padded to
// the longest column so callers can index them in lockstep.
func readRowColumns(form url.Values, keys ...string) [][]string {
	cols := make([][]string, len(keys))
	n := 0
	for i, k := range keys {
		cols[i] = form[k]
		if len(cols[i]) > n {
			n = len(cols[i])
		}
	}
	for i := range cols {
		if len(cols[i]) < n {
			pad := make([]string, n-len(cols[i]))
			cols[i] = append(cols[i], pad...)
		}
	}
	return cols
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
		ssh := &policy.SSHPreset{Port: port, From: splitCIDRs(f.SSHFrom)}
		if ifaces := splitTokens(f.SSHInterfaces); len(ifaces) > 0 {
			ssh.Interfaces = ifaces
		}
		if f.SSHRateLimit > 0 {
			ssh.RateLimit = &policy.SSHRateLimit{PerMinute: f.SSHRateLimit}
		}
		p.SSH = ssh
	}
	if sets := parseBlockSets(f.BlockSetsRaw); len(sets) > 0 {
		p.BlockSets = sets
	}
	if f.DBEnabled {
		port := f.DBPort
		if port == 0 {
			port = 5432
		}
		p.Database = &policy.DatabasePreset{Port: port, From: splitCIDRs(f.DBFrom)}
	}
	if f.MailSMTP || f.MailSubmission || f.MailIMAPS || f.MailPOP3S {
		p.Mail = &policy.MailPreset{
			SMTP:       f.MailSMTP,
			Submission: f.MailSubmission,
			IMAPS:      f.MailIMAPS,
			POP3S:      f.MailPOP3S,
		}
	}
	if out, ok := f.toOutbound(); ok {
		p.Outbound = out
	}
	// v0.4 routing/NAT/ct: structured slices already.
	p.PortForwards = append([]policy.PortForward(nil), f.PortForwards...)
	p.Masquerade = append([]policy.Masquerade(nil), f.Masquerades...)
	p.Marks = append([]policy.Mark(nil), f.Marks...)
	if f.CTHelperFTP || f.CTHelperSIP || f.CTHelperTFTP || f.CTHelperPPTP || f.CTHelperIRC || f.CTHelperH323 {
		p.CTHelpers = &policy.CTHelpers{
			FTP:  f.CTHelperFTP,
			SIP:  f.CTHelperSIP,
			TFTP: f.CTHelperTFTP,
			PPTP: f.CTHelperPPTP,
			IRC:  f.CTHelperIRC,
			H323: f.CTHelperH323,
		}
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
	rate := 0
	if s := strings.TrimSpace(r.PostFormValue("ssh_rate_limit")); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 0 {
			return presetForm{}, fmt.Errorf("ssh rate limit: must be a non-negative integer")
		}
		rate = n
	}

	// SSH: prefer the audience radio; fall back to legacy checkbox so old
	// preview-form round-trips and tests keep working.
	sshFrom := r.PostFormValue("ssh_from")
	sshEnabled := r.PostFormValue("ssh_enabled") == "on"
	switch r.PostFormValue("ssh_audience") {
	case "off":
		sshEnabled = false
	case "any":
		sshEnabled = true
		sshFrom = ""
	case "restricted":
		sshEnabled = true
	}

	// Web: same pattern.
	caddy := r.PostFormValue("caddy_box") == "on"
	switch r.PostFormValue("web_audience") {
	case "off":
		caddy = false
	case "any":
		caddy = true
	}

	// Database
	dbPort := 0
	if s := strings.TrimSpace(r.PostFormValue("db_port")); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil {
			return presetForm{}, fmt.Errorf("database port: %w", err)
		}
		dbPort = n
	}
	dbFrom := r.PostFormValue("db_from")
	dbEnabled := r.PostFormValue("db_enabled") == "on"
	switch r.PostFormValue("db_audience") {
	case "off":
		dbEnabled = false
	case "any":
		dbEnabled = true
		dbFrom = ""
	case "restricted":
		dbEnabled = true
	}

	// Mail — each port independent.
	mailSMTP := r.PostFormValue("mail_smtp") == "on"
	mailSub := r.PostFormValue("mail_submission") == "on"
	mailIMAPS := r.PostFormValue("mail_imaps") == "on"
	mailPOP3S := r.PostFormValue("mail_pop3s") == "on"

	pfs, err := parsePortForwardRows(r.PostForm)
	if err != nil {
		return presetForm{}, err
	}
	masq, err := parseMasqueradeRows(r.PostForm)
	if err != nil {
		return presetForm{}, err
	}
	marks, err := parseMarkRows(r.PostForm)
	if err != nil {
		return presetForm{}, err
	}

	return presetForm{
		DefaultDenyInbound: r.PostFormValue("default_deny_inbound") == "on",
		SSHEnabled:         sshEnabled,
		SSHPort:            port,
		SSHFrom:            sshFrom,
		SSHInterfaces:      r.PostFormValue("ssh_interfaces"),
		SSHRateLimit:       rate,
		CaddyBox:           caddy,
		DBEnabled:          dbEnabled,
		DBPort:             dbPort,
		DBFrom:             dbFrom,
		MailSMTP:           mailSMTP,
		MailSubmission:     mailSub,
		MailIMAPS:          mailIMAPS,
		MailPOP3S:          mailPOP3S,
		OutRestrict:        r.PostFormValue("out_restrict") == "on",
		OutAllowDNS:        r.PostFormValue("out_allow_dns") == "on",
		OutAllowHTTP:       r.PostFormValue("out_allow_http") == "on",
		OutAllowHTTPS:      r.PostFormValue("out_allow_https") == "on",
		OutAllowNTP:        r.PostFormValue("out_allow_ntp") == "on",
		OutAllowSMTP:       r.PostFormValue("out_allow_smtp") == "on",
		OutAllowPing:       r.PostFormValue("out_allow_ping") == "on",
		OutCustomTCP:       r.PostFormValue("out_custom_tcp"),
		OutBlock:           r.PostFormValue("out_block"),
		OutBlockRefs:       r.PostFormValue("out_block_refs"),
		BlockSetsRaw:       r.PostFormValue("block_sets_raw"),

		PortForwards: pfs,
		Masquerades:  masq,
		Marks:        marks,
		CTHelperFTP:  r.PostFormValue("ct_helper_ftp") == "on",
		CTHelperSIP:  r.PostFormValue("ct_helper_sip") == "on",
		CTHelperTFTP: r.PostFormValue("ct_helper_tftp") == "on",
		CTHelperPPTP: r.PostFormValue("ct_helper_pptp") == "on",
		CTHelperIRC:  r.PostFormValue("ct_helper_irc") == "on",
		CTHelperH323: r.PostFormValue("ct_helper_h323") == "on",
	}, nil
}

// parsePortForwardRows reads the indexed POST fields produced by the
// NAT editor's row UI. Each row owns one slot in every parallel column;
// rows whose only meaningful field is empty are skipped silently so
// "+ Add" buttons that left blank rows behind don't fail validation.
func parsePortForwardRows(form url.Values) ([]policy.PortForward, error) {
	cols := readRowColumns(form, "pf_proto", "pf_ext_port", "pf_to", "pf_to_port", "pf_iif", "pf_from", "pf_comment")
	proto, ext, to, toPort, iif, from, cmt := cols[0], cols[1], cols[2], cols[3], cols[4], cols[5], cols[6]
	var out []policy.PortForward
	for i := range proto {
		if strings.TrimSpace(ext[i]) == "" && strings.TrimSpace(to[i]) == "" {
			continue
		}
		pf := policy.PortForward{
			Proto:   strings.TrimSpace(strings.ToLower(proto[i])),
			To:      strings.TrimSpace(to[i]),
			IIF:     strings.TrimSpace(iif[i]),
			From:    strings.TrimSpace(from[i]),
			Comment: strings.TrimSpace(cmt[i]),
		}
		extStr := strings.TrimSpace(ext[i])
		if extStr == "" {
			return nil, fmt.Errorf("port forward row %d: external port required", i+1)
		}
		n, err := strconv.Atoi(extStr)
		if err != nil {
			return nil, fmt.Errorf("port forward row %d: external port: %w", i+1, err)
		}
		pf.ExtPort = n
		if tp := strings.TrimSpace(toPort[i]); tp != "" {
			n, err := strconv.Atoi(tp)
			if err != nil {
				return nil, fmt.Errorf("port forward row %d: internal port: %w", i+1, err)
			}
			pf.ToPort = n
		}
		out = append(out, pf)
	}
	return out, nil
}

func parseMasqueradeRows(form url.Values) ([]policy.Masquerade, error) {
	cols := readRowColumns(form, "mq_oif", "mq_source", "mq_comment")
	oif, src, cmt := cols[0], cols[1], cols[2]
	var out []policy.Masquerade
	for i := range oif {
		o := strings.TrimSpace(oif[i])
		s := strings.TrimSpace(src[i])
		c := strings.TrimSpace(cmt[i])
		if o == "" && s == "" {
			continue
		}
		if o == "" {
			return nil, fmt.Errorf("masquerade row %d: outbound interface required", i+1)
		}
		out = append(out, policy.Masquerade{OIF: o, Source: s, Comment: c})
	}
	return out, nil
}

func parseMarkRows(form url.Values) ([]policy.Mark, error) {
	cols := readRowColumns(form, "mk_name", "mk_set", "mk_proto", "mk_dport", "mk_oif", "mk_daddr", "mk_comment")
	name, set, proto, dport, oif, daddr, cmt := cols[0], cols[1], cols[2], cols[3], cols[4], cols[5], cols[6]
	var out []policy.Mark
	for i := range name {
		n := strings.TrimSpace(name[i])
		s := strings.TrimSpace(set[i])
		if n == "" && s == "" {
			continue
		}
		if n == "" {
			return nil, fmt.Errorf("mark row %d: name required", i+1)
		}
		if s == "" {
			return nil, fmt.Errorf("mark row %d: set value required", i+1)
		}
		v, err := strconv.ParseUint(s, 0, 32)
		if err != nil {
			return nil, fmt.Errorf("mark row %d: set: %w", i+1, err)
		}
		m := policy.Mark{
			Name:    n,
			Set:     uint32(v),
			Proto:   strings.TrimSpace(strings.ToLower(proto[i])),
			OIF:     strings.TrimSpace(oif[i]),
			Daddr:   strings.TrimSpace(daddr[i]),
			Comment: strings.TrimSpace(cmt[i]),
		}
		if dp := strings.TrimSpace(dport[i]); dp != "" {
			n, err := strconv.Atoi(dp)
			if err != nil {
				return nil, fmt.Errorf("mark row %d: dport: %w", i+1, err)
			}
			m.DPort = n
		}
		out = append(out, m)
	}
	return out, nil
}

func (h *Handler) presetsForm(w http.ResponseWriter, r *http.Request) {
	h.render(w, r, "presets.html", baseData{
		Title: "Presets",
		Flash: r.URL.Query().Get("flash"),
		Page: map[string]any{
			"Form": presetForm{SSHPort: 22, DBPort: 5432},
		},
	})
}

// editServiceMeta describes each per-service editor page.
var editServiceMeta = map[string]struct {
	Icon, Name, Subtitle string
}{
	"ssh":        {"key", "Remote access (SSH)", "Who can log in to this machine remotely."},
	"web":        {"globe", "Website", "Who can reach the public website (HTTP/HTTPS)."},
	"db":         {"database", "Database", "Who can connect to the database."},
	"mail":       {"mail", "Mail", "Which mail ports are open."},
	"protection": {"shield", "Default protection", "Block everything that isn't explicitly allowed."},
	"outbound":   {"upload", "Outbound traffic", "What this machine is allowed to send to the internet."},
	"nat":        {"upload", "NAT & port forwards", "DNAT inbound ports to internal hosts; SNAT outbound traffic via masquerade."},
	"marks":      {"upload", "Traffic routing rules", "Steer traffic through a specific VPN tunnel, network interface, or routing table."},
	"ct":         {"shield", "Protocol helpers", "Let older protocols (FTP, SIP, …) open secondary connections through the firewall automatically."},
}

// presetFormFromPresets seeds a presetForm from the currently applied presets.
func presetFormFromPresets(p policy.Presets) presetForm {
	f := presetForm{
		DefaultDenyInbound: p.DefaultDenyInbound,
		CaddyBox:           p.CaddyBox,
		SSHPort:            22,
		DBPort:             5432,
	}
	if p.SSH != nil {
		f.SSHEnabled = true
		if p.SSH.Port > 0 {
			f.SSHPort = p.SSH.Port
		}
		if len(p.SSH.From) > 0 {
			f.SSHFrom = strings.Join(p.SSH.From, "\n")
		}
		if len(p.SSH.Interfaces) > 0 {
			f.SSHInterfaces = strings.Join(p.SSH.Interfaces, " ")
		}
		if p.SSH.RateLimit != nil {
			f.SSHRateLimit = p.SSH.RateLimit.PerMinute
		}
	}
	if p.Database != nil {
		f.DBEnabled = true
		if p.Database.Port > 0 {
			f.DBPort = p.Database.Port
		}
		if len(p.Database.From) > 0 {
			f.DBFrom = strings.Join(p.Database.From, "\n")
		}
	}
	if p.Mail != nil {
		f.MailSMTP = p.Mail.SMTP
		f.MailSubmission = p.Mail.Submission
		f.MailIMAPS = p.Mail.IMAPS
		f.MailPOP3S = p.Mail.POP3S
	}
	if p.Outbound != nil {
		f.OutRestrict = p.Outbound.Restrict
		f.OutAllowDNS = p.Outbound.AllowDNS
		f.OutAllowHTTP = p.Outbound.AllowHTTP
		f.OutAllowHTTPS = p.Outbound.AllowHTTPS
		f.OutAllowNTP = p.Outbound.AllowNTP
		f.OutAllowSMTP = p.Outbound.AllowSMTP
		f.OutAllowPing = p.Outbound.AllowPing
		if len(p.Outbound.CustomTCP) > 0 {
			parts := make([]string, len(p.Outbound.CustomTCP))
			for i, n := range p.Outbound.CustomTCP {
				parts[i] = strconv.Itoa(n)
			}
			f.OutCustomTCP = strings.Join(parts, "\n")
		}
		if len(p.Outbound.Block) > 0 {
			f.OutBlock = strings.Join(p.Outbound.Block, "\n")
		}
		if len(p.Outbound.BlockRefs) > 0 {
			f.OutBlockRefs = strings.Join(p.Outbound.BlockRefs, " ")
		}
	}
	if len(p.BlockSets) > 0 {
		var lines []string
		for _, s := range p.BlockSets {
			for _, c := range s.CIDRs {
				lines = append(lines, s.Name+" "+c)
			}
		}
		f.BlockSetsRaw = strings.Join(lines, "\n")
	}
	f.PortForwards = append([]policy.PortForward(nil), p.PortForwards...)
	f.Masquerades = append([]policy.Masquerade(nil), p.Masquerade...)
	f.Marks = append([]policy.Mark(nil), p.Marks...)
	if p.CTHelpers != nil {
		f.CTHelperFTP = p.CTHelpers.FTP
		f.CTHelperSIP = p.CTHelpers.SIP
		f.CTHelperTFTP = p.CTHelpers.TFTP
		f.CTHelperPPTP = p.CTHelpers.PPTP
		f.CTHelperIRC = p.CTHelpers.IRC
		f.CTHelperH323 = p.CTHelpers.H323
	}
	return f
}

func (h *Handler) presetsPicker(w http.ResponseWriter, r *http.Request) {
	h.render(w, r, "presets.html", baseData{
		Title: "Add or change a service",
		Page: map[string]any{
			"Cards": serviceCards(h.currentPresets()),
		},
	})
}

func (h *Handler) editService(w http.ResponseWriter, r *http.Request) {
	kind := r.PathValue("kind")
	meta, ok := editServiceMeta[kind]
	if !ok {
		http.NotFound(w, r)
		return
	}
	h.render(w, r, "edit-service.html", baseData{
		Title: meta.Name,
		Page: map[string]any{
			"Kind":     kind,
			"Icon":     meta.Icon,
			"Name":     meta.Name,
			"Subtitle": meta.Subtitle,
			"Form":     presetFormFromPresets(h.currentPresets()),
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
			"Before":   serviceCards(h.currentPresets()),
			"After":    serviceCards(cfg.Presets),
			"Summary":  presetsSummary(cfg.Presets),
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
	// Stash the pending presets so the dashboard reflects them once confirmed.
	h.mu.Lock()
	h.pendingPresets = cfg.Presets
	h.pendingPresetsSet = true
	h.mu.Unlock()
	h.logEvent(activity.Event{Kind: activity.KindStaged, Message: "You staged a change.", Detail: presetsSummary(cfg.Presets)})
	http.Redirect(w, r, "/?flash=staged", http.StatusSeeOther)
}

// --- confirm / rollback -----------------------------------------------------

func (h *Handler) confirm(w http.ResponseWriter, r *http.Request) {
	if err := h.stg.Confirm(); err != nil {
		http.Redirect(w, r, "/?error="+urlSafe(err.Error()), http.StatusSeeOther)
		return
	}
	h.mu.Lock()
	if h.pendingPresetsSet {
		h.current = h.pendingPresets
	}
	h.pendingPresets = policy.Presets{}
	h.pendingPresetsSet = false
	h.mu.Unlock()
	h.logEvent(activity.Event{Kind: activity.KindConfirmed, Message: "You confirmed the change."})
	http.Redirect(w, r, "/?flash=confirmed", http.StatusSeeOther)
}

func (h *Handler) rollback(w http.ResponseWriter, r *http.Request) {
	if err := h.stg.Rollback(r.Context()); err != nil {
		http.Redirect(w, r, "/?error="+urlSafe(err.Error()), http.StatusSeeOther)
		return
	}
	h.mu.Lock()
	h.pendingPresets = policy.Presets{}
	h.pendingPresetsSet = false
	h.mu.Unlock()
	h.logEvent(activity.Event{Kind: activity.KindReverted, Message: "You reverted the staged change."})
	http.Redirect(w, r, "/?flash=rolledback", http.StatusSeeOther)
}

// --- helpers ----------------------------------------------------------------

func (h *Handler) render(w http.ResponseWriter, r *http.Request, tmpl string, data baseData) {
	if data.Version == "" {
		data.Version = h.version
	}
	data.Status = h.status()
	// Routing chips live in the global topbar; compute once per render so every
	// page sees the same NAT/marks/ct status without each handler wiring it.
	data.Routing = routingVM(h.currentPresets())
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

// toOutbound converts the form's outbound fields into a policy preset.
// Returns (nil, false) when no outbound feature is enabled.
func (f presetForm) toOutbound() (*policy.OutboundPreset, bool) {
	out := &policy.OutboundPreset{
		Restrict:   f.OutRestrict,
		AllowDNS:   f.OutAllowDNS,
		AllowHTTP:  f.OutAllowHTTP,
		AllowHTTPS: f.OutAllowHTTPS,
		AllowNTP:   f.OutAllowNTP,
		AllowSMTP:  f.OutAllowSMTP,
		AllowPing:  f.OutAllowPing,
		Block:      splitCIDRs(f.OutBlock),
		BlockRefs:  splitTokens(f.OutBlockRefs),
	}
	for _, raw := range strings.FieldsFunc(f.OutCustomTCP, func(r rune) bool {
		return r == '\n' || r == ',' || r == ' ' || r == '\t' || r == '\r'
	}) {
		if n, err := strconv.Atoi(strings.TrimSpace(raw)); err == nil {
			out.CustomTCP = append(out.CustomTCP, n)
		}
	}
	if !out.Active() && !out.AllowDNS && !out.AllowHTTP && !out.AllowHTTPS &&
		!out.AllowNTP && !out.AllowSMTP && !out.AllowPing &&
		len(out.CustomTCP) == 0 {
		return nil, false
	}
	return out, true
}
