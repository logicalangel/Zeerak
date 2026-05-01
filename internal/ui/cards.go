// Service-card derivation for the home dashboard.
//
// The home page paints "what can reach this machine right now" as a small
// grid of human-readable cards. We derive them from the last applied presets
// (see Handler.SetCurrent) instead of parsing the live nft ruleset, so the
// cards stay in plain English (no port numbers, no chains).
//
// Card status pills:
//
//   - "open"        reachable from anywhere
//   - "restricted"  reachable only from a CIDR allowlist
//   - "blocked"     not reachable
package ui

import (
	"context"
	"fmt"
	"strings"

	caddyint "github.com/zeerak/zeerak/internal/integrations/caddy"
	dockerint "github.com/zeerak/zeerak/internal/integrations/docker"
	tailscaleint "github.com/zeerak/zeerak/internal/integrations/tailscale"
	wireguardint "github.com/zeerak/zeerak/internal/integrations/wireguard"
	"github.com/zeerak/zeerak/internal/policy"
)

// ServiceCard is the view-model for one tile on the home grid.
//
// Visual language:
//   - Pills represent ENTITIES (this machine, internet, audiences) and the
//     card's status. They are *not* used for transport.
//   - The flow line on the card shows TRANSPORT (ports/protocols) as a
//     single label sitting on an arrow — never a row of port pills.
type ServiceCard struct {
	Key       string // stable id ("ssh", "web", ...)
	Icon      string // icon name (matches inline <svg> sprites in templates)
	Name      string // user-facing label, e.g. "Remote access"
	Subtitle  string // one-line summary, e.g. "Open from 2 networks"
	Status    string // "open" | "restricted" | "blocked" | "soon"
	Disabled  bool   // true → "Coming soon" tile, not clickable to edit
	FlowDir   string // "in" (inbound) or "out" (outbound) — drives arrow glyph
	FlowLabel string // transport label on the flow line, e.g. "tcp 22, 80, 443"
}

// DefenseSummary is the headline string under the safety strip, e.g.
// "Default-deny is on. Only the services below can reach this machine."
type DefenseSummary struct {
	Headline string
	Detail   string
	Strong   bool // true when default-deny is on
}

func defenseSummary(p policy.Presets) DefenseSummary {
	if p.DefaultDenyInbound {
		return DefenseSummary{
			Headline: "Default-deny is on.",
			Detail:   "Only the services below can reach this machine. Everything else is blocked.",
			Strong:   true,
		}
	}
	return DefenseSummary{
		Headline: "Default-deny is off.",
		Detail:   "Anything not explicitly blocked can reach this machine. Turn on default-deny to harden the host.",
		Strong:   false,
	}
}

func serviceCards(p policy.Presets) []ServiceCard {
	cards := make([]ServiceCard, 0, 5)

	// SSH / Remote access
	switch {
	case p.SSH == nil && p.DefaultDenyInbound:
		cards = append(cards, ServiceCard{
			Key: "ssh", Icon: "key", Name: "Remote access",
			Subtitle: "Blocked",
			Status:   "blocked",
		})
	case p.SSH == nil:
		cards = append(cards, ServiceCard{
			Key: "ssh", Icon: "key", Name: "Remote access",
			Subtitle: "Not configured",
			Status:   "blocked",
		})
	default:
		port := p.SSH.Port
		if port == 0 {
			port = 22
		}
		cards = append(cards, ServiceCard{
			Key: "ssh", Icon: "key", Name: "Remote access",
			Subtitle:  sshSubtitle(*p.SSH),
			Status:    sshStatus(*p.SSH),
			FlowDir:   "in",
			FlowLabel: portsLabel([]int{port}),
		})
	}

	// Web (Caddy box preset)
	if p.CaddyBox {
		cards = append(cards, ServiceCard{
			Key: "web", Icon: "globe", Name: "Website",
			Subtitle:  "Open from anywhere",
			Status:    "open",
			FlowDir:   "in",
			FlowLabel: portsLabel([]int{80, 443}),
		})
	} else if p.DefaultDenyInbound {
		cards = append(cards, ServiceCard{
			Key: "web", Icon: "globe", Name: "Website",
			Subtitle: "Blocked",
			Status:   "blocked",
		})
	} else {
		cards = append(cards, ServiceCard{
			Key: "web", Icon: "globe", Name: "Website",
			Subtitle: "Not configured",
			Status:   "blocked",
		})
	}

	// Database
	switch {
	case p.Database == nil && p.DefaultDenyInbound:
		cards = append(cards, ServiceCard{
			Key: "db", Icon: "database", Name: "Database",
			Subtitle: "Blocked", Status: "blocked",
		})
	case p.Database == nil:
		cards = append(cards, ServiceCard{
			Key: "db", Icon: "database", Name: "Database",
			Subtitle: "Not configured", Status: "blocked",
		})
	default:
		port := p.Database.Port
		if port == 0 {
			port = 5432
		}
		cards = append(cards, ServiceCard{
			Key: "db", Icon: "database", Name: "Database",
			Subtitle:  dbSubtitle(*p.Database),
			Status:    dbStatus(*p.Database),
			FlowDir:   "in",
			FlowLabel: portsLabel([]int{port}),
		})
	}

	// Mail
	switch {
	case (p.Mail == nil || !p.Mail.AnyPort()) && p.DefaultDenyInbound:
		cards = append(cards, ServiceCard{
			Key: "mail", Icon: "mail", Name: "Mail",
			Subtitle: "Blocked", Status: "blocked",
		})
	case p.Mail == nil || !p.Mail.AnyPort():
		cards = append(cards, ServiceCard{
			Key: "mail", Icon: "mail", Name: "Mail",
			Subtitle: "Not configured", Status: "blocked",
		})
	default:
		cards = append(cards, ServiceCard{
			Key: "mail", Icon: "mail", Name: "Mail",
			Subtitle:  mailSubtitle(*p.Mail),
			Status:    "open",
			FlowDir:   "in",
			FlowLabel: portsLabel(mailPorts(*p.Mail)),
		})
	}

	// Outbound — what this machine can send out.
	cards = append(cards, outboundCard(p.Outbound))

	return cards
}

func sshStatus(s policy.SSHPreset) string {
	if len(s.From) > 0 {
		return "restricted"
	}
	return "open"
}

func sshSubtitle(s policy.SSHPreset) string {
	if len(s.From) == 0 {
		return "Open from anywhere"
	}
	if len(s.From) == 1 {
		return "Open from 1 trusted network"
	}
	return fmt.Sprintf("Open from %d trusted networks", len(s.From))
}

func dbStatus(d policy.DatabasePreset) string {
	if len(d.From) > 0 {
		return "restricted"
	}
	return "open"
}

func dbSubtitle(d policy.DatabasePreset) string {
	if len(d.From) == 0 {
		return "Open from anywhere"
	}
	if len(d.From) == 1 {
		return "Open from 1 trusted network"
	}
	return fmt.Sprintf("Open from %d trusted networks", len(d.From))
}

func mailSubtitle(m policy.MailPreset) string {	var names []string
	if m.SMTP {
		names = append(names, "SMTP")
	}
	if m.Submission {
		names = append(names, "Submission")
	}
	if m.IMAPS {
		names = append(names, "IMAPS")
	}
	if m.POP3S {
		names = append(names, "POP3S")
	}
	if len(names) == 0 {
		return "Off"
	}
	return "Open: " + strings.Join(names, ", ")
}

// presetsSummary renders a one-sentence detail line for an activity entry,
// e.g. "Default-deny on; SSH from 2 networks; Website open".
func presetsSummary(p policy.Presets) string {
	parts := []string{}
	if p.DefaultDenyInbound {
		parts = append(parts, "Default-deny on")
	}
	if p.SSH != nil {
		switch len(p.SSH.From) {
		case 0:
			parts = append(parts, "SSH open from anywhere")
		case 1:
			parts = append(parts, "SSH from 1 network")
		default:
			parts = append(parts, fmt.Sprintf("SSH from %d networks", len(p.SSH.From)))
		}
	}
	if p.CaddyBox {
		parts = append(parts, "Website open")
	}
	if p.Database != nil {
		switch len(p.Database.From) {
		case 0:
			parts = append(parts, "Database open from anywhere")
		case 1:
			parts = append(parts, "Database from 1 network")
		default:
			parts = append(parts, fmt.Sprintf("Database from %d networks", len(p.Database.From)))
		}
	}
	if p.Mail != nil && p.Mail.AnyPort() {
		parts = append(parts, "Mail open")
	}
	if len(parts) == 0 {
		return "No services enabled"
	}
	out := parts[0]
	for _, s := range parts[1:] {
		out += "; " + s
	}
	return out
}

// mailPorts returns the inbound TCP ports opened by a MailPreset.
func mailPorts(m policy.MailPreset) []int {
	var ps []int
	if m.SMTP {
		ps = append(ps, 25)
	}
	if m.Submission {
		ps = append(ps, 587)
	}
	if m.IMAPS {
		ps = append(ps, 993)
	}
	if m.POP3S {
		ps = append(ps, 995)
	}
	return ps
}

// outboundCard renders the dashboard tile for outbound (egress) policy.
// Status semantics:
//   - "open"       — outbound unrestricted (default)
//   - "restricted" — restrict mode is on or block list non-empty
func outboundCard(o *policy.OutboundPreset) ServiceCard {
	c := ServiceCard{
		Key: "outbound", Icon: "upload", Name: "Outbound traffic",
		FlowDir: "out",
	}
	if o == nil || (!o.Restrict && len(o.Block) == 0) {
		c.Status = "open"
		c.Subtitle = "Open — this machine can talk to anything"
		c.FlowLabel = "anything"
		return c
	}
	if o.Restrict {
		c.Status = "restricted"
		c.Subtitle = outboundRestrictSubtitle(*o)
		c.FlowLabel = outboundRestrictLabel(*o)
		return c
	}
	// Block list only.
	n := len(o.Block)
	c.Status = "restricted"
	if n == 1 {
		c.Subtitle = "Open with 1 blocked destination"
	} else {
		c.Subtitle = fmt.Sprintf("Open with %d blocked destinations", n)
	}
	c.FlowLabel = "anything except blocked"
	return c
}

func outboundRestrictSubtitle(o policy.OutboundPreset) string {
	on := outboundAllowedNames(o)
	if len(on) == 0 {
		return "Restricted — nothing allowed out"
	}
	return "Restricted: " + strings.Join(on, ", ")
}

func outboundRestrictLabel(o policy.OutboundPreset) string {
	on := outboundAllowedNames(o)
	if len(on) == 0 {
		return "nothing"
	}
	return strings.Join(on, ", ")
}

func outboundAllowedNames(o policy.OutboundPreset) []string {
	var on []string
	if o.AllowDNS {
		on = append(on, "dns")
	}
	if o.AllowHTTPS {
		on = append(on, "https")
	}
	if o.AllowHTTP {
		on = append(on, "http")
	}
	if o.AllowNTP {
		on = append(on, "ntp")
	}
	if o.AllowSMTP {
		on = append(on, "smtp")
	}
	if o.AllowPing {
		on = append(on, "ping")
	}
	if len(o.CustomTCP) > 0 {
		on = append(on, fmt.Sprintf("%d custom", len(o.CustomTCP)))
	}
	return on
}

// portsLabel formats a port list for the flow line, e.g. [22,80,443] -> "tcp 22, 80, 443".
// Pills are reserved for entities; transport (ports/protocols) sits as a single
// label on the arrow.
func portsLabel(ports []int) string {
	if len(ports) == 0 {
		return ""
	}
	parts := make([]string, len(ports))
	for i, p := range ports {
		parts[i] = fmt.Sprintf("%d", p)
	}
	return "tcp " + strings.Join(parts, ", ")
}

// IntegrationsVM is the dashboard "Detected on this host" section payload.
// VISION.md §10 v0.3: tailscale0/wg awareness + docker chain awareness.
// All three are detection-only; we never auto-modify their rules.
type IntegrationsVM struct {
	Tailscale tailscaleint.Result
	WireGuard wireguardint.Result
	Docker    dockerint.Result
	Caddy     caddyint.Result
	// CaddyPortGaps is the subset of Caddy-bound TCP ports that the current
	// inbound preset configuration does not allow. It's the classic footgun:
	// Caddy answers on :443 but the firewall drops it. Empty when Caddy
	// isn't detected or every port is covered.
	CaddyPortGaps []int
}

func detectIntegrations(ctx context.Context, r Reader, p policy.Presets) IntegrationsVM {
	vm := IntegrationsVM{
		Tailscale: tailscaleint.Detect(),
		WireGuard: wireguardint.Detect(),
		Docker:    dockerint.Detect(ctx, r),
		Caddy:     caddyint.Detect(ctx),
	}
	return vm.withCaddyGaps(allowedInboundPorts(p))
}

// allowedInboundPorts returns the set of TCP ports the current preset
// configuration accepts inbound. Used to spot the "Caddy bound but
// firewall drops it" footgun.
func allowedInboundPorts(p policy.Presets) map[int]bool {
	out := map[int]bool{}
	if p.SSH != nil {
		port := p.SSH.Port
		if port == 0 {
			port = 22
		}
		out[port] = true
	}
	if p.CaddyBox {
		out[80] = true
		out[443] = true
	}
	if p.Database != nil {
		port := p.Database.Port
		if port == 0 {
			port = 5432
		}
		out[port] = true
	}
	if p.Mail != nil {
		for _, port := range mailPorts(*p.Mail) {
			out[port] = true
		}
	}
	return out
}

// withCaddyGaps annotates the integrations VM with the list of Caddy-bound
// ports that aren't covered by the supplied set of allowed inbound TCP
// ports.
func (vm IntegrationsVM) withCaddyGaps(allowed map[int]bool) IntegrationsVM {
	if !vm.Caddy.Detected {
		return vm
	}
	for _, p := range vm.Caddy.Ports() {
		if !allowed[p] {
			vm.CaddyPortGaps = append(vm.CaddyPortGaps, p)
		}
	}
	return vm
}
