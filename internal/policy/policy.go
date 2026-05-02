// Package policy compiles higher-level "presets" into nftables-mirror tables.
//
// VISION.md §11 Q1 calls for a two-layer model: the on-disk YAML can use
// human-friendly shapes (zones, services, presets), but everything compiles
// down to plain nftables objects in a user-owned table the operator can
// always see with `nft list table inet zeerak-presets`. No shadow chains,
// no hidden state.
//
// v0.1 ships three presets — enough to firewall a typical "Caddy box" VPS:
//
//	default_deny_inbound: true       # policy drop on input + lo + ct established
//	ssh:                             # opens TCP/22 (or custom port)
//	  port: 22
//	  from: ["198.51.100.0/24"]      # optional CIDR allowlist
//	caddy_box: true                  # opens TCP/80 + TCP/443
//
// All presets co-compile into ONE table (TableName, family inet) so the diff
// view stays compact. Presets are deterministic: same input -> identical
// output bytes.
package policy

import (
	"fmt"
	"sort"
	"strings"

	"github.com/zeerak/zeerak/internal/model"
)

// TableName is the well-known table presets compile into. Operators can
// inspect it with `nft list table inet zeerak-presets`.
const TableName = "zeerak-presets"

// Presets is the YAML-facing shape under the `presets:` key.
type Presets struct {
	DefaultDenyInbound bool                `yaml:"default_deny_inbound,omitempty"`
	SSH                *SSHPreset          `yaml:"ssh,omitempty"`
	CaddyBox           bool                `yaml:"caddy_box,omitempty"`
	Database           *DatabasePreset     `yaml:"database,omitempty"`
	Mail               *MailPreset         `yaml:"mail,omitempty"`
	Outbound           *OutboundPreset     `yaml:"outbound,omitempty"`
	BlockSets          []NamedBlockSet     `yaml:"block_sets,omitempty"`

	// VISION.md §1 nftables-native scope: NAT, policy-routing marks, and
	// conntrack helpers. Each compiles into its own table; see routing.go.
	PortForwards []PortForward `yaml:"port_forwards,omitempty"`
	Masquerade   []Masquerade  `yaml:"masquerade,omitempty"`
	Marks        []Mark        `yaml:"marks,omitempty"`
	CTHelpers    *CTHelpers    `yaml:"ct_helpers,omitempty"`
}

// NamedBlockSet is a user-named CIDR list (think "country blocks",
// "abuse-feeds", "vpn-providers"). It compiles into a single nftables
// `set` declaration on the same `inet zeerak-presets` table, with
// `flags interval` so CIDR ranges work correctly. It is a passive
// declaration on its own — reference the set from OutboundPreset.BlockRefs
// or (manually, in v0.4) from custom rules.
//
// VISION.md §10 v0.3 calls this out as the foundation for the named-sets
// editor. The editor UI itself lands in v0.4 — v0.3 ships the data path.
type NamedBlockSet struct {
	Name  string   `yaml:"name"`            // e.g. "country-block", "abuse-feed"
	Family string  `yaml:"family,omitempty"` // "v4" (default) or "v6"
	CIDRs []string `yaml:"cidrs,omitempty"` // CIDR elements (interval flag is implied)
}

// SSHPreset opens an inbound TCP port for SSH (default 22), optionally
// restricted to a CIDR allowlist, an inbound interface allowlist (e.g.
// tailscale0 / wg0 — the "admin only over the tunnel" pattern from
// VISION.md §8), and an optional per-source-IP rate limit.
type SSHPreset struct {
	Port       int            `yaml:"port,omitempty"`       // default 22
	From       []string       `yaml:"from,omitempty"`       // CIDR allowlist; empty = any source
	Interfaces []string       `yaml:"interfaces,omitempty"` // iifname allowlist (tailscale0, wg0, ...); empty = any iface
	RateLimit  *SSHRateLimit  `yaml:"rate_limit,omitempty"` // optional per-source-IP cap on new connections
}

// SSHRateLimit caps the number of *new* SSH connections per source IP per
// minute. Compiles to an nft `meter` so each source has its own bucket
// rather than a single global one. Established connections are unaffected.
type SSHRateLimit struct {
	PerMinute int `yaml:"per_minute,omitempty"` // default 5; minimum 1
}

// DatabasePreset opens an inbound TCP port for a database (default 5432 –
// Postgres). The CIDR allowlist behaves like SSH; running a DB "open from
// anywhere" is dangerous but supported for completeness.
type DatabasePreset struct {
	Port int      `yaml:"port,omitempty"` // default 5432
	From []string `yaml:"from,omitempty"` // CIDR allowlist; empty = any source
}

// MailPreset opens the standard inbound mail ports. SMTP (25) is for server-
// to-server delivery; submission (587), IMAPS (993) and POP3S (995) are for
// clients sending/reading mail. Each is independently togglable.
type MailPreset struct {
	SMTP       bool `yaml:"smtp,omitempty"`        // 25
	Submission bool `yaml:"submission,omitempty"`  // 587
	IMAPS      bool `yaml:"imaps,omitempty"`       // 993
	POP3S      bool `yaml:"pop3s,omitempty"`       // 995
}

// AnyPort reports whether the mail preset opens any port at all.
func (m MailPreset) AnyPort() bool {
	return m.SMTP || m.Submission || m.IMAPS || m.POP3S
}

// OutboundPreset filters traffic *leaving* this machine.
//
// Two modes:
//   - Restrict=false: the output chain is not installed (default; full pass-
//     through). Block destinations are still applied as explicit drop rules
//     so an operator can blacklist hosts without going full restrict mode.
//   - Restrict=true:  output chain policy=drop, with allow-rules for each
//     enabled toggle plus loopback and ct-established. Anything else leaving
//     the machine is dropped.
//
// Block CIDRs are applied first in the chain so they win over any allow.
type OutboundPreset struct {
	Restrict   bool     `yaml:"restrict,omitempty"`    // default-deny on output
	AllowDNS   bool     `yaml:"allow_dns,omitempty"`   // udp/tcp 53
	AllowHTTP  bool     `yaml:"allow_http,omitempty"`  // tcp 80
	AllowHTTPS bool     `yaml:"allow_https,omitempty"` // tcp 443
	AllowNTP   bool     `yaml:"allow_ntp,omitempty"`   // udp 123
	AllowSMTP  bool     `yaml:"allow_smtp,omitempty"`  // tcp 25, 465, 587 (sending mail)
	AllowPing  bool     `yaml:"allow_ping,omitempty"`  // icmp / icmpv6 echo-request
	CustomTCP  []int    `yaml:"custom_tcp,omitempty"`  // extra outbound TCP ports
	Block      []string `yaml:"block,omitempty"`       // destination CIDRs to drop
	BlockRefs  []string `yaml:"block_refs,omitempty"`  // names of NamedBlockSets to drop traffic to
}

// Active reports whether the preset has any effect (restrict mode or any
// blocked destination, including referenced named sets).
func (o OutboundPreset) Active() bool {
	return o.Restrict || len(o.Block) > 0 || len(o.BlockRefs) > 0
}

// Empty reports whether no preset is enabled (compile is a no-op).
func (p Presets) Empty() bool {
	return !p.hasFilterPresets() && !p.hasRoutingPresets()
}

// hasFilterPresets is true if any inbound/outbound/named-set preset is on,
// i.e. anything that compiles into the `inet zeerak-presets` table.
func (p Presets) hasFilterPresets() bool {
	return p.DefaultDenyInbound || p.SSH != nil || p.CaddyBox ||
		p.Database != nil || (p.Mail != nil && p.Mail.AnyPort()) ||
		(p.Outbound != nil && p.Outbound.Active()) ||
		len(p.BlockSets) > 0
}

// hasRoutingPresets is true if any NAT/marks/ct-helper preset is on, i.e.
// anything that compiles into the routing tables (zeerak-nat, zeerak-marks,
// zeerak-ct).
func (p Presets) hasRoutingPresets() bool {
	return len(p.PortForwards) > 0 || len(p.Masquerade) > 0 ||
		len(p.Marks) > 0 || (p.CTHelpers != nil && p.CTHelpers.AnyEnabled())
}

// Validate performs cheap sanity checks. Real semantic validation happens
// when the renderer hands the script to `nft -f -`.
func (p Presets) Validate() error {
	if p.SSH != nil {
		if p.SSH.Port < 0 || p.SSH.Port > 65535 {
			return fmt.Errorf("presets.ssh.port out of range: %d", p.SSH.Port)
		}
		for i, c := range p.SSH.From {
			if !strings.Contains(c, "/") {
				return fmt.Errorf("presets.ssh.from[%d]: %q is not a CIDR (need /mask)", i, c)
			}
		}
		for i, ifname := range p.SSH.Interfaces {
			if ifname == "" || strings.ContainsAny(ifname, " \t\n,{}") {
				return fmt.Errorf("presets.ssh.interfaces[%d]: %q is not a valid interface name", i, ifname)
			}
		}
		if p.SSH.RateLimit != nil && p.SSH.RateLimit.PerMinute < 0 {
			return fmt.Errorf("presets.ssh.rate_limit.per_minute must be >= 0, got %d", p.SSH.RateLimit.PerMinute)
		}
	}
	if p.Database != nil {
		if p.Database.Port < 0 || p.Database.Port > 65535 {
			return fmt.Errorf("presets.database.port out of range: %d", p.Database.Port)
		}
		for i, c := range p.Database.From {
			if !strings.Contains(c, "/") {
				return fmt.Errorf("presets.database.from[%d]: %q is not a CIDR (need /mask)", i, c)
			}
		}
	}
	if p.Outbound != nil {
		for i, port := range p.Outbound.CustomTCP {
			if port < 1 || port > 65535 {
				return fmt.Errorf("presets.outbound.custom_tcp[%d]: %d out of range", i, port)
			}
		}
		for i, c := range p.Outbound.Block {
			if !strings.Contains(c, "/") {
				return fmt.Errorf("presets.outbound.block[%d]: %q is not a CIDR (need /mask)", i, c)
			}
		}
		// BlockRefs must reference declared sets.
		known := make(map[string]bool, len(p.BlockSets))
		for _, s := range p.BlockSets {
			known[s.Name] = true
		}
		for i, ref := range p.Outbound.BlockRefs {
			if !known[ref] {
				return fmt.Errorf("presets.outbound.block_refs[%d]: set %q is not declared in presets.block_sets", i, ref)
			}
		}
	}
	names := make(map[string]bool, len(p.BlockSets))
	for i, s := range p.BlockSets {
		if s.Name == "" {
			return fmt.Errorf("presets.block_sets[%d]: name is required", i)
		}
		if names[s.Name] {
			return fmt.Errorf("presets.block_sets[%d]: duplicate name %q", i, s.Name)
		}
		names[s.Name] = true
		if s.Family != "" && s.Family != "v4" && s.Family != "v6" {
			return fmt.Errorf("presets.block_sets[%d].family: %q (want \"v4\" or \"v6\")", i, s.Family)
		}
		for j, c := range s.CIDRs {
			if !strings.Contains(c, "/") {
				return fmt.Errorf("presets.block_sets[%d].cidrs[%d]: %q is not a CIDR (need /mask)", i, j, c)
			}
		}
	}
	if err := p.validateRouting(); err != nil {
		return err
	}
	return nil
}

// Compile renders the preset set into a single inet table. Returns nil if
// no preset is enabled.
//
// The chain layout is:
//
//	chain input (type filter, hook input, priority 0, policy <drop|accept>)
//	  ct state established,related accept   # if default_deny_inbound
//	  iifname lo accept                     # if default_deny_inbound
//	  <ssh rules>                           # if ssh
//	  tcp dport { 80, 443 } accept          # if caddy_box
func (p Presets) Compile() *model.Table {
	if !p.hasFilterPresets() {
		return nil
	}

	chain := model.Chain{
		Name:     "input",
		Type:     model.ChainTypeFilter,
		Hook:     model.HookInput,
		Priority: 0,
		Policy:   model.VerdictAccept,
	}
	if p.DefaultDenyInbound {
		chain.Policy = model.VerdictDrop
		chain.Rules = append(chain.Rules,
			model.Rule{Expr: "ct state established,related accept", Comment: "conntrack"},
			model.Rule{Expr: "iifname lo accept", Comment: "loopback"},
		)
	}

	if p.SSH != nil {
		chain.Rules = append(chain.Rules, sshRules(*p.SSH)...)
	}

	if p.CaddyBox {
		chain.Rules = append(chain.Rules,
			model.Rule{Expr: "tcp dport { 80, 443 } accept", Comment: "caddy_box"},
		)
	}

	if p.Database != nil {
		chain.Rules = append(chain.Rules, dbRules(*p.Database)...)
	}

	if p.Mail != nil && p.Mail.AnyPort() {
		chain.Rules = append(chain.Rules, mailRules(*p.Mail)...)
	}

	chains := []model.Chain{chain}
	if p.Outbound != nil && p.Outbound.Active() {
		families := make(map[string]string, len(p.BlockSets))
		for _, s := range p.BlockSets {
			if s.Family == "v6" {
				families[s.Name] = "v6"
			} else {
				families[s.Name] = "v4"
			}
		}
		chains = append(chains, outboundChain(*p.Outbound, families))
	}

	var sets []model.Set
	for _, s := range p.BlockSets {
		sets = append(sets, compileBlockSet(s))
	}

	return &model.Table{
		Family: model.FamilyINet,
		Name:   TableName,
		Owned:  true,
		Chains: chains,
		Sets:   sets,
	}
}

// CompileTables returns every table the preset set produces. The classic
// `inet zeerak-presets` filter table is always first (when non-empty);
// then, in deterministic order, an `ip zeerak-nat` table for port
// forwards/masquerade, an `inet zeerak-marks` table for policy routing
// marks, and an `inet zeerak-ct` table for conntrack-helper attachments.
//
// Each is independently emitted only if its inputs are non-empty, so a
// minimal `presets:` block still renders a minimal ruleset.
func (p Presets) CompileTables() []model.Table {
	var out []model.Table
	if t := p.Compile(); t != nil {
		out = append(out, *t)
	}
	if t := compileNATTable(p.PortForwards, p.Masquerade); t != nil {
		out = append(out, *t)
	}
	if t := compileMarksTable(p.Marks); t != nil {
		out = append(out, *t)
	}
	if p.CTHelpers != nil {
		if t := compileCTTable(*p.CTHelpers); t != nil {
			out = append(out, *t)
		}
	}
	return out
}

// compileBlockSet renders a NamedBlockSet into a model.Set ready for the
// renderer. v6 sets get an explicit ipv6_addr type; everything else defaults
// to ipv4_addr. `flags interval` is always set so CIDR ranges work.
func compileBlockSet(s NamedBlockSet) model.Set {
	t := "ipv4_addr"
	if s.Family == "v6" {
		t = "ipv6_addr"
	}
	elements := append([]string(nil), s.CIDRs...)
	sort.Strings(elements)
	return model.Set{
		Name:     s.Name,
		Type:     t,
		Flags:    []string{"interval"},
		Elements: elements,
	}
}

// sshRules generates the rule(s) for the ssh preset. The shape is:
//
//	[iifname { tunnels }] [ip saddr { cidrs }] tcp dport N \
//	    [ct state new meter ssh-throttle { ip saddr limit rate N/minute }] accept
//
// Interface and CIDR clauses are independent (you can pin to tailscale0
// AND further restrict by source IP). Rate-limit applies to all variants.
func sshRules(s SSHPreset) []model.Rule {
	port := s.Port
	if port == 0 {
		port = 22
	}

	ifClause := ""
	ifComment := ""
	if len(s.Interfaces) > 0 {
		ifs := append([]string(nil), s.Interfaces...)
		sort.Strings(ifs)
		if len(ifs) == 1 {
			ifClause = fmt.Sprintf("iifname %q ", ifs[0])
		} else {
			quoted := make([]string, len(ifs))
			for i, n := range ifs {
				quoted[i] = fmt.Sprintf("%q", n)
			}
			ifClause = fmt.Sprintf("iifname { %s } ", strings.Join(quoted, ", "))
		}
		ifComment = " (iface)"
	}

	// Rate-limit suffix using a meter so each source IP has its own bucket.
	// Empty when no rate-limit is configured.
	rlSuffix := ""
	if s.RateLimit != nil && s.RateLimit.PerMinute > 0 {
		rlSuffix = fmt.Sprintf(" ct state new meter ssh-throttle-v4 { ip saddr limit rate %d/minute }", s.RateLimit.PerMinute)
	}
	rlSuffix6 := ""
	if s.RateLimit != nil && s.RateLimit.PerMinute > 0 {
		rlSuffix6 = fmt.Sprintf(" ct state new meter ssh-throttle-v6 { ip6 saddr limit rate %d/minute }", s.RateLimit.PerMinute)
	}

	if len(s.From) == 0 {
		// No CIDR split needed. If a rate-limit is configured we still split
		// v4/v6 because meters are family-specific.
		if rlSuffix == "" {
			return []model.Rule{{
				Expr:    fmt.Sprintf("%stcp dport %d accept", ifClause, port),
				Comment: "ssh" + ifComment,
			}}
		}
		return []model.Rule{
			{
				Expr:    fmt.Sprintf("%smeta nfproto ipv4 tcp dport %d%s accept", ifClause, port, rlSuffix),
				Comment: "ssh (v4 throttled)" + ifComment,
			},
			{
				Expr:    fmt.Sprintf("%smeta nfproto ipv6 tcp dport %d%s accept", ifClause, port, rlSuffix6),
				Comment: "ssh (v6 throttled)" + ifComment,
			},
		}
	}

	// Sort CIDRs for deterministic output, then split by family.
	cidrs := append([]string(nil), s.From...)
	sort.Strings(cidrs)

	var v4, v6 []string
	for _, c := range cidrs {
		if strings.Contains(c, ":") {
			v6 = append(v6, c)
		} else {
			v4 = append(v4, c)
		}
	}

	var out []model.Rule
	if len(v4) > 0 {
		out = append(out, model.Rule{
			Expr:    fmt.Sprintf("%sip saddr { %s } tcp dport %d%s accept", ifClause, strings.Join(v4, ", "), port, rlSuffix),
			Comment: "ssh (v4 allowlist)" + ifComment,
		})
	}
	if len(v6) > 0 {
		out = append(out, model.Rule{
			Expr:    fmt.Sprintf("%sip6 saddr { %s } tcp dport %d%s accept", ifClause, strings.Join(v6, ", "), port, rlSuffix6),
			Comment: "ssh (v6 allowlist)" + ifComment,
		})
	}
	return out
}

// dbRules generates rules for the Database preset. Mirrors sshRules: with
// no allowlist, one open rule; with one, split by family.
func dbRules(d DatabasePreset) []model.Rule {
	port := d.Port
	if port == 0 {
		port = 5432
	}

	if len(d.From) == 0 {
		return []model.Rule{{
			Expr:    fmt.Sprintf("tcp dport %d accept", port),
			Comment: "database",
		}}
	}

	cidrs := append([]string(nil), d.From...)
	sort.Strings(cidrs)

	var v4, v6 []string
	for _, c := range cidrs {
		if strings.Contains(c, ":") {
			v6 = append(v6, c)
		} else {
			v4 = append(v4, c)
		}
	}

	var out []model.Rule
	if len(v4) > 0 {
		out = append(out, model.Rule{
			Expr:    fmt.Sprintf("ip saddr { %s } tcp dport %d accept", strings.Join(v4, ", "), port),
			Comment: "database (v4 allowlist)",
		})
	}
	if len(v6) > 0 {
		out = append(out, model.Rule{
			Expr:    fmt.Sprintf("ip6 saddr { %s } tcp dport %d accept", strings.Join(v6, ", "), port),
			Comment: "database (v6 allowlist)",
		})
	}
	return out
}

// mailRules generates one rule per enabled mail port, all from any source
// (mail receivers must accept connections from arbitrary peers).
func mailRules(m MailPreset) []model.Rule {
	var ports []int
	if m.SMTP {
		ports = append(ports, 25)
	}
	if m.Submission {
		ports = append(ports, 587)
	}
	if m.IMAPS {
		ports = append(ports, 993)
	}
	if m.POP3S {
		ports = append(ports, 995)
	}
	if len(ports) == 0 {
		return nil
	}
	if len(ports) == 1 {
		return []model.Rule{{
			Expr:    fmt.Sprintf("tcp dport %d accept", ports[0]),
			Comment: "mail",
		}}
	}
	parts := make([]string, len(ports))
	for i, p := range ports {
		parts[i] = fmt.Sprintf("%d", p)
	}
	return []model.Rule{{
		Expr:    fmt.Sprintf("tcp dport { %s } accept", strings.Join(parts, ", ")),
		Comment: "mail",
	}}
}

// outboundChain renders the output chain for OutboundPreset. Block CIDRs are
// always applied (drop), then — when Restrict is on — the chain policy is
// drop with allow rules for loopback, ct-established, and each enabled
// service toggle. Order is deterministic.
func outboundChain(o OutboundPreset, setFamilies map[string]string) model.Chain {
	c := model.Chain{
		Name:     "output",
		Type:     model.ChainTypeFilter,
		Hook:     model.HookOutput,
		Priority: 0,
		Policy:   model.VerdictAccept,
	}

	// Explicit block list first, regardless of Restrict.
	if len(o.Block) > 0 {
		cidrs := append([]string(nil), o.Block...)
		sort.Strings(cidrs)
		var v4, v6 []string
		for _, x := range cidrs {
			if strings.Contains(x, ":") {
				v6 = append(v6, x)
			} else {
				v4 = append(v4, x)
			}
		}
		if len(v4) > 0 {
			c.Rules = append(c.Rules, model.Rule{
				Expr:    fmt.Sprintf("ip daddr { %s } drop", strings.Join(v4, ", ")),
				Comment: "outbound block (v4)",
			})
		}
		if len(v6) > 0 {
			c.Rules = append(c.Rules, model.Rule{
				Expr:    fmt.Sprintf("ip6 daddr { %s } drop", strings.Join(v6, ", ")),
				Comment: "outbound block (v6)",
			})
		}
	}

	// Named-set drops (v0.3): each ref becomes one drop rule using the
	// declared family of the referenced set. Sort for determinism.
	if len(o.BlockRefs) > 0 {
		refs := append([]string(nil), o.BlockRefs...)
		sort.Strings(refs)
		for _, name := range refs {
			fam := setFamilies[name]
			daddr := "ip daddr"
			if fam == "v6" {
				daddr = "ip6 daddr"
			}
			c.Rules = append(c.Rules, model.Rule{
				Expr:    fmt.Sprintf("%s @%s drop", daddr, name),
				Comment: fmt.Sprintf("outbound block (set %s)", name),
			})
		}
	}

	if !o.Restrict {
		return c
	}

	// Restrict mode: default-drop + allow only what's explicitly listed.
	c.Policy = model.VerdictDrop
	c.Rules = append(c.Rules,
		model.Rule{Expr: "oifname lo accept", Comment: "loopback"},
		model.Rule{Expr: "ct state established,related accept", Comment: "conntrack"},
	)
	if o.AllowDNS {
		c.Rules = append(c.Rules,
			model.Rule{Expr: "udp dport 53 accept", Comment: "dns (udp)"},
			model.Rule{Expr: "tcp dport 53 accept", Comment: "dns (tcp)"},
		)
	}
	if o.AllowHTTP {
		c.Rules = append(c.Rules, model.Rule{Expr: "tcp dport 80 accept", Comment: "http"})
	}
	if o.AllowHTTPS {
		c.Rules = append(c.Rules, model.Rule{Expr: "tcp dport 443 accept", Comment: "https"})
	}
	if o.AllowNTP {
		c.Rules = append(c.Rules, model.Rule{Expr: "udp dport 123 accept", Comment: "ntp"})
	}
	if o.AllowSMTP {
		c.Rules = append(c.Rules, model.Rule{
			Expr:    "tcp dport { 25, 465, 587 } accept",
			Comment: "smtp (sending)",
		})
	}
	if o.AllowPing {
		c.Rules = append(c.Rules,
			model.Rule{Expr: "icmp type echo-request accept", Comment: "ping (v4)"},
			model.Rule{Expr: "icmpv6 type echo-request accept", Comment: "ping (v6)"},
		)
	}
	if len(o.CustomTCP) > 0 {
		ports := append([]int(nil), o.CustomTCP...)
		sort.Ints(ports)
		parts := make([]string, len(ports))
		for i, p := range ports {
			parts[i] = fmt.Sprintf("%d", p)
		}
		if len(parts) == 1 {
			c.Rules = append(c.Rules, model.Rule{
				Expr:    fmt.Sprintf("tcp dport %s accept", parts[0]),
				Comment: "outbound custom",
			})
		} else {
			c.Rules = append(c.Rules, model.Rule{
				Expr:    fmt.Sprintf("tcp dport { %s } accept", strings.Join(parts, ", ")),
				Comment: "outbound custom",
			})
		}
	}
	return c
}
