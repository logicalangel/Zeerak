package policy

// VISION.md §1 "In scope: anything nftables does natively" lists three
// kernel features that ride next to the existing inbound/outbound presets
// but live in *separate* tables for two reasons:
//
//  1. Family/type mismatch. NAT needs `type nat`, mark routing needs
//     `type route`, conntrack helpers need `ct helper` declarations at
//     table scope. None of these fit the single `inet zeerak-presets`
//     filter table.
//  2. Operational legibility. `nft list table ip zeerak-nat` should show
//     all NAT decisions in one place; `nft list table inet zeerak-marks`
//     all mark policy; `nft list table inet zeerak-ct` all helpers.
//     One concern per table mirrors how operators reason about firewalls.
//
// All three feature areas keep the same deterministic-output discipline as
// the inbound/outbound presets: identical YAML in -> identical bytes out.

import (
	"fmt"
	"sort"
	"strings"

	"github.com/zeerak/zeerak/internal/model"
)

// Well-known table names. Each is independently emitted only when the
// corresponding YAML stanza is non-empty.
const (
	NATTableName    = "zeerak-nat"
	MarksTableName  = "zeerak-marks"
	CTTableName     = "zeerak-ct"
)

// PortForward DNATs an inbound packet to an internal host. v0.4 ships
// IPv4-only — the common "expose service from a private LAN" case. IPv6
// rarely needs DNAT (global addressing); we'll add an `ip6 zeerak-nat`
// table when there's demand.
type PortForward struct {
	Proto    string `yaml:"proto,omitempty"`     // "tcp" (default) | "udp"
	IIF      string `yaml:"iif,omitempty"`       // optional inbound interface (e.g. "eth0")
	From     string `yaml:"from,omitempty"`      // optional source CIDR allowlist
	ExtPort  int    `yaml:"ext_port"`            // public port on this host
	To       string `yaml:"to"`                  // internal IPv4 address
	ToPort   int    `yaml:"to_port,omitempty"`   // internal port (defaults to ExtPort)
	Comment  string `yaml:"comment,omitempty"`
}

// Masquerade rewrites the source address of outbound packets to whatever
// IP the egress interface holds. The classic "router box" gateway pattern.
type Masquerade struct {
	OIF     string `yaml:"oif"`               // outbound interface (required)
	Source  string `yaml:"source,omitempty"`  // optional CIDR — only masquerade traffic from this network
	Comment string `yaml:"comment,omitempty"`
}

// Mark stamps `meta mark` on packets matching simple criteria so a
// sibling routing table (configured via `ip rule fwmark`) can steer them.
// Used for split-tunnel VPN, QoS, and policy routing.
//
// The chain hooks `output` with `type route` so route lookup happens
// after the mark is set — the standard split-tunnel pattern.
type Mark struct {
	Name    string `yaml:"name"`              // identifier (used in comment)
	Daddr   string `yaml:"daddr,omitempty"`   // optional destination CIDR (v4 or v6)
	Proto   string `yaml:"proto,omitempty"`   // optional L4 proto: "tcp" | "udp" | "icmp"
	DPort   int    `yaml:"dport,omitempty"`   // optional destination port (requires Proto)
	OIF     string `yaml:"oif,omitempty"`     // optional outbound interface match
	Set     uint32 `yaml:"set"`               // mark value to set (e.g. 0x100)
	Comment string `yaml:"comment,omitempty"`
}

// CTHelpers toggles the well-known nftables conntrack helpers. Each helper
// declared = one declaration in the table + one rule attaching it to the
// canonical port. Operators with bespoke ports can fall back to raw
// `tables:` entries.
type CTHelpers struct {
	FTP   bool `yaml:"ftp,omitempty"`   // tcp/21    -> "ftp"
	SIP   bool `yaml:"sip,omitempty"`   // udp/5060  -> "sip"
	TFTP  bool `yaml:"tftp,omitempty"`  // udp/69    -> "tftp"
	PPTP  bool `yaml:"pptp,omitempty"`  // tcp/1723  -> "pptp"
	IRC   bool `yaml:"irc,omitempty"`   // tcp/6667  -> "irc"
	H323  bool `yaml:"h323,omitempty"`  // tcp/1720  -> "RAS"
}

// AnyEnabled reports whether any helper is on.
func (h CTHelpers) AnyEnabled() bool {
	return h.FTP || h.SIP || h.TFTP || h.PPTP || h.IRC || h.H323
}

// Active reports whether anything in this group needs compiling.
func anyMasquerade(m []Masquerade) bool { return len(m) > 0 }

// validateRouting performs cheap shape checks. Like the existing presets,
// real semantic validation comes from `nft -f -` at apply time.
func (p Presets) validateRouting() error {
	for i, f := range p.PortForwards {
		switch f.Proto {
		case "", "tcp", "udp":
		default:
			return fmt.Errorf("presets.port_forwards[%d].proto: %q (want tcp|udp)", i, f.Proto)
		}
		if f.ExtPort < 1 || f.ExtPort > 65535 {
			return fmt.Errorf("presets.port_forwards[%d].ext_port: %d out of range", i, f.ExtPort)
		}
		if f.ToPort != 0 && (f.ToPort < 1 || f.ToPort > 65535) {
			return fmt.Errorf("presets.port_forwards[%d].to_port: %d out of range", i, f.ToPort)
		}
		if f.To == "" {
			return fmt.Errorf("presets.port_forwards[%d].to: required", i)
		}
		if strings.Contains(f.To, ":") || strings.Contains(f.To, "/") {
			return fmt.Errorf("presets.port_forwards[%d].to: %q must be a plain IPv4 address (no port, no CIDR)", i, f.To)
		}
		if f.From != "" && !strings.Contains(f.From, "/") {
			return fmt.Errorf("presets.port_forwards[%d].from: %q is not a CIDR (need /mask)", i, f.From)
		}
		if f.IIF != "" && strings.ContainsAny(f.IIF, " \t\n,{}") {
			return fmt.Errorf("presets.port_forwards[%d].iif: %q is not a valid interface name", i, f.IIF)
		}
	}
	for i, m := range p.Masquerade {
		if m.OIF == "" {
			return fmt.Errorf("presets.masquerade[%d].oif: required", i)
		}
		if strings.ContainsAny(m.OIF, " \t\n,{}") {
			return fmt.Errorf("presets.masquerade[%d].oif: %q is not a valid interface name", i, m.OIF)
		}
		if m.Source != "" && !strings.Contains(m.Source, "/") {
			return fmt.Errorf("presets.masquerade[%d].source: %q is not a CIDR (need /mask)", i, m.Source)
		}
	}
	seen := map[string]bool{}
	for i, m := range p.Marks {
		if m.Name == "" {
			return fmt.Errorf("presets.marks[%d].name: required", i)
		}
		if seen[m.Name] {
			return fmt.Errorf("presets.marks[%d]: duplicate name %q", i, m.Name)
		}
		seen[m.Name] = true
		if m.Set == 0 {
			return fmt.Errorf("presets.marks[%d].set: required and non-zero", i)
		}
		switch m.Proto {
		case "", "tcp", "udp", "icmp":
		default:
			return fmt.Errorf("presets.marks[%d].proto: %q (want tcp|udp|icmp)", i, m.Proto)
		}
		if m.DPort != 0 {
			if m.Proto != "tcp" && m.Proto != "udp" {
				return fmt.Errorf("presets.marks[%d].dport requires proto tcp|udp", i)
			}
			if m.DPort < 1 || m.DPort > 65535 {
				return fmt.Errorf("presets.marks[%d].dport: %d out of range", i, m.DPort)
			}
		}
		if m.Daddr != "" && !strings.Contains(m.Daddr, "/") {
			return fmt.Errorf("presets.marks[%d].daddr: %q is not a CIDR (need /mask)", i, m.Daddr)
		}
		if m.OIF != "" && strings.ContainsAny(m.OIF, " \t\n,{}") {
			return fmt.Errorf("presets.marks[%d].oif: %q is not a valid interface name", i, m.OIF)
		}
	}
	return nil
}

// compileNATTable produces an `ip zeerak-nat` table covering port forwards
// and masquerades. Returns nil if neither is configured.
func compileNATTable(forwards []PortForward, masq []Masquerade) *model.Table {
	if len(forwards) == 0 && !anyMasquerade(masq) {
		return nil
	}

	var prerouting, postrouting []model.Rule

	// Sort port forwards for deterministic output: by ext_port, then proto, then to.
	fws := append([]PortForward(nil), forwards...)
	sort.SliceStable(fws, func(i, j int) bool {
		if fws[i].ExtPort != fws[j].ExtPort {
			return fws[i].ExtPort < fws[j].ExtPort
		}
		if fws[i].Proto != fws[j].Proto {
			return fws[i].Proto < fws[j].Proto
		}
		return fws[i].To < fws[j].To
	})
	for _, f := range fws {
		proto := f.Proto
		if proto == "" {
			proto = "tcp"
		}
		toPort := f.ToPort
		if toPort == 0 {
			toPort = f.ExtPort
		}
		var parts []string
		if f.IIF != "" {
			parts = append(parts, fmt.Sprintf("iifname %q", f.IIF))
		}
		if f.From != "" {
			parts = append(parts, fmt.Sprintf("ip saddr %s", f.From))
		}
		parts = append(parts, fmt.Sprintf("%s dport %d dnat to %s:%d", proto, f.ExtPort, f.To, toPort))
		comment := f.Comment
		if comment == "" {
			comment = fmt.Sprintf("forward %s/%d -> %s:%d", proto, f.ExtPort, f.To, toPort)
		}
		prerouting = append(prerouting, model.Rule{
			Expr:    strings.Join(parts, " "),
			Comment: comment,
		})
	}

	// Sort masquerades by oif then source for determinism.
	ms := append([]Masquerade(nil), masq...)
	sort.SliceStable(ms, func(i, j int) bool {
		if ms[i].OIF != ms[j].OIF {
			return ms[i].OIF < ms[j].OIF
		}
		return ms[i].Source < ms[j].Source
	})
	for _, m := range ms {
		var parts []string
		parts = append(parts, fmt.Sprintf("oifname %q", m.OIF))
		if m.Source != "" {
			parts = append(parts, fmt.Sprintf("ip saddr %s", m.Source))
		}
		parts = append(parts, "masquerade")
		comment := m.Comment
		if comment == "" {
			if m.Source != "" {
				comment = fmt.Sprintf("masq %s out %s", m.Source, m.OIF)
			} else {
				comment = fmt.Sprintf("masq out %s", m.OIF)
			}
		}
		postrouting = append(postrouting, model.Rule{
			Expr:    strings.Join(parts, " "),
			Comment: comment,
		})
	}

	chains := []model.Chain{
		{
			Name:     "prerouting",
			Type:     model.ChainTypeNAT,
			Hook:     model.HookPrerouting,
			Priority: -100, // dstnat
			Rules:    prerouting,
		},
		{
			Name:     "postrouting",
			Type:     model.ChainTypeNAT,
			Hook:     model.HookPostrouting,
			Priority: 100, // srcnat
			Rules:    postrouting,
		},
	}

	return &model.Table{
		Family: model.FamilyIP,
		Name:   NATTableName,
		Owned:  true,
		Chains: chains,
	}
}

// compileMarksTable produces `inet zeerak-marks` with a single output
// chain (`type route`) that stamps marks. Locally-generated traffic is the
// common case (split-tunnel VPN, QoS); prerouting marks for forwarded
// traffic can be added in a follow-up.
func compileMarksTable(marks []Mark) *model.Table {
	if len(marks) == 0 {
		return nil
	}

	ms := append([]Mark(nil), marks...)
	// Sort by mark value, then name, for determinism.
	sort.SliceStable(ms, func(i, j int) bool {
		if ms[i].Set != ms[j].Set {
			return ms[i].Set < ms[j].Set
		}
		return ms[i].Name < ms[j].Name
	})

	rules := make([]model.Rule, 0, len(ms))
	for _, m := range ms {
		var parts []string
		if m.OIF != "" {
			parts = append(parts, fmt.Sprintf("oifname %q", m.OIF))
		}
		if m.Daddr != "" {
			if strings.Contains(m.Daddr, ":") {
				parts = append(parts, fmt.Sprintf("ip6 daddr %s", m.Daddr))
			} else {
				parts = append(parts, fmt.Sprintf("ip daddr %s", m.Daddr))
			}
		}
		if m.Proto != "" && m.DPort != 0 {
			parts = append(parts, fmt.Sprintf("%s dport %d", m.Proto, m.DPort))
		} else if m.Proto != "" {
			parts = append(parts, fmt.Sprintf("meta l4proto %s", m.Proto))
		}
		parts = append(parts, fmt.Sprintf("meta mark set 0x%x", m.Set))
		comment := m.Comment
		if comment == "" {
			comment = m.Name
		}
		rules = append(rules, model.Rule{
			Expr:    strings.Join(parts, " "),
			Comment: comment,
		})
	}

	chain := model.Chain{
		Name:     "output",
		Type:     model.ChainTypeRoute,
		Hook:     model.HookOutput,
		Priority: -150, // mangle, before route lookup
		Rules:    rules,
	}

	return &model.Table{
		Family: model.FamilyINet,
		Name:   MarksTableName,
		Owned:  true,
		Chains: []model.Chain{chain},
	}
}

// helperSpec maps a CTHelpers toggle to its declaration + rule.
type helperSpec struct {
	field   string // YAML key (for stable sort)
	name    string // declaration name
	helper  string // kernel helper name (passed via `type "..."`)
	l4proto string // tcp | udp
	port    int    // canonical port
}

func enabledHelpers(h CTHelpers) []helperSpec {
	all := []struct {
		on   bool
		spec helperSpec
	}{
		{h.FTP, helperSpec{"ftp", "ftp-standard", "ftp", "tcp", 21}},
		{h.SIP, helperSpec{"sip", "sip-standard", "sip", "udp", 5060}},
		{h.TFTP, helperSpec{"tftp", "tftp-standard", "tftp", "udp", 69}},
		{h.PPTP, helperSpec{"pptp", "pptp-standard", "pptp", "tcp", 1723}},
		{h.IRC, helperSpec{"irc", "irc-standard", "irc", "tcp", 6667}},
		{h.H323, helperSpec{"h323", "h323-ras", "RAS", "tcp", 1720}},
	}
	var out []helperSpec
	for _, x := range all {
		if x.on {
			out = append(out, x.spec)
		}
	}
	// already in stable field order; declarations + rules will be deterministic.
	return out
}

// compileCTTable produces `inet zeerak-ct` with helper declarations and a
// prerouting chain that attaches each helper to its canonical port.
//
// Priority -200 puts the attach earlier than filter (0) so the helper is
// active when later chains see the packet, but after raw (-300) so we
// don't fight conntrack initialization.
func compileCTTable(h CTHelpers) *model.Table {
	if !h.AnyEnabled() {
		return nil
	}
	specs := enabledHelpers(h)

	helpers := make([]model.CTHelper, 0, len(specs))
	rules := make([]model.Rule, 0, len(specs))
	for _, s := range specs {
		helpers = append(helpers, model.CTHelper{
			Name:    s.name,
			Type:    s.helper,
			L4Proto: s.l4proto,
		})
		rules = append(rules, model.Rule{
			Expr:    fmt.Sprintf("%s dport %d ct helper set %q", s.l4proto, s.port, s.name),
			Comment: fmt.Sprintf("ct helper %s", s.field),
		})
	}

	chain := model.Chain{
		Name:     "prerouting",
		Type:     model.ChainTypeFilter,
		Hook:     model.HookPrerouting,
		Priority: -200,
		Rules:    rules,
	}
	return &model.Table{
		Family:  model.FamilyINet,
		Name:    CTTableName,
		Owned:   true,
		Helpers: helpers,
		Chains:  []model.Chain{chain},
	}
}
