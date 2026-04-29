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
	DefaultDenyInbound bool       `yaml:"default_deny_inbound,omitempty"`
	SSH                *SSHPreset `yaml:"ssh,omitempty"`
	CaddyBox           bool       `yaml:"caddy_box,omitempty"`
}

// SSHPreset opens an inbound TCP port for SSH (default 22), optionally
// restricted to a CIDR allowlist.
type SSHPreset struct {
	Port int      `yaml:"port,omitempty"` // default 22
	From []string `yaml:"from,omitempty"` // CIDR allowlist; empty = any source
}

// Empty reports whether no preset is enabled (compile is a no-op).
func (p Presets) Empty() bool {
	return !p.DefaultDenyInbound && p.SSH == nil && !p.CaddyBox
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
	if p.Empty() {
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

	return &model.Table{
		Family: model.FamilyINet,
		Name:   TableName,
		Owned:  true,
		Chains: []model.Chain{chain},
	}
}

// sshRules generates the rule(s) for the ssh preset. With no allowlist it's
// one rule; with an allowlist it splits by family so both v4 and v6 sources
// work under the inet table.
func sshRules(s SSHPreset) []model.Rule {
	port := s.Port
	if port == 0 {
		port = 22
	}

	if len(s.From) == 0 {
		return []model.Rule{{
			Expr:    fmt.Sprintf("tcp dport %d accept", port),
			Comment: "ssh",
		}}
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
			Expr:    fmt.Sprintf("ip saddr { %s } tcp dport %d accept", strings.Join(v4, ", "), port),
			Comment: "ssh (v4 allowlist)",
		})
	}
	if len(v6) > 0 {
		out = append(out, model.Rule{
			Expr:    fmt.Sprintf("ip6 saddr { %s } tcp dport %d accept", strings.Join(v6, ", "), port),
			Comment: "ssh (v6 allowlist)",
		})
	}
	return out
}
