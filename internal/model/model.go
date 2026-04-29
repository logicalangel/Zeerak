// Package model defines Zeerak's internal rule model.
//
// Per VISION.md §11 Q1 (rule model), the model is a thin, faithful mirror of
// nftables — families, tables, chains, hooks, priorities, sets/maps, verdicts,
// expressions. It is *not* a proprietary abstraction; the kernel's primitives
// stay authoritative and `nft list ruleset` always tells the truth.
//
// The higher-level "policy" UI (zones, services, presets) lives one layer up
// in internal/policy and compiles *down* to the types defined here.
//
// Render path: model.Ruleset -> internal/render -> google/nftables (netlink),
// with `nft -f -` shell as a fallback. Round-trip-fuzzed against `nft -j`.
package model

// Family is an nftables address family.
type Family string

const (
	FamilyIP    Family = "ip"
	FamilyIP6   Family = "ip6"
	FamilyINet  Family = "inet"
	FamilyARP   Family = "arp"
	FamilyBri   Family = "bridge"
	FamilyNetdev Family = "netdev"
)

// Hook is the chain attachment point in the kernel network stack.
type Hook string

const (
	HookPrerouting  Hook = "prerouting"
	HookInput       Hook = "input"
	HookForward     Hook = "forward"
	HookOutput      Hook = "output"
	HookPostrouting Hook = "postrouting"
	HookIngress     Hook = "ingress"
	HookEgress      Hook = "egress"
)

// ChainType matches nftables' `type` keyword: filter | nat | route.
type ChainType string

const (
	ChainTypeFilter ChainType = "filter"
	ChainTypeNAT    ChainType = "nat"
	ChainTypeRoute  ChainType = "route"
)

// Verdict is the terminal action on a rule match.
type Verdict string

const (
	VerdictAccept   Verdict = "accept"
	VerdictDrop     Verdict = "drop"
	VerdictReject   Verdict = "reject"
	VerdictReturn   Verdict = "return"
	VerdictContinue Verdict = "continue"
	VerdictJump     Verdict = "jump"
	VerdictGoto     Verdict = "goto"
)

// Ruleset is the full nftables view Zeerak owns or observes.
//
// A live ruleset typically contains tables Zeerak does NOT own (e.g. Docker's
// `ip nat` chains, fail2ban sets). The model represents them faithfully so
// the diff/preview UI shows the truth; only tables marked Owned=true are ever
// modified by Zeerak's apply path.
type Ruleset struct {
	Tables []Table `json:"tables" yaml:"tables"`
}

// Table is an nftables table. Owned=true means Zeerak manages it (typically
// `inet zeerak-policy` for policy-rendered rules, plus user-edited tables).
type Table struct {
	Family Family  `json:"family" yaml:"family"`
	Name   string  `json:"name"   yaml:"name"`
	Owned  bool    `json:"owned"  yaml:"owned"`
	Chains []Chain `json:"chains" yaml:"chains"`
	Sets   []Set   `json:"sets,omitempty" yaml:"sets,omitempty"`
	// TODO: Maps, Counters, Quotas, Flowtables.
}

// Chain is an ordered list of rules attached at a hook (or a regular chain
// reachable only via jump/goto).
type Chain struct {
	Name     string    `json:"name" yaml:"name"`
	Type     ChainType `json:"type,omitempty" yaml:"type,omitempty"`         // empty for regular chains
	Hook     Hook      `json:"hook,omitempty" yaml:"hook,omitempty"`         // empty for regular chains
	Priority int       `json:"priority,omitempty" yaml:"priority,omitempty"` // nft priority (e.g. filter=0)
	Policy   Verdict   `json:"policy,omitempty" yaml:"policy,omitempty"`     // base chain default verdict
	Rules    []Rule    `json:"rules" yaml:"rules"`
}

// Rule is a single nftables rule. Expr is a raw nft expression string for v0.1
// (e.g. `tcp dport 22 accept`); a structured expression AST will replace it
// once the renderer round-trip fuzzer is green.
//
// Comment is round-tripped to `nft` as a `comment "..."` annotation; Zeerak
// uses it to track policy-generated rules.
type Rule struct {
	Expr    string `json:"expr"              yaml:"expr"`
	Comment string `json:"comment,omitempty" yaml:"comment,omitempty"`
}

// Set is a named nftables set (CIDR lists, port lists, country blocks, etc.).
type Set struct {
	Name     string   `json:"name"     yaml:"name"`
	Type     string   `json:"type"     yaml:"type"` // e.g. "ipv4_addr", "inet_service"
	Flags    []string `json:"flags,omitempty"    yaml:"flags,omitempty"`
	Elements []string `json:"elements,omitempty" yaml:"elements,omitempty"`
}
