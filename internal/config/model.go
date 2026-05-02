package config

import "github.com/zeerak/zeerak/internal/model"

// ToRuleset projects the YAML config into the internal model.
//
// Compilation order:
//
//  1. Presets (caddy_box, ssh, default_deny_inbound) -> single inet table
//     `zeerak-presets`. Skipped if no preset is enabled.
//  2. Raw `tables:` from the YAML, in declared order.
//
// Every emitted table is marked Owned=true: by definition, anything the
// operator wrote in zeerak.yaml is Zeerak-managed. Tables not in the YAML
// stay untouched on the kernel side.
func (c *Config) ToRuleset() *model.Ruleset {
	rs := &model.Ruleset{Tables: make([]model.Table, 0, 4+len(c.Tables))}

	rs.Tables = append(rs.Tables, c.Presets.CompileTables()...)

	for _, t := range c.Tables {
		mt := model.Table{
			Family: model.Family(t.Family),
			Name:   t.Name,
			Owned:  true,
			Chains: make([]model.Chain, 0, len(t.Chains)),
		}
		for _, c := range t.Chains {
			mc := model.Chain{
				Name:     c.Name,
				Type:     model.ChainType(c.Type),
				Hook:     model.Hook(c.Hook),
				Priority: c.Priority,
				Policy:   model.Verdict(c.Policy),
				Rules:    make([]model.Rule, 0, len(c.Rules)),
			}
			for _, r := range c.Rules {
				mc.Rules = append(mc.Rules, model.Rule{Expr: r.Expr, Comment: r.Comment})
			}
			mt.Chains = append(mt.Chains, mc)
		}
		rs.Tables = append(rs.Tables, mt)
	}
	return rs
}
