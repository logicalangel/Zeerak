package mcp

import (
	"fmt"
	"strconv"
	"strings"
)

// ExplainRule turns an nft expression into plain English.
//
// This is a heuristic tokeniser, not a parser. It recognises the common
// matches Zeerak emits (saddr/daddr CIDRs, dport/sport, ct state, iif/oif,
// meta l4proto, ip protocol, accept/drop/reject/log) and falls back to
// "(raw rule: ...)" for anything it doesn't know.
func ExplainRule(expr string) string {
	tokens := strings.Fields(expr)
	if len(tokens) == 0 {
		return "(empty rule)"
	}
	var clauses []string
	verdict := ""
	i := 0
	get := func(d int) string {
		if i+d < len(tokens) {
			return tokens[i+d]
		}
		return ""
	}

	for i < len(tokens) {
		tok := tokens[i]
		switch tok {
		case "ip", "ip6":
			switch get(1) {
			case "saddr":
				clauses = append(clauses, fmt.Sprintf("source address is %s", get(2)))
				i += 3
				continue
			case "daddr":
				clauses = append(clauses, fmt.Sprintf("destination address is %s", get(2)))
				i += 3
				continue
			case "protocol":
				clauses = append(clauses, fmt.Sprintf("IP protocol is %s", get(2)))
				i += 3
				continue
			}
		case "tcp", "udp":
			proto := tok
			switch get(1) {
			case "dport":
				clauses = append(clauses, fmt.Sprintf("%s destination port is %s", proto, get(2)))
				i += 3
				continue
			case "sport":
				clauses = append(clauses, fmt.Sprintf("%s source port is %s", proto, get(2)))
				i += 3
				continue
			}
		case "ct":
			if get(1) == "state" {
				clauses = append(clauses, fmt.Sprintf("connection state is %s", get(2)))
				i += 3
				continue
			}
		case "iif", "iifname":
			clauses = append(clauses, fmt.Sprintf("input interface is %s", get(1)))
			i += 2
			continue
		case "oif", "oifname":
			clauses = append(clauses, fmt.Sprintf("output interface is %s", get(1)))
			i += 2
			continue
		case "meta":
			if get(1) == "l4proto" {
				clauses = append(clauses, fmt.Sprintf("L4 protocol is %s", get(2)))
				i += 3
				continue
			}
		case "icmp", "icmpv6":
			clauses = append(clauses, fmt.Sprintf("packet is %s", tok))
			i++
			continue
		case "log":
			clauses = append(clauses, "log the packet")
			i++
			continue
		case "accept", "drop", "reject", "return", "continue":
			verdict = tok
			i++
			continue
		case "jump", "goto":
			verdict = fmt.Sprintf("%s to chain %q", tok, get(1))
			i += 2
			continue
		case "counter":
			clauses = append(clauses, "(counted)")
			i++
			continue
		}
		// Unknown token: stop parsing structurally and quote the rest.
		rest := strings.Join(tokens[i:], " ")
		return fmt.Sprintf("Matches when (raw): %s.", rest)
	}

	var head string
	if len(clauses) == 0 {
		head = "Always matches"
	} else {
		head = "Matches when " + strings.Join(clauses, ", and ")
	}
	if verdict == "" {
		return head + "; no terminal verdict."
	}
	return head + " — verdict: " + verdict + "."
}

// Packet is the input to SimulatePacket. Only fields relevant to the
// heuristic matcher are read; absent fields don't constrain the match.
type Packet struct {
	Hook     string `json:"hook"`     // input | forward | output (default input)
	Protocol string `json:"protocol"` // tcp | udp | icmp | icmpv6
	Saddr    string `json:"saddr"`
	Daddr    string `json:"daddr"`
	Sport    int    `json:"sport"`
	Dport    int    `json:"dport"`
	IIF      string `json:"iif"`
	OIF      string `json:"oif"`
}

// SimResult is what simulate_packet returns.
type SimResult struct {
	Verdict     string   `json:"verdict"`     // accept | drop | reject | (chain policy)
	Matched     bool     `json:"matched"`     // true iff a rule terminated the walk
	Hook        string   `json:"hook"`        // resolved hook
	Chain       string   `json:"chain"`       // chain name where decision was made
	MatchedRule string   `json:"matched_rule,omitempty"`
	Trace       []string `json:"trace"`       // step-by-step log
}

// SimulatePacket walks owned chains (ones starting with `chain ... {`) at the
// requested hook and returns the first rule whose tokens are all satisfied
// by pkt.
//
// This is intentionally simple: for v0 we only honour the same tokens
// ExplainRule recognises. Sets, maps, named anonymous sets, NAT, and
// jumps/gotos are NOT followed; we record them in Trace and continue.
func SimulatePacket(rulesetText string, pkt Packet) SimResult {
	if pkt.Hook == "" {
		pkt.Hook = "input"
	}
	res := SimResult{Hook: pkt.Hook}
	chains := parseChains(rulesetText)

	for _, ch := range chains {
		if ch.hook != pkt.Hook {
			continue
		}
		res.Chain = ch.name
		res.Trace = append(res.Trace, fmt.Sprintf("entering chain %q (table %s, policy=%s)", ch.name, ch.table, ch.policy))
		for idx, rule := range ch.rules {
			if !ruleMatches(rule, pkt) {
				res.Trace = append(res.Trace, fmt.Sprintf("  rule[%d] miss: %s", idx, rule))
				continue
			}
			v := extractVerdict(rule)
			res.Trace = append(res.Trace, fmt.Sprintf("  rule[%d] HIT (%s): %s", idx, v, rule))
			if v == "" || v == "jump" || v == "goto" || v == "return" || v == "continue" {
				// Non-terminal in our model — keep walking.
				continue
			}
			res.Matched = true
			res.Verdict = v
			res.MatchedRule = rule
			return res
		}
		res.Trace = append(res.Trace, fmt.Sprintf("end of chain %q; falling through to policy=%s", ch.name, ch.policy))
		if ch.policy != "" {
			res.Verdict = ch.policy
			return res
		}
	}
	if res.Verdict == "" {
		res.Verdict = "accept" // nft default when no base chain matches
		res.Trace = append(res.Trace, "no base chain at this hook — kernel default: accept")
	}
	return res
}

// parsedChain is a flattened view of a base chain.
type parsedChain struct {
	table  string
	name   string
	hook   string
	policy string
	rules  []string
}

// parseChains is a forgiving line scanner over `nft list ruleset` output.
// It recognises only what we need: `table FAMILY NAME { ... chain NAME { type
// ... hook H ... policy P; <rules>; } ... }`.
func parseChains(text string) []parsedChain {
	var out []parsedChain
	lines := strings.Split(text, "\n")
	curTable := ""
	var cur *parsedChain
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		switch {
		case strings.HasPrefix(line, "table "):
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				curTable = parts[1] + " " + parts[2]
			}
		case strings.HasPrefix(line, "chain "):
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				cur = &parsedChain{table: curTable, name: strings.TrimSuffix(parts[1], "{")}
			}
		case cur != nil && strings.HasPrefix(line, "type "):
			// e.g. "type filter hook input priority 0; policy drop;"
			if i := strings.Index(line, "hook "); i >= 0 {
				rest := strings.Fields(line[i+5:])
				if len(rest) > 0 {
					cur.hook = rest[0]
				}
			}
			if i := strings.Index(line, "policy "); i >= 0 {
				rest := strings.Fields(line[i+7:])
				if len(rest) > 0 {
					cur.policy = strings.TrimRight(rest[0], ";")
				}
			}
		case line == "}" && cur != nil:
			out = append(out, *cur)
			cur = nil
		case cur != nil:
			r := strings.TrimRight(line, ";")
			if r != "" && !strings.HasPrefix(r, "type ") && !strings.HasPrefix(r, "policy ") {
				cur.rules = append(cur.rules, r)
			}
		}
	}
	return out
}

// ruleMatches returns true if every constraint in rule is satisfied by pkt.
// Unrecognised match expressions are conservatively treated as "uncertain"
// and abort the match (return false). Set/map references abort too.
// Verdicts and benign keywords like `counter` / `log` are skipped without
// affecting the result.
func ruleMatches(rule string, pkt Packet) bool {
	tokens := strings.Fields(rule)
	for i := 0; i < len(tokens); i++ {
		tok := tokens[i]
		next := func(d int) string {
			if i+d < len(tokens) {
				return tokens[i+d]
			}
			return ""
		}
		switch tok {
		// Terminal / non-match tokens: skip, don't constrain.
		case "accept", "drop", "reject", "return", "continue", "counter", "log":
			// move on
		case "jump", "goto":
			// Skip the chain name argument.
			i++
		case "tcp", "udp":
			if pkt.Protocol == "" || pkt.Protocol != tok {
				return false
			}
			switch next(1) {
			case "dport":
				if !portMatches(next(2), pkt.Dport) {
					return false
				}
				i += 2
			case "sport":
				if !portMatches(next(2), pkt.Sport) {
					return false
				}
				i += 2
			}
		case "ip", "ip6":
			switch next(1) {
			case "saddr":
				if pkt.Saddr == "" || !addrMatches(next(2), pkt.Saddr) {
					return false
				}
				i += 2
			case "daddr":
				if pkt.Daddr == "" || !addrMatches(next(2), pkt.Daddr) {
					return false
				}
				i += 2
			case "protocol":
				if pkt.Protocol == "" || next(2) != pkt.Protocol {
					return false
				}
				i += 2
			default:
				// `ip` followed by something we don't grok.
				return false
			}
		case "iif", "iifname":
			want := strings.Trim(next(1), "\"")
			if pkt.IIF == "" || pkt.IIF != want {
				return false
			}
			i++
		case "oif", "oifname":
			want := strings.Trim(next(1), "\"")
			if pkt.OIF == "" || pkt.OIF != want {
				return false
			}
			i++
		default:
			// Anything we don't recognise is a constraint we can't evaluate.
			// Be safe: declare the rule a miss.
			return false
		}
	}
	return true
}

// portMatches handles "22", "22-25", and refuses sets/maps.
func portMatches(spec string, p int) bool {
	if p == 0 || spec == "" {
		return spec == ""
	}
	if strings.HasPrefix(spec, "@") || strings.HasPrefix(spec, "{") {
		return false
	}
	if dash := strings.IndexByte(spec, '-'); dash > 0 {
		lo, errLo := strconv.Atoi(spec[:dash])
		hi, errHi := strconv.Atoi(spec[dash+1:])
		if errLo != nil || errHi != nil {
			return false
		}
		return p >= lo && p <= hi
	}
	n, err := strconv.Atoi(spec)
	if err != nil {
		return false
	}
	return n == p
}

// addrMatches handles bare IPs and CIDRs. Sets are rejected.
func addrMatches(spec, addr string) bool {
	if addr == "" {
		return spec == ""
	}
	if strings.HasPrefix(spec, "@") || strings.HasPrefix(spec, "{") {
		return false
	}
	// Trim trailing comma (nft sometimes emits "addr,").
	spec = strings.TrimRight(spec, ",")
	if !strings.Contains(spec, "/") {
		return spec == addr
	}
	return cidrContains(spec, addr)
}

func extractVerdict(rule string) string {
	for _, v := range []string{"accept", "drop", "reject", "return", "continue", "jump", "goto"} {
		if strings.Contains(" "+rule+" ", " "+v+" ") || strings.HasSuffix(rule, " "+v) || rule == v {
			return v
		}
	}
	return ""
}
