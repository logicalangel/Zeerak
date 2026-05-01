// Package docker provides best-effort Docker awareness for Zeerak.
//
// VISION.md §10 v0.3 list calls out "Docker chain awareness, with a
// non-destructive plan to coexist." This package implements detection only:
// it asks the kernel whether the well-known Docker iptables/nftables chains
// exist. Any *modification* of those chains (the DOCKER-USER hand-off
// pattern) is deferred to v0.4 — too easy to brick a host's container
// networking by accident.
package docker

import (
	"context"
	"strings"

	"github.com/zeerak/zeerak/internal/model"
)

// Reader is the subset of nft.Adapter we need. internal/api.Reader and
// internal/ui.Reader are both compatible.
type Reader interface {
	LiveText(ctx context.Context) (string, error)
	LiveTable(ctx context.Context, family model.Family, name string) (string, error)
}

// Result describes whether Docker is touching netfilter on this host.
type Result struct {
	// Detected is true when at least one Docker-managed chain or table is present.
	Detected bool
	// HasDockerUser is true when the canonical hand-off chain (ip filter
	// chain DOCKER-USER) exists. That's the safe place for Zeerak to
	// inject extra rules in v0.4.
	HasDockerUser bool
	// Tables is the list of Docker-related tables we noticed in the live
	// ruleset (e.g. "ip nat", "ip filter"). Empty when nothing detected.
	Tables []string
}

// Detect inspects the live ruleset for Docker-managed objects. It is a
// pure read; safe to call on every dashboard render.
//
// We grep the textual output rather than walk a structured model because
// `nft list ruleset` is the canonical authoritative source and works
// regardless of whether Docker is using legacy iptables-nft or native nft.
func Detect(ctx context.Context, r Reader) Result {
	out := Result{}
	if r == nil {
		return out
	}
	text, err := r.LiveText(ctx)
	if err != nil || text == "" {
		return out
	}
	// Tokens: Docker creates `chain DOCKER`, `chain DOCKER-USER`,
	// `chain DOCKER-ISOLATION-STAGE-1`, etc. The DOCKER-USER chain is the
	// well-known integration point.
	if strings.Contains(text, "chain DOCKER-USER") {
		out.HasDockerUser = true
		out.Detected = true
	}
	if strings.Contains(text, "chain DOCKER ") || strings.Contains(text, "chain DOCKER\n") || strings.Contains(text, "chain DOCKER-ISOLATION") {
		out.Detected = true
	}
	// Track which tables they live in so the dashboard can show a hint.
	seen := map[string]bool{}
	scanner := text
	for _, line := range strings.Split(scanner, "\n") {
		line = strings.TrimSpace(line)
		// `table ip filter {` or `table ip nat {`
		if strings.HasPrefix(line, "table ") && strings.HasSuffix(line, "{") {
			body := strings.TrimSuffix(strings.TrimPrefix(line, "table "), "{")
			body = strings.TrimSpace(body)
			seen[body] = false // candidate
		}
	}
	// Walk again block-by-block: any table that contains a DOCKER-prefixed
	// chain is recorded. We use a nesting depth counter so chain closing
	// braces don't pop us out of the table.
	current := ""
	depth := 0
	for _, line := range strings.Split(scanner, "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "table ") && strings.HasSuffix(t, "{") {
			current = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(t, "table "), "{"))
			depth = 1
			continue
		}
		if current == "" {
			continue
		}
		if strings.HasPrefix(t, "chain DOCKER") {
			seen[current] = true
		}
		if strings.HasSuffix(t, "{") {
			depth++
		}
		if t == "}" {
			depth--
			if depth <= 0 {
				current = ""
				depth = 0
			}
		}
	}
	for name, hit := range seen {
		if hit {
			out.Tables = append(out.Tables, name)
		}
	}
	return out
}
