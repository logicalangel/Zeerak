//go:build linux

package nft

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"sync"

	"github.com/zeerak/zeerak/internal/model"
	"github.com/zeerak/zeerak/internal/render"
)

// linuxAdapter shells out to `nft` for atomic apply.
//
// Snapshot strategy (v0.1): in-memory cache of the last successful apply.
// The daemon's persistent source of truth is autosave.yaml on disk; this
// cache is purely for the rollback window. On daemon restart the cache is
// empty and the first Apply starts a new history.
//
// Snapshot strategy (v0.2): parse `nft -j list ruleset` for owned tables
// so reads survive daemon restarts. Tracked under VISION.md §10 v0.2.
type linuxAdapter struct {
	nftPath string

	mu   sync.Mutex
	last *model.Ruleset
}

func newPlatform() Adapter {
	path, _ := exec.LookPath("nft")
	if path == "" {
		path = "nft" // let exec fail loudly with PATH error
	}
	return &linuxAdapter{nftPath: path, last: &model.Ruleset{}}
}

// Snapshot returns a deep-ish copy of the last applied ruleset.
func (a *linuxAdapter) Snapshot(ctx context.Context) (*model.Ruleset, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return cloneRuleset(a.last), nil
}

// Apply renders rs and pipes it through `nft -f -`. nft applies the entire
// stream atomically (single netlink transaction).
//
// We prepend a `flush table` for each owned table in rs, so apply is a true
// replace, not a merge. Unowned tables in rs are ignored (defense in depth;
// the renderer already filters them).
func (a *linuxAdapter) Apply(ctx context.Context, rs *model.Ruleset) error {
	if rs == nil {
		rs = &model.Ruleset{}
	}

	var script bytes.Buffer
	for _, t := range rs.Tables {
		if !t.Owned {
			continue
		}
		// `flush table` empties contents but keeps the table itself; safe
		// even if the table doesn't exist yet because we follow with the
		// renderer's `table ... { ... }` block which (re)creates it.
		fmt.Fprintf(&script, "add table %s %s\n", t.Family, t.Name)
		fmt.Fprintf(&script, "flush table %s %s\n", t.Family, t.Name)
	}
	if err := render.Text(&script, rs, false); err != nil {
		return fmt.Errorf("render: %w", err)
	}

	cmd := exec.CommandContext(ctx, a.nftPath, "-f", "-")
	cmd.Stdin = &script
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("nft -f -: %w (%s)", err, bytes.TrimSpace(out))
	}

	a.mu.Lock()
	a.last = cloneRuleset(rs)
	a.mu.Unlock()
	return nil
}

// LiveText shells `nft list ruleset` and returns its stdout. The output
// includes every table on the host, owned or not — that's the point of the
// read-only ruleset view.
func (a *linuxAdapter) LiveText(ctx context.Context) (string, error) {
	cmd := exec.CommandContext(ctx, a.nftPath, "list", "ruleset")
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("nft list ruleset: %w", err)
	}
	return string(out), nil
}

// LiveTable shells `nft list table FAMILY NAME`. A missing table is not an
// error here — we return ("", nil) so /preview can diff a candidate that
// creates a brand-new table.
func (a *linuxAdapter) LiveTable(ctx context.Context, family model.Family, name string) (string, error) {
	cmd := exec.CommandContext(ctx, a.nftPath, "list", "table", string(family), name)
	out, err := cmd.Output()
	if err != nil {
		// nft prints "Error: No such file or directory" on stderr and exits 1.
		if ee, ok := err.(*exec.ExitError); ok && bytes.Contains(ee.Stderr, []byte("No such file or directory")) {
			return "", nil
		}
		return "", fmt.Errorf("nft list table %s %s: %w", family, name, err)
	}
	return string(out), nil
}

// cloneRuleset returns a defensive copy. Cheap because rules are tiny
// strings; we never mutate slices in place anyway, but the stager keeps a
// long-lived snapshot reference and we don't want shared backing arrays.
func cloneRuleset(rs *model.Ruleset) *model.Ruleset {
	if rs == nil {
		return &model.Ruleset{}
	}
	out := &model.Ruleset{Tables: make([]model.Table, len(rs.Tables))}
	for i, t := range rs.Tables {
		nt := t
		nt.Chains = append([]model.Chain(nil), t.Chains...)
		for j, c := range nt.Chains {
			nt.Chains[j].Rules = append([]model.Rule(nil), c.Rules...)
		}
		nt.Sets = append([]model.Set(nil), t.Sets...)
		out.Tables[i] = nt
	}
	return out
}
