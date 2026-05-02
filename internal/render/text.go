// Package render converts model.Ruleset into the textual nftables ruleset
// accepted by `nft -f -` and (eventually) into google/nftables transactions
// for atomic netlink apply.
//
// The text renderer ships first because it's:
//   - human-readable (drives the diff/preview UI),
//   - exactly the format `nft list ruleset` emits, so round-trip fuzzing
//     against `nft -j` validates that our model never drifts from the kernel
//     (VISION.md §11 Q1, §7 Fuzzing).
//
// The netlink path (google/nftables) lands in v0.1 once the text path is
// round-trip-clean.
package render

import (
	"fmt"
	"io"
	"strings"

	"github.com/zeerak/zeerak/internal/model"
)

// Text renders a Ruleset to nft text format, writing to w.
//
// Only Tables with Owned=true are emitted by default; pass includeUnowned=true
// to dump everything (useful for the read-only "live ruleset" view).
func Text(w io.Writer, rs *model.Ruleset, includeUnowned bool) error {
	for _, t := range rs.Tables {
		if !includeUnowned && !t.Owned {
			continue
		}
		if err := renderTable(w, &t); err != nil {
			return err
		}
	}
	return nil
}

// String is a convenience wrapper around Text that returns a string.
func String(rs *model.Ruleset, includeUnowned bool) (string, error) {
	var sb strings.Builder
	if err := Text(&sb, rs, includeUnowned); err != nil {
		return "", err
	}
	return sb.String(), nil
}

func renderTable(w io.Writer, t *model.Table) error {
	if _, err := fmt.Fprintf(w, "table %s %s {\n", t.Family, t.Name); err != nil {
		return err
	}
	for _, h := range t.Helpers {
		if err := renderHelper(w, &h); err != nil {
			return err
		}
	}
	for _, s := range t.Sets {
		if err := renderSet(w, &s); err != nil {
			return err
		}
	}
	for _, c := range t.Chains {
		if err := renderChain(w, &c); err != nil {
			return err
		}
	}
	_, err := fmt.Fprintln(w, "}")
	return err
}

func renderHelper(w io.Writer, h *model.CTHelper) error {
	_, err := fmt.Fprintf(w,
		"\tct helper %q {\n\t\ttype %q protocol %s;\n\t}\n",
		h.Name, h.Type, h.L4Proto)
	return err
}

func renderSet(w io.Writer, s *model.Set) error {
	if _, err := fmt.Fprintf(w, "\tset %s {\n\t\ttype %s\n", s.Name, s.Type); err != nil {
		return err
	}
	if len(s.Flags) > 0 {
		if _, err := fmt.Fprintf(w, "\t\tflags %s\n", strings.Join(s.Flags, ", ")); err != nil {
			return err
		}
	}
	if len(s.Elements) > 0 {
		if _, err := fmt.Fprintf(w, "\t\telements = { %s }\n", strings.Join(s.Elements, ", ")); err != nil {
			return err
		}
	}
	_, err := fmt.Fprintln(w, "\t}")
	return err
}

func renderChain(w io.Writer, c *model.Chain) error {
	if _, err := fmt.Fprintf(w, "\tchain %s {\n", c.Name); err != nil {
		return err
	}
	// Base chain header (type/hook/priority/policy) only emitted for hooked chains.
	if c.Hook != "" {
		if _, err := fmt.Fprintf(w, "\t\ttype %s hook %s priority %d;", c.Type, c.Hook, c.Priority); err != nil {
			return err
		}
		if c.Policy != "" {
			if _, err := fmt.Fprintf(w, " policy %s;", c.Policy); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprintln(w); err != nil {
			return err
		}
	}
	for _, r := range c.Rules {
		if r.Comment != "" {
			if _, err := fmt.Fprintf(w, "\t\t%s comment %q\n", r.Expr, r.Comment); err != nil {
				return err
			}
		} else {
			if _, err := fmt.Fprintf(w, "\t\t%s\n", r.Expr); err != nil {
				return err
			}
		}
	}
	_, err := fmt.Fprintln(w, "\t}")
	return err
}
