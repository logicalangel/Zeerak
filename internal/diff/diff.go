// Package diff produces a small unified-diff between two strings.
//
// Used by /preview to show the operator what their staged config will
// change before they commit. The format is the familiar `diff -u` shape:
//
//	--- live
//	+++ candidate
//	@@ -L,N +L,N @@
//	-removed line
//	+added line
//	 context line
//
// The algorithm is a straight LCS-DP — O(n*m) memory and time. Rulesets
// are tiny (rarely > 200 lines) so this is fine. If we ever care, swap
// in Myers under the same Unified() signature.
package diff

import (
	"fmt"
	"strings"
)

// DefaultContext is the number of unchanged lines kept around each hunk.
const DefaultContext = 3

// Unified returns a unified diff of a vs b. labelA / labelB are the
// `--- ` / `+++ ` headers (typically "live" and "candidate"). When the
// inputs are identical the result is an empty string.
func Unified(a, b, labelA, labelB string) string {
	la := splitLines(a)
	lb := splitLines(b)
	ops := lcsDiff(la, lb)
	if !hasChanges(ops) {
		return ""
	}
	hunks := groupHunks(ops, DefaultContext)
	if len(hunks) == 0 {
		return ""
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "--- %s\n+++ %s\n", labelA, labelB)
	for _, h := range hunks {
		writeHunk(&sb, h)
	}
	return sb.String()
}

// --- internals --------------------------------------------------------------

type opKind int

const (
	opEqual  opKind = iota // line in both
	opDelete               // line only in a
	opInsert               // line only in b
)

type op struct {
	kind opKind
	line string
}

// splitLines preserves the trailing-newline convention by always producing
// at least one entry per logical line.
func splitLines(s string) []string {
	if s == "" {
		return nil
	}
	// Strip exactly one trailing newline so we don't end with an empty line.
	if strings.HasSuffix(s, "\n") {
		s = s[:len(s)-1]
	}
	return strings.Split(s, "\n")
}

// lcsDiff returns the edit script that turns a into b.
func lcsDiff(a, b []string) []op {
	n, m := len(a), len(b)
	// dp[i][j] = LCS length of a[i:], b[j:].
	dp := make([][]int, n+1)
	for i := range dp {
		dp[i] = make([]int, m+1)
	}
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			if a[i] == b[j] {
				dp[i][j] = dp[i+1][j+1] + 1
			} else if dp[i+1][j] >= dp[i][j+1] {
				dp[i][j] = dp[i+1][j]
			} else {
				dp[i][j] = dp[i][j+1]
			}
		}
	}

	var ops []op
	i, j := 0, 0
	for i < n && j < m {
		switch {
		case a[i] == b[j]:
			ops = append(ops, op{opEqual, a[i]})
			i++
			j++
		case dp[i+1][j] >= dp[i][j+1]:
			ops = append(ops, op{opDelete, a[i]})
			i++
		default:
			ops = append(ops, op{opInsert, b[j]})
			j++
		}
	}
	for ; i < n; i++ {
		ops = append(ops, op{opDelete, a[i]})
	}
	for ; j < m; j++ {
		ops = append(ops, op{opInsert, b[j]})
	}
	return ops
}

func hasChanges(ops []op) bool {
	for _, o := range ops {
		if o.kind != opEqual {
			return true
		}
	}
	return false
}

// hunk is a contiguous run of ops with up to `context` equal lines on
// either side. Tracks 1-based start lines into a and b.
type hunk struct {
	startA, startB int
	ops            []op
}

// groupHunks slices the edit script into hunks separated by runs of more
// than 2*context unchanged lines.
func groupHunks(ops []op, context int) []hunk {
	var hunks []hunk

	// Pre-compute per-op (lineA, lineB) so we can stamp hunk headers.
	type lined struct {
		op
		lineA, lineB int // 1-based pre-edit positions
	}
	lined1 := make([]lined, 0, len(ops))
	la, lb := 1, 1
	for _, o := range ops {
		l := lined{op: o, lineA: la, lineB: lb}
		switch o.kind {
		case opEqual:
			la++
			lb++
		case opDelete:
			la++
		case opInsert:
			lb++
		}
		lined1 = append(lined1, l)
	}

	i := 0
	for i < len(lined1) {
		// Find next change.
		for i < len(lined1) && lined1[i].kind == opEqual {
			i++
		}
		if i == len(lined1) {
			break
		}
		// Hunk starts up to `context` lines before this change.
		start := i - context
		if start < 0 {
			start = 0
		}
		// Walk forward, extending the hunk as long as a non-equal op
		// appears within `context` of the last change.
		end := i
		for end < len(lined1) {
			if lined1[end].kind != opEqual {
				end++
				continue
			}
			// equal — peek ahead for another change within 2*context.
			look := end + 1
			for look < len(lined1) && look-end <= 2*context && lined1[look].kind == opEqual {
				look++
			}
			if look < len(lined1) && look-end <= 2*context {
				end = look
				continue
			}
			break
		}
		// Trail up to `context` equal lines after the last change.
		trail := end + context
		if trail > len(lined1) {
			trail = len(lined1)
		}
		// But cap trail so we don't include equal lines past the next change-free zone.
		for trail > end && lined1[trail-1].kind == opEqual {
			// keep
			break
		}

		h := hunk{
			startA: lined1[start].lineA,
			startB: lined1[start].lineB,
		}
		// trail again, cleanly: include up to `context` equal lines after end.
		extra := 0
		for end < len(lined1) && extra < context && lined1[end].kind == opEqual {
			end++
			extra++
		}
		for k := start; k < end; k++ {
			h.ops = append(h.ops, lined1[k].op)
		}
		hunks = append(hunks, h)
		i = end
	}
	return hunks
}

func writeHunk(sb *strings.Builder, h hunk) {
	var aCount, bCount int
	for _, o := range h.ops {
		switch o.kind {
		case opEqual:
			aCount++
			bCount++
		case opDelete:
			aCount++
		case opInsert:
			bCount++
		}
	}
	// Empty-side line numbers are emitted as "0,0" by GNU diff.
	startA := h.startA
	if aCount == 0 {
		startA = 0
	}
	startB := h.startB
	if bCount == 0 {
		startB = 0
	}
	fmt.Fprintf(sb, "@@ -%d,%d +%d,%d @@\n", startA, aCount, startB, bCount)
	for _, o := range h.ops {
		switch o.kind {
		case opEqual:
			fmt.Fprintf(sb, " %s\n", o.line)
		case opDelete:
			fmt.Fprintf(sb, "-%s\n", o.line)
		case opInsert:
			fmt.Fprintf(sb, "+%s\n", o.line)
		}
	}
}
