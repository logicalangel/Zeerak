package diff

import (
	"strings"
	"testing"
)

func TestUnified_Identical(t *testing.T) {
	if got := Unified("a\nb\nc\n", "a\nb\nc\n", "live", "candidate"); got != "" {
		t.Fatalf("identical inputs: got %q, want empty", got)
	}
}

func TestUnified_BothEmpty(t *testing.T) {
	if got := Unified("", "", "live", "candidate"); got != "" {
		t.Fatalf("empty inputs: got %q", got)
	}
}

func TestUnified_FullReplace(t *testing.T) {
	got := Unified("old\n", "new\n", "live", "candidate")
	if !strings.HasPrefix(got, "--- live\n+++ candidate\n") {
		t.Fatalf("missing header: %q", got)
	}
	if !strings.Contains(got, "-old") || !strings.Contains(got, "+new") {
		t.Fatalf("missing edits: %q", got)
	}
}

func TestUnified_PartialChange(t *testing.T) {
	a := "table inet zeerak-presets {\n\tchain input {\n\t\ttcp dport 22 accept\n\t}\n}\n"
	b := "table inet zeerak-presets {\n\tchain input {\n\t\ttcp dport 22 accept\n\t\ttcp dport { 80, 443 } accept\n\t}\n}\n"
	got := Unified(a, b, "live", "candidate")
	if !strings.Contains(got, "+\t\ttcp dport { 80, 443 } accept") {
		t.Fatalf("expected addition not found: %q", got)
	}
	// Unchanged lines should appear with leading space.
	if !strings.Contains(got, " \tchain input {") {
		t.Fatalf("context not preserved: %q", got)
	}
}

func TestUnified_AdditionOnly(t *testing.T) {
	got := Unified("", "new line\n", "live", "candidate")
	if !strings.Contains(got, "+new line") {
		t.Fatalf("addition missing: %q", got)
	}
	// Empty-side count is 0.
	if !strings.Contains(got, "@@ -0,0 +1,1 @@") {
		t.Fatalf("hunk header wrong: %q", got)
	}
}

func TestUnified_DeletionOnly(t *testing.T) {
	got := Unified("gone\n", "", "live", "candidate")
	if !strings.Contains(got, "-gone") {
		t.Fatalf("deletion missing: %q", got)
	}
	if !strings.Contains(got, "@@ -1,1 +0,0 @@") {
		t.Fatalf("hunk header wrong: %q", got)
	}
}

func TestUnified_MultipleHunks(t *testing.T) {
	// 12 lines, edit lines 1 and 12 — context=3 so hunks should be separate.
	a := strings.Join([]string{"A1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "A12"}, "\n") + "\n"
	b := strings.Join([]string{"B1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "B12"}, "\n") + "\n"
	got := Unified(a, b, "live", "candidate")
	hunks := strings.Count(got, "@@")
	// "@@" appears twice per hunk header.
	if hunks/2 != 2 {
		t.Fatalf("expected 2 hunks, got %d:\n%s", hunks/2, got)
	}
}
