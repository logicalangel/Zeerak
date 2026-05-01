package activity

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAppendAndRecent(t *testing.T) {
	dir := t.TempDir()
	log, err := New(filepath.Join(dir, "a.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []Kind{KindBoot, KindStaged, KindConfirmed} {
		if err := log.Append(Event{Kind: k, Message: string(k)}); err != nil {
			t.Fatal(err)
		}
	}
	got, err := log.Recent(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("want 3, got %d", len(got))
	}
	if got[0].Kind != KindConfirmed {
		t.Errorf("newest first; got %s", got[0].Kind)
	}
}

func TestRecentMissingFile(t *testing.T) {
	log := &Logger{path: filepath.Join(t.TempDir(), "missing.jsonl")}
	got, err := log.Recent(5)
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Errorf("want nil, got %v", got)
	}
}

func TestCompaction(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "a.jsonl")
	log, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	// Force a tiny cap by writing a big file then mutating MaxBytes via
	// many small appends past the threshold. We can't change MaxBytes from
	// outside; instead, write a chunky file then call maybeCompactLocked.
	big := make([]byte, MaxBytes+1024)
	for i := range big {
		big[i] = 'x'
	}
	if err := os.WriteFile(path, big, 0o640); err != nil {
		t.Fatal(err)
	}
	// Append a real event — triggers compaction.
	if err := log.Append(Event{Kind: KindBoot, Message: "after compact"}); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Size() > MaxBytes {
		t.Errorf("expected compacted size <= %d, got %d", MaxBytes, st.Size())
	}
}
