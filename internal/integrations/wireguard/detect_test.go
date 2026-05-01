package wireguard

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestScanSysNet(t *testing.T) {
	dir := t.TempDir()
	// Make a mix: matching, non-matching, edge cases.
	for _, name := range []string{"lo", "eth0", "wg0", "wg-corp", "wgbridge", "wg"} {
		if err := os.Mkdir(filepath.Join(dir, name), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	got := scanSysNet(dir)
	want := []string{"wg-corp", "wg0"}
	if !got.Detected || !reflect.DeepEqual(got.Interfaces, want) {
		t.Fatalf("got %+v, want detected=true ifaces=%v", got, want)
	}
}

func TestScanSysNet_None(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "eth0"), 0o755); err != nil {
		t.Fatal(err)
	}
	got := scanSysNet(dir)
	if got.Detected {
		t.Fatalf("expected not detected: %+v", got)
	}
}
