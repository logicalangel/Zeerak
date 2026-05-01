package tailscale

import (
	"os"
	"path/filepath"
	"testing"
)

func TestScanSysNet_NoTailscale(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"lo", "eth0", "wg0"} {
		if err := os.Mkdir(filepath.Join(dir, name), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	got := scanSysNet(dir)
	if got.Detected {
		t.Fatalf("expected not detected, got %+v", got)
	}
}

func TestScanSysNet_HasTailscale0(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"lo", "eth0", "tailscale0"} {
		if err := os.Mkdir(filepath.Join(dir, name), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	got := scanSysNet(dir)
	if !got.Detected || len(got.Interfaces) != 1 || got.Interfaces[0] != "tailscale0" {
		t.Fatalf("unexpected: %+v", got)
	}
}

func TestScanSysNet_MissingDir(t *testing.T) {
	got := scanSysNet("/definitely/not/a/path/xyz123")
	if got.Detected {
		t.Fatalf("expected detected=false on missing dir, got %+v", got)
	}
}
