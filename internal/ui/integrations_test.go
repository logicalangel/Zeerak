package ui

import (
	"reflect"
	"testing"

	caddyint "github.com/zeerak/zeerak/internal/integrations/caddy"
	"github.com/zeerak/zeerak/internal/policy"
)

func TestAllowedInboundPorts(t *testing.T) {
	p := policy.Presets{
		SSH:      &policy.SSHPreset{Port: 2222},
		CaddyBox: true,
		Database: &policy.DatabasePreset{},
		Mail:     &policy.MailPreset{SMTP: true, Submission: true},
	}
	got := allowedInboundPorts(p)
	for _, port := range []int{2222, 80, 443, 5432, 25, 587} {
		if !got[port] {
			t.Errorf("expected port %d in allowed set, got %v", port, got)
		}
	}
	if got[22] {
		t.Errorf("port 22 should not be allowed when SSH custom port is 2222")
	}
}

func TestWithCaddyGaps(t *testing.T) {
	vm := IntegrationsVM{
		Caddy: caddyint.Result{
			Detected: true,
			Sites: []caddyint.Site{
				{Port: 80, Listen: ":80"},
				{Port: 443, Listen: ":443"},
				{Port: 8443, Listen: ":8443"},
			},
		},
	}
	annotated := vm.withCaddyGaps(map[int]bool{80: true, 443: true})
	if !reflect.DeepEqual(annotated.CaddyPortGaps, []int{8443}) {
		t.Fatalf("want gap [8443], got %v", annotated.CaddyPortGaps)
	}

	// No detection ⇒ no gaps recorded.
	empty := IntegrationsVM{}.withCaddyGaps(map[int]bool{})
	if empty.CaddyPortGaps != nil {
		t.Fatalf("expected nil gaps when not detected, got %v", empty.CaddyPortGaps)
	}
}
