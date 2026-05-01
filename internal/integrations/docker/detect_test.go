package docker

import (
	"context"
	"reflect"
	"sort"
	"testing"

	"github.com/zeerak/zeerak/internal/model"
)

type fakeReader struct{ text string }

func (f fakeReader) LiveText(_ context.Context) (string, error) { return f.text, nil }
func (f fakeReader) LiveTable(_ context.Context, _ model.Family, _ string) (string, error) {
	return "", nil
}

const dockerSample = `table ip filter {
	chain INPUT {
	}
	chain DOCKER-USER {
	}
	chain DOCKER-ISOLATION-STAGE-1 {
	}
}
table ip nat {
	chain DOCKER {
	}
}
`

const noDockerSample = `table inet zeerak-presets {
	chain input {
		type filter hook input priority 0; policy drop;
	}
}
`

func TestDetect_Docker(t *testing.T) {
	got := Detect(context.Background(), fakeReader{text: dockerSample})
	if !got.Detected || !got.HasDockerUser {
		t.Fatalf("expected detected + DOCKER-USER, got %+v", got)
	}
	sort.Strings(got.Tables)
	want := []string{"ip filter", "ip nat"}
	if !reflect.DeepEqual(got.Tables, want) {
		t.Fatalf("tables: %v, want %v", got.Tables, want)
	}
}

func TestDetect_NoDocker(t *testing.T) {
	got := Detect(context.Background(), fakeReader{text: noDockerSample})
	if got.Detected || got.HasDockerUser {
		t.Fatalf("expected not detected: %+v", got)
	}
}

func TestDetect_NilReader(t *testing.T) {
	got := Detect(context.Background(), nil)
	if got.Detected {
		t.Fatalf("nil reader: %+v", got)
	}
}
