//go:build !linux

package nft

import (
	"context"
	"errors"
	"runtime"

	"github.com/zeerak/zeerak/internal/model"
)

// stubAdapter exists so `go build ./...` works on macOS/Windows dev hosts.
// Any actual call returns ErrUnsupported; production runs on Linux only.
type stubAdapter struct{}

// ErrUnsupported is returned by every Adapter call on non-Linux platforms.
var ErrUnsupported = errors.New("nft: nftables is Linux-only; build on Linux to apply rules")

func newPlatform() Adapter { return stubAdapter{} }

func (stubAdapter) Snapshot(ctx context.Context) (*model.Ruleset, error) {
	return nil, wrap()
}

func (stubAdapter) Apply(ctx context.Context, rs *model.Ruleset) error {
	return wrap()
}

func wrap() error { return errors.New("nft: " + runtime.GOOS + " unsupported: " + ErrUnsupported.Error()) }
