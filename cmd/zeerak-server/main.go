// Package main is the entry point for zeerak-server, the Zeerak daemon.
//
// zeerak-server runs in two modes:
//
//   - "master" (default) — serves the HTTP API + UI, owns the running config,
//     optionally distributes config to agents over SSH (cluster mode).
//   - "agent" (--agent) — headless, applies pushed config to the local
//     nftables, reports back. No UI.
//
// See VISION.md §3 (Architecture) and §6 (Cluster mode).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/zeerak/zeerak/internal/activity"
	"github.com/zeerak/zeerak/internal/api"
	"github.com/zeerak/zeerak/internal/config"
	"github.com/zeerak/zeerak/internal/nft"
	"github.com/zeerak/zeerak/internal/stager"
	"github.com/zeerak/zeerak/internal/ui"
)

// Version is set at build time via -ldflags "-X main.Version=...".
var Version = "0.0.0-dev"

func main() {
	var (
		agentMode  = flag.Bool("agent", false, "run in headless agent mode (cluster slave)")
		configPath = flag.String("config", config.DefaultPath, "path to zeerak.yaml")
		listen     = flag.String("listen", "127.0.0.1:17878", "HTTP listen address (loopback by default)")
		socketPath = flag.String("socket", "/run/zeerak/zeerak.sock", "unix socket path for CLI/admin access")
		activityLog = flag.String("activity-log", "/var/lib/zeerak/activity.jsonl", "path to the activity log (JSONL); empty disables it")
		showVer    = flag.Bool("version", false, "print version and exit")
	)
	flag.Parse()

	if *showVer {
		fmt.Println("zeerak-server", Version)
		return
	}

	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{}))
	slog.SetDefault(logger)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, logger, *agentMode, *configPath, *listen, *socketPath, *activityLog); err != nil {
		logger.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, logger *slog.Logger, agentMode bool, configPath, listen, socketPath, activityLogPath string) error {
	if agentMode {
		logger.Info("zeerak-server starting", "mode", "agent", "version", Version)
		// TODO(v0.3): cluster agent loop.
		<-ctx.Done()
		return nil
	}

	logger.Info("zeerak-server starting",
		"mode", "master",
		"version", Version,
		"config", configPath,
		"listen", listen,
		"socket", socketPath,
	)

	cfg, err := config.Load(configPath)
	if err != nil {
		// Missing file is recoverable in v0.1: start empty, let the operator
		// commit a config via the API. Anything else is fatal.
		if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("load config: %w", err)
		}
		logger.Warn("config file not found; starting with empty ruleset", "path", configPath)
		cfg = &config.Config{Version: 1}
	}

	adapter := nft.New()

	var actLog *activity.Logger
	if activityLogPath != "" {
		al, err := activity.New(activityLogPath)
		if err != nil {
			logger.Warn("activity log unavailable", "path", activityLogPath, "err", err)
		} else {
			actLog = al
			_ = actLog.Append(activity.Event{
				Kind:    activity.KindBoot,
				Message: "Zeerak started.",
				Detail:  fmt.Sprintf("v%s", Version),
			})
		}
	}

	stg := stager.New(adapter, stager.WithOnAutoRevert(func() {
		if actLog != nil {
			_ = actLog.Append(activity.Event{
				Kind:    activity.KindAutoRevert,
				Message: "System auto-reverted a change.",
				Detail:  "No confirmation arrived in time.",
			})
		}
	}))

	// Boot apply: the on-disk config is authoritative at startup. We commit
	// it directly (no rollback window) because there's nobody to confirm —
	// the operator already approved it by writing the file.
	if err := adapter.Apply(ctx, cfg.ToRuleset()); err != nil {
		return fmt.Errorf("boot apply: %w", err)
	}
	logger.Info("boot apply ok", "tables", len(cfg.Tables))

	uiHandler, err := ui.New(stg, adapter, logger, Version)
	if err != nil {
		return fmt.Errorf("init ui: %w", err)
	}
	uiHandler.SetCurrent(cfg.Presets)
	uiHandler.SetActivityLog(actLog)
	apiSrv := api.New(stg, adapter, logger, Version, api.WithExtraRoutes(uiHandler.Register))
	if err := apiSrv.Serve(ctx, listen, socketPath); err != nil {
		return fmt.Errorf("api: %w", err)
	}

	logger.Info("zeerak-server shutting down")
	return nil
}
