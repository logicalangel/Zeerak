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
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
)

// Version is set at build time via -ldflags "-X main.Version=...".
var Version = "0.0.0-dev"

func main() {
	var (
		agentMode  = flag.Bool("agent", false, "run in headless agent mode (cluster slave)")
		configPath = flag.String("config", "/etc/zeerak/zeerak.yaml", "path to zeerak.yaml")
		listen     = flag.String("listen", "127.0.0.1:7878", "HTTP listen address (loopback by default)")
		socketPath = flag.String("socket", "/run/zeerak/zeerak.sock", "unix socket path for CLI/admin access")
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

	if *agentMode {
		logger.Info("zeerak-server starting", "mode", "agent", "version", Version)
		// TODO(v0.3): cluster agent loop.
		<-ctx.Done()
		return
	}

	logger.Info("zeerak-server starting",
		"mode", "master",
		"version", Version,
		"config", *configPath,
		"listen", *listen,
		"socket", *socketPath,
	)

	// TODO(v0.1):
	//   1. Load config from *configPath (internal/config).
	//   2. Read current nftables ruleset (internal/nft).
	//   3. Start HTTP API on *listen + unix socket on *socketPath (internal/api).
	//   4. Start config watcher for SIGHUP / reload.

	<-ctx.Done()
	logger.Info("zeerak-server shutting down")
}
