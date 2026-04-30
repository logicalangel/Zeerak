// Package main is the zeerak-mcp binary — the Model Context Protocol
// server that exposes Zeerak's read-only state to LLM agents.
//
// Transports:
//
//	zeerak-mcp                  # stdio (default), reads JSON-RPC from stdin
//	zeerak-mcp --http :7879     # HTTP, POST JSON-RPC to /mcp
//
// Daemon connection:
//
//	zeerak-mcp --addr unix:///run/zeerak/zeerak.sock   # default
//	zeerak-mcp --addr http://127.0.0.1:7878
//
// See VISION.md §9 (MCP).
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/zeerak/zeerak/internal/cliclient"
	"github.com/zeerak/zeerak/internal/mcp"
)

var Version = "0.0.0-dev"

func main() {
	var (
		addr     = flag.String("addr", os.Getenv("ZEERAK_ADDR"), "daemon address (unix path or http URL); env: ZEERAK_ADDR")
		httpAddr = flag.String("http", "", "if set, serve MCP over HTTP at this address (e.g. 127.0.0.1:7879)")
		showVer  = flag.Bool("version", false, "print version and exit")
	)
	flag.Parse()

	if *showVer {
		fmt.Println("zeerak-mcp", Version)
		return
	}

	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{}))
	slog.SetDefault(logger)

	// Strip a leading "unix://" if the user supplied it; cliclient takes
	// a bare path or http URL.
	if strings.HasPrefix(*addr, "unix://") {
		*addr = strings.TrimPrefix(*addr, "unix://")
	}
	client := cliclient.New(*addr)
	srv := mcp.New(client, Version)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if *httpAddr != "" {
		hs := &http.Server{
			Addr:              *httpAddr,
			Handler:           srv.HTTPHandler(),
			ReadHeaderTimeout: 5 * time.Second,
		}
		logger.Info("zeerak-mcp listening (http)", "addr", *httpAddr, "daemon", *addr)
		errCh := make(chan error, 1)
		go func() { errCh <- hs.ListenAndServe() }()
		select {
		case <-ctx.Done():
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = hs.Shutdown(shutdownCtx)
		case err := <-errCh:
			logger.Error("http server died", "err", err)
			os.Exit(1)
		}
		return
	}

	logger.Info("zeerak-mcp ready (stdio)", "daemon", *addr)
	if err := srv.ServeStdio(ctx, os.Stdin, os.Stdout); err != nil {
		// EOF on stdin is a clean exit; ctx cancel too.
		if ctx.Err() != nil {
			return
		}
		logger.Error("stdio loop error", "err", err)
		os.Exit(1)
	}
}
