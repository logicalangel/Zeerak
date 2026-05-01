// Package main is the zeerak CLI — a thin client over zeerak-server's
// HTTP API. It mirrors what the UI calls: status, apply, rollback,
// confirm, preview, ruleset.
//
// By default it talks to the unix socket at /run/zeerak/zeerak.sock.
// Override with --addr or ZEERAK_ADDR (e.g. http://127.0.0.1:17878).
//
// See VISION.md §3 (CLI).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/zeerak/zeerak/internal/cliclient"
)

// Version is set at build time via -ldflags "-X main.Version=...".
var Version = "0.0.0-dev"

func main() {
	if len(os.Args) < 2 {
		usage(os.Stderr)
		os.Exit(2)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	cmd := os.Args[1]
	args := os.Args[2:]

	switch cmd {
	case "version", "--version", "-v":
		fmt.Println("zeerak", Version)
	case "help", "-h", "--help":
		usage(os.Stdout)
	case "status":
		exit(cmdStatus(ctx, args))
	case "apply":
		exit(cmdApply(ctx, args))
	case "preview":
		exit(cmdPreview(ctx, args))
	case "confirm":
		exit(cmdConfirm(ctx, args))
	case "rollback":
		exit(cmdRollback(ctx, args))
	case "ruleset":
		exit(cmdRuleset(ctx, args))
	default:
		fmt.Fprintf(os.Stderr, "zeerak: unknown command %q\n\n", cmd)
		usage(os.Stderr)
		os.Exit(2)
	}
}

func exit(err error) {
	if err == nil {
		return
	}
	fmt.Fprintln(os.Stderr, "zeerak:", err)
	os.Exit(1)
}

// flagset returns a FlagSet with the shared --addr flag.
func flagset(name string) (*flag.FlagSet, *string) {
	fs := flag.NewFlagSet(name, flag.ExitOnError)
	addr := fs.String("addr", os.Getenv("ZEERAK_ADDR"), "daemon address (unix path or http URL); env: ZEERAK_ADDR")
	return fs, addr
}

func cmdStatus(ctx context.Context, args []string) error {
	fs, addr := flagset("status")
	_ = fs.Parse(args)
	c := cliclient.New(*addr)
	st, err := c.Status(ctx)
	if err != nil {
		return err
	}
	fmt.Printf("state:    %v\n", st["state"])
	if dl, ok := st["deadline"]; ok && dl != nil {
		fmt.Printf("deadline: %v\n", dl)
	}
	return nil
}

func cmdApply(ctx context.Context, args []string) error {
	fs, addr := flagset("apply")
	file := fs.String("f", "", "path to zeerak.yaml (or - for stdin)")
	autoConfirm := fs.Bool("yes", false, "auto-confirm after stage (skip rollback window)")
	_ = fs.Parse(args)
	if *file == "" {
		return errors.New("apply: -f FILE is required")
	}
	body, err := readFile(*file)
	if err != nil {
		return err
	}
	c := cliclient.New(*addr)
	st, err := c.Stage(ctx, body)
	if err != nil {
		return fmt.Errorf("stage: %w", err)
	}
	fmt.Printf("staged: state=%v deadline=%v\n", st["state"], st["deadline"])
	if *autoConfirm {
		if err := c.Confirm(ctx); err != nil {
			return fmt.Errorf("confirm: %w", err)
		}
		fmt.Println("confirmed")
	}
	return nil
}

func cmdPreview(ctx context.Context, args []string) error {
	fs, addr := flagset("preview")
	file := fs.String("f", "", "path to zeerak.yaml (or - for stdin)")
	_ = fs.Parse(args)
	if *file == "" {
		return errors.New("preview: -f FILE is required")
	}
	body, err := readFile(*file)
	if err != nil {
		return err
	}
	c := cliclient.New(*addr)
	_, _, diff, err := c.Preview(ctx, body)
	if err != nil {
		return err
	}
	if diff == "" {
		fmt.Println("(no changes — candidate matches live ruleset)")
		return nil
	}
	fmt.Print(diff)
	return nil
}

func cmdConfirm(ctx context.Context, args []string) error {
	fs, addr := flagset("confirm")
	_ = fs.Parse(args)
	c := cliclient.New(*addr)
	if err := c.Confirm(ctx); err != nil {
		return err
	}
	fmt.Println("confirmed")
	return nil
}

func cmdRollback(ctx context.Context, args []string) error {
	fs, addr := flagset("rollback")
	_ = fs.Parse(args)
	c := cliclient.New(*addr)
	if err := c.Rollback(ctx); err != nil {
		return err
	}
	fmt.Println("rolled back")
	return nil
}

func cmdRuleset(ctx context.Context, args []string) error {
	fs, addr := flagset("ruleset")
	_ = fs.Parse(args)
	c := cliclient.New(*addr)
	text, err := c.LiveRuleset(ctx)
	if err != nil {
		return err
	}
	fmt.Print(text)
	return nil
}

func readFile(path string) ([]byte, error) {
	if path == "-" {
		return io.ReadAll(os.Stdin)
	}
	return os.ReadFile(path)
}

func usage(w io.Writer) {
	fmt.Fprintln(w, `zeerak — CLI for the Zeerak firewall daemon

Usage:
  zeerak <command> [flags]

Commands:
  status              show stager state + rollback deadline
  apply -f FILE       stage a config (use --yes to auto-confirm)
  preview -f FILE     show unified diff vs the live ruleset
  confirm             confirm the pending change
  rollback            roll the pending change back
  ruleset             print the live nftables ruleset
  version             print version

Global flags:
  --addr ADDR         daemon address (unix path or http URL)
                      env: ZEERAK_ADDR  (default: /run/zeerak/zeerak.sock)`)
}
