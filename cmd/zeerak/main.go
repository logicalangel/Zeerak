// Package main is the entry point for the zeerak CLI.
//
// The CLI speaks to a running zeerak-server over its unix socket and mirrors
// the HTTP API. Useful for scripts and GitOps:
//
//	zeerak status
//	zeerak config show
//	zeerak config export > zeerak.yaml      # for git
//	zeerak reload                            # SIGHUP-equivalent
//	zeerak apply -f new.yaml                 # stage + commit with rollback
//	zeerak rollback                          # discard staged change
//	zeerak mcp serve --stdio                 # launch MCP server (v0.2)
//
// See VISION.md §3 (CLI) and §9 (MCP).
package main

import (
	"flag"
	"fmt"
	"os"
)

var Version = "0.0.0-dev"

func main() {
	flag.Usage = usage
	flag.Parse()

	args := flag.Args()
	if len(args) == 0 {
		usage()
		os.Exit(2)
	}

	switch args[0] {
	case "version", "--version", "-v":
		fmt.Println("zeerak", Version)
	default:
		// TODO(v0.1): wire subcommands to the unix-socket client.
		fmt.Fprintf(os.Stderr, "zeerak: unknown subcommand %q\n", args[0])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `zeerak — CLI for the Zeerak firewall daemon

Usage:
  zeerak <command> [flags]

Commands (planned, v0.1):
  status              show running ruleset summary + drift
  config show         print the running config (YAML)
  config export       dump clean YAML for git (no autosave)
  reload              tell zeerak-server to reload zeerak.yaml
  apply -f FILE       stage + commit with auto-rollback
  rollback            discard the current staged change
  testkit run NAME    run a testkit scenario (zeerak-testkit)
  mcp serve           run the MCP server (v0.2; see zeerak-mcp)

Use "zeerak --version" to print the version.`)
}
