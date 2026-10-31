// Command mcpbridge lets an ordinary MCP host use an Androvia relay over stdio, without being handed a token.
//
//	mcpbridge pair -relay https://relay.example.com -code <one-time code> [-label name] [-dir ~/.config/androvia]
//	mcpbridge run  -relay https://relay.example.com [-origin wss://relay.example.com] [-dir ...]
//
// `run` speaks MCP on stdin/stdout, so all diagnostics go to stderr.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/aman-dhakar-191/androvia/relay/internal/bridge"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const usage = `usage:
  mcpbridge pair -relay URL -code CODE [-label NAME] [-dir DIR]
  mcpbridge run  -relay URL [-origin ORIGIN] [-dir DIR] [-allow-insecure]

pair  redeems a one-time pairing code (issued by the relay's admin) and stores a new private key in DIR.
run   serves MCP on stdin/stdout for an MCP host; it logs in to the relay itself and keeps the token fresh.
`

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "mcpbridge:", err)
		os.Exit(1)
	}
}

func defaultDir() string {
	if d, err := os.UserConfigDir(); err == nil {
		return filepath.Join(d, "androvia")
	}
	return "androvia"
}

func run(args []string) error {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, usage)
		return fmt.Errorf("missing command")
	}
	fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
	relay := fs.String("relay", os.Getenv("ANDROVIA_RELAY_URL"), "relay base URL, e.g. https://relay.example.com")
	dir := fs.String("dir", defaultDir(), "directory holding the client key and ids")
	origin := fs.String("origin", "", "relay public origin to sign (default: derived from -relay; must equal RELAY_PUBLIC_ORIGIN)")
	insecure := fs.Bool("allow-insecure", false, "allow http:// to a loopback address (development only)")
	code := fs.String("code", "", "pairing code (pair only)")
	label := fs.String("label", "mcpbridge", "label for this client (pair only)")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	cfg := bridge.Config{
		RelayURL: *relay, Origin: *origin, Dir: *dir, AllowInsecure: *insecure,
		Logf: func(f string, a ...any) { fmt.Fprintf(os.Stderr, "mcpbridge: "+f+"\n", a...) },
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	switch args[0] {
	case "pair":
		// A code on the command line is visible to other local users in the process list; prefer the environment.
		c := *code
		if c == "" {
			c = os.Getenv("ANDROVIA_PAIRING_CODE")
		}
		return bridge.Pair(ctx, cfg, c, *label)
	case "run":
		return bridge.Run(ctx, cfg, &mcp.StdioTransport{})
	default:
		fmt.Fprint(os.Stderr, usage)
		return fmt.Errorf("unknown command %q", args[0])
	}
}
