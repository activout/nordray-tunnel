// Command nordray-tunnel provisions a self-hosted frp relay in the operator's
// own Bunny account and runs unmodified upstream frpc against it.
package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
)

// Pinned upstream versions. The relay image is supplied with --image until an
// official image is published.
const (
	frpVersion = "0.71.1"
	userAgent  = "nordray-tunnel"
)

const usage = `nordray-tunnel: self-hosted HTTP tunnels in your own Bunny account.

Operator commands (need the Bunny API key):
  setup         Create or reconcile the relay (Magic Containers, CDN, Shield)
  add           Publish a local HTTP service on a public hostname
  remove        Unpublish a service
  status        Show local status; --remote also queries Bunny
  update        Deploy a new pinned relay image
  destroy       Delete every resource this installation created

Agent commands (no Bunny API key):
  run           Run frpc with the generated configuration
  agent-config  Export an frpc configuration for another machine
  install-frpc  Download and verify frpc from the frp GitHub releases

Run "nordray-tunnel <command> -h" for the options of a command.
`

type command struct {
	run func(args []string) error
}

var commands = map[string]command{
	"setup":        {cmdSetup},
	"add":          {cmdAdd},
	"remove":       {cmdRemove},
	"status":       {cmdStatus},
	"update":       {cmdUpdate},
	"destroy":      {cmdDestroy},
	"run":          {cmdRun},
	"agent-config": {cmdAgentConfig},
	"install-frpc": {cmdInstallFrpc},
}

// exitError carries a child process exit status out of run.
type exitError struct{ code int }

func (e exitError) Error() string { return fmt.Sprintf("exit status %d", e.code) }

func main() {
	if len(os.Args) < 2 || os.Args[1] == "-h" || os.Args[1] == "--help" || os.Args[1] == "help" {
		fmt.Print(usage)
		return
	}
	cmd, ok := commands[os.Args[1]]
	if !ok {
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", os.Args[1], usage)
		os.Exit(2)
	}
	err := cmd.run(os.Args[2:])
	var exit exitError
	switch {
	case err == nil:
	case errors.As(err, &exit):
		os.Exit(exit.code)
	case errors.Is(err, flag.ErrHelp):
		os.Exit(2)
	default:
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

// newFlags returns a flag set with the --name option every command shares.
func newFlags(name, synopsis string) (*flag.FlagSet, *string) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: nordray-tunnel %s %s\n\nOptions:\n", name, synopsis)
		fs.PrintDefaults()
	}
	installation := fs.String("name", "default", "installation `name`")
	return fs, installation
}

// confirm asks a yes/no question on the terminal; anything but y/yes is no.
var confirm = func(in io.Reader, question string) bool {
	fmt.Printf("%s [y/N] ", question)
	line, _ := bufio.NewReader(in).ReadString('\n')
	answer := strings.ToLower(strings.TrimSpace(line))
	return answer == "y" || answer == "yes"
}
