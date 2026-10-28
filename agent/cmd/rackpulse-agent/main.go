package main

import (
	"fmt"
	"os"

	"github.com/en3sis/rackpulse/agent/internal/install"
	"github.com/en3sis/rackpulse/agent/internal/server"
)

var version = "dev"

const usage = `Usage: rackpulse-agent <command>

Commands:
  run          Run the agent (used by systemd)
  install      Install or update the agent and its service
               --pair <key>   Pairing key from Rackpulse
               --port <port>  TCP port (default 7311)
               --listen <ip>  Listen only on this address, or tailscale
                              for this server's Tailscale address
  set-key      Replace the pairing key, from an argument or stdin
  uninstall    Stop the service and remove the agent
  status       Show the service state
  version      Print the version
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "run":
		err = server.Run(version)
	case "install":
		err = install.Run(os.Args[2:], version)
	case "set-key":
		err = install.SetKey(os.Args[2:])
	case "uninstall":
		err = install.Uninstall()
	case "status":
		err = install.Status(version)
	case "version", "--version", "-v":
		fmt.Println("rackpulse-agent " + version)
	case "help", "--help", "-h":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "Unknown command %q\n\n%s", os.Args[1], usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
