package install

import (
	"context"
	"fmt"
	"net"

	"github.com/en3sis/rackpulse/agent/internal/collect"
	"github.com/en3sis/rackpulse/agent/internal/config"
)

func printSummary(cfg config.Config, summary installSummary, version string) {
	if summary.updated {
		fmt.Printf("Rackpulse agent %s is updated and running.\n", version)
	} else {
		fmt.Printf("Rackpulse agent %s is installed and running.\n", version)
	}
	if cfg.Listen == "" {
		fmt.Printf("It listens on TCP port %d on all addresses.\n", cfg.Port)
	} else {
		fmt.Printf("It listens on TCP port %d on %s.\n", cfg.Port, cfg.Listen)
	}
	if cfg.TailscaleName != "" {
		fmt.Printf("Tailscale name: %s\n", cfg.TailscaleName)
	}
	switch {
	case summary.migrated:
		line := "Replaced " + legacyName + " with " + serviceName + "."
		if summary.certKept {
			line += " The certificate and history were kept."
		}
		if summary.newKey {
			line += " A new key is in use."
		} else {
			line += " The key was kept."
		}
		fmt.Println(line)
	case summary.replacedKey:
		fmt.Println("The new pairing key replaces the old one. The old key no longer works.")
	}
	if !summary.updated && !summary.migrated {
		if summary.backfilled {
			fmt.Println("Uptime history starts with the past boots in the system journal.")
		} else {
			fmt.Println("The system journal has no past boots, so uptime history starts now.")
		}
	}

	ip := net.ParseIP(cfg.Listen)
	tailscale := ip != nil && isTailscaleAddress(ip)
	private := ip != nil && !tailscale && (ip.IsPrivate() || ip.IsLoopback())
	ufwOn := summary.ufw != ufwOff
	firewalldRunning := commandOutput("firewall-cmd", "--state") == "running"
	_, metadataErr := collect.FetchServerID(context.Background())
	onHetzner := metadataErr == nil

	fmt.Println()
	fmt.Println("Firewall:")
	advice := 0
	if summary.ufw == ufwAllowed {
		fmt.Printf("  ufw is active. Allowed TCP port %d %s.\n", cfg.Port, ufwScope(cfg))
		advice++
	} else if ufwOn {
		if tailscale {
			fmt.Printf("  ufw is active. Allow the port on Tailscale: sudo ufw allow in on tailscale0 to any port %d proto tcp\n", cfg.Port)
		} else {
			fmt.Printf("  ufw is active. Allow the port: sudo ufw allow %d/tcp\n", cfg.Port)
		}
		advice++
	}
	if firewalldRunning {
		fmt.Printf("  firewalld is running. Allow the port: firewall-cmd --permanent --add-port=%d/tcp && firewall-cmd --reload\n", cfg.Port)
		advice++
	}
	if onHetzner && !tailscale && !private {
		fmt.Printf("  Hetzner Cloud Firewall: if one is attached to this server, add an inbound rule for TCP port %d. If you have a fixed IP, set it as the source.\n", cfg.Port)
		advice++
	}
	if tailscale || private {
		fmt.Println("  No public firewall rule is needed for this address.")
		advice++
	}
	if advice == 0 {
		fmt.Println("  No firewall found on this server. The port accepts connections on all addresses.")
	}
	fmt.Println()
	fmt.Println("Rackpulse connects within a few seconds.")
}
