package install

import (
	"errors"
	"net"
	"os/exec"
	"strconv"
	"strings"

	"github.com/en3sis/rackpulse/agent/internal/config"
)

const tailscaleListen = "tailscale"

func isTailscaleAddress(ip net.IP) bool {
	_, v4, _ := net.ParseCIDR("100.64.0.0/10")
	_, v6, _ := net.ParseCIDR("fd7a:115c:a1e0::/48")
	return v4.Contains(ip) || v6.Contains(ip)
}

func tailscaleAddress() (string, error) {
	if iface, err := net.InterfaceByName("tailscale0"); err == nil {
		if addrs, err := iface.Addrs(); err == nil {
			for _, addr := range addrs {
				if network, ok := addr.(*net.IPNet); ok && network.IP.To4() != nil && isTailscaleAddress(network.IP) {
					return network.IP.String(), nil
				}
			}
		}
	}
	if ip := net.ParseIP(commandOutput("tailscale", "ip", "-4")); ip != nil && isTailscaleAddress(ip) {
		return ip.String(), nil
	}
	return "", errors.New("Tailscale is not running on this server. Install it, run tailscale up, then run the command again")
}

func ufwActive() bool {
	return strings.Contains(commandOutput("ufw", "status"), "Status: active")
}

func ufwRule(cfg config.Config) []string {
	port := strconv.Itoa(cfg.Port)
	ip := net.ParseIP(cfg.Listen)
	switch {
	case ip != nil && isTailscaleAddress(ip):
		return []string{"allow", "in", "on", "tailscale0", "to", "any", "port", port, "proto", "tcp"}
	case ip != nil:
		return []string{"allow", "in", "to", cfg.Listen, "port", port, "proto", "tcp"}
	default:
		return []string{"allow", port + "/tcp"}
	}
}

func ufwScope(cfg config.Config) string {
	ip := net.ParseIP(cfg.Listen)
	switch {
	case ip != nil && isTailscaleAddress(ip):
		return "on tailscale0"
	case ip != nil:
		return "to " + cfg.Listen
	default:
		return "on all addresses"
	}
}

func allowInUFW(cfg config.Config, previous *config.Config) error {
	if previous != nil && strings.Join(ufwRule(*previous), " ") != strings.Join(ufwRule(cfg), " ") {
		removeFromUFW(*previous)
	}
	return command("ufw", append(ufwRule(cfg), "comment", serviceName)...)
}

func removeFromUFW(cfg config.Config) bool {
	return exec.Command("ufw", append([]string{"delete"}, ufwRule(cfg)...)...).Run() == nil
}
