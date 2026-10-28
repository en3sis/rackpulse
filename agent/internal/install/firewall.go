package install

import (
	"errors"
	"net"
	"os/exec"
	"strconv"
	"strings"

	"github.com/en3sis/rackpulse/agent/internal/collect"
	"github.com/en3sis/rackpulse/agent/internal/config"
)

const tailscaleListen = "tailscale"

func isTailscaleAddress(ip net.IP) bool {
	return collect.IsTailscaleAddress(ip)
}

func tailscaleName() string {
	return collect.TailscaleName([]byte(commandOutput("tailscale", "status", "--json")))
}

func tailscaleAddress() (string, error) {
	if ip := collect.TailscaleIPv4(); ip != "" {
		return ip, nil
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
