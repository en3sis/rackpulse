package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
)

const (
	Dir            = "/etc/rackpulse-agent"
	Path           = Dir + "/config.json"
	StateDir       = "/var/lib/rackpulse-agent"
	CertPath       = StateDir + "/cert.pem"
	KeyPath        = StateDir + "/key.pem"
	HistoryPath    = StateDir + "/history.json"
	ContainersPath = StateDir + "/containers.json"
	DefaultPort    = 7311
	tokenPrefix    = "rb1_"
)

type Config struct {
	Token         string `json:"token"`
	Port          int    `json:"port"`
	Listen        string `json:"listen"`
	TailscaleName string `json:"tailscaleName,omitempty"`
}

func Load(path string) (Config, error) {
	var cfg Config
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return cfg, fmt.Errorf("read %s: %w", path, err)
	}
	if cfg.Port == 0 {
		cfg.Port = DefaultPort
	}
	return cfg, nil
}

func (c Config) Validate() error {
	if err := ValidateToken(c.Token); err != nil {
		return err
	}
	if c.Port < 1 || c.Port > 65535 {
		return fmt.Errorf("port %d is out of range", c.Port)
	}
	if c.Listen != "" && net.ParseIP(c.Listen) == nil {
		return fmt.Errorf("--listen must be an IP address, not %q", c.Listen)
	}
	return nil
}

func (c Config) Address() string {
	return net.JoinHostPort(c.Listen, strconv.Itoa(c.Port))
}

func ValidateToken(token string) error {
	rest, ok := strings.CutPrefix(token, tokenPrefix)
	if !ok {
		return errors.New("The pairing key must start with rb1_. Copy the command again from Rackpulse")
	}
	if len(rest) < 16 {
		return errors.New("The pairing key is too short. Copy the command again from Rackpulse")
	}
	for _, r := range rest {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			return errors.New("The pairing key contains invalid characters. Copy the command again from Rackpulse")
		}
	}
	return nil
}
