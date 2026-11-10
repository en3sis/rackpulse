package install

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/en3sis/rackpulse/agent/internal/collect"
	"github.com/en3sis/rackpulse/agent/internal/config"
	"github.com/en3sis/rackpulse/agent/internal/pairing"
)

func Status(version string) error {
	state := commandOutput("systemctl", "is-active", serviceName)
	if state == "" {
		state = "unknown"
	}
	fmt.Printf("Service: %s\n", state)
	fmt.Printf("Version: %s\n", version)
	cfg, err := config.Load(config.Path)
	if err != nil {
		fmt.Println(dockerAccessLine(currentDockerAccess(), false))
		if errors.Is(err, os.ErrPermission) {
			return errors.New("Run this command as root to see the port and the agent state")
		}
		return fmt.Errorf("read config: %w", err)
	}
	fmt.Println(dockerAccessLine(currentDockerAccess(), cfg.NoDocker))
	if cfg.Listen == "" {
		fmt.Printf("Port: %d on all addresses\n", cfg.Port)
	} else {
		fmt.Printf("Port: %d on %s\n", cfg.Port, cfg.Listen)
	}
	snapshot, err := localSnapshot(cfg)
	if err != nil {
		fmt.Printf("Agent: not reachable (%v)\n", err)
		return nil
	}
	fmt.Printf("Running version: %s\n", snapshot.Version)
	fmt.Printf("Last sample: %s\n", time.Unix(snapshot.Time, 0).Format("2006-01-02 15:04:05 MST"))
	switch {
	case snapshot.Docker == nil:
		fmt.Println("Docker: not installed")
	case snapshot.Docker.Error != nil:
		fmt.Printf("Docker: %s\n", *snapshot.Docker.Error)
	default:
		fmt.Printf("Docker: OK, %d containers\n", len(snapshot.Docker.Containers))
	}
	return nil
}

func localSnapshot(cfg config.Config) (collect.Snapshot, error) {
	var snapshot collect.Snapshot
	_, expected, err := pairing.LoadCertificate(config.CertPath, config.KeyPath)
	if err != nil {
		return snapshot, err
	}
	host := cfg.Listen
	if host == "" || net.ParseIP(host).IsUnspecified() {
		host = "127.0.0.1"
	}
	transport := &http.Transport{
		Proxy: nil,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS13,
			VerifyConnection: func(state tls.ConnectionState) error {
				if len(state.PeerCertificates) == 0 || pairing.Fingerprint(state.PeerCertificates[0].Raw) != expected {
					return errors.New("the agent presents a different certificate")
				}
				return nil
			},
		},
	}
	client := &http.Client{Transport: transport, Timeout: 25 * time.Second}
	req, err := http.NewRequest(http.MethodGet, "https://"+net.JoinHostPort(host, strconv.Itoa(cfg.Port))+"/v1/snapshot", nil)
	if err != nil {
		return snapshot, err
	}
	req.Header.Set("Authorization", "Bearer "+cfg.Token)
	resp, err := client.Do(req)
	if err != nil {
		return snapshot, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, resp.Body)
		return snapshot, fmt.Errorf("HTTP %s", resp.Status)
	}
	err = json.NewDecoder(resp.Body).Decode(&snapshot)
	return snapshot, err
}
