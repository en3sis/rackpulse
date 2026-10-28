package install

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/en3sis/rackpulse/agent/internal/atomicfile"
	"github.com/en3sis/rackpulse/agent/internal/boots"
	"github.com/en3sis/rackpulse/agent/internal/config"
	"github.com/en3sis/rackpulse/agent/internal/history"
	"github.com/en3sis/rackpulse/agent/internal/pairing"
)

func Run(args []string, version string) error {
	flags := flag.NewFlagSet("install", flag.ContinueOnError)
	pair := flags.String("pair", "", "pairing key from Rackpulse")
	port := flags.Int("port", config.DefaultPort, "TCP port")
	listen := flags.String("listen", "", "listen only on this address, or tailscale")
	flags.SetOutput(io.Discard)
	if err := flags.Parse(args); err != nil {
		return fmt.Errorf("%v. Options: --pair <key>, --port <port>, --listen <ip|tailscale>", err)
	}
	if flags.NArg() > 0 {
		return fmt.Errorf("Unexpected argument %q", flags.Arg(0))
	}
	set := map[string]bool{}
	flags.Visit(func(f *flag.Flag) { set[f.Name] = true })

	if err := requireRoot(); err != nil {
		return err
	}
	if err := requireSystemd(); err != nil {
		return err
	}

	cfg := config.Config{Port: config.DefaultPort}
	existing, err := config.Load(config.Path)
	hadConfig := err == nil
	migrating := legacyInstallFound()
	if hadConfig {
		cfg = existing
	} else if migrating {
		if legacy, err := config.Load(legacyConfigPath); err == nil {
			cfg = legacy
			existing = legacy
		}
	}
	replacedKey := false
	if set["pair"] {
		if err := config.ValidateToken(*pair); err != nil {
			return err
		}
		replacedKey = (hadConfig || migrating) && existing.Token != "" && existing.Token != *pair
		cfg.Token = *pair
	}
	if set["port"] {
		cfg.Port = *port
	}
	if set["listen"] {
		cfg.Listen = *listen
		if *listen == tailscaleListen {
			address, err := tailscaleAddress()
			if err != nil {
				return err
			}
			cfg.Listen = address
		}
	}
	if cfg.Token == "" {
		return errors.New("No pairing key. Run the command from Rackpulse, which includes --pair rb1_...")
	}
	if err := cfg.Validate(); err != nil {
		return err
	}

	if err := installBinary(); err != nil {
		return fmt.Errorf("copy the binary: %w", err)
	}
	account, err := ensureUser()
	if err != nil {
		return err
	}
	if err := writeConfig(cfg, account); err != nil {
		return fmt.Errorf("write %s: %w", config.Path, err)
	}

	wasActive := serviceActive()
	if wasActive {
		if err := command("systemctl", "stop", serviceName); err != nil {
			return err
		}
	}

	certKept := false
	if migrating {
		stopLegacyService()
		if certKept, err = copyLegacyState(); err != nil {
			return fmt.Errorf("copy the state of %s: %w", legacyName, err)
		}
	}
	if err := os.MkdirAll(config.StateDir, 0o700); err != nil {
		return err
	}
	if _, err := pairing.EnsureCertificate(config.CertPath, config.KeyPath); err != nil {
		return fmt.Errorf("create TLS certificate: %w", err)
	}
	backfilled := backfillHistory()
	if err := chownTree(config.StateDir, account); err != nil {
		return err
	}

	if err := atomicfile.Write(unitPath, []byte(unitFile), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", unitPath, err)
	}
	if err := command("systemctl", "daemon-reload"); err != nil {
		return err
	}
	if err := command("systemctl", "enable", serviceName); err != nil {
		return err
	}
	if err := command("systemctl", "start", serviceName); err != nil {
		return err
	}
	if !waitForListening(cfg, 5*time.Second) {
		return fmt.Errorf("The service did not start listening on %s. See: journalctl -u rackpulse-agent -n 20", cfg.Address())
	}
	summary := installSummary{updated: wasActive || hadConfig, replacedKey: replacedKey, backfilled: backfilled}
	if ufwActive() {
		var previous *config.Config
		if hadConfig {
			previous = &existing
		}
		if err := allowInUFW(cfg, previous); err != nil {
			fmt.Fprintf(os.Stderr, "Could not add the ufw rule: %v\n", err)
			summary.ufw = ufwManual
		} else {
			summary.ufw = ufwAllowed
		}
	}
	if migrating {
		summary.migrated = true
		summary.certKept = certKept
		summary.newKey = set["pair"]
		if err := removeLegacy(); err != nil {
			fmt.Fprintf(os.Stderr, "Could not remove all of %s: %v\n", legacyName, err)
		}
	}
	printSummary(cfg, summary, version)
	return nil
}

type installSummary struct {
	updated     bool
	replacedKey bool
	backfilled  bool
	migrated    bool
	certKept    bool
	newKey      bool
	ufw         ufwState
}

type ufwState int

const (
	ufwOff ufwState = iota
	ufwAllowed
	ufwManual
)

func installBinary() error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	self, err = filepath.EvalSymlinks(self)
	if err != nil {
		return err
	}
	if target, err := filepath.EvalSymlinks(binPath); err == nil && target == self {
		return nil
	}
	data, err := os.ReadFile(self)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(binPath), 0o755); err != nil {
		return err
	}
	return atomicfile.Write(binPath, data, 0o755)
}

func backfillHistory() bool {
	now := time.Now().Unix()
	host, err := history.LoadHost(config.HistoryPath)
	if err != nil {
		host = history.NewHost(now)
	}
	backfilled := boots.Apply(host, boots.FromJournal(), now)
	host.Prune(now)
	if err := host.Save(config.HistoryPath); err != nil {
		fmt.Fprintf(os.Stderr, "Could not write %s: %v\n", config.HistoryPath, err)
	}
	return backfilled
}
