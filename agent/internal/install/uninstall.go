package install

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"strings"

	"github.com/en3sis/rackpulse/agent/internal/config"
)

func Uninstall() error {
	if err := requireRoot(); err != nil {
		return err
	}
	cfg, cfgErr := config.Load(config.Path)
	port := config.DefaultPort
	if cfgErr == nil {
		port = cfg.Port
	}
	ufwRemoved := cfgErr == nil && ufwActive() && removeFromUFW(cfg)
	exec.Command("systemctl", "disable", "--now", serviceName).Run()
	removed := false
	if err := os.Remove(unitPath); err == nil {
		removed = true
	}
	if removed {
		exec.Command("systemctl", "daemon-reload").Run()
	}
	exec.Command("systemctl", "reset-failed", serviceName).Run()
	var problems []string
	for _, path := range []string{binPath, config.Dir, config.StateDir} {
		if err := os.RemoveAll(path); err != nil {
			problems = append(problems, err.Error())
		}
	}
	if _, err := user.Lookup(userName); err == nil {
		if err := command("userdel", userName); err != nil {
			problems = append(problems, err.Error())
		}
	}
	if _, err := user.LookupGroup(userName); err == nil {
		exec.Command("groupdel", userName).Run()
	}
	if legacyLeftoversFound() {
		if err := removeLegacy(); err != nil {
			problems = append(problems, err.Error())
		}
	}
	if len(problems) > 0 {
		return errors.New(strings.Join(problems, "\n"))
	}
	fmt.Println("Rackpulse agent is removed.")
	if ufwRemoved {
		fmt.Printf("Removed the ufw rule for TCP port %d.\n", port)
	}
	fmt.Printf("Remove the Hetzner Cloud Firewall rule for TCP port %d yourself if you added one.\n", port)
	return nil
}
