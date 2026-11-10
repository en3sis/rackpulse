package security

import (
	"errors"
	"io/fs"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/en3sis/rackpulse/agent/internal/collect"
)

const (
	ufwConfigPath = "/etc/ufw/ufw.conf"
	passwdPath    = "/etc/passwd"
	nameListLimit = 5
	oldImageAge   = 90 * 24 * time.Hour
)

type auditInput struct {
	root       string
	manager    string
	packages   []Package
	kernel     Kernel
	containers []collect.ContainerSettings
	docker     bool
	aptConfig  []byte
	now        time.Time
}

func runChecks(input auditInput) []Check {
	checks := []Check{}
	if config, ok := readSSHConfig(input.root); ok {
		checks = append(checks, sshChecks(config)...)
	}
	installed := map[string]bool{}
	for _, item := range input.packages {
		installed[item.Name] = true
	}
	if input.manager == "dpkg" {
		checks = append(checks, automaticUpdatesCheck(input.root, installed, input.aptConfig))
	}
	if check, ok := ufwCheck(input.root, input.manager, installed); ok {
		checks = append(checks, check)
	}
	if check, ok := extraRootCheck(input.root); ok {
		checks = append(checks, check)
	}
	if check, ok := kernelCheck(input.kernel, input.packages); ok {
		checks = append(checks, check)
	}
	if input.docker {
		checks = append(checks, dockerChecks(input.containers, input.now)...)
	}
	return checks
}

func ufwCheck(root, manager string, installed map[string]bool) (Check, bool) {
	if manager == "dpkg" && !installed["ufw"] {
		return Check{}, false
	}
	data, err := os.ReadFile(hostPath(root, ufwConfigPath))
	if errors.Is(err, fs.ErrNotExist) {
		return Check{}, false
	}
	if err != nil {
		return unreadableCheck("firewall.ufw", "ufw firewall could not be checked", ufwConfigPath), true
	}
	enabled := ""
	for _, line := range strings.Split(string(data), "\n") {
		if value, ok := strings.CutPrefix(strings.TrimSpace(line), "ENABLED="); ok {
			enabled = strings.ToLower(unquoteShell(value))
		}
	}
	check := Check{ID: "firewall.ufw", Source: stringPointer(ufwConfigPath), Detail: "ENABLED=" + enabled}
	switch enabled {
	case "yes":
		check.Status, check.Title = statusPass, "ufw firewall is on"
	case "no":
		check.Status, check.Title = statusFail, "ufw firewall is off"
	default:
		check.Status, check.Title = statusUnknown, "ufw firewall could not be checked"
		if enabled == "" {
			check.Detail = "ENABLED is not set"
		}
	}
	return check, true
}

func extraRootCheck(root string) (Check, bool) {
	data, err := os.ReadFile(hostPath(root, passwdPath))
	if errors.Is(err, fs.ErrNotExist) {
		return Check{}, false
	}
	if err != nil {
		return unreadableCheck("users.extraRoot", "Accounts with UID 0 could not be checked", passwdPath), true
	}
	names := extraRootAccounts(string(data))
	check := Check{ID: "users.extraRoot", Status: statusPass, Title: "Only root has UID 0", Detail: "No other account has UID 0", Source: stringPointer(passwdPath)}
	if len(names) > 0 {
		check.Status = statusFail
		check.Title = "Another account has UID 0"
		if len(names) > 1 {
			check.Title = "Other accounts have UID 0"
		}
		check.Detail = "UID 0: " + nameList(names)
	}
	return check, true
}

func extraRootAccounts(passwd string) []string {
	names := []string{}
	for _, line := range strings.Split(passwd, "\n") {
		fields := strings.Split(strings.TrimSpace(line), ":")
		if len(fields) < 3 || strings.HasPrefix(fields[0], "#") || fields[0] == "root" {
			continue
		}
		if uid, err := strconv.Atoi(fields[2]); err == nil && uid == 0 {
			names = append(names, fields[0])
		}
	}
	return names
}

func nameList(names []string) string {
	if len(names) <= nameListLimit {
		return strings.Join(names, ", ")
	}
	return strings.Join(names[:nameListLimit], ", ") + " and " + strconv.Itoa(len(names)-nameListLimit) + " more"
}

var socketSources = map[string]bool{"/var/run/docker.sock": true, "/run/docker.sock": true, "/var/run": true, "/run": true, "/": true}

func dockerChecks(containers []collect.ContainerSettings, now time.Time) []Check {
	var privileged, socket, hostNetwork, hostPID, capAdd, root, latest, old []string
	cutoff := now.Add(-oldImageAge).Unix()
	for _, container := range containers {
		if !container.Running {
			continue
		}
		name := container.Name
		if container.Privileged {
			privileged = append(privileged, name)
		}
		if mountsSocket(container.MountSources) {
			socket = append(socket, name)
		}
		if container.NetworkMode == "host" {
			hostNetwork = append(hostNetwork, name)
		}
		if container.PidMode == "host" {
			hostPID = append(hostPID, name)
		}
		if len(container.CapAdd) > 0 {
			capAdd = append(capAdd, name)
		}
		if runsAsRoot(container.User) {
			root = append(root, name)
		}
		if unpinnedImage(container.ImageRef) {
			latest = append(latest, name)
		}
		if image := container.Image; image != nil && image.Created != nil && *image.Created < cutoff {
			old = append(old, name)
		}
	}
	return []Check{
		containerCheck("docker.privileged", privileged, "No running container is privileged", "A privileged container is running", "Privileged containers are running"),
		containerCheck("docker.socketMount", socket, "No running container mounts the Docker socket", "A container mounts the Docker socket", "Containers mount the Docker socket"),
		containerCheck("docker.hostNetwork", hostNetwork, "No running container uses the host network", "A container uses the host network", "Containers use the host network"),
		containerCheck("docker.hostPID", hostPID, "No running container uses the host PID namespace", "A container uses the host PID namespace", "Containers use the host PID namespace"),
		containerCheck("docker.capAdd", capAdd, "No running container adds capabilities", "A container adds capabilities", "Containers add capabilities"),
		containerCheck("docker.root", root, "No running container runs as root", "A container runs as root", "Containers run as root"),
		containerCheck("docker.latestTag", latest, "Every running container uses a pinned image tag", "A container uses the latest tag or no tag", "Containers use the latest tag or no tag"),
		containerCheck("docker.oldImage", old, "No running container uses an image older than 90 days", "A container uses an image older than 90 days", "Containers use images older than 90 days"),
	}
}

func mountsSocket(sources []string) bool {
	for _, source := range sources {
		if source != "" && socketSources[path.Clean(source)] {
			return true
		}
	}
	return false
}

func runsAsRoot(user string) bool {
	name, _, _ := strings.Cut(strings.TrimSpace(user), ":")
	return name == "" || name == "0" || name == "root"
}

func unpinnedImage(ref string) bool {
	if strings.Contains(ref, "@") {
		return false
	}
	if strings.HasPrefix(ref, "sha256:") {
		return true
	}
	last := ref[strings.LastIndex(ref, "/")+1:]
	_, tag, ok := strings.Cut(last, ":")
	return !ok || tag == "" || tag == "latest"
}

func containerCheck(id string, names []string, passTitle, oneTitle, manyTitle string) Check {
	switch len(names) {
	case 0:
		return Check{ID: id, Status: statusPass, Title: passTitle, Detail: "None"}
	case 1:
		return Check{ID: id, Status: statusFail, Title: oneTitle, Detail: names[0]}
	}
	return Check{ID: id, Status: statusFail, Title: manyTitle, Detail: nameList(names)}
}
