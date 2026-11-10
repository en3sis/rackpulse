package security

import (
	"bytes"
	"reflect"
	"testing"
	"time"

	"github.com/en3sis/rackpulse/agent/internal/collect"
)

func TestAutomaticUpdatesCheck(t *testing.T) {
	installed := map[string]bool{"unattended-upgrades": true}
	cases := []struct {
		name      string
		files     map[string]string
		installed map[string]bool
		dump      []byte
		want      checkResult
	}{
		{
			name:      "not installed",
			files:     map[string]string{},
			installed: map[string]bool{},
			want:      checkResult{statusFail, "unattended-upgrades is not installed", ""},
		},
		{
			name: "ubuntu default",
			files: map[string]string{
				"etc/apt/apt.conf.d/20auto-upgrades":       "APT::Periodic::Update-Package-Lists \"1\";\nAPT::Periodic::Unattended-Upgrade \"1\";\n",
				"etc/apt/apt.conf.d/50unattended-upgrades": "// comment\nUnattended-Upgrade::Allowed-Origins {\n\t\"${distro_id}:${distro_codename}-security\";\n};\n",
			},
			installed: installed,
			want:      checkResult{statusPass, `APT::Periodic::Unattended-Upgrade "1"`, "/etc/apt/apt.conf.d/20auto-upgrades"},
		},
		{
			name: "later file disables",
			files: map[string]string{
				"etc/apt/apt.conf.d/20auto-upgrades": "APT::Periodic::Unattended-Upgrade \"1\";\n",
				"etc/apt/apt.conf.d/99local":         "/* turned off */\nAPT { Periodic { Unattended-Upgrade \"0\"; }; };\n",
			},
			installed: installed,
			want:      checkResult{statusFail, `APT::Periodic::Unattended-Upgrade "0"`, "/etc/apt/apt.conf.d/99local"},
		},
		{
			name: "ignored file names",
			files: map[string]string{
				"etc/apt/apt.conf.d/20auto-upgrades":                "APT::Periodic::Unattended-Upgrade \"1\";\n",
				"etc/apt/apt.conf.d/99off.disabled":                 "APT::Periodic::Unattended-Upgrade \"0\";\n",
				"etc/apt/apt.conf.d/99off.dpkg-old":                 "APT::Periodic::Unattended-Upgrade \"0\";\n",
				"etc/apt/apt.conf.d/99off~":                         "APT::Periodic::Unattended-Upgrade \"0\";\n",
				"etc/apt/apt.conf.d/99off.txt":                      "APT::Periodic::Unattended-Upgrade \"0\";\n",
				"etc/apt/apt.conf.d/50unattended-upgrades.ucf-dist": "APT::Periodic::Unattended-Upgrade \"0\";\n",
			},
			installed: installed,
			want:      checkResult{statusPass, `APT::Periodic::Unattended-Upgrade "1"`, "/etc/apt/apt.conf.d/20auto-upgrades"},
		},
		{
			name: "periodic disabled",
			files: map[string]string{
				"etc/apt/apt.conf.d/20auto-upgrades": "APT::Periodic::Unattended-Upgrade \"1\";\n",
				"etc/apt/apt.conf":                   "# local\nAPT::Periodic::Enable \"0\";\n",
			},
			installed: installed,
			want:      checkResult{statusFail, `APT::Periodic::Enable "0"`, "/etc/apt/apt.conf"},
		},
		{
			name:      "apt-config value wins",
			files:     map[string]string{"etc/apt/apt.conf.d/20auto-upgrades": "APT::Periodic::Unattended-Upgrade \"1\";\n"},
			installed: installed,
			dump:      []byte("APT::Periodic \"\";\nAPT::Periodic::Update-Package-Lists \"1\";\nAPT::Periodic::Unattended-Upgrade \"0\";\n"),
			want:      checkResult{statusFail, `APT::Periodic::Unattended-Upgrade "0"`, ""},
		},
		{
			name:      "apt-config agrees with the file",
			files:     map[string]string{"etc/apt/apt.conf.d/20auto-upgrades": "APT::Periodic::Unattended-Upgrade \"1\";\n"},
			installed: installed,
			dump:      []byte("APT::Periodic \"\";\nAPT::Periodic::Unattended-Upgrade \"1\";\n"),
			want:      checkResult{statusPass, `APT::Periodic::Unattended-Upgrade "1"`, "/etc/apt/apt.conf.d/20auto-upgrades"},
		},
		{
			name:      "apt-config without the key",
			files:     map[string]string{"etc/apt/apt.conf.d/20auto-upgrades": "APT::Periodic::Unattended-Upgrade \"1\";\n"},
			installed: installed,
			dump:      []byte("APT::Periodic \"\";\n"),
			want:      checkResult{statusFail, "APT::Periodic::Unattended-Upgrade is not set", ""},
		},
		{
			name:      "not set",
			files:     map[string]string{"etc/apt/apt.conf.d/70debconf": "DPkg::Pre-Install-Pkgs {\"/usr/sbin/dpkg-preconfigure --apt || true\";};\n"},
			installed: installed,
			want:      checkResult{statusFail, "APT::Periodic::Unattended-Upgrade is not set", ""},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			check := automaticUpdatesCheck(writeTree(t, c.files), c.installed, c.dump)
			if got := resultOf(check); got != c.want {
				t.Fatalf("got %+v\nwant %+v", got, c.want)
			}
		})
	}
}

func TestUfwCheck(t *testing.T) {
	cases := []struct {
		name      string
		files     map[string]string
		manager   string
		installed map[string]bool
		want      *checkResult
	}{
		{"enabled", map[string]string{"etc/ufw/ufw.conf": "# comment\nENABLED=yes\nLOGLEVEL=low\n"}, "dpkg", map[string]bool{"ufw": true}, &checkResult{statusPass, "ENABLED=yes", ufwConfigPath}},
		{"disabled", map[string]string{"etc/ufw/ufw.conf": "ENABLED=no\n"}, "dpkg", map[string]bool{"ufw": true}, &checkResult{statusFail, "ENABLED=no", ufwConfigPath}},
		{"removed package", map[string]string{"etc/ufw/ufw.conf": "ENABLED=no\n"}, "dpkg", map[string]bool{}, nil},
		{"not installed", map[string]string{}, "apk", map[string]bool{}, nil},
		{"quoted on alpine", map[string]string{"etc/ufw/ufw.conf": "ENABLED=\"yes\"\n"}, "apk", map[string]bool{}, &checkResult{statusPass, "ENABLED=yes", ufwConfigPath}},
	}
	for _, c := range cases {
		check, ok := ufwCheck(writeTree(t, c.files), c.manager, c.installed)
		if c.want == nil {
			if ok {
				t.Errorf("%s: want no check, got %+v", c.name, check)
			}
			continue
		}
		if got := resultOf(check); !ok || got != *c.want {
			t.Errorf("%s: got %+v want %+v", c.name, got, *c.want)
		}
	}
}

func TestExtraRootCheck(t *testing.T) {
	passwd := "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1::/usr/sbin:/usr/sbin/nologin\n"
	check, ok := extraRootCheck(writeTree(t, map[string]string{"etc/passwd": passwd}))
	if !ok || check.Status != statusPass {
		t.Fatalf("check %+v", check)
	}
	check, _ = extraRootCheck(writeTree(t, map[string]string{"etc/passwd": passwd + "toor:x:0:0::/root:/bin/sh\nbackup:x:00:0::/:/bin/sh\n"}))
	if check.Status != statusFail || check.Detail != "UID 0: toor, backup" || check.Title != "Other accounts have UID 0" {
		t.Fatalf("check %+v", check)
	}
	if _, ok := extraRootCheck(t.TempDir()); ok {
		t.Fatal("missing passwd must omit the check")
	}
}

func TestDockerChecks(t *testing.T) {
	now := time.Unix(1793000000, 0)
	fresh := now.Add(-10 * 24 * time.Hour).Unix()
	stale := now.Add(-100 * 24 * time.Hour).Unix()
	containers := []collect.ContainerSettings{
		{Name: "web", Running: true, NetworkMode: "app_default", User: "node", ImageRef: "node:22-alpine", MountSources: []string{"/srv/app"}, Image: &collect.ImageDetails{Created: &fresh}},
		{Name: "agent", Running: true, Privileged: true, NetworkMode: "host", PidMode: "host", CapAdd: []string{"SYS_ADMIN"}, ImageRef: "agent:latest", MountSources: []string{"/var/run/docker.sock"}, Image: &collect.ImageDetails{Created: &stale}},
		{Name: "cadvisor", Running: true, User: "0:0", ImageRef: "localhost:5000/cadvisor", MountSources: []string{"/var/run/"}},
		{Name: "proxy", Running: true, User: "101", ImageRef: "traefik@sha256:abc", MountSources: []string{"/run"}},
		{Name: "old", Running: false, Privileged: true, NetworkMode: "host", PidMode: "host", CapAdd: []string{"NET_ADMIN"}, MountSources: []string{"/run/docker.sock"}},
	}
	got := map[string]checkResult{}
	for _, check := range dockerChecks(containers, now) {
		got[check.ID] = resultOf(check)
	}
	want := map[string]checkResult{
		"docker.privileged":  {statusFail, "agent", ""},
		"docker.socketMount": {statusFail, "agent, cadvisor, proxy", ""},
		"docker.hostNetwork": {statusFail, "agent", ""},
		"docker.hostPID":     {statusFail, "agent", ""},
		"docker.capAdd":      {statusFail, "agent", ""},
		"docker.root":        {statusFail, "agent, cadvisor", ""},
		"docker.latestTag":   {statusFail, "agent, cadvisor", ""},
		"docker.oldImage":    {statusFail, "agent", ""},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v\nwant %+v", got, want)
	}
	for _, check := range dockerChecks(containers[:1], now) {
		if check.Status != statusPass {
			t.Fatalf("check %+v", check)
		}
	}
	names := []string{"a", "b", "c", "d", "e", "f", "g"}
	if got := nameList(names); got != "a, b, c, d, e and 2 more" {
		t.Fatalf("name list %q", got)
	}
}

func TestImageReferences(t *testing.T) {
	cases := map[string]bool{
		"nginx": true, "nginx:latest": true, "nginx:1.27": false, "library/nginx:1.27-alpine": false,
		"localhost:5000/app": true, "localhost:5000/app:2": false, "localhost:5000/app:latest": true,
		"ghcr.io/org/app@sha256:0123": false, "app:1@sha256:0123": false, "sha256:0123abcd": true, "": true,
	}
	for ref, want := range cases {
		if got := unpinnedImage(ref); got != want {
			t.Errorf("%q: %v, want %v", ref, got, want)
		}
	}
	for user, want := range map[string]bool{"": true, "0": true, "root": true, "0:0": true, "root:docker": true, "1000": false, "node": false, "1000:0": false, "rootless": false} {
		if got := runsAsRoot(user); got != want {
			t.Errorf("user %q: %v, want %v", user, got, want)
		}
	}
}

func TestKernel(t *testing.T) {
	items, _ := parseDpkgStatus(bytes.NewReader(readFixture(t, "dpkg/status")))
	latest := latestKernel(items)
	if latest == nil || *latest != "6.8.0-88-generic" {
		t.Fatalf("latest %v", latest)
	}
	cases := []struct {
		running string
		status  string
	}{
		{"6.8.0-85-generic", statusFail},
		{"6.8.0-88-generic", statusPass},
		{"6.10.1-custom", statusPass},
		{"6.1.0-1-generic", statusFail},
	}
	for _, c := range cases {
		running := c.running
		check, ok := kernelCheck(Kernel{Running: &running, LatestInstalled: latest}, items)
		if !ok || check.Status != c.status {
			t.Errorf("running %s: %+v", c.running, check)
		}
	}
	if _, ok := kernelCheck(Kernel{Running: stringPointer("6.8.0-85-generic")}, nil); ok {
		t.Fatal("unknown latest kernel must omit the check")
	}
	debian := []Package{
		{Name: "linux-image-6.1.0-25-cloud-arm64", Version: "6.1.106-3"},
		{Name: "linux-image-6.1.0-26-cloud-arm64", Version: "6.1.112-1"},
		{Name: "linux-image-cloud-arm64", Version: "6.1.112-1"},
	}
	if got := latestKernel(debian); got == nil || *got != "6.1.0-26-cloud-arm64" {
		t.Fatalf("debian latest %v", got)
	}
}

func TestReadListening(t *testing.T) {
	root := t.TempDir()
	writeFile := func(name string) {
		data := readFixture(t, "proc/"+name)
		path := root + "/proc/net/" + name
		mustWrite(t, path, data)
	}
	writeFile("tcp")
	writeFile("tcp6")
	got := readListening(root)
	want := []Listener{
		{"tcp", "0.0.0.0", 22},
		{"tcp", "::", 22},
		{"tcp", "2001:db8::dead:beef", 443},
		{"tcp", "10.0.0.6", 3000},
		{"tcp", "10.0.0.5", 5432},
		{"tcp", "0.0.0.0", 7311},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v\nwant %+v", got, want)
	}
	if empty := readListening(t.TempDir()); empty == nil || len(empty) != 0 {
		t.Fatalf("empty %+v", empty)
	}
}
