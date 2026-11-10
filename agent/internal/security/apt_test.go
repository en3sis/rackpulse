package security

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestParseAptSimulationUbuntu(t *testing.T) {
	items := parseAptSimulation(readFixture(t, "apt/ubuntu.txt"))
	current := func(value string) *string { return &value }
	want := []Update{
		{Name: "docker-ce", Current: current("5:27.3.1-1~ubuntu.24.04~noble"), Available: "5:28.0.1-1~ubuntu.24.04~noble", Origins: []string{"Docker CE:noble/noble"}},
		{Name: "liblzma5", Current: current("5.6.1+really5.4.5-1ubuntu0.3"), Available: "5.6.1+really5.4.5-1ubuntu0.4", Security: true, Origins: []string{"Ubuntu:24.04/noble-updates", "Ubuntu:24.04/noble-security"}},
		{Name: "libssl3t64", Current: current("3.0.13-0ubuntu3.4"), Available: "3.0.13-0ubuntu3.5", Security: true, Origins: []string{"Ubuntu:24.04/noble-security"}},
		{Name: "linux-image-6.8.0-90-generic", Available: "6.8.0-90.91", Origins: []string{"Ubuntu:24.04/noble-updates"}},
		{Name: "vim-common", Current: current("2:9.1.0016-1ubuntu7.2"), Available: "2:9.1.0016-1ubuntu7.3", Origins: []string{"Ubuntu:24.04/noble-updates"}},
	}
	if !reflect.DeepEqual(items, want) {
		t.Fatalf("got %+v\nwant %+v", items, want)
	}
}

func TestParseAptSimulationDebian(t *testing.T) {
	items := parseAptSimulation(readFixture(t, "apt/debian.txt"))
	security := map[string]bool{}
	for _, item := range items {
		security[item.Name] = item.Security
	}
	want := map[string]bool{"libc6": true, "tzdata": false, "openssh-client": false}
	if !reflect.DeepEqual(security, want) {
		t.Fatalf("got %v want %v", security, want)
	}
	if len(parseAptSimulation(nil)) != 0 || parseAptSimulation(nil) == nil {
		t.Fatal("empty output must give an empty list")
	}
}

func TestSecurityOrigin(t *testing.T) {
	cases := map[string]bool{
		"Ubuntu:24.04/noble-security":             true,
		"UbuntuESMApps:24.04/noble-apps-security": true,
		"Debian-Security:12/stable-security":      true,
		"Debian-Security:10/buster":               true,
		"Debian-Security:12/oldstable-security":   true,
		"UbuntuESM:24.04/noble-infra-security":    true,
		"Debian:12.8/stable":                      false,
		"Ubuntu:24.04/noble-updates":              false,
		"security-team:1/stable":                  false,
	}
	for origin, want := range cases {
		if got := securityOrigin(origin); got != want {
			t.Errorf("securityOrigin(%q) = %v", origin, got)
		}
	}
}

func TestAptListsTime(t *testing.T) {
	root := writeTree(t, map[string]string{
		"var/lib/apt/lists/archive_InRelease": "x",
		"var/lib/apt/lists/lock":              "",
		"var/lib/apt/lists/partial/x":         "",
	})
	old := time.Unix(1761400000, 0)
	newer := time.Unix(1761450000, 0)
	os.Chtimes(filepath.Join(root, "var/lib/apt/lists/archive_InRelease"), old, old)
	os.Chtimes(filepath.Join(root, "var/lib/apt/lists/lock"), newer, newer)
	os.Chtimes(filepath.Join(root, "var/lib/apt/lists/partial"), newer, newer)
	if got := aptListsTime(root); got == nil || *got != old.Unix() {
		t.Fatalf("lists time %v", got)
	}
	stamp := filepath.Join(root, "var/lib/apt/periodic/update-success-stamp")
	os.MkdirAll(filepath.Dir(stamp), 0o755)
	os.WriteFile(stamp, nil, 0o644)
	os.Chtimes(stamp, newer, newer)
	if got := aptListsTime(root); got == nil || *got != newer.Unix() {
		t.Fatalf("lists time with stamp %v", got)
	}
	if aptListsTime(t.TempDir()) != nil {
		t.Fatal("no lists must give nil")
	}
}

func TestCappedBufferKeepsDraining(t *testing.T) {
	buffer := &cappedBuffer{limit: 4}
	for _, chunk := range []string{"ab", "cdef", "gh"} {
		if n, err := buffer.Write([]byte(chunk)); n != len(chunk) || err != nil {
			t.Fatalf("write %q: %d %v", chunk, n, err)
		}
	}
	if buffer.buffer.String() != "abcd" || !buffer.overflow {
		t.Fatalf("buffer %q overflow %v", buffer.buffer.String(), buffer.overflow)
	}
}

func TestAptErrorLine(t *testing.T) {
	stderr := "W: something\nE: Could not open lock file\nE: Unable to lock directory\n"
	if got := aptErrorLine(stderr); got != "Unable to lock directory" {
		t.Fatalf("got %q", got)
	}
}
