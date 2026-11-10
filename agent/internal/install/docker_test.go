package install

import (
	"strings"
	"testing"
)

func TestDockerAccess(t *testing.T) {
	if !hasGroup([]string{"999", "120"}, "120") || hasGroup([]string{"999"}, "120") {
		t.Fatal("group membership")
	}
	lines := []struct {
		access   dockerAccess
		noDocker bool
		want     string
	}{
		{dockerOn, false, "Docker access: on."},
		{dockerOff, true, "set with --no-docker"},
		{dockerOff, false, "Run the install command again"},
		{dockerMissing, false, "Docker is not installed."},
		{dockerMissing, true, "--no-docker is set"},
	}
	for _, line := range lines {
		if got := dockerAccessLine(line.access, line.noDocker); !strings.Contains(got, line.want) {
			t.Errorf("%d %v: %q", line.access, line.noDocker, got)
		}
	}
	if !strings.Contains(dockerAccessLine(dockerOff, true), "image scanning") {
		t.Fatal("off line must say what is lost")
	}
}

func TestDockerChoiceSurvivesUpdates(t *testing.T) {
	cases := []struct {
		stored bool
		set    map[string]bool
		want   bool
	}{
		{false, map[string]bool{}, false},
		{true, map[string]bool{}, true},
		{false, map[string]bool{"no-docker": true}, true},
		{true, map[string]bool{"docker": true}, false},
		{true, map[string]bool{"pair": true, "port": true}, true},
	}
	for _, c := range cases {
		if got := dockerChoice(c.stored, c.set); got != c.want {
			t.Errorf("%+v: %v", c, got)
		}
	}
}

func TestDockerFlags(t *testing.T) {
	cases := []struct {
		set              map[string]bool
		docker, noDocker bool
		ok               bool
	}{
		{map[string]bool{}, false, false, true},
		{map[string]bool{"docker": true}, true, false, true},
		{map[string]bool{"no-docker": true}, false, true, true},
		{map[string]bool{"docker": true, "no-docker": true}, true, true, false},
		{map[string]bool{"docker": true}, false, false, false},
		{map[string]bool{"no-docker": true}, false, false, false},
	}
	for _, c := range cases {
		if err := checkDockerFlags(c.set, c.docker, c.noDocker); (err == nil) != c.ok {
			t.Errorf("%+v: %v", c, err)
		}
	}
}
