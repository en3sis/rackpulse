package config

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateToken(t *testing.T) {
	if err := ValidateToken("rb1_" + strings.Repeat("aZ0-_", 8) + "abc"); err != nil {
		t.Errorf("valid key rejected: %v", err)
	}
	for _, token := range []string{"", "rb2_" + strings.Repeat("a", 43), "rb1_short", "rb1_" + strings.Repeat("a", 42) + "=", "rb1_" + strings.Repeat("a", 42) + " "} {
		if ValidateToken(token) == nil {
			t.Errorf("invalid key %q accepted", token)
		}
	}
}

func TestNoDockerIsStored(t *testing.T) {
	dir := t.TempDir()
	old := filepath.Join(dir, "old.json")
	os.WriteFile(old, []byte(`{"token":"rb1_aaaaaaaaaaaaaaaaaaaa","port":7311,"listen":""}`), 0o600)
	cfg, err := Load(old)
	if err != nil || cfg.NoDocker {
		t.Fatalf("0.3.0 config %+v %v", cfg, err)
	}
	cfg.NoDocker = true
	data, _ := json.Marshal(cfg)
	stored := filepath.Join(dir, "new.json")
	os.WriteFile(stored, data, 0o600)
	if cfg, err := Load(stored); err != nil || !cfg.NoDocker {
		t.Fatalf("stored config %+v %v", cfg, err)
	}
	cfg.NoDocker = false
	if data, _ := json.Marshal(cfg); strings.Contains(string(data), "noDocker") {
		t.Fatalf("default written: %s", data)
	}
}

func TestLoadSeparatesMissingFromBroken(t *testing.T) {
	dir := t.TempDir()
	if _, err := Load(filepath.Join(dir, "missing.json")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("missing: %v", err)
	}
	broken := filepath.Join(dir, "broken.json")
	os.WriteFile(broken, []byte(`{"token":"rb1_`), 0o600)
	if _, err := Load(broken); err == nil || errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("broken: %v", err)
	}
}
