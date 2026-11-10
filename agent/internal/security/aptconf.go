package security

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

const (
	aptConfDir  = "/etc/apt/apt.conf.d"
	aptConfMain = "/etc/apt/apt.conf"
)

var (
	aptPartName    = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)
	aptIgnoredPart = regexp.MustCompile(`(~|\.disabled|\.bak|\.dpkg-[a-z]+|\.ucf-[a-z]+|\.save|\.orig|\.distUpgrade)$`)
)

type aptSetting struct {
	value  string
	source string
}

func aptConfigFiles(root string) []string {
	files := []string{}
	entries, _ := os.ReadDir(hostPath(root, aptConfDir))
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !aptPartName.MatchString(name) || aptIgnoredPart.MatchString(name) {
			continue
		}
		if ext := filepath.Ext(name); ext != "" && ext != ".conf" {
			continue
		}
		files = append(files, aptConfDir+"/"+name)
	}
	sort.Strings(files)
	return append(files, aptConfMain)
}

func readAptConfig(root string, keys ...string) map[string]aptSetting {
	wanted := map[string]bool{}
	for _, key := range keys {
		wanted[strings.ToLower(key)] = true
	}
	settings := map[string]aptSetting{}
	for _, path := range aptConfigFiles(root) {
		data, err := os.ReadFile(hostPath(root, path))
		if err != nil {
			continue
		}
		for key, value := range parseAptConfig(string(data)) {
			if wanted[key] {
				settings[key] = aptSetting{value: value, source: path}
			}
		}
	}
	return settings
}

func parseAptConfig(data string) map[string]string {
	values := map[string]string{}
	scope := []string{}
	pending := ""
	for _, token := range aptTokens(data) {
		switch {
		case token == "{":
			scope = append(scope, pending)
			pending = ""
		case token == "}":
			if len(scope) > 0 {
				scope = scope[:len(scope)-1]
			}
			pending = ""
		case token == ";":
			pending = ""
		case pending == "":
			pending = strings.Trim(token, `"`)
		default:
			key := strings.ToLower(strings.Join(append(append([]string{}, scope...), pending), "::"))
			values[key] = strings.Trim(token, `"`)
			pending = ""
		}
	}
	return values
}

func aptTokens(data string) []string {
	tokens := []string{}
	for i := 0; i < len(data); {
		c := data[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			i++
		case strings.HasPrefix(data[i:], "//") || c == '#':
			for i < len(data) && data[i] != '\n' {
				i++
			}
		case strings.HasPrefix(data[i:], "/*"):
			end := strings.Index(data[i+2:], "*/")
			if end < 0 {
				return tokens
			}
			i += end + 4
		case c == '{' || c == '}' || c == ';':
			tokens = append(tokens, string(c))
			i++
		case c == '"':
			end := strings.IndexByte(data[i+1:], '"')
			if end < 0 {
				return tokens
			}
			tokens = append(tokens, data[i:i+end+2])
			i += end + 2
		default:
			start := i
			for i < len(data) && !strings.ContainsRune(" \t\r\n{};\"", rune(data[i])) {
				i++
			}
			tokens = append(tokens, data[start:i])
		}
	}
	return tokens
}

func automaticUpdatesCheck(root string, installed map[string]bool, dump []byte) Check {
	check := Check{ID: "updates.automatic", Status: statusFail, Title: "Automatic security updates are off"}
	if !installed["unattended-upgrades"] {
		check.Title = "Automatic security updates are not set up"
		check.Detail = "unattended-upgrades is not installed"
		return check
	}
	const enableKey, upgradeKey = "apt::periodic::enable", "apt::periodic::unattended-upgrade"
	settings := readAptConfig(root, enableKey, upgradeKey)
	if dump != nil {
		merged := parseAptConfig(string(dump))
		for _, key := range []string{enableKey, upgradeKey} {
			value, ok := merged[key]
			if !ok {
				delete(settings, key)
				continue
			}
			if settings[key].value != value {
				settings[key] = aptSetting{value: value}
			}
		}
	}
	if enable, ok := settings[enableKey]; ok && enable.value == "0" {
		check.Detail = `APT::Periodic::Enable "0"`
		check.Source = optionalString(enable.source)
		return check
	}
	upgrade, ok := settings[upgradeKey]
	if !ok {
		check.Detail = "APT::Periodic::Unattended-Upgrade is not set"
		return check
	}
	check.Detail = `APT::Periodic::Unattended-Upgrade "` + upgrade.value + `"`
	check.Source = optionalString(upgrade.source)
	if upgrade.value != "0" && upgrade.value != "" {
		check.Status = statusPass
		check.Title = "Automatic security updates are on"
	}
	return check
}
