package security

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	sshDir          = "/etc/ssh"
	sshdConfigPath  = "/etc/ssh/sshd_config"
	sshIncludeLimit = 16
	sshDepthLimit   = 4
)

var sshKeywords = map[string]string{
	"passwordauthentication":          "passwordauthentication",
	"kbdinteractiveauthentication":    "kbdinteractiveauthentication",
	"challengeresponseauthentication": "kbdinteractiveauthentication",
	"usepam":                          "usepam",
	"permitrootlogin":                 "permitrootlogin",
}

type sshSetting struct {
	keyword    string
	value      string
	source     string
	unreadable string
}

type sshConfig struct {
	root      string
	includes  int
	settings  map[string]sshSetting
	overrides map[string]sshSetting
}

func readSSHConfig(root string) (*sshConfig, bool) {
	if _, err := os.Stat(hostPath(root, sshdConfigPath)); errors.Is(err, fs.ErrNotExist) {
		return nil, false
	}
	config := &sshConfig{root: root, settings: map[string]sshSetting{}, overrides: map[string]sshSetting{}}
	config.parseFile(sshdConfigPath, 0, config.settings)
	return config, true
}

func (c *sshConfig) get(keyword string) (sshSetting, bool) {
	if setting, ok := c.overrides[keyword]; ok {
		return setting, true
	}
	setting, ok := c.settings[keyword]
	return setting, ok
}

func markUnreadable(settings map[string]sshSetting, path string) {
	for _, keyword := range sshKeywords {
		if _, decided := settings[keyword]; !decided {
			settings[keyword] = sshSetting{unreadable: path}
		}
	}
}

func (c *sshConfig) parseFile(path string, depth int, settings map[string]sshSetting) {
	data, err := os.ReadFile(hostPath(c.root, path))
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			markUnreadable(settings, path)
		}
		return
	}
	for _, line := range strings.Split(string(data), "\n") {
		keyword, args := splitSSHLine(line)
		switch {
		case keyword == "":
		case keyword == "match":
			settings = nil
			if len(args) == 1 && strings.EqualFold(args[0], "all") {
				settings = c.overrides
			}
		case settings == nil:
		case keyword == "include":
			for _, pattern := range args {
				c.include(pattern, depth, settings)
			}
		default:
			canonical, tracked := sshKeywords[keyword]
			if !tracked || len(args) == 0 {
				continue
			}
			if _, decided := settings[canonical]; !decided {
				settings[canonical] = sshSetting{keyword: sshDisplayName(keyword), value: strings.ToLower(args[0]), source: path}
			}
		}
	}
}

func splitSSHLine(line string) (string, []string) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return "", nil
	}
	end := strings.IndexAny(line, " \t=")
	if end < 0 {
		return strings.ToLower(line), nil
	}
	keyword := strings.ToLower(line[:end])
	rest := strings.TrimLeft(line[end:], " \t")
	rest = strings.TrimLeft(strings.TrimPrefix(rest, "="), " \t")
	args := strings.Fields(rest)
	for i, arg := range args {
		if strings.HasPrefix(arg, "#") {
			args = args[:i]
			break
		}
		args[i] = strings.Trim(arg, `"`)
	}
	return keyword, args
}

func sshDisplayName(keyword string) string {
	switch keyword {
	case "passwordauthentication":
		return "PasswordAuthentication"
	case "kbdinteractiveauthentication":
		return "KbdInteractiveAuthentication"
	case "challengeresponseauthentication":
		return "ChallengeResponseAuthentication"
	case "usepam":
		return "UsePAM"
	case "permitrootlogin":
		return "PermitRootLogin"
	}
	return keyword
}

func (c *sshConfig) include(pattern string, depth int, settings map[string]sshSetting) {
	if depth >= sshDepthLimit {
		return
	}
	if !filepath.IsAbs(pattern) {
		pattern = sshDir + "/" + pattern
	}
	pattern = filepath.Clean(pattern)
	if !strings.HasPrefix(pattern, sshDir+"/") {
		return
	}
	for _, path := range c.expand(pattern, settings) {
		if c.includes >= sshIncludeLimit {
			return
		}
		c.includes++
		c.parseFile(path, depth+1, settings)
	}
}

func hasGlobMeta(path string) bool {
	return strings.ContainsAny(path, `*?[\`)
}

func (c *sshConfig) expand(pattern string, settings map[string]sshSetting) []string {
	dir, base := filepath.Split(pattern)
	dir = filepath.Clean(dir)
	if !hasGlobMeta(pattern) {
		return []string{pattern}
	}
	if hasGlobMeta(dir) {
		matches, _ := filepath.Glob(hostPath(c.root, pattern))
		paths := []string{}
		prefix := strings.TrimSuffix(hostPath(c.root, "/"), "/")
		for _, match := range matches {
			path := strings.TrimPrefix(match, prefix)
			if strings.HasPrefix(path, sshDir+"/") && !strings.HasPrefix(filepath.Base(path), ".") {
				paths = append(paths, path)
			}
		}
		return paths
	}
	entries, err := os.ReadDir(hostPath(c.root, dir))
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			markUnreadable(settings, dir)
		}
		return nil
	}
	paths := []string{}
	for _, entry := range entries {
		if entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
			continue
		}
		if matched, _ := filepath.Match(base, entry.Name()); matched {
			paths = append(paths, dir+"/"+entry.Name())
		}
	}
	sort.Strings(paths)
	return paths
}

func sshChecks(config *sshConfig) []Check {
	return []Check{passwordLoginCheck(config), rootLoginCheck(config)}
}

func unreadableCheck(id, title, path string) Check {
	return Check{ID: id, Status: statusUnknown, Title: title, Detail: "Cannot read " + path, Source: stringPointer(path)}
}

func sshValue(setting sshSetting, ok bool, fallback string) (string, string, *string) {
	if !ok {
		return fallback, "", nil
	}
	return setting.value, setting.keyword + " " + setting.value, stringPointer(setting.source)
}

func passwordLoginCheck(config *sshConfig) Check {
	const id, unknownTitle = "ssh.passwordLogin", "SSH password login could not be checked"
	password, havePassword := config.get("passwordauthentication")
	if password.unreadable != "" {
		return unreadableCheck(id, unknownTitle, password.unreadable)
	}
	value, detail, source := sshValue(password, havePassword, "yes")
	if value == "yes" {
		if detail == "" {
			detail, source = "PasswordAuthentication is not set, the default is yes", stringPointer(sshdConfigPath)
		}
		return Check{ID: id, Status: statusFail, Title: "SSH accepts passwords", Detail: detail, Source: source}
	}
	keyboard, haveKeyboard := config.get("kbdinteractiveauthentication")
	if keyboard.unreadable != "" {
		return unreadableCheck(id, unknownTitle, keyboard.unreadable)
	}
	keyboardValue, keyboardDetail, keyboardSource := sshValue(keyboard, haveKeyboard, "yes")
	if keyboardValue == "yes" {
		pam, havePAM := config.get("usepam")
		if pam.unreadable != "" {
			return unreadableCheck(id, unknownTitle, pam.unreadable)
		}
		if pamValue, _, _ := sshValue(pam, havePAM, "no"); pamValue == "yes" {
			if keyboardDetail == "" {
				keyboardDetail, keyboardSource = "KbdInteractiveAuthentication is not set, the default is yes", stringPointer(sshdConfigPath)
			}
			return Check{ID: id, Status: statusFail, Title: "SSH accepts passwords", Detail: keyboardDetail + ", UsePAM yes", Source: keyboardSource}
		}
	}
	return Check{ID: id, Status: statusPass, Title: "SSH rejects passwords", Detail: detail, Source: source}
}

func rootLoginCheck(config *sshConfig) Check {
	const id = "ssh.rootLogin"
	setting, ok := config.get("permitrootlogin")
	if setting.unreadable != "" {
		return unreadableCheck(id, "SSH root login could not be checked", setting.unreadable)
	}
	value, detail, source := sshValue(setting, ok, "prohibit-password")
	if detail == "" {
		detail = "PermitRootLogin is not set, the default is prohibit-password"
	}
	check := Check{ID: id, Status: statusPass, Detail: detail, Source: source}
	switch value {
	case "yes":
		check.Status = statusFail
		check.Title = "SSH allows root login with a password"
	case "no":
		check.Title = "SSH does not allow root login"
	case "prohibit-password", "without-password":
		check.Title = "SSH root login needs a key"
	case "forced-commands-only":
		check.Title = "SSH root login is limited to forced commands"
	default:
		check.Status = statusUnknown
		check.Title = "SSH root login could not be checked"
	}
	return check
}
