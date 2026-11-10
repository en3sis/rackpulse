package security

import (
	"encoding/json"
	"regexp"
	"strings"
)

var (
	pythonSeparators = regexp.MustCompile(`[-_.]+`)
	pythonName       = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
)

func normalizePythonName(name string) string {
	return strings.ToLower(pythonSeparators.ReplaceAllString(name, "-"))
}

func appendPython(dependencies []Dependency, name, version string) []Dependency {
	name = strings.TrimSpace(name)
	version = strings.TrimSpace(version)
	if !pythonName.MatchString(name) || version == "" || strings.ContainsAny(version, "*,<>=! ") {
		return dependencies
	}
	return append(dependencies, Dependency{Name: normalizePythonName(name), Version: version})
}

func parseRequirements(data []byte) ([]Dependency, error) {
	dependencies := []Dependency{}
	text := strings.ReplaceAll(strings.ReplaceAll(string(data), "\r\n", "\n"), "\\\n", " ")
	for _, line := range strings.Split(text, "\n") {
		if index := strings.Index(line, "#"); index >= 0 {
			line = line[:index]
		}
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "-") {
			continue
		}
		if index := strings.IndexByte(line, ';'); index >= 0 {
			line = line[:index]
		}
		if index := strings.Index(line, " -"); index >= 0 {
			line = line[:index]
		}
		spec := strings.Join(strings.Fields(line), "")
		name, version, ok := strings.Cut(spec, "==")
		if !ok || strings.HasPrefix(version, "=") {
			continue
		}
		if index := strings.IndexByte(name, '['); index >= 0 {
			name = name[:index]
		}
		dependencies = appendPython(dependencies, name, version)
	}
	return dependencies, nil
}

func parsePythonLock(data []byte) ([]Dependency, error) {
	dependencies := []Dependency{}
	section := ""
	var name, version string
	local := false
	flush := func() {
		if name != "" && !local {
			dependencies = appendPython(dependencies, name, version)
		}
		name, version, local = "", "", false
	}
	for _, line := range lines(data) {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(line, "[") {
			header := strings.Trim(trimmed, "[]")
			if trimmed == "[[package]]" || !strings.HasPrefix(header, "package.") {
				flush()
			}
			section = header
			continue
		}
		key, value, ok := tomlPair(line)
		if !ok {
			continue
		}
		switch {
		case section == "package" && key == "name":
			name = unquote(value)
		case section == "package" && key == "version":
			version = unquote(value)
		case section == "package" && key == "source":
			for _, marker := range []string{"editable", "virtual", "directory", "path"} {
				if strings.Contains(value, marker+" =") || strings.Contains(value, marker+"=") {
					local = true
				}
			}
		case section == "package.source" && key == "type":
			if kind := unquote(value); kind == "directory" || kind == "file" {
				local = true
			}
		}
	}
	flush()
	return dependencies, nil
}

func parsePipfileLock(data []byte) ([]Dependency, error) {
	var lock map[string]json.RawMessage
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, err
	}
	dependencies := []Dependency{}
	for _, group := range []string{"default", "develop"} {
		raw, ok := lock[group]
		if !ok {
			continue
		}
		var entries map[string]struct {
			Version string `json:"version"`
		}
		if err := json.Unmarshal(raw, &entries); err != nil {
			return nil, err
		}
		for name, entry := range entries {
			if version, ok := strings.CutPrefix(entry.Version, "=="); ok {
				dependencies = appendPython(dependencies, name, version)
			}
		}
	}
	return dependencies, nil
}
