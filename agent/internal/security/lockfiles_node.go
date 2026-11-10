package security

import (
	"encoding/json"
	"strconv"
	"strings"
)

type npmLock struct {
	Packages map[string]struct {
		Name    string `json:"name"`
		Version string `json:"version"`
		Link    bool   `json:"link"`
	} `json:"packages"`
	Dependencies map[string]npmDependency `json:"dependencies"`
}

type npmDependency struct {
	Version      string                   `json:"version"`
	Dependencies map[string]npmDependency `json:"dependencies"`
}

func parseNpmLock(data []byte) ([]Dependency, error) {
	var lock npmLock
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, err
	}
	dependencies := []Dependency{}
	if len(lock.Packages) > 0 {
		for key, entry := range lock.Packages {
			index := strings.LastIndex(key, "node_modules/")
			if key == "" || entry.Link || index < 0 {
				continue
			}
			name := key[index+len("node_modules/"):]
			if entry.Name != "" {
				name = entry.Name
			}
			dependencies = appendNpm(dependencies, name, entry.Version)
		}
		return dependencies, nil
	}
	var walk func(map[string]npmDependency)
	walk = func(tree map[string]npmDependency) {
		for name, entry := range tree {
			dependencies = appendNpm(dependencies, name, entry.Version)
			walk(entry.Dependencies)
		}
	}
	walk(lock.Dependencies)
	return dependencies, nil
}

func appendNpm(dependencies []Dependency, name, version string) []Dependency {
	if alias, ok := strings.CutPrefix(version, "npm:"); ok {
		if at := strings.LastIndexByte(alias, '@'); at > 0 {
			name, version = alias[:at], alias[at+1:]
		}
	}
	if name == "" || !registryVersion(version) {
		return dependencies
	}
	return append(dependencies, Dependency{Name: name, Version: version})
}

func parsePnpmLock(data []byte) ([]Dependency, error) {
	dependencies := []Dependency{}
	major := 0
	inPackages := false
	for _, line := range lines(data) {
		if strings.TrimSpace(line) == "" || strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		if line[0] != ' ' {
			if value, ok := strings.CutPrefix(line, "lockfileVersion:"); ok {
				major, _ = strconv.Atoi(strings.SplitN(unquote(value), ".", 2)[0])
			}
			inPackages = strings.TrimSpace(line) == "packages:"
			continue
		}
		if !inPackages || !strings.HasPrefix(line, "  ") || strings.HasPrefix(line, "   ") {
			continue
		}
		key := strings.TrimSpace(line)
		if index := strings.Index(key, ": "); index >= 0 {
			key = key[:index]
		}
		key = unquote(strings.TrimSuffix(key, ":"))
		if name, version, ok := splitPnpmKey(key, major); ok {
			dependencies = append(dependencies, Dependency{Name: name, Version: version})
		}
	}
	return dependencies, nil
}

func splitPnpmKey(key string, major int) (string, string, bool) {
	key = strings.TrimPrefix(key, "/")
	if index := strings.IndexByte(key, '('); index >= 0 {
		key = key[:index]
	}
	var name, version string
	if major > 0 && major < 6 {
		slash := strings.LastIndexByte(key, '/')
		if slash <= 0 {
			return "", "", false
		}
		name, version = key[:slash], key[slash+1:]
	} else {
		at := strings.LastIndexByte(key, '@')
		if at <= 0 {
			return "", "", false
		}
		name, version = key[:at], key[at+1:]
	}
	if index := strings.IndexByte(version, '_'); index >= 0 {
		version = version[:index]
	}
	return name, version, name != "" && registryVersion(version)
}

func parseYarnLock(data []byte) ([]Dependency, error) {
	dependencies := []Dependency{}
	var header, version, resolution string
	flush := func() {
		defer func() { header, version, resolution = "", "", "" }()
		if header == "" || header == "__metadata" {
			return
		}
		if resolution != "" {
			at := strings.IndexByte(resolution[1:], '@') + 1
			if at <= 0 {
				return
			}
			name, rest := resolution[:at], resolution[at+1:]
			resolved, ok := strings.CutPrefix(rest, "npm:")
			if !ok {
				return
			}
			if version == "" {
				version = resolved
			}
			dependencies = appendNpm(dependencies, name, version)
			return
		}
		spec := unquote(strings.TrimSpace(strings.Split(header, ",")[0]))
		at := strings.IndexByte(spec[min(1, len(spec)):], '@') + 1
		if at <= 0 {
			return
		}
		rest := spec[at+1:]
		for _, protocol := range []string{"workspace:", "link:", "file:", "portal:", "patch:"} {
			if strings.HasPrefix(rest, protocol) {
				return
			}
		}
		dependencies = appendNpm(dependencies, spec[:at], version)
	}
	for _, line := range lines(data) {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if line[0] != ' ' {
			flush()
			header = strings.TrimSuffix(trimmed, ":")
			continue
		}
		if strings.HasPrefix(line, "   ") {
			continue
		}
		if value, ok := strings.CutPrefix(trimmed, "version:"); ok {
			version = unquote(value)
		} else if value, ok := strings.CutPrefix(trimmed, "version "); ok {
			version = unquote(value)
		} else if value, ok := strings.CutPrefix(trimmed, "resolution:"); ok {
			resolution = unquote(value)
		}
	}
	flush()
	return dependencies, nil
}
