package security

import (
	"encoding/json"
	"strings"
)

type goReplacement struct {
	name, version string
	local         bool
}

func parseGoMod(data []byte) ([]Dependency, error) {
	required := []Dependency{}
	replacements := map[string]goReplacement{}
	block := ""
	directive := func(kind string, fields []string) {
		switch kind {
		case "require":
			required = appendGo(required, fields)
		case "replace":
			addGoReplacement(replacements, fields)
		}
	}
	for _, line := range lines(data) {
		if index := strings.Index(line, "//"); index >= 0 {
			line = line[:index]
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if block != "" {
			if fields[0] == ")" {
				block = ""
			} else {
				directive(block, fields)
			}
			continue
		}
		if len(fields) == 2 && fields[1] == "(" {
			block = fields[0]
			continue
		}
		directive(fields[0], fields[1:])
	}
	dependencies := []Dependency{}
	for _, dependency := range required {
		replacement, ok := replacements[dependency.Name+"@"+dependency.Version]
		if !ok {
			replacement, ok = replacements[dependency.Name]
		}
		switch {
		case !ok:
			dependencies = append(dependencies, dependency)
		case !replacement.local:
			dependencies = append(dependencies, Dependency{Name: replacement.name, Version: replacement.version})
		}
	}
	return dependencies, nil
}

func addGoReplacement(replacements map[string]goReplacement, fields []string) {
	arrow := -1
	for i, field := range fields {
		if field == "=>" {
			arrow = i
		}
	}
	if arrow < 1 || arrow > 2 || len(fields) <= arrow+1 {
		return
	}
	key := unquote(fields[0])
	if arrow == 2 {
		key += "@" + strings.TrimPrefix(fields[1], "v")
	}
	target := fields[arrow+1:]
	if len(target) == 1 {
		replacements[key] = goReplacement{local: true}
		return
	}
	version := strings.TrimPrefix(target[1], "v")
	if !registryVersion(version) {
		return
	}
	replacements[key] = goReplacement{name: unquote(target[0]), version: version}
}

func parseCargoLock(data []byte) ([]Dependency, error) {
	dependencies := []Dependency{}
	inPackage := false
	var name, version, source string
	flush := func() {
		if inPackage && name != "" && version != "" && source != "" {
			dependencies = append(dependencies, Dependency{Name: name, Version: version})
		}
		name, version, source = "", "", ""
	}
	for _, line := range lines(data) {
		if strings.HasPrefix(line, "[") {
			flush()
			inPackage = strings.TrimSpace(line) == "[[package]]"
			continue
		}
		key, value, ok := tomlPair(line)
		if !ok || !inPackage {
			continue
		}
		switch key {
		case "name":
			name = unquote(value)
		case "version":
			version = unquote(value)
		case "source":
			source = unquote(value)
		}
	}
	flush()
	return dependencies, nil
}

func parseComposerLock(data []byte) ([]Dependency, error) {
	type entry struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}
	var lock struct {
		Packages    []entry `json:"packages"`
		PackagesDev []entry `json:"packages-dev"`
	}
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, err
	}
	dependencies := []Dependency{}
	for _, item := range append(lock.Packages, lock.PackagesDev...) {
		if item.Name != "" && item.Version != "" && !strings.HasPrefix(item.Version, "dev-") {
			dependencies = append(dependencies, Dependency{Name: item.Name, Version: strings.TrimPrefix(item.Version, "v")})
		}
	}
	return dependencies, nil
}

func parseGemfileLock(data []byte) ([]Dependency, error) {
	dependencies := []Dependency{}
	section := ""
	inSpecs := false
	for _, line := range lines(data) {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if line[0] != ' ' {
			section, inSpecs = trimmed, false
			continue
		}
		if section != "GEM" {
			continue
		}
		if trimmed == "specs:" {
			inSpecs = true
			continue
		}
		if !inSpecs || !strings.HasPrefix(line, "    ") || strings.HasPrefix(line, "     ") {
			continue
		}
		name, rest, ok := strings.Cut(trimmed, " (")
		if !ok || !strings.HasSuffix(rest, ")") {
			continue
		}
		version := strings.TrimSuffix(rest, ")")
		if index := strings.IndexByte(version, '-'); index >= 0 {
			version = version[:index]
		}
		if name != "" && version != "" {
			dependencies = append(dependencies, Dependency{Name: name, Version: version})
		}
	}
	return dependencies, nil
}

func appendGo(dependencies []Dependency, fields []string) []Dependency {
	if len(fields) < 2 {
		return dependencies
	}
	name := unquote(fields[0])
	version := strings.TrimPrefix(fields[1], "v")
	if name == "" || !registryVersion(version) {
		return dependencies
	}
	return append(dependencies, Dependency{Name: name, Version: version})
}
