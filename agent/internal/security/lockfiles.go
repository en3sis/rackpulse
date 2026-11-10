package security

import "strings"

type lockfileParser struct {
	ecosystem string
	parse     func([]byte) ([]Dependency, error)
}

var lockfileParsers = map[string]lockfileParser{
	"package-lock.json": {"npm", parseNpmLock},
	"pnpm-lock.yaml":    {"npm", parsePnpmLock},
	"yarn.lock":         {"npm", parseYarnLock},
	"requirements.txt":  {"PyPI", parseRequirements},
	"poetry.lock":       {"PyPI", parsePythonLock},
	"uv.lock":           {"PyPI", parsePythonLock},
	"Pipfile.lock":      {"PyPI", parsePipfileLock},
	"go.mod":            {"Go", parseGoMod},
	"Cargo.lock":        {"crates.io", parseCargoLock},
	"composer.lock":     {"Packagist", parseComposerLock},
	"Gemfile.lock":      {"RubyGems", parseGemfileLock},
}

func lines(data []byte) []string {
	return strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
}

func unquote(value string) string {
	value = strings.TrimSpace(value)
	if len(value) >= 2 && (value[0] == '"' || value[0] == '\'') && value[len(value)-1] == value[0] {
		return value[1 : len(value)-1]
	}
	return value
}

func registryVersion(version string) bool {
	return version != "" && !strings.ContainsAny(version, ":/ #") && isDigit(version[0])
}

func tomlPair(line string) (string, string, bool) {
	if line == "" || line[0] == ' ' || line[0] == '\t' {
		return "", "", false
	}
	key, value, ok := strings.Cut(line, "=")
	if !ok {
		return "", "", false
	}
	return strings.TrimSpace(key), strings.TrimSpace(value), true
}
