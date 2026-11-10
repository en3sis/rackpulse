package security

import (
	"os"
	"strings"
)

func readOSRelease(root string) OSInfo {
	for _, path := range []string{"/etc/os-release", "/usr/lib/os-release"} {
		data, err := os.ReadFile(hostPath(root, path))
		if err == nil {
			return parseOSRelease(string(data))
		}
	}
	return OSInfo{Like: []string{}}
}

func parseOSRelease(data string) OSInfo {
	values := map[string]string{}
	for _, line := range strings.Split(data, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		values[key] = unquoteShell(value)
	}
	info := OSInfo{
		ID:        optionalString(values["ID"]),
		VersionID: optionalString(values["VERSION_ID"]),
		Codename:  optionalString(values["VERSION_CODENAME"]),
		Name:      optionalString(values["PRETTY_NAME"]),
		Like:      strings.Fields(values["ID_LIKE"]),
	}
	if info.Like == nil {
		info.Like = []string{}
	}
	return info
}

func unquoteShell(value string) string {
	value = strings.TrimSpace(value)
	if len(value) >= 2 && value[0] == '\'' && value[len(value)-1] == '\'' {
		return value[1 : len(value)-1]
	}
	if len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"' {
		value = value[1 : len(value)-1]
	}
	var out strings.Builder
	for i := 0; i < len(value); i++ {
		if value[i] == '\\' && i+1 < len(value) {
			i++
		}
		out.WriteByte(value[i])
	}
	return out.String()
}
