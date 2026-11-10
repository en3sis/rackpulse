package security

import (
	"bufio"
	"io"
	"sort"
	"strings"
)

const (
	dpkgStatusPath = "/var/lib/dpkg/status"
	packageLimit   = 20000
)

func parseStanzas(r io.Reader, visit func(map[string]string) bool) error {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64<<10), 4<<20)
	fields := map[string]string{}
	flush := func() bool {
		if len(fields) == 0 {
			return true
		}
		keep := visit(fields)
		fields = map[string]string{}
		return keep
	}
	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			if !flush() {
				return nil
			}
			continue
		}
		if line[0] == ' ' || line[0] == '\t' {
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		fields[key] = strings.TrimSpace(value)
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	flush()
	return nil
}

func parseDpkgStatus(r io.Reader) ([]Package, error) {
	items, err := appendDpkg([]Package{}, r, false)
	sortPackages(items)
	return items, err
}

func appendDpkg(items []Package, r io.Reader, statusOptional bool) ([]Package, error) {
	if len(items) >= packageLimit {
		return items, nil
	}
	err := parseStanzas(r, func(fields map[string]string) bool {
		status, hasStatus := fields["Status"]
		installed := dpkgInstalled(status) || (statusOptional && !hasStatus)
		if !installed || fields["Package"] == "" || fields["Version"] == "" {
			return true
		}
		item := Package{
			Name:          fields["Package"],
			Version:       fields["Version"],
			Source:        fields["Package"],
			SourceVersion: fields["Version"],
			Arch:          fields["Architecture"],
		}
		if source := fields["Source"]; source != "" {
			name, version, ok := strings.Cut(source, " ")
			item.Source = name
			if ok {
				if version = strings.Trim(strings.TrimSpace(version), "()"); version != "" {
					item.SourceVersion = version
				}
			}
		}
		items = append(items, item)
		return len(items) < packageLimit
	})
	return items, err
}

func dpkgInstalled(status string) bool {
	fields := strings.Fields(status)
	return len(fields) == 3 && (fields[0] == "install" || fields[0] == "hold") && fields[1] == "ok" && fields[2] == "installed"
}

func sortPackages(items []Package) {
	sort.Slice(items, func(i, j int) bool {
		if items[i].Name != items[j].Name {
			return items[i].Name < items[j].Name
		}
		return items[i].Arch < items[j].Arch
	})
}
