package security

import "io"

const apkInstalledPath = "/lib/apk/db/installed"

func parseApkInstalled(r io.Reader) ([]Package, error) {
	items := []Package{}
	err := parseStanzas(r, func(fields map[string]string) bool {
		name, version := fields["P"], fields["V"]
		if name == "" || version == "" {
			return true
		}
		source := fields["o"]
		if source == "" {
			source = name
		}
		items = append(items, Package{Name: name, Version: version, Source: source, SourceVersion: version, Arch: fields["A"]})
		return len(items) < packageLimit
	})
	sortPackages(items)
	return items, err
}
