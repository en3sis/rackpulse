package security

import "strings"

func CompareVersions(a, b string) int {
	epochA, upstreamA, revisionA := splitVersion(a)
	epochB, upstreamB, revisionB := splitVersion(b)
	if epochA != epochB {
		if epochA < epochB {
			return -1
		}
		return 1
	}
	if result := compareSegment(upstreamA, upstreamB); result != 0 {
		return result
	}
	return compareSegment(revisionA, revisionB)
}

func splitVersion(version string) (int, string, string) {
	version = strings.TrimSpace(version)
	epoch := 0
	if head, rest, ok := strings.Cut(version, ":"); ok {
		valid := head != ""
		value := 0
		for _, r := range head {
			if r < '0' || r > '9' {
				valid = false
				break
			}
			value = value*10 + int(r-'0')
		}
		if valid {
			epoch = value
			version = rest
		}
	}
	upstream, revision := version, ""
	if index := strings.LastIndexByte(version, '-'); index >= 0 {
		upstream, revision = version[:index], version[index+1:]
	}
	return epoch, upstream, revision
}

func isDigit(c byte) bool {
	return c >= '0' && c <= '9'
}

func isLetter(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

func order(s string, i int) int {
	if i >= len(s) {
		return 0
	}
	c := s[i]
	switch {
	case isDigit(c):
		return 0
	case isLetter(c):
		return int(c)
	case c == '~':
		return -1
	}
	return int(c) + 256
}

func compareSegment(a, b string) int {
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		for i < len(a) && !isDigit(a[i]) || j < len(b) && !isDigit(b[j]) {
			if ac, bc := order(a, i), order(b, j); ac != bc {
				return sign(ac - bc)
			}
			i++
			j++
		}
		for i < len(a) && a[i] == '0' {
			i++
		}
		for j < len(b) && b[j] == '0' {
			j++
		}
		firstDiff := 0
		for i < len(a) && isDigit(a[i]) && j < len(b) && isDigit(b[j]) {
			if firstDiff == 0 {
				firstDiff = int(a[i]) - int(b[j])
			}
			i++
			j++
		}
		if i < len(a) && isDigit(a[i]) {
			return 1
		}
		if j < len(b) && isDigit(b[j]) {
			return -1
		}
		if firstDiff != 0 {
			return sign(firstDiff)
		}
	}
	return 0
}

func sign(value int) int {
	switch {
	case value < 0:
		return -1
	case value > 0:
		return 1
	}
	return 0
}
