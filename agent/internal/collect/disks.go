package collect

import (
	"os"
	"sort"
	"strconv"
	"strings"
	"syscall"
)

type Disk struct {
	Mount       string `json:"mount"`
	Device      string `json:"device"`
	FS          string `json:"fs"`
	Total       int64  `json:"total"`
	Used        int64  `json:"used"`
	Available   int64  `json:"available"`
	InodesTotal int64  `json:"inodesTotal"`
	InodesUsed  int64  `json:"inodesUsed"`
	ReadOnly    bool   `json:"readOnly"`
	Kind        string `json:"kind,omitempty"`
	Model       string `json:"model,omitempty"`
}

type mountEntry struct {
	Mount    string
	Device   string
	FS       string
	ReadOnly bool
}

func parseMountinfo(data string) []mountEntry {
	byDevice := map[string]mountEntry{}
	for _, line := range strings.Split(data, "\n") {
		fields := strings.Fields(line)
		separator := -1
		for i, field := range fields {
			if field == "-" {
				separator = i
				break
			}
		}
		if separator < 6 || separator+3 >= len(fields) {
			continue
		}
		mount := unescapeMountPath(fields[4])
		fsType := fields[separator+1]
		source := fields[separator+2]
		if !strings.HasPrefix(source, "/dev/") || fsType == "squashfs" {
			continue
		}
		entry := mountEntry{Mount: mount, Device: source, FS: fsType, ReadOnly: hasOption(fields[separator+3], "ro")}
		if existing, ok := byDevice[source]; ok && !shorterMount(mount, existing.Mount) {
			continue
		}
		byDevice[source] = entry
	}
	entries := make([]mountEntry, 0, len(byDevice))
	for _, entry := range byDevice {
		entries = append(entries, entry)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Mount < entries[j].Mount })
	return entries
}

func shorterMount(candidate, current string) bool {
	if len(candidate) != len(current) {
		return len(candidate) < len(current)
	}
	return candidate < current
}

func hasOption(options, option string) bool {
	for _, value := range strings.Split(options, ",") {
		if value == option {
			return true
		}
	}
	return false
}

func unescapeMountPath(path string) string {
	if !strings.Contains(path, `\`) {
		return path
	}
	var out strings.Builder
	for i := 0; i < len(path); i++ {
		if path[i] == '\\' && i+3 < len(path) {
			if value, err := strconv.ParseUint(path[i+1:i+4], 8, 8); err == nil {
				out.WriteByte(byte(value))
				i += 3
				continue
			}
		}
		out.WriteByte(path[i])
	}
	return out.String()
}

func readDisks() []Disk {
	disks := []Disk{}
	data, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return disks
	}
	for _, entry := range parseMountinfo(string(data)) {
		var stat syscall.Statfs_t
		if err := syscall.Statfs(entry.Mount, &stat); err != nil {
			continue
		}
		size := int64(stat.Bsize)
		var info syscall.Stat_t
		var dev uint64
		if syscall.Stat(entry.Mount, &info) == nil {
			dev = uint64(info.Dev)
		}
		media := describeStorage("/sys", entry.Device, dev)
		disks = append(disks, Disk{
			Mount:       entry.Mount,
			Device:      media.Device,
			Kind:        media.Kind,
			Model:       media.Model,
			FS:          entry.FS,
			Total:       int64(stat.Blocks) * size,
			Used:        int64(stat.Blocks-stat.Bfree) * size,
			Available:   int64(stat.Bavail) * size,
			InodesTotal: int64(stat.Files),
			InodesUsed:  int64(stat.Files - stat.Ffree),
			ReadOnly:    entry.ReadOnly,
		})
	}
	return disks
}
