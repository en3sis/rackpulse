package collect

import (
	"bufio"
	"errors"
	"os"
	"runtime"
	"strconv"
	"strings"
)

type HostInfo struct {
	Hostname  string         `json:"hostname"`
	OS        string         `json:"os"`
	Kernel    string         `json:"kernel"`
	Arch      string         `json:"arch"`
	ServerID  *int64         `json:"serverID"`
	BootTime  int64          `json:"bootTime"`
	Cores     int            `json:"cores"`
	Load      [3]float64     `json:"load"`
	Tailscale *TailscaleInfo `json:"tailscale,omitempty"`
}

type MemoryInfo struct {
	Total     int64 `json:"total"`
	Available int64 `json:"available"`
	SwapTotal int64 `json:"swapTotal"`
	SwapFree  int64 `json:"swapFree"`
}

func readHost() HostInfo {
	host := HostInfo{
		Arch:   runtime.GOARCH,
		Cores:  runtime.NumCPU(),
		OS:     prettyName(),
		Kernel: readTrimmed("/proc/sys/kernel/osrelease"),
	}
	host.Hostname, _ = os.Hostname()
	host.BootTime, _ = BootTime()
	host.Load, _ = loadAverage()
	return host
}

func readTrimmed(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func prettyName() string {
	for _, path := range []string{"/etc/os-release", "/usr/lib/os-release"} {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			if value, ok := strings.CutPrefix(line, "PRETTY_NAME="); ok {
				return unquote(strings.TrimSpace(value))
			}
		}
	}
	return "Linux"
}

func unquote(value string) string {
	if len(value) >= 2 && (value[0] == '"' || value[0] == '\'') && value[len(value)-1] == value[0] {
		value = value[1 : len(value)-1]
	}
	return strings.ReplaceAll(value, `\"`, `"`)
}

func BootTime() (int64, error) {
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if value, ok := strings.CutPrefix(line, "btime "); ok {
			return strconv.ParseInt(strings.TrimSpace(value), 10, 64)
		}
	}
	return 0, errors.New("btime not found in /proc/stat")
}

func loadAverage() ([3]float64, error) {
	var load [3]float64
	data, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return load, err
	}
	fields := strings.Fields(string(data))
	if len(fields) < 3 {
		return load, errors.New("unexpected /proc/loadavg")
	}
	for i := range 3 {
		load[i], _ = strconv.ParseFloat(fields[i], 64)
	}
	return load, nil
}

func readMemory() (MemoryInfo, error) {
	var mem MemoryInfo
	file, err := os.Open("/proc/meminfo")
	if err != nil {
		return mem, err
	}
	defer file.Close()
	targets := map[string]*int64{
		"MemTotal":     &mem.Total,
		"MemAvailable": &mem.Available,
		"SwapTotal":    &mem.SwapTotal,
		"SwapFree":     &mem.SwapFree,
	}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		name, rest, ok := strings.Cut(scanner.Text(), ":")
		target, wanted := targets[name]
		if !ok || !wanted {
			continue
		}
		fields := strings.Fields(rest)
		if len(fields) == 0 {
			continue
		}
		value, err := strconv.ParseInt(fields[0], 10, 64)
		if err != nil {
			continue
		}
		if len(fields) > 1 && fields[1] == "kB" {
			value *= 1024
		}
		*target = value
	}
	return mem, scanner.Err()
}
