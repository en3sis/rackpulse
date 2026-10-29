package collect

import (
	"math"
	"os"
	"strconv"
	"strings"
	"time"
)

type Activity struct {
	CPU            float64 `json:"cpu"`
	DiskReadIOPS   float64 `json:"diskReadIOPS"`
	DiskWriteIOPS  float64 `json:"diskWriteIOPS"`
	DiskReadBytes  float64 `json:"diskReadBytes"`
	DiskWriteBytes float64 `json:"diskWriteBytes"`
	NetInBytes     float64 `json:"netInBytes"`
	NetOutBytes    float64 `json:"netOutBytes"`
}

type counters struct {
	at                                  time.Time
	cpuBusy, cpuTotal                   uint64
	reads, writes, readSectors, written uint64
	netIn, netOut                       uint64
}

type activityMeter struct {
	previous *counters
}

const sectorBytes = 512

func (m *activityMeter) next(now time.Time) *Activity {
	current := readCounters(now)
	previous := m.previous
	m.previous = current
	if previous == nil || current == nil {
		return nil
	}
	return rates(*previous, *current)
}

func rates(before, after counters) *Activity {
	seconds := after.at.Sub(before.at).Seconds()
	if seconds < 1 || after.cpuTotal <= before.cpuTotal || after.cpuBusy < before.cpuBusy {
		return nil
	}
	perSecond := func(a, b uint64) float64 {
		if b < a {
			return 0
		}
		return round2(float64(b-a) / seconds)
	}
	return &Activity{
		CPU:            round2(100 * float64(after.cpuBusy-before.cpuBusy) / float64(after.cpuTotal-before.cpuTotal)),
		DiskReadIOPS:   perSecond(before.reads, after.reads),
		DiskWriteIOPS:  perSecond(before.writes, after.writes),
		DiskReadBytes:  perSecond(before.readSectors*sectorBytes, after.readSectors*sectorBytes),
		DiskWriteBytes: perSecond(before.written*sectorBytes, after.written*sectorBytes),
		NetInBytes:     perSecond(before.netIn, after.netIn),
		NetOutBytes:    perSecond(before.netOut, after.netOut),
	}
}

func round2(value float64) float64 {
	return math.Round(value*100) / 100
}

func readCounters(now time.Time) *counters {
	stat, err := os.ReadFile("/proc/stat")
	if err != nil {
		return nil
	}
	busy, total, ok := parseCPU(string(stat))
	if !ok {
		return nil
	}
	result := counters{at: now, cpuBusy: busy, cpuTotal: total}
	if data, err := os.ReadFile("/proc/diskstats"); err == nil {
		result.reads, result.writes, result.readSectors, result.written = parseDiskstats(string(data), isWholeDisk)
	}
	if data, err := os.ReadFile("/proc/net/dev"); err == nil {
		result.netIn, result.netOut = parseNetDev(string(data), isNetworkCard)
	}
	return &result
}

func parseCPU(stat string) (busy, total uint64, ok bool) {
	for _, line := range strings.Split(stat, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 || fields[0] != "cpu" {
			continue
		}
		for index, field := range fields[1:] {
			if index >= 8 {
				break
			}
			value, err := strconv.ParseUint(field, 10, 64)
			if err != nil {
				return 0, 0, false
			}
			total += value
			if index != 3 && index != 4 {
				busy += value
			}
		}
		return busy, total, total > 0
	}
	return 0, 0, false
}

func parseDiskstats(data string, include func(string) bool) (reads, writes, readSectors, written uint64) {
	for _, line := range strings.Split(data, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 10 || !include(fields[2]) {
			continue
		}
		reads += parseCounter(fields[3])
		readSectors += parseCounter(fields[5])
		writes += parseCounter(fields[7])
		written += parseCounter(fields[9])
	}
	return
}

func parseNetDev(data string, include func(string) bool) (in, out uint64) {
	for _, line := range strings.Split(data, "\n") {
		name, rest, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		name = strings.TrimSpace(name)
		fields := strings.Fields(rest)
		if len(fields) < 9 || !include(name) {
			continue
		}
		in += parseCounter(fields[0])
		out += parseCounter(fields[8])
	}
	return
}

func parseCounter(text string) uint64 {
	value, _ := strconv.ParseUint(text, 10, 64)
	return value
}

func isWholeDisk(name string) bool {
	_, err := os.Stat("/sys/block/" + strings.ReplaceAll(name, "/", "!") + "/device")
	return err == nil
}

func isNetworkCard(name string) bool {
	if name == "lo" {
		return false
	}
	_, err := os.Stat("/sys/class/net/" + name + "/device")
	return err == nil
}
