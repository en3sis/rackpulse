package history

import (
	"encoding/json"
	"errors"
	"math"
	"math/bits"
	"os"
	"strconv"
	"sync"

	"github.com/en3sis/rackpulse/agent/internal/atomicfile"
	"github.com/en3sis/rackpulse/agent/internal/collect"
)

const (
	RetentionSeconds = 31 * 86400
	minuteRetention  = 86400
	fineStep         = 60
	coarseStep       = 300
)

type Sample struct {
	T              int64    `json:"t"`
	Memory         float64  `json:"memory"`
	Swap           float64  `json:"swap"`
	Disk           float64  `json:"disk"`
	Load           float64  `json:"load"`
	CPU            *float64 `json:"cpu,omitempty"`
	DiskReadIOPS   *float64 `json:"diskReadIOPS,omitempty"`
	DiskWriteIOPS  *float64 `json:"diskWriteIOPS,omitempty"`
	DiskReadBytes  *float64 `json:"diskReadBytes,omitempty"`
	DiskWriteBytes *float64 `json:"diskWriteBytes,omitempty"`
	NetInBytes     *float64 `json:"netInBytes,omitempty"`
	NetOutBytes    *float64 `json:"netOutBytes,omitempty"`
}

type Host struct {
	mu            sync.Mutex
	coverageStart int64
	hours         map[int64]uint64
	minutes       []Sample
	fiveMinutes   []Sample
}

type hostFile struct {
	CoverageStart int64             `json:"coverageStart"`
	Hours         map[string]uint64 `json:"hours"`
	Minutes       []Sample          `json:"minutes"`
	FiveMinutes   []Sample          `json:"fiveMinutes"`
}

type HostResponse struct {
	Time          int64          `json:"time"`
	CoverageStart int64          `json:"coverageStart"`
	Hours         map[string]int `json:"hours"`
	Step          int            `json:"step"`
	Samples       []Sample       `json:"samples"`
}

func NewHost(coverageStart int64) *Host {
	return &Host{coverageStart: coverageStart, hours: map[int64]uint64{}}
}

func LoadHost(path string) (*Host, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var file hostFile
	if err := json.Unmarshal(data, &file); err != nil {
		return nil, err
	}
	if file.CoverageStart <= 0 {
		return nil, errors.New("history has no coverage start")
	}
	history := NewHost(file.CoverageStart)
	for key, mask := range file.Hours {
		hour, err := strconv.ParseInt(key, 10, 64)
		if err == nil && hour%3600 == 0 {
			history.hours[hour] |= mask & fullHourMask
		}
	}
	history.minutes = file.Minutes
	history.fiveMinutes = file.FiveMinutes
	return history, nil
}

const fullHourMask = uint64(1)<<60 - 1

func (h *Host) Save(path string) error {
	h.mu.Lock()
	file := hostFile{
		CoverageStart: h.coverageStart,
		Hours:         make(map[string]uint64, len(h.hours)),
		Minutes:       h.minutes,
		FiveMinutes:   h.fiveMinutes,
	}
	for hour, mask := range h.hours {
		file.Hours[strconv.FormatInt(hour, 10)] = mask
	}
	data, err := json.Marshal(file)
	h.mu.Unlock()
	if err != nil {
		return err
	}
	return atomicfile.Write(path, data, 0o600)
}

func (h *Host) MarkMinute(t int64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.markLocked(t)
}

func (h *Host) markLocked(t int64) {
	minute := t - t%60
	hour := minute - minute%3600
	h.hours[hour] |= 1 << uint((minute-hour)/60)
}

func (h *Host) MarkRange(from, to, now int64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if earliest := now - RetentionSeconds; from < earliest {
		from = earliest
	}
	if to > now {
		to = now
	}
	for t := from - from%60; t <= to; t += 60 {
		h.markLocked(t)
	}
}

func (h *Host) LowerCoverageStart(t int64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if t > 0 && t < h.coverageStart {
		h.coverageStart = t
	}
}

func (h *Host) Prune(now int64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.pruneLocked(now)
}

func retentionCutoff(now int64) int64 {
	cutoff := now - RetentionSeconds
	return cutoff - cutoff%3600
}

func (h *Host) pruneLocked(now int64) {
	cutoff := retentionCutoff(now)
	for hour := range h.hours {
		if hour < cutoff {
			delete(h.hours, hour)
		}
	}
	h.minutes = dropBefore(h.minutes, now-minuteRetention)
	h.fiveMinutes = dropBefore(h.fiveMinutes, now-RetentionSeconds)
}

func (h *Host) AddSample(sample Sample, now int64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	sample.T -= sample.T % fineStep
	h.minutes = appendMinute(h.minutes, sample)
	h.fiveMinutes = rollUp(h.minutes, h.fiveMinutes, sample.T-sample.T%coarseStep, averageSamples)
	h.pruneLocked(now)
}

func averageSamples(bucket int64, group []Sample) Sample {
	var sum Sample
	for _, sample := range group {
		sum.Memory += sample.Memory
		sum.Swap += sample.Swap
		sum.Disk += sample.Disk
		sum.Load += sample.Load
	}
	count := float64(len(group))
	field := func(get func(Sample) *float64) *float64 {
		total, n := 0.0, 0
		for _, sample := range group {
			if value := get(sample); value != nil {
				total += *value
				n++
			}
		}
		if n == 0 {
			return nil
		}
		value := roundTo(total/float64(n), 2)
		return &value
	}
	return Sample{
		T:              bucket,
		Memory:         roundTo(sum.Memory/count, 4),
		Swap:           roundTo(sum.Swap/count, 4),
		Disk:           roundTo(sum.Disk/count, 4),
		Load:           roundTo(sum.Load/count, 2),
		CPU:            field(func(s Sample) *float64 { return s.CPU }),
		DiskReadIOPS:   field(func(s Sample) *float64 { return s.DiskReadIOPS }),
		DiskWriteIOPS:  field(func(s Sample) *float64 { return s.DiskWriteIOPS }),
		DiskReadBytes:  field(func(s Sample) *float64 { return s.DiskReadBytes }),
		DiskWriteBytes: field(func(s Sample) *float64 { return s.DiskWriteBytes }),
		NetInBytes:     field(func(s Sample) *float64 { return s.NetInBytes }),
		NetOutBytes:    field(func(s Sample) *float64 { return s.NetOutBytes }),
	}
}

func (h *Host) Query(since, now int64) HostResponse {
	h.mu.Lock()
	defer h.mu.Unlock()
	coverage := h.coverageStart
	if cutoff := retentionCutoff(now); coverage < cutoff {
		coverage = cutoff
	}
	response := HostResponse{Time: now, CoverageStart: coverage, Hours: map[string]int{}}
	for hour, mask := range h.hours {
		if hour >= since && mask != 0 {
			response.Hours[strconv.FormatInt(hour, 10)] = bits.OnesCount64(mask)
		}
	}
	source := h.fiveMinutes
	response.Step = coarseStep
	if since >= now-minuteRetention {
		source = h.minutes
		response.Step = fineStep
	}
	response.Samples = samplesSince(source, since)
	return response
}

func roundTo(value float64, places int) float64 {
	if math.IsNaN(value) || math.IsInf(value, 0) {
		return 0
	}
	scale := math.Pow(10, float64(places))
	return math.Round(value*scale) / scale
}

func SampleFrom(snapshot collect.Snapshot) Sample {
	sample := Sample{T: snapshot.Time, Load: roundTo(snapshot.Host.Load[0], 2)}
	if memory := snapshot.Memory; memory.Total > 0 {
		sample.Memory = roundTo(1-float64(memory.Available)/float64(memory.Total), 4)
		if memory.SwapTotal > 0 {
			sample.Swap = roundTo(float64(memory.SwapTotal-memory.SwapFree)/float64(memory.SwapTotal), 4)
		}
	}
	if activity := snapshot.Activity; activity != nil {
		value := func(v float64) *float64 { return &v }
		sample.CPU = value(activity.CPU)
		sample.DiskReadIOPS = value(activity.DiskReadIOPS)
		sample.DiskWriteIOPS = value(activity.DiskWriteIOPS)
		sample.DiskReadBytes = value(activity.DiskReadBytes)
		sample.DiskWriteBytes = value(activity.DiskWriteBytes)
		sample.NetInBytes = value(activity.NetInBytes)
		sample.NetOutBytes = value(activity.NetOutBytes)
	}
	for _, disk := range snapshot.Disks {
		if capacity := disk.Used + disk.Available; capacity > 0 {
			sample.Disk = max(sample.Disk, roundTo(float64(disk.Used)/float64(capacity), 4))
		}
	}
	return sample
}
