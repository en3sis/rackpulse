package collect

import (
	"context"
	"encoding/json"
	"log"
	"math"
	"sync"
	"time"
)

type Snapshot struct {
	Version string      `json:"version"`
	Time    int64       `json:"time"`
	Host    HostInfo    `json:"host"`
	Memory  MemoryInfo  `json:"memory"`
	Disks   []Disk      `json:"disks"`
	System  SystemInfo  `json:"system"`
	Docker  *DockerInfo `json:"docker"`
}

type Collector struct {
	version string
	docker  *dockerCollector

	mu        sync.Mutex
	serverID  *int64
	tailscale string
	snapshot  []byte
	ready     chan struct{}
	readyOnce sync.Once
	lastError string

	diskTried     chan struct{}
	serverIDTried chan struct{}
}

func New(version, tailscaleName string) *Collector {
	return &Collector{
		version:       version,
		tailscale:     tailscaleName,
		docker:        newDockerCollector(),
		ready:         make(chan struct{}),
		diskTried:     make(chan struct{}),
		serverIDTried: make(chan struct{}),
	}
}

func (c *Collector) Ready() <-chan struct{} {
	return c.ready
}

func (c *Collector) Latest() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.snapshot
}

func (c *Collector) Run(ctx context.Context, onSnapshot func(Snapshot)) {
	go c.serverIDLoop(ctx)
	go c.diskLoop(ctx)
	deadline := time.After(10 * time.Second)
	for _, tried := range []chan struct{}{c.serverIDTried, c.diskTried} {
		select {
		case <-tried:
		case <-deadline:
		case <-ctx.Done():
			return
		}
	}
	c.collect(ctx, onSnapshot)
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.collect(ctx, onSnapshot)
		}
	}
}

func (c *Collector) collect(ctx context.Context, onSnapshot func(Snapshot)) {
	snapshot := Snapshot{
		Version: c.version,
		Time:    time.Now().Unix(),
		Host:    readHost(),
		Disks:   readDisks(),
		System:  readSystem(ctx),
	}
	memory, err := readMemory()
	if err != nil {
		log.Printf("Reading memory failed: %v", err)
	}
	snapshot.Memory = memory
	snapshot.Docker = c.docker.collect(ctx, memory.Total)
	c.logDockerError(snapshot.Docker)

	c.mu.Lock()
	snapshot.Host.ServerID = c.serverID
	c.mu.Unlock()
	snapshot.Host.Tailscale = tailscaleInfo(c.tailscale)

	data, err := json.Marshal(snapshot)
	if err != nil {
		log.Printf("Encoding snapshot failed: %v", err)
		return
	}
	c.mu.Lock()
	c.snapshot = data
	c.mu.Unlock()
	c.readyOnce.Do(func() { close(c.ready) })
	if onSnapshot != nil {
		onSnapshot(snapshot)
	}
}

func (c *Collector) logDockerError(info *DockerInfo) {
	message := ""
	if info != nil && info.Error != nil {
		message = *info.Error
	}
	if message != c.lastError && message != "" {
		log.Printf("Docker: %s", message)
	}
	c.lastError = message
}

func (c *Collector) diskLoop(ctx context.Context) {
	first := true
	for {
		if err := c.docker.refreshDisk(ctx); err != nil {
			log.Printf("Docker disk usage: %s", dockerErrorMessage(err))
		}
		if first {
			close(c.diskTried)
			first = false
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(15 * time.Minute):
		}
	}
}

func (c *Collector) serverIDLoop(ctx context.Context) {
	first := true
	for {
		id, err := FetchServerID(ctx)
		if err == nil {
			c.mu.Lock()
			c.serverID = &id
			c.mu.Unlock()
		}
		if first {
			close(c.serverIDTried)
			first = false
		}
		if err == nil {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(10 * time.Minute):
		}
	}
}

func round(value float64, places int) float64 {
	if math.IsNaN(value) || math.IsInf(value, 0) {
		return 0
	}
	scale := math.Pow(10, float64(places))
	return math.Round(value*scale) / scale
}
