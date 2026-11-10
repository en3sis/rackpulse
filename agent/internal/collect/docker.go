package collect

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/user"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const dockerSocket = "/var/run/docker.sock"

type DockerInfo struct {
	Error       *string     `json:"error"`
	Containers  []Container `json:"containers"`
	Volumes     []Volume    `json:"volumes"`
	VolumesTime *int64      `json:"volumesTime"`
	Disk        *DockerDisk `json:"disk"`
}

type DockerDisk struct {
	Images                int64 `json:"images"`
	ImagesReclaimable     int64 `json:"imagesReclaimable"`
	BuildCache            int64 `json:"buildCache"`
	BuildCacheReclaimable int64 `json:"buildCacheReclaimable"`
	Volumes               int64 `json:"volumes"`
	VolumesReclaimable    int64 `json:"volumesReclaimable"`
	Containers            int64 `json:"containers"`
}

type Container struct {
	ID               string   `json:"id"`
	Name             string   `json:"name"`
	Image            string   `json:"image"`
	Project          *string  `json:"project"`
	State            string   `json:"state"`
	Health           *string  `json:"health"`
	ExitCode         int      `json:"exitCode"`
	StartedAt        *int64   `json:"startedAt"`
	FinishedAt       *int64   `json:"finishedAt"`
	RestartCount     int      `json:"restartCount"`
	RestartsLastHour int      `json:"restartsLastHour"`
	CPU              *float64 `json:"cpu"`
	Memory           *int64   `json:"memory"`
	MemoryLimit      *int64   `json:"memoryLimit"`
	CreatedAt        int64    `json:"createdAt"`
	Ports            []Port   `json:"ports"`
	Mounts           []Mount  `json:"mounts"`
	Networks         []string `json:"networks"`
	HealthLog        *Health  `json:"healthLog"`
}

type Port struct {
	Private int     `json:"private"`
	Public  *int    `json:"public"`
	Type    string  `json:"type"`
	IP      *string `json:"ip"`
}

type Mount struct {
	Type        string  `json:"type"`
	Name        *string `json:"name"`
	Source      *string `json:"source"`
	Destination string  `json:"destination"`
	ReadOnly    bool    `json:"readOnly"`
}

type Health struct {
	ExitCode int    `json:"exitCode"`
	Output   string `json:"output"`
	Time     int64  `json:"time"`
}

type Volume struct {
	Name       string `json:"name"`
	Size       int64  `json:"size"`
	Containers int    `json:"containers"`
}

type cpuReading struct {
	container uint64
	system    uint64
}

type restartReading struct {
	time  time.Time
	count int
}

type dockerCollector struct {
	client   *http.Client
	cpu      map[string]cpuReading
	restarts map[string][]restartReading

	volumesMu   sync.Mutex
	disk        *DockerDisk
	volumes     []Volume
	volumesTime *int64
}

func newDockerCollector() *dockerCollector {
	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var dialer net.Dialer
			return dialer.DialContext(ctx, "unix", dockerSocket)
		},
		MaxIdleConns:    8,
		IdleConnTimeout: 90 * time.Second,
	}
	return &dockerCollector{
		client:   &http.Client{Transport: transport},
		cpu:      map[string]cpuReading{},
		restarts: map[string][]restartReading{},
		volumes:  []Volume{},
	}
}

func dockerInstalled() bool {
	_, err := os.Stat(dockerSocket)
	return err == nil
}

func (d *dockerCollector) get(ctx context.Context, path string, target any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker"+path, nil)
	if err != nil {
		return err
	}
	resp, err := d.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		return &APIError{Code: resp.StatusCode, Status: resp.Status, Path: strings.SplitN(path, "?", 2)[0]}
	}
	return json.NewDecoder(resp.Body).Decode(target)
}

type APIError struct {
	Code   int
	Status string
	Path   string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("Docker API returned %s for %s", e.Status, e.Path)
}

func dockerErrorMessage(err error) string {
	switch {
	case errors.Is(err, syscall.EACCES), errors.Is(err, syscall.EPERM):
		if !inDockerGroup() {
			return "Docker access is off. The rackpulse user is not in the docker group"
		}
		return "Permission denied on " + dockerSocket
	case errors.Is(err, syscall.ECONNREFUSED), errors.Is(err, syscall.ENOENT):
		return "Docker is not running"
	case errors.Is(err, context.DeadlineExceeded):
		return "Docker did not answer in time"
	}
	return err.Error()
}

func inDockerGroup() bool {
	group, err := user.LookupGroup("docker")
	if err != nil {
		return true
	}
	gid, err := strconv.Atoi(group.Gid)
	if err != nil {
		return true
	}
	if os.Getegid() == gid {
		return true
	}
	groups, err := os.Getgroups()
	if err != nil {
		return true
	}
	for _, id := range groups {
		if id == gid {
			return true
		}
	}
	return false
}

type listedContainer struct {
	ID      string            `json:"Id"`
	Names   []string          `json:"Names"`
	Image   string            `json:"Image"`
	State   string            `json:"State"`
	Labels  map[string]string `json:"Labels"`
	Created int64             `json:"Created"`
	Ports   []struct {
		IP          string `json:"IP"`
		PrivatePort int    `json:"PrivatePort"`
		PublicPort  int    `json:"PublicPort"`
		Type        string `json:"Type"`
	} `json:"Ports"`
}

type inspectedContainer struct {
	Name         string `json:"Name"`
	RestartCount int    `json:"RestartCount"`
	State        struct {
		Status     string `json:"Status"`
		ExitCode   int    `json:"ExitCode"`
		StartedAt  string `json:"StartedAt"`
		FinishedAt string `json:"FinishedAt"`
		Health     *struct {
			Status string `json:"Status"`
			Log    []struct {
				Start    string `json:"Start"`
				End      string `json:"End"`
				ExitCode int    `json:"ExitCode"`
				Output   string `json:"Output"`
			} `json:"Log"`
		} `json:"Health"`
	} `json:"State"`
	Mounts []struct {
		Type        string `json:"Type"`
		Name        string `json:"Name"`
		Source      string `json:"Source"`
		Destination string `json:"Destination"`
		RW          bool   `json:"RW"`
	} `json:"Mounts"`
	HostConfig struct {
		Tmpfs map[string]string `json:"Tmpfs"`
	} `json:"HostConfig"`
	NetworkSettings struct {
		Networks map[string]json.RawMessage `json:"Networks"`
	} `json:"NetworkSettings"`
}

type containerStats struct {
	MemoryStats struct {
		Usage uint64            `json:"usage"`
		Limit uint64            `json:"limit"`
		Stats map[string]uint64 `json:"stats"`
	} `json:"memory_stats"`
	CPUStats struct {
		CPUUsage struct {
			TotalUsage uint64 `json:"total_usage"`
		} `json:"cpu_usage"`
		SystemCPUUsage uint64 `json:"system_cpu_usage"`
	} `json:"cpu_stats"`
}

func (d *dockerCollector) collect(ctx context.Context, hostMemory int64) *DockerInfo {
	if !dockerInstalled() {
		return nil
	}
	info := &DockerInfo{Containers: []Container{}, Volumes: []Volume{}}
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	var listed []listedContainer
	if err := d.get(ctx, "/containers/json?all=1", &listed); err != nil {
		message := dockerErrorMessage(err)
		info.Error = &message
		return info
	}
	now := time.Now()
	containers := make([]Container, len(listed))
	limit := make(chan struct{}, 8)
	var wg sync.WaitGroup
	var mu sync.Mutex
	seen := map[string]bool{}
	for i, item := range listed {
		seen[item.ID] = true
		wg.Add(1)
		go func(i int, item listedContainer) {
			defer wg.Done()
			limit <- struct{}{}
			defer func() { <-limit }()
			container, stats := d.describe(ctx, item, hostMemory)
			mu.Lock()
			defer mu.Unlock()
			if stats != nil {
				d.applyCPU(&container, stats)
			}
			container.RestartsLastHour = d.trackRestarts(item.ID, container.RestartCount, now)
			containers[i] = container
		}(i, item)
	}
	wg.Wait()
	for id := range d.cpu {
		if !seen[id] {
			delete(d.cpu, id)
		}
	}
	for id := range d.restarts {
		if !seen[id] {
			delete(d.restarts, id)
		}
	}
	info.Containers = containers
	d.volumesMu.Lock()
	info.Volumes = d.volumes
	info.VolumesTime = d.volumesTime
	info.Disk = d.disk
	d.volumesMu.Unlock()
	return info
}

func (d *dockerCollector) describe(ctx context.Context, item listedContainer, hostMemory int64) (Container, *containerStats) {
	container := Container{
		ID:        item.ID,
		Image:     item.Image,
		State:     item.State,
		CreatedAt: item.Created,
		Ports:     listedPorts(item),
		Mounts:    []Mount{},
		Networks:  []string{},
	}
	if len(item.Names) > 0 {
		container.Name = strings.TrimPrefix(item.Names[0], "/")
	}
	if project, ok := item.Labels["com.docker.compose.project"]; ok && project != "" {
		container.Project = &project
	}
	var inspected inspectedContainer
	if err := d.get(ctx, "/containers/"+url.PathEscape(item.ID)+"/json", &inspected); err == nil {
		if inspected.Name != "" {
			container.Name = strings.TrimPrefix(inspected.Name, "/")
		}
		if inspected.State.Status != "" {
			container.State = inspected.State.Status
		}
		container.RestartCount = inspected.RestartCount
		container.ExitCode = inspected.State.ExitCode
		container.StartedAt = dockerTime(inspected.State.StartedAt)
		container.FinishedAt = dockerTime(inspected.State.FinishedAt)
		if health := inspected.State.Health; health != nil {
			switch status := health.Status; status {
			case "healthy", "unhealthy", "starting":
				container.Health = &status
			}
			if n := len(health.Log); n > 0 {
				container.HealthLog = healthEntry(health.Log[n-1].Start, health.Log[n-1].End, health.Log[n-1].ExitCode, health.Log[n-1].Output)
			}
		}
		container.Mounts = inspectedMounts(inspected)
		container.Networks = sortedKeys(inspected.NetworkSettings.Networks)
	}
	if container.State != "running" {
		return container, nil
	}
	var stats containerStats
	if err := d.get(ctx, "/containers/"+url.PathEscape(item.ID)+"/stats?stream=false&one-shot=true", &stats); err != nil {
		return container, nil
	}
	memory := stats.MemoryStats
	if memory.Usage > 0 {
		inactive, ok := memory.Stats["inactive_file"]
		if !ok {
			inactive = memory.Stats["total_inactive_file"]
		}
		used := int64(memory.Usage)
		if inactive < memory.Usage {
			used = int64(memory.Usage - inactive)
		}
		container.Memory = &used
	}
	if memory.Limit > 0 && memory.Limit < 1<<60 && (hostMemory <= 0 || int64(memory.Limit) < hostMemory) {
		limit := int64(memory.Limit)
		container.MemoryLimit = &limit
	}
	return container, &stats
}

func (d *dockerCollector) applyCPU(container *Container, stats *containerStats) {
	current := cpuReading{container: stats.CPUStats.CPUUsage.TotalUsage, system: stats.CPUStats.SystemCPUUsage}
	previous, ok := d.cpu[container.ID]
	d.cpu[container.ID] = current
	if !ok || current.system <= previous.system || current.container < previous.container {
		return
	}
	percent := float64(current.container-previous.container) / float64(current.system-previous.system) * 100
	percent = round(percent, 2)
	container.CPU = &percent
}

func (d *dockerCollector) trackRestarts(id string, count int, now time.Time) int {
	cutoff := now.Add(-time.Hour)
	readings := d.restarts[id]
	kept := readings[:0]
	for _, reading := range readings {
		if reading.time.After(cutoff) {
			kept = append(kept, reading)
		}
	}
	kept = append(kept, restartReading{time: now, count: count})
	d.restarts[id] = kept
	lowest := count
	for _, reading := range kept {
		if reading.count < lowest {
			lowest = reading.count
		}
	}
	return count - lowest
}

func dockerTime(value string) *int64 {
	if value == "" {
		return nil
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || parsed.Year() <= 1 {
		return nil
	}
	unix := parsed.Unix()
	return &unix
}

func listedPorts(item listedContainer) []Port {
	type portKey struct {
		private, public int
		kind            string
	}
	ports := []Port{}
	index := map[portKey]int{}
	for _, entry := range item.Ports {
		port := Port{Private: entry.PrivatePort, Type: entry.Type}
		if entry.PublicPort > 0 {
			public := entry.PublicPort
			port.Public = &public
		}
		if entry.IP != "" {
			ip := entry.IP
			port.IP = &ip
		}
		key := portKey{entry.PrivatePort, entry.PublicPort, entry.Type}
		if existing, ok := index[key]; ok {
			if current := ports[existing].IP; current != nil && strings.Contains(*current, ":") && port.IP != nil && !strings.Contains(*port.IP, ":") {
				ports[existing].IP = port.IP
			}
			continue
		}
		index[key] = len(ports)
		ports = append(ports, port)
	}
	sort.Slice(ports, func(i, j int) bool {
		if ports[i].Private != ports[j].Private {
			return ports[i].Private < ports[j].Private
		}
		if ports[i].Type != ports[j].Type {
			return ports[i].Type < ports[j].Type
		}
		return portNumber(ports[i].Public) < portNumber(ports[j].Public)
	})
	return ports
}

func portNumber(port *int) int {
	if port == nil {
		return 0
	}
	return *port
}

func inspectedMounts(inspected inspectedContainer) []Mount {
	mounts := []Mount{}
	seen := map[string]bool{}
	for _, entry := range inspected.Mounts {
		mount := Mount{Type: entry.Type, Destination: entry.Destination, ReadOnly: !entry.RW}
		if entry.Type == "volume" && entry.Name != "" {
			name := entry.Name
			mount.Name = &name
		}
		if entry.Source != "" {
			source := entry.Source
			mount.Source = &source
		}
		seen[entry.Destination] = true
		mounts = append(mounts, mount)
	}
	for destination, options := range inspected.HostConfig.Tmpfs {
		if seen[destination] {
			continue
		}
		mounts = append(mounts, Mount{Type: "tmpfs", Destination: destination, ReadOnly: hasOption(options, "ro")})
	}
	sort.Slice(mounts, func(i, j int) bool { return mounts[i].Destination < mounts[j].Destination })
	return mounts
}

func sortedKeys[V any](values map[string]V) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

const healthOutputLimit = 300

func healthEntry(start, end string, exitCode int, output string) *Health {
	stamp := dockerTime(end)
	if stamp == nil {
		stamp = dockerTime(start)
	}
	if stamp == nil {
		return nil
	}
	output = strings.TrimSpace(strings.ToValidUTF8(output, ""))
	if runes := []rune(output); len(runes) > healthOutputLimit {
		output = strings.TrimSpace(string(runes[:healthOutputLimit]))
	}
	return &Health{ExitCode: exitCode, Output: output, Time: *stamp}
}
