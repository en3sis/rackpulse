package security

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"os"
	"sync"
	"time"

	"github.com/en3sis/rackpulse/agent/internal/collect"
)

const (
	tickInterval     = time.Minute
	packagesInterval = 5 * time.Minute
	auditInterval    = 15 * time.Minute
	updatesMinimum   = 30 * time.Minute
	updatesMaximum   = 6 * time.Hour
	projectsInterval = 6 * time.Hour
	projectsWait     = 10 * time.Second
)

type Docker interface {
	ContainerSettings(ctx context.Context) ([]collect.ContainerSettings, error)
	ContainerArchive(ctx context.Context, id, path string) (io.ReadCloser, error)
}

type Collector struct {
	version string
	root    string
	docker  Docker
	runApt  func(context.Context) ([]byte, error)
	dumpApt func(context.Context) ([]byte, error)

	mu        sync.Mutex
	data      []byte
	ready     chan struct{}
	readyOnce sync.Once

	report         Report
	manager        string
	packagesStamp  int64
	packagesTime   time.Time
	auditTime      time.Time
	updatesTime    time.Time
	updatesStamp   [2]int64
	projectsTime   time.Time
	projectsKey    string
	projectsScan   chan []Project
	compose        []composeProject
	dockerReadable bool
	running        map[string][]collect.ContainerSettings
	seen           map[string]seenImage
	dockerSeen     time.Time
	images         map[string]imageResult
	imagesScan     chan map[string]imageResult
	limits         scanLimits
}

func New(version string, docker Docker) *Collector {
	collector := newCollector(version, "/", docker, runAptGet)
	collector.dumpApt = runAptConfig
	return collector
}

func newCollector(version, root string, docker Docker, runApt func(context.Context) ([]byte, error)) *Collector {
	return &Collector{
		version: version,
		root:    root,
		docker:  docker,
		runApt:  runApt,
		ready:   make(chan struct{}),
		images:  map[string]imageResult{},
		seen:    map[string]seenImage{},
		limits:  defaultScanLimits,
		report: Report{
			Version:   version,
			OS:        OSInfo{Like: []string{}},
			Packages:  Packages{Items: []Package{}},
			Updates:   Updates{Items: []Update{}},
			Checks:    []Check{},
			Listening: []Listener{},
			Projects:  []Project{},
			Images:    []Image{},
		},
	}
}

func (c *Collector) Ready() <-chan struct{} {
	return c.ready
}

func (c *Collector) Latest() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.data
}

func (c *Collector) Run(ctx context.Context) {
	c.pass(ctx, time.Now())
	ticker := time.NewTicker(tickInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			c.pass(ctx, now)
		}
	}
}

func (c *Collector) pass(ctx context.Context, now time.Time) {
	changed := false
	packagesChanged := false
	if c.packagesTime.IsZero() || now.Sub(c.packagesTime) >= packagesInterval {
		packagesChanged = c.refreshPackages(now)
		changed = packagesChanged
	}
	if packagesChanged || c.auditTime.IsZero() || now.Sub(c.auditTime) >= auditInterval {
		c.audit(ctx, now)
		changed = true
	}
	key := projectsKey(c.compose)
	if c.projectsScan == nil && (c.projectsTime.IsZero() || key != c.projectsKey || now.Sub(c.projectsTime) >= projectsInterval) {
		c.startProjectScan()
		c.projectsKey = key
		c.projectsTime = now
	}
	if c.finishProjectScan(projectsWait) {
		changed = true
	}
	if c.imagesScan == nil {
		if jobs := pendingImages(c.running, c.images, c.limits, now); len(jobs) > 0 {
			c.startImageScan(ctx, jobs, now)
		}
	}
	if c.finishImageScan(imagesWait) {
		changed = true
	}
	if c.updatesDue(now) {
		c.refreshUpdates(ctx, now)
		changed = true
	}
	if changed {
		c.publish(now)
	}
	c.readyOnce.Do(func() { close(c.ready) })
}

func (c *Collector) startProjectScan() {
	root := c.root
	compose := append([]composeProject(nil), c.compose...)
	result := make(chan []Project, 1)
	go func() { result <- scanProjects(root, compose) }()
	c.projectsScan = result
}

func (c *Collector) finishProjectScan(wait time.Duration) bool {
	if c.projectsScan == nil {
		return false
	}
	select {
	case projects := <-c.projectsScan:
		c.report.Projects = projects
		c.projectsScan = nil
		return true
	case <-time.After(wait):
		return false
	}
}

func (c *Collector) startImageScan(ctx context.Context, jobs []imageJob, now time.Time) {
	docker, limits := c.docker, c.limits
	result := make(chan map[string]imageResult, 1)
	go func() { result <- scanImages(ctx, docker, jobs, limits, now) }()
	c.imagesScan = result
}

func (c *Collector) finishImageScan(wait time.Duration) bool {
	if c.imagesScan == nil {
		return false
	}
	select {
	case results := <-c.imagesScan:
		c.imagesScan = nil
		for id, result := range results {
			if _, used := c.running[id]; used && !result.skipped {
				c.images[id] = result
			}
		}
		c.report.Images = assembleImages(c.running, c.images, c.limits)
		return true
	case <-time.After(wait):
		return false
	}
}

type seenImage struct {
	containers []collect.ContainerSettings
	time       time.Time
}

func (c *Collector) updateImages(containers []collect.ContainerSettings, now time.Time) {
	for id, group := range runningImages(containers) {
		c.seen[id] = seenImage{containers: group, time: now}
	}
	c.running = map[string][]collect.ContainerSettings{}
	for id, seen := range c.seen {
		if now.Sub(seen.time) > c.limits.grace {
			delete(c.seen, id)
			continue
		}
		c.running[id] = seen.containers
	}
	for id := range c.images {
		if _, used := c.running[id]; !used {
			delete(c.images, id)
		}
	}
	c.report.Images = assembleImages(c.running, c.images, c.limits)
}

func (c *Collector) clearImages() {
	c.running = map[string][]collect.ContainerSettings{}
	c.seen = map[string]seenImage{}
	c.images = map[string]imageResult{}
	c.report.Images = []Image{}
}

func (c *Collector) refreshPackages(now time.Time) bool {
	c.packagesTime = now
	manager, path := "", ""
	for _, candidate := range []struct{ manager, path string }{{"dpkg", dpkgStatusPath}, {"apk", apkInstalledPath}} {
		if _, err := os.Stat(hostPath(c.root, candidate.path)); err == nil {
			manager, path = candidate.manager, candidate.path
			break
		}
	}
	stamp := int64(0)
	if path != "" {
		stamp = modTime(c.root, path)
	}
	if manager == c.manager && stamp == c.packagesStamp && c.report.Packages.Time != 0 {
		return false
	}
	c.manager, c.packagesStamp = manager, stamp
	packages := &c.report.Packages
	packages.Time = now.Unix()
	packages.Manager = optionalString(manager)
	packages.Error = nil
	if manager == "" {
		packages.Items = []Package{}
		packages.Error = stringPointer("No supported package manager found")
		c.unsupportedUpdates(now, "Not supported on this system")
		return true
	}
	items, err := readPackages(hostPath(c.root, path), manager)
	if err != nil {
		packages.Error = stringPointer("Cannot read " + path + ": " + folderError(err))
		return true
	}
	packages.Items = items
	if manager == "apk" {
		c.unsupportedUpdates(now, "Not supported on Alpine yet")
	}
	return true
}

func readPackages(path, manager string) ([]Package, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	if manager == "apk" {
		return parseApkInstalled(file)
	}
	return parseDpkgStatus(file)
}

func (c *Collector) unsupportedUpdates(now time.Time, message string) {
	c.report.Updates = Updates{Time: now.Unix(), Error: stringPointer(message), Items: []Update{}}
}

func (c *Collector) currentUpdatesStamp() [2]int64 {
	lists := int64(0)
	if listsTime := aptListsTime(c.root); listsTime != nil {
		lists = *listsTime
	}
	return [2]int64{lists, modTime(c.root, dpkgStatusPath)}
}

func (c *Collector) updatesDue(now time.Time) bool {
	if c.manager != "dpkg" {
		return false
	}
	if c.updatesTime.IsZero() {
		return true
	}
	elapsed := now.Sub(c.updatesTime)
	if elapsed >= updatesMaximum {
		return true
	}
	return elapsed >= updatesMinimum && c.currentUpdatesStamp() != c.updatesStamp
}

func (c *Collector) refreshUpdates(ctx context.Context, now time.Time) {
	c.updatesTime = now
	c.updatesStamp = c.currentUpdatesStamp()
	updates := &c.report.Updates
	updates.Time = now.Unix()
	updates.ListsTime = aptListsTime(c.root)
	if c.runApt == nil {
		updates.Error = stringPointer("apt-get not found")
		return
	}
	output, err := c.runApt(ctx)
	if err != nil {
		updates.Error = stringPointer(err.Error())
		log.Printf("Security updates: %v", err)
		return
	}
	updates.Error = nil
	updates.Items = parseAptSimulation(output)
}

func (c *Collector) audit(ctx context.Context, now time.Time) {
	c.auditTime = now
	c.report.OS = readOSRelease(c.root)
	c.report.Kernel = readKernel(c.root, c.report.Packages.Items)
	c.report.Listening = readListening(c.root)
	input := auditInput{root: c.root, manager: c.manager, packages: c.report.Packages.Items, kernel: c.report.Kernel, now: now}
	if c.manager == "dpkg" && c.dumpApt != nil {
		if dump, err := c.dumpApt(ctx); err == nil {
			input.aptConfig = dump
		}
	}
	if c.docker != nil {
		containers, err := c.docker.ContainerSettings(ctx)
		readable := err == nil
		if err != nil && !errors.Is(err, collect.ErrNoDocker) && c.dockerReadable {
			log.Printf("Security: Docker: %v", err)
		}
		c.dockerReadable = readable
		input.docker = readable
		input.containers = containers
		switch {
		case readable:
			c.dockerSeen = now
			c.compose = composeProjects(containers)
			c.updateImages(containers, now)
		case errors.Is(err, collect.ErrNoDocker) || now.Sub(c.dockerSeen) > c.limits.grace:
			c.compose = nil
			c.clearImages()
		}
	}
	c.report.Checks = runChecks(input)
}

func (c *Collector) publish(now time.Time) {
	c.report.Time = now.Unix()
	data, err := json.Marshal(c.report)
	if err != nil {
		log.Printf("Encoding security report failed: %v", err)
		return
	}
	c.mu.Lock()
	c.data = data
	c.mu.Unlock()
}
