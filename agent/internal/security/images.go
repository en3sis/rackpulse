package security

import (
	"archive/tar"
	"context"
	"errors"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/en3sis/rackpulse/agent/internal/collect"
)

type scanLimits struct {
	images       int
	perPass      int
	timeout      time.Duration
	retry        time.Duration
	imageBytes   int64
	packageBytes int64
	osRelease    int64
	lockfile     int64
	entries      int
	dependencies int
	reported     int
	grace        time.Duration
}

var defaultScanLimits = scanLimits{
	images:       50,
	perPass:      4,
	timeout:      60 * time.Second,
	retry:        time.Hour,
	imageBytes:   64 << 20,
	packageBytes: 32 << 20,
	osRelease:    64 << 10,
	lockfile:     lockfileSizeLimit,
	entries:      4000,
	dependencies: 20000,
	reported:     30000,
	grace:        time.Hour,
}

const (
	imagesWait      = 5 * time.Second
	dpkgStatusDir   = "/var/lib/dpkg/status.d"
	usrOSRelease    = "/usr/lib/os-release"
	etcOSRelease    = "/etc/os-release"
	tarBlock        = 512
	archiveOverhead = 8 * tarBlock
)

var (
	errArchiveTooLarge = errors.New("file is too large")
	errImageTooLarge   = errors.New("image files are too large")
	errMalformed       = errors.New("not a valid archive")
	errStop            = errors.New("stop")
)

type imageJob struct {
	id         string
	container  string
	workingDir string
}

type imageResult struct {
	image   Image
	time    time.Time
	failed  bool
	skipped bool
}

func runningImages(containers []collect.ContainerSettings) map[string][]collect.ContainerSettings {
	groups := map[string][]collect.ContainerSettings{}
	for _, container := range containers {
		if container.Running && container.ImageID != "" {
			groups[container.ImageID] = append(groups[container.ImageID], container)
		}
	}
	for _, group := range groups {
		sort.Slice(group, func(i, j int) bool { return group[i].Name < group[j].Name })
	}
	return groups
}

func sortedImageIDs(groups map[string][]collect.ContainerSettings, limit int) []string {
	ids := make([]string, 0, len(groups))
	for id := range groups {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool {
		a, b := groups[ids[i]][0].Name, groups[ids[j]][0].Name
		if a != b {
			return a < b
		}
		return ids[i] < ids[j]
	})
	if len(ids) > limit {
		ids = ids[:limit]
	}
	return ids
}

func pendingImages(groups map[string][]collect.ContainerSettings, cache map[string]imageResult, limits scanLimits, now time.Time) []imageJob {
	jobs := []imageJob{}
	for _, id := range sortedImageIDs(groups, limits.images) {
		if cached, ok := cache[id]; ok && (!cached.failed || now.Sub(cached.time) < limits.retry) {
			continue
		}
		container := groups[id][0]
		jobs = append(jobs, imageJob{id: id, container: container.ID, workingDir: container.WorkingDir})
		if len(jobs) >= limits.perPass {
			break
		}
	}
	return jobs
}

func scanImages(ctx context.Context, docker Docker, jobs []imageJob, limits scanLimits, now time.Time) map[string]imageResult {
	results := map[string]imageResult{}
	for _, job := range jobs {
		if ctx.Err() != nil {
			break
		}
		results[job.id] = scanImage(ctx, docker, job, limits, now)
	}
	return results
}

func scanImage(parent context.Context, docker Docker, job imageJob, limits scanLimits, now time.Time) imageResult {
	ctx, cancel := context.WithTimeout(parent, limits.timeout)
	defer cancel()
	scanner := &imageScanner{ctx: ctx, docker: docker, container: job.container, limits: limits, budget: limits.imageBytes}
	image := Image{
		ID:        job.id,
		OS:        scanner.osRelease(),
		Packages:  scanner.packages(now),
		Lockfiles: []Lockfile{},
	}
	if scanner.fatal == nil {
		image.Lockfiles = scanner.lockfiles(job.workingDir)
	}
	result := imageResult{image: image, time: now}
	switch {
	case errors.Is(scanner.fatal, collect.ErrContainerGone):
		result.skipped = true
	case ctx.Err() != nil && parent.Err() == nil:
		result.failed = true
		result.image.Error = stringPointer(fmt.Sprintf("The scan took longer than %d seconds", int(limits.timeout.Seconds())))
	case errors.Is(scanner.fatal, errImageTooLarge):
		result.failed = true
		result.image.Error = stringPointer(fmt.Sprintf("The image files are larger than %d MB in total", limits.imageBytes>>20))
	case scanner.fatal != nil:
		result.failed = true
		result.image.Error = stringPointer(scanner.fatal.Error())
	case scanner.warning != nil:
		result.image.Error = scanner.warning
	}
	return result
}

type imageScanner struct {
	ctx       context.Context
	docker    Docker
	container string
	limits    scanLimits
	budget    int64
	fatal     error
	warning   *string
}

func (s *imageScanner) fetch(target string, limit int64, entries int, visit func(*tar.Header, io.Reader) error) error {
	body, err := s.docker.ContainerArchive(s.ctx, s.container, target)
	if err != nil {
		return err
	}
	defer body.Close()
	raw := &io.LimitedReader{R: body, N: limit + int64(entries)*2*tarBlock + archiveOverhead}
	reader := tar.NewReader(raw)
	used := int64(0)
	for count := 0; ; count++ {
		header, err := reader.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			if s.ctx.Err() != nil {
				return s.ctx.Err()
			}
			if raw.N <= 0 {
				return errArchiveTooLarge
			}
			return errMalformed
		}
		if count >= entries {
			return errArchiveTooLarge
		}
		if header.Typeflag == tar.TypeReg {
			if header.Size > limit-used {
				return errArchiveTooLarge
			}
			if header.Size > s.budget {
				return errImageTooLarge
			}
			used += header.Size
			s.budget -= header.Size
		}
		if err := visit(header, reader); err != nil {
			if errors.Is(err, errStop) {
				return nil
			}
			return err
		}
	}
}

func (s *imageScanner) file(target string, limit int64) ([]byte, string, error) {
	var data []byte
	link := ""
	found := false
	err := s.fetch(target, limit, 1, func(header *tar.Header, r io.Reader) error {
		found = true
		if header.Name != path.Base(target) {
			return errNotRegular
		}
		switch header.Typeflag {
		case tar.TypeSymlink:
			link = header.Linkname
		case tar.TypeReg:
			read, err := io.ReadAll(r)
			if err != nil {
				return errMalformed
			}
			data = read
		default:
			return errNotRegular
		}
		return errStop
	})
	if err == nil && !found {
		err = errMalformed
	}
	return data, link, err
}

func (s *imageScanner) stream(target string, limit int64, parse func(io.Reader) error) error {
	found := false
	err := s.fetch(target, limit, 1, func(header *tar.Header, r io.Reader) error {
		found = true
		if header.Typeflag != tar.TypeReg || header.Name != path.Base(target) {
			return errNotRegular
		}
		if err := parse(r); err != nil {
			return errMalformed
		}
		return errStop
	})
	if err == nil && !found {
		err = errMalformed
	}
	return err
}

func (s *imageScanner) record(err error) {
	if s.fatal != nil || err == nil || collect.IsNotFound(err) {
		return
	}
	for _, local := range []error{errArchiveTooLarge, errNotRegular, errMalformed} {
		if errors.Is(err, local) {
			return
		}
	}
	s.fatal = err
}

func (s *imageScanner) osRelease() OSInfo {
	empty := OSInfo{Like: []string{}}
	data, link, err := s.file(etcOSRelease, s.limits.osRelease)
	s.record(err)
	if err == nil && link != "" {
		target := link
		if !path.IsAbs(target) {
			target = path.Join(path.Dir(etcOSRelease), target)
		}
		data, link, err = s.file(path.Clean(target), s.limits.osRelease)
		s.record(err)
	}
	if (err != nil || link != "") && s.fatal == nil {
		data, link, err = s.file(usrOSRelease, s.limits.osRelease)
		s.record(err)
	}
	if err != nil || link != "" || data == nil {
		return empty
	}
	return parseOSRelease(string(data))
}

func (s *imageScanner) packages(now time.Time) Packages {
	result := Packages{Time: now.Unix(), Items: []Package{}}
	if s.fatal != nil {
		return result
	}
	candidates := []struct {
		manager, path string
		read          func(string) ([]Package, error)
	}{
		{"dpkg", dpkgStatusPath, s.dpkgStatus},
		{"dpkg", dpkgStatusDir, s.dpkgStatusDir},
		{"apk", apkInstalledPath, s.apkInstalled},
	}
	for _, candidate := range candidates {
		items, err := candidate.read(candidate.path)
		if collect.IsNotFound(err) {
			continue
		}
		s.record(err)
		if s.fatal != nil {
			return result
		}
		result.Manager = stringPointer(candidate.manager)
		if err != nil {
			result.Error = stringPointer("Cannot read " + candidate.path + ": " + s.describe(err, s.limits.packageBytes))
			return result
		}
		sortPackages(items)
		result.Items = items
		return result
	}
	return result
}

func (s *imageScanner) describe(err error, limit int64) string {
	switch {
	case errors.Is(err, errArchiveTooLarge):
		return fmt.Sprintf("larger than %d MB", limit>>20)
	case errors.Is(err, errNotRegular):
		return "not a regular file"
	case errors.Is(err, errMalformed):
		return "not a valid file"
	}
	return err.Error()
}

func (s *imageScanner) dpkgStatus(target string) ([]Package, error) {
	items := []Package{}
	err := s.stream(target, s.limits.packageBytes, func(r io.Reader) error {
		var err error
		items, err = appendDpkg(items, r, false)
		return err
	})
	return items, err
}

func (s *imageScanner) apkInstalled(target string) ([]Package, error) {
	items := []Package{}
	err := s.stream(target, s.limits.packageBytes, func(r io.Reader) error {
		var err error
		items, err = parseApkInstalled(r)
		return err
	})
	return items, err
}

func (s *imageScanner) dpkgStatusDir(target string) ([]Package, error) {
	items := []Package{}
	prefix := path.Base(target) + "/"
	err := s.fetch(target, s.limits.packageBytes, s.limits.entries, func(header *tar.Header, r io.Reader) error {
		name, ok := strings.CutPrefix(header.Name, prefix)
		if !ok || header.Typeflag != tar.TypeReg || name == "" || strings.Contains(name, "/") || strings.HasSuffix(name, ".md5sums") {
			return nil
		}
		var err error
		if items, err = appendDpkg(items, r, true); err != nil {
			return errMalformed
		}
		return nil
	})
	return items, err
}

func (s *imageScanner) lockfiles(workingDir string) []Lockfile {
	lockfiles := []Lockfile{}
	if workingDir == "" || !path.IsAbs(workingDir) || path.Clean(workingDir) != workingDir {
		return lockfiles
	}
	names := make([]string, 0, len(lockfileParsers))
	for name := range lockfileParsers {
		names = append(names, name)
	}
	sort.Strings(names)
	budget := s.limits.dependencies
	for _, name := range names {
		target := path.Join(workingDir, name)
		data, link, err := s.file(target, s.limits.lockfile)
		s.record(err)
		if s.fatal != nil {
			return lockfiles
		}
		if err != nil || link != "" {
			continue
		}
		parser := lockfileParsers[name]
		if budget <= 0 {
			lockfiles = append(lockfiles, Lockfile{Path: target, Ecosystem: parser.ecosystem, Packages: []Dependency{}, Truncated: true})
			continue
		}
		dependencies, err := parser.parse(data)
		if err != nil {
			if s.warning == nil {
				s.warning = stringPointer("Cannot parse " + target)
			}
			continue
		}
		dependencies = uniqueDependencies(dependencies)
		truncated := len(dependencies) > budget
		if truncated {
			dependencies = dependencies[:budget]
		}
		budget -= len(dependencies)
		lockfiles = append(lockfiles, Lockfile{Path: target, Ecosystem: parser.ecosystem, Packages: dependencies, Truncated: truncated})
	}
	return lockfiles
}

func assembleImages(groups map[string][]collect.ContainerSettings, cache map[string]imageResult, limits scanLimits) []Image {
	images := []Image{}
	budget := limits.reported
	for _, id := range sortedImageIDs(groups, limits.images) {
		cached, ok := cache[id]
		if !ok {
			continue
		}
		image := cached.image
		containers := groups[id]
		image.Names = imageNames(containers)
		image.Containers = make([]string, len(containers))
		for i, container := range containers {
			image.Containers[i] = container.Name
		}
		if details := containers[0].Image; details != nil {
			image.Created = details.Created
		}
		size := len(image.Packages.Items)
		for _, lockfile := range image.Lockfiles {
			size += len(lockfile.Packages)
		}
		if size > budget {
			image.Packages.Items = []Package{}
			image.Lockfiles = []Lockfile{}
			image.Error = stringPointer(fmt.Sprintf("Packages left out: the report already lists %d packages from other images", limits.reported-budget))
			size = 0
		}
		budget -= size
		images = append(images, image)
	}
	return images
}

func imageNames(containers []collect.ContainerSettings) []string {
	if details := containers[0].Image; details != nil {
		if len(details.Tags) > 0 {
			return append([]string{}, details.Tags...)
		}
		if len(details.Digests) > 0 {
			return append([]string{}, details.Digests...)
		}
	}
	seen := map[string]bool{}
	names := []string{}
	for _, container := range containers {
		if ref := container.ImageRef; ref != "" && !strings.HasPrefix(ref, "sha256:") && !seen[ref] {
			seen[ref] = true
			names = append(names, ref)
		}
	}
	return names
}
