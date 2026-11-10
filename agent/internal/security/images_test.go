package security

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/en3sis/rackpulse/agent/internal/collect"
)

type tarEntry struct {
	name string
	kind byte
	body string
	link string
	size int64
}

func makeTar(t *testing.T, entries ...tarEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	writer := tar.NewWriter(&buf)
	for _, entry := range entries {
		kind := entry.kind
		if kind == 0 {
			kind = tar.TypeReg
		}
		size := int64(0)
		if kind == tar.TypeReg {
			size = int64(len(entry.body))
			if entry.size > 0 {
				size = entry.size
			}
		}
		if err := writer.WriteHeader(&tar.Header{Name: entry.name, Typeflag: kind, Linkname: entry.link, Size: size, Mode: 0o644}); err != nil {
			t.Fatal(err)
		}
		if entry.size > 0 {
			writer.Flush()
			return buf.Bytes()
		}
		if _, err := writer.Write([]byte(entry.body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func file(t *testing.T, name, body string) []byte {
	return makeTar(t, tarEntry{name: name, body: body})
}

const (
	debianRelease = "ID=debian\nVERSION_ID=\"12\"\nVERSION_CODENAME=bookworm\nPRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\n"
	dpkgStatus    = "Package: libssl3\nStatus: install ok installed\nArchitecture: amd64\nSource: openssl\nVersion: 3.0.11-1~deb12u2\n\nPackage: removed\nStatus: deinstall ok config-files\nVersion: 1.0\n"
)

func imageContainers() []collect.ContainerSettings {
	created := time.Now().Add(-24 * time.Hour).Unix()
	details := &collect.ImageDetails{Tags: []string{"app:1.2"}, Digests: []string{}, Created: &created}
	return []collect.ContainerSettings{
		{ID: "c2", Name: "web-2", Running: true, ImageID: "sha256:aaa", ImageRef: "app:1.2", User: "app", WorkingDir: "/app", Image: details},
		{ID: "c1", Name: "web-1", Running: true, ImageID: "sha256:aaa", ImageRef: "app:1.2", User: "app", WorkingDir: "/app", Image: details},
		{ID: "c3", Name: "old", Running: false, ImageID: "sha256:bbb", ImageRef: "old:1"},
	}
}

func scanJob(t *testing.T, docker fakeDocker, limits scanLimits) imageResult {
	t.Helper()
	return scanImage(context.Background(), docker, imageJob{id: "sha256:aaa", container: "c1", workingDir: "/app"}, limits, time.Unix(1793000000, 0))
}

func TestCollectorScansImagesInTheBackground(t *testing.T) {
	calls := 0
	docker := fakeDocker{containers: imageContainers(), calls: &calls, files: map[string][]byte{
		"/etc/os-release":         makeTar(t, tarEntry{name: "os-release", kind: tar.TypeSymlink, link: "../usr/lib/os-release"}),
		"/usr/lib/os-release":     file(t, "os-release", debianRelease),
		"/var/lib/dpkg/status":    file(t, "status", dpkgStatus),
		"/app/package-lock.json":  file(t, "package-lock.json", npmLockfile),
		"/app/requirements.txt":   makeTar(t, tarEntry{name: "requirements.txt", kind: tar.TypeSymlink, link: "/etc/shadow"}),
		"/app/node_modules/x.txt": file(t, "x.txt", "never read"),
	}}
	c := newCollector("0.4.0", t.TempDir(), docker, nil)
	start := time.Unix(1793000000, 0)
	c.pass(context.Background(), start)
	c.finishImageScan(time.Second)
	c.publish(start)
	images := decodeReport(t, c)["images"].([]any)
	if len(images) != 1 {
		t.Fatalf("images %v", images)
	}
	image := images[0].(map[string]any)
	if image["id"] != "sha256:aaa" || image["error"] != nil || image["created"] == nil {
		t.Fatalf("image %v", image)
	}
	if names := image["names"].([]any); len(names) != 1 || names[0] != "app:1.2" {
		t.Fatalf("names %v", names)
	}
	if containers := image["containers"].([]any); len(containers) != 2 || containers[0] != "web-1" || containers[1] != "web-2" {
		t.Fatalf("containers %v", containers)
	}
	if os := image["os"].(map[string]any); os["id"] != "debian" || os["versionID"] != "12" {
		t.Fatalf("os %v", os)
	}
	packages := image["packages"].(map[string]any)
	if packages["manager"] != "dpkg" || len(packages["items"].([]any)) != 1 || packages["error"] != nil {
		t.Fatalf("packages %v", packages)
	}
	lockfiles := image["lockfiles"].([]any)
	if len(lockfiles) != 1 || lockfiles[0].(map[string]any)["path"] != "/app/package-lock.json" {
		t.Fatalf("lockfiles %v", lockfiles)
	}

	scanned := calls
	c.audit(context.Background(), start.Add(time.Minute))
	c.pass(context.Background(), start.Add(time.Minute))
	c.finishImageScan(time.Second)
	if calls != scanned || len(c.report.Images) != 1 {
		t.Fatalf("image scanned again: %d calls, then %d", scanned, calls)
	}

	timeout := fakeDocker{err: errors.New("Docker did not answer in time")}
	c.docker = timeout
	c.audit(context.Background(), start.Add(2*time.Minute))
	if len(c.report.Images) != 1 || len(c.images) != 1 || len(c.running) != 1 {
		t.Fatalf("a Docker timeout dropped the images: %v", c.report.Images)
	}

	stopped := imageContainers()
	stopped[0].Running, stopped[1].Running = false, false
	c.docker = fakeDocker{containers: stopped}
	c.audit(context.Background(), start.Add(30*time.Minute))
	if len(c.report.Images) != 1 || len(c.images) != 1 {
		t.Fatalf("image of a briefly stopped container dropped: %v", c.report.Images)
	}
	c.audit(context.Background(), start.Add(2*time.Hour))
	if len(c.report.Images) != 0 || len(c.images) != 0 || len(c.seen) != 0 {
		t.Fatalf("unused image kept after the grace period: %v %v", c.report.Images, c.images)
	}

	c.docker = fakeDocker{containers: imageContainers()}
	c.audit(context.Background(), start.Add(3*time.Hour))
	c.docker = timeout
	c.audit(context.Background(), start.Add(5*time.Hour))
	if len(c.report.Images) != 0 || len(c.running) != 0 {
		t.Fatalf("images kept after Docker failed for longer than the grace period: %v", c.report.Images)
	}

	c.docker = fakeDocker{containers: imageContainers()}
	c.audit(context.Background(), start.Add(6*time.Hour))
	c.docker = fakeDocker{err: collect.ErrNoDocker}
	c.audit(context.Background(), start.Add(6*time.Hour+time.Minute))
	c.publish(start.Add(6 * time.Hour))
	if images, ok := decodeReport(t, c)["images"].([]any); !ok || len(images) != 0 {
		t.Fatalf("images without Docker %v", decodeReport(t, c)["images"])
	}
}

func TestImageScanSurvivesDockerTimeout(t *testing.T) {
	release := make(chan struct{})
	osRelease := file(t, "os-release", debianRelease)
	docker := fakeDocker{containers: imageContainers(), archive: func(ctx context.Context, _, path string) (io.ReadCloser, error) {
		<-release
		if path == "/etc/os-release" {
			return io.NopCloser(bytes.NewReader(osRelease)), nil
		}
		return nil, &collect.APIError{Code: http.StatusNotFound, Status: "404 Not Found", Path: path}
	}}
	c := newCollector("0.4.0", t.TempDir(), docker, nil)
	start := time.Unix(1793000000, 0)
	c.audit(context.Background(), start)
	c.startImageScan(context.Background(), pendingImages(c.running, c.images, c.limits, start), start)
	c.docker = fakeDocker{err: errors.New("Docker did not answer in time")}
	c.audit(context.Background(), start.Add(time.Minute))
	close(release)
	if !c.finishImageScan(time.Second) || len(c.report.Images) != 1 || c.report.Images[0].OS.ID == nil {
		t.Fatalf("scan in flight discarded: %+v", c.report.Images)
	}
}

func TestImageScanDistrolessAndAlpine(t *testing.T) {
	distroless := fakeDocker{files: map[string][]byte{
		"/usr/lib/os-release": file(t, "os-release", debianRelease),
		"/var/lib/dpkg/status.d": makeTar(t,
			tarEntry{name: "status.d/", kind: tar.TypeDir},
			tarEntry{name: "status.d/base-files", body: "Package: base-files\nVersion: 12.4+deb12u5\nArchitecture: amd64\n"},
			tarEntry{name: "status.d/base-files.md5sums", body: "abc  etc/debian_version\n"},
			tarEntry{name: "status.d/libc6", body: "Package: libc6\nVersion: 2.36-9+deb12u7\nSource: glibc\n"},
			tarEntry{name: "status.d/nested/evil", body: "Package: evil\nVersion: 1\n"},
			tarEntry{name: "status.d/link", kind: tar.TypeSymlink, link: "/etc/passwd"},
		),
	}}
	result := scanJob(t, distroless, defaultScanLimits)
	items := result.image.Packages.Items
	if result.failed || result.image.Error != nil || len(items) != 2 || items[0].Name != "base-files" || items[1].Source != "glibc" {
		t.Fatalf("distroless %+v", result)
	}
	if result.image.OS.ID == nil || *result.image.OS.ID != "debian" {
		t.Fatalf("os %+v", result.image.OS)
	}

	alpine := fakeDocker{files: map[string][]byte{
		"/etc/os-release":       file(t, "os-release", "ID=alpine\nVERSION_ID=3.20.3\n"),
		"/lib/apk/db/installed": file(t, "installed", "P:musl\nV:1.2.5-r0\nA:x86_64\n\nP:busybox\nV:1.36.1-r29\n"),
	}}
	result = scanJob(t, alpine, defaultScanLimits)
	if *result.image.Packages.Manager != "apk" || len(result.image.Packages.Items) != 2 {
		t.Fatalf("alpine %+v", result.image.Packages)
	}

	scratch := scanJob(t, fakeDocker{}, defaultScanLimits)
	if scratch.failed || scratch.image.Error != nil || scratch.image.Packages.Manager != nil || scratch.image.Packages.Items == nil || scratch.image.OS.Like == nil {
		t.Fatalf("scratch %+v", scratch)
	}
}

func TestImageScanSymlinks(t *testing.T) {
	loop := fakeDocker{files: map[string][]byte{
		"/etc/os-release":     makeTar(t, tarEntry{name: "os-release", kind: tar.TypeSymlink, link: "os-release.d"}),
		"/etc/os-release.d":   makeTar(t, tarEntry{name: "os-release.d", kind: tar.TypeSymlink, link: "/etc/os-release"}),
		"/usr/lib/os-release": makeTar(t, tarEntry{name: "os-release", kind: tar.TypeSymlink, link: "/etc/os-release"}),
	}}
	calls := 0
	loop.calls = &calls
	result := scanJob(t, loop, defaultScanLimits)
	if result.image.OS.ID != nil || calls > 3+3+len(lockfileParsers) {
		t.Fatalf("followed symlinks: %+v after %d calls", result.image.OS, calls)
	}
	escaped := fakeDocker{files: map[string][]byte{
		"/var/lib/dpkg/status": makeTar(t, tarEntry{name: "status", kind: tar.TypeSymlink, link: "/host/var/lib/dpkg/status"}),
		"/app/go.mod":          file(t, "other-name", "module x\n\nrequire golang.org/x/net v0.1.0\n"),
	}}
	result = scanJob(t, escaped, defaultScanLimits)
	if result.image.Packages.Error == nil || !strings.Contains(*result.image.Packages.Error, "not a regular file") || len(result.image.Lockfiles) != 0 {
		t.Fatalf("symlink or renamed entry accepted: %+v", result.image)
	}
}

func TestImageScanCaps(t *testing.T) {
	limits := defaultScanLimits
	limits.packageBytes = 1 << 20
	bomb := fakeDocker{files: map[string][]byte{
		"/var/lib/dpkg/status": makeTar(t, tarEntry{name: "status", size: 8 << 30}),
	}}
	result := scanJob(t, bomb, limits)
	if result.image.Packages.Error == nil || *result.image.Packages.Error != "Cannot read /var/lib/dpkg/status: larger than 1 MB" {
		t.Fatalf("bomb %+v", result.image.Packages)
	}

	entries := []tarEntry{{name: "status.d/", kind: tar.TypeDir}}
	for i := 0; i < 50; i++ {
		entries = append(entries, tarEntry{name: "status.d/p" + strings.Repeat("x", i), body: "Package: p\nVersion: 1\n"})
	}
	limits = defaultScanLimits
	limits.entries = 20
	many := fakeDocker{files: map[string][]byte{"/var/lib/dpkg/status.d": makeTar(t, entries...)}}
	if result := scanJob(t, many, limits); result.image.Packages.Error == nil {
		t.Fatalf("entry limit not applied: %+v", result.image.Packages)
	}

	padded := makeTar(t, tarEntry{name: "status", body: dpkgStatus})
	padded = append(padded, make([]byte, 4<<20)...)
	limits = defaultScanLimits
	limits.packageBytes = 4 << 10
	trailing := fakeDocker{files: map[string][]byte{"/var/lib/dpkg/status": padded}}
	if result := scanJob(t, trailing, limits); result.image.Packages.Error != nil || len(result.image.Packages.Items) != 1 {
		t.Fatalf("trailing data %+v", result.image.Packages)
	}

	limits = defaultScanLimits
	limits.imageBytes = 200
	budget := fakeDocker{files: map[string][]byte{
		"/etc/os-release":      file(t, "os-release", debianRelease),
		"/var/lib/dpkg/status": file(t, "status", dpkgStatus),
	}}
	result = scanJob(t, budget, limits)
	if !result.failed || result.image.Error == nil || !strings.Contains(*result.image.Error, "larger than 0 MB in total") {
		t.Fatalf("image budget %+v", result)
	}

	limits = defaultScanLimits
	limits.lockfile = 10
	large := fakeDocker{files: map[string][]byte{"/app/package-lock.json": file(t, "package-lock.json", npmLockfile)}}
	if result := scanJob(t, large, limits); len(result.image.Lockfiles) != 0 || result.image.Error != nil {
		t.Fatalf("large lockfile %+v", result.image)
	}
}

func TestImageScanMalformedArchives(t *testing.T) {
	truncated := makeTar(t, tarEntry{name: "status", body: dpkgStatus})[:600]
	cases := map[string][]byte{
		"garbage":   []byte(strings.Repeat("not a tar archive ", 100)),
		"truncated": truncated,
		"empty":     {},
	}
	for name, data := range cases {
		docker := fakeDocker{files: map[string][]byte{"/var/lib/dpkg/status": data}}
		result := scanJob(t, docker, defaultScanLimits)
		if result.failed || result.image.Packages.Error == nil || !strings.HasPrefix(*result.image.Packages.Error, "Cannot read /var/lib/dpkg/status") {
			t.Errorf("%s: %+v", name, result.image.Packages)
		}
	}
	broken := fakeDocker{files: map[string][]byte{"/app/package-lock.json": file(t, "package-lock.json", "{not json")}}
	if result := scanJob(t, broken, defaultScanLimits); result.failed || result.image.Error == nil || *result.image.Error != "Cannot parse /app/package-lock.json" {
		t.Fatalf("broken lockfile %+v", result.image)
	}
}

func TestImageScanFailures(t *testing.T) {
	limits := defaultScanLimits
	limits.timeout = 30 * time.Millisecond
	slow := fakeDocker{archive: func(ctx context.Context, _, _ string) (io.ReadCloser, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	started := time.Now()
	result := scanJob(t, slow, limits)
	if !result.failed || result.image.Error == nil || !strings.HasPrefix(*result.image.Error, "The scan took longer than") || time.Since(started) > time.Second {
		t.Fatalf("timeout %+v", result)
	}

	gone := fakeDocker{archive: func(context.Context, string, string) (io.ReadCloser, error) { return nil, collect.ErrContainerGone }}
	if result := scanJob(t, gone, defaultScanLimits); !result.skipped {
		t.Fatalf("gone %+v", result)
	}

	calls := 0
	failing := fakeDocker{calls: &calls, archive: func(context.Context, string, string) (io.ReadCloser, error) {
		return nil, &collect.APIError{Code: http.StatusInternalServerError, Status: "500 Internal Server Error", Path: "/containers/c1/archive"}
	}}
	result = scanJob(t, failing, defaultScanLimits)
	if !result.failed || result.image.Error == nil || *result.image.Error != "Docker API returned 500 Internal Server Error for /containers/c1/archive" || calls != 1 {
		t.Fatalf("docker error %+v after %d calls", result, calls)
	}

	groups := runningImages(imageContainers())
	now := time.Unix(1793000000, 0)
	cache := map[string]imageResult{"sha256:aaa": {time: now, failed: true}}
	if jobs := pendingImages(groups, cache, defaultScanLimits, now.Add(time.Minute)); len(jobs) != 0 {
		t.Fatalf("failed image retried too soon: %+v", jobs)
	}
	if jobs := pendingImages(groups, cache, defaultScanLimits, now.Add(2*time.Hour)); len(jobs) != 1 || jobs[0].container != "c1" {
		t.Fatalf("failed image not retried: %+v", jobs)
	}
}

func TestImageLimits(t *testing.T) {
	containers := []collect.ContainerSettings{}
	cache := map[string]imageResult{}
	for i := 0; i < 8; i++ {
		id := "sha256:" + string(rune('a'+i))
		containers = append(containers, collect.ContainerSettings{ID: id, Name: "c" + string(rune('a'+i)), Running: true, ImageID: id, ImageRef: "img:1"})
		cache[id] = imageResult{image: Image{ID: id, Packages: Packages{Items: make([]Package, 40)}, Lockfiles: []Lockfile{}}}
	}
	groups := runningImages(containers)
	limits := defaultScanLimits
	limits.images, limits.perPass, limits.reported = 6, 4, 100
	if jobs := pendingImages(groups, map[string]imageResult{}, limits, time.Now()); len(jobs) != 4 {
		t.Fatalf("jobs %d", len(jobs))
	}
	images := assembleImages(groups, cache, limits)
	if len(images) != 6 {
		t.Fatalf("images %d", len(images))
	}
	if len(images[1].Packages.Items) != 40 || images[1].Error != nil || len(images[2].Packages.Items) != 0 || images[2].Error == nil {
		t.Fatalf("package budget not applied: %+v", images[2])
	}
	if defaultScanLimits.packageBytes != 32<<20 || defaultScanLimits.imageBytes != 64<<20 || defaultScanLimits.timeout != time.Minute || defaultScanLimits.perPass != 4 {
		t.Fatalf("default limits %+v", defaultScanLimits)
	}
}
