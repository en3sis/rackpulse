package security

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/en3sis/rackpulse/agent/internal/collect"
)

type fakeDocker struct {
	containers []collect.ContainerSettings
	err        error
	files      map[string][]byte
	archive    func(ctx context.Context, id, path string) (io.ReadCloser, error)
	calls      *int
}

func (f fakeDocker) ContainerSettings(context.Context) ([]collect.ContainerSettings, error) {
	return f.containers, f.err
}

func (f fakeDocker) ContainerArchive(ctx context.Context, id, path string) (io.ReadCloser, error) {
	if f.calls != nil {
		*f.calls++
	}
	if f.archive != nil {
		return f.archive(ctx, id, path)
	}
	if data, ok := f.files[path]; ok {
		return io.NopCloser(bytes.NewReader(data)), nil
	}
	return nil, &collect.APIError{Code: http.StatusNotFound, Status: "404 Not Found", Path: path}
}

func fakeRoot(t *testing.T) string {
	t.Helper()
	root := writeTree(t, map[string]string{
		"etc/os-release":                      "ID=ubuntu\nVERSION_ID=\"24.04\"\nVERSION_CODENAME=noble\nPRETTY_NAME=\"Ubuntu 24.04.3 LTS\"\nID_LIKE=debian\n",
		"proc/sys/kernel/osrelease":           "6.8.0-85-generic\n",
		"etc/ssh/sshd_config":                 "PasswordAuthentication no\nKbdInteractiveAuthentication no\n",
		"etc/passwd":                          "root:x:0:0:root:/root:/bin/bash\n",
		"etc/apt/apt.conf.d/20auto-upgrades":  "APT::Periodic::Unattended-Upgrade \"1\";\n",
		"var/lib/apt/lists/archive_InRelease": "x",
		"srv/app/package-lock.json":           npmLockfile,
	})
	mustWrite(t, root+dpkgStatusPath, readFixture(t, "dpkg/status"))
	mustWrite(t, root+"/proc/net/tcp", readFixture(t, "proc/tcp"))
	return root
}

func decodeReport(t *testing.T, c *Collector) map[string]any {
	t.Helper()
	var report map[string]any
	if err := json.Unmarshal(c.Latest(), &report); err != nil {
		t.Fatal(err)
	}
	return report
}

func TestCollectorPass(t *testing.T) {
	aptOutput := readFixture(t, "apt/ubuntu.txt")
	aptErr := error(nil)
	runs := 0
	docker := fakeDocker{containers: []collect.ContainerSettings{
		{Name: "app-web-1", Running: true, User: "node", ImageRef: "node:22", Labels: map[string]string{composeProjectLabel: "app", composeDirLabel: "/srv/app"}, MountSources: []string{}},
	}}
	c := newCollector("0.3.0", fakeRoot(t), docker, func(context.Context) ([]byte, error) {
		runs++
		return aptOutput, aptErr
	})
	start := time.Unix(1761480000, 0)
	c.pass(context.Background(), start)
	select {
	case <-c.Ready():
	default:
		t.Fatal("not ready after the first pass")
	}
	report := decodeReport(t, c)
	for _, key := range []string{"version", "time", "os", "packages", "updates", "kernel", "checks", "listening", "projects"} {
		if _, ok := report[key]; !ok {
			t.Errorf("missing %s", key)
		}
	}
	packages := report["packages"].(map[string]any)
	if packages["manager"] != "dpkg" || len(packages["items"].([]any)) != 7 || packages["error"] != nil {
		t.Fatalf("packages %v", packages)
	}
	updates := report["updates"].(map[string]any)
	if len(updates["items"].([]any)) != 5 || updates["error"] != nil || updates["listsTime"] == nil {
		t.Fatalf("updates %v", updates)
	}
	kernel := report["kernel"].(map[string]any)
	if kernel["running"] != "6.8.0-85-generic" || kernel["latestInstalled"] != "6.8.0-88-generic" {
		t.Fatalf("kernel %v", kernel)
	}
	statuses := map[string]string{}
	for _, check := range report["checks"].([]any) {
		entry := check.(map[string]any)
		statuses[entry["id"].(string)] = entry["status"].(string)
	}
	want := map[string]string{
		"ssh.passwordLogin": "pass", "ssh.rootLogin": "pass", "updates.automatic": "pass", "users.extraRoot": "pass",
		"kernel.reboot": "fail", "docker.privileged": "pass", "docker.socketMount": "pass", "docker.hostNetwork": "pass",
		"docker.hostPID": "pass", "docker.capAdd": "pass", "docker.root": "pass", "docker.latestTag": "pass", "docker.oldImage": "pass",
	}
	if len(statuses) != len(want) {
		t.Fatalf("checks %v", statuses)
	}
	for id, status := range want {
		if statuses[id] != status {
			t.Errorf("%s: %s, want %s", id, statuses[id], status)
		}
	}
	projects := report["projects"].([]any)
	if len(projects) != 1 || len(projects[0].(map[string]any)["lockfiles"].([]any)) != 1 {
		t.Fatalf("projects %v", projects)
	}

	aptErr = errors.New("apt-get failed: broken")
	c.pass(context.Background(), start.Add(7*time.Hour))
	updates = decodeReport(t, c)["updates"].(map[string]any)
	if runs != 2 || updates["error"] != "apt-get failed: broken" || len(updates["items"].([]any)) != 5 {
		t.Fatalf("runs %d updates %v", runs, updates)
	}
	c.pass(context.Background(), start.Add(7*time.Hour+time.Minute))
	if runs != 2 {
		t.Fatalf("apt-get ran again after a minute: %d", runs)
	}
}

func TestCollectorWithoutDockerOrPackages(t *testing.T) {
	root := writeTree(t, map[string]string{"etc/os-release": "ID=alpine\nVERSION_ID=3.20.3\n", "lib/apk/db/installed": "P:musl\nV:1.2.5-r0\nA:aarch64\n"})
	c := newCollector("0.3.0", root, fakeDocker{err: errors.New("Permission denied on /var/run/docker.sock")}, nil)
	c.pass(context.Background(), time.Unix(1761480000, 0))
	report := decodeReport(t, c)
	if report["packages"].(map[string]any)["manager"] != "apk" {
		t.Fatalf("packages %v", report["packages"])
	}
	updates := report["updates"].(map[string]any)
	if updates["error"] != "Not supported on Alpine yet" || updates["items"] == nil {
		t.Fatalf("updates %v", updates)
	}
	if checks := report["checks"].([]any); len(checks) != 0 {
		t.Fatalf("checks %v", checks)
	}
	for _, key := range []string{"listening", "projects"} {
		if list, ok := report[key].([]any); !ok || len(list) != 0 {
			t.Fatalf("%s %v", key, report[key])
		}
	}
	empty := newCollector("0.3.0", t.TempDir(), nil, nil)
	empty.pass(context.Background(), time.Unix(1761480000, 0))
	report = decodeReport(t, empty)
	if report["packages"].(map[string]any)["manager"] != nil || report["os"].(map[string]any)["like"] == nil {
		t.Fatalf("report %v", report)
	}
}

func TestProjectScanDoesNotBlockThePass(t *testing.T) {
	c := newCollector("0.3.0", t.TempDir(), nil, nil)
	release := make(chan []Project)
	c.projectsScan = release
	start := time.Now()
	if c.finishProjectScan(20 * time.Millisecond) {
		t.Fatal("a running scan must not finish the pass")
	}
	if time.Since(start) > time.Second {
		t.Fatal("waited too long for a hung scan")
	}
	go func() { release <- []Project{{Name: "app"}} }()
	if !c.finishProjectScan(time.Second) || len(c.report.Projects) != 1 || c.projectsScan != nil {
		t.Fatalf("finished scan not applied: %+v", c.report.Projects)
	}
}
