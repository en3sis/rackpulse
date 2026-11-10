package collect

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestApplySettings(t *testing.T) {
	var inspected inspectedSettings
	if err := json.Unmarshal([]byte(`{"Name":"/web","Image":"sha256:abc",
		"Config":{"Image":"nginx:1.27","User":"101:101","WorkingDir":"/app"},
		"HostConfig":{"Privileged":false,"NetworkMode":"bridge","PidMode":"host","CapAdd":["NET_ADMIN"]},
		"Mounts":[{"Source":"/var/run"}]}`), &inspected); err != nil {
		t.Fatal(err)
	}
	settings := ContainerSettings{ImageRef: "sha256:abc", MountSources: []string{}}
	applySettings(&settings, inspected)
	if settings.Name != "web" || settings.ImageRef != "nginx:1.27" || settings.ImageID != "sha256:abc" || settings.User != "101:101" ||
		settings.WorkingDir != "/app" || settings.PidMode != "host" || len(settings.CapAdd) != 1 || settings.MountSources[0] != "/var/run" {
		t.Fatalf("settings %+v", settings)
	}
}

func TestImageDetails(t *testing.T) {
	details := imageDetails(inspectedImage{
		RepoTags:    []string{"<none>:<none>", "nginx:1.27"},
		RepoDigests: []string{"nginx@sha256:def"},
		Created:     "2026-10-01T10:00:00.123Z",
	})
	if len(details.Tags) != 1 || len(details.Digests) != 1 || details.Created == nil || *details.Created != 1790848800 {
		t.Fatalf("details %+v", details)
	}
	if reproducible := imageDetails(inspectedImage{Created: "1970-01-01T00:00:00Z"}); reproducible.Created != nil {
		t.Fatalf("epoch created %v", *reproducible.Created)
	}
}

func TestArchiveRequest(t *testing.T) {
	var seen string
	d := &dockerCollector{client: &http.Client{Transport: roundTrip(func(req *http.Request) (*http.Response, error) {
		seen = req.URL.RequestURI()
		status, body := http.StatusOK, "tar"
		switch {
		case strings.Contains(req.URL.Path, "gone"):
			status, body = http.StatusNotFound, `{"message":"No such container: gone"}`
		case strings.Contains(req.URL.RawQuery, "missing"):
			status, body = http.StatusNotFound, `{"message":"Could not find the file /missing in container abc"}`
		}
		return &http.Response{StatusCode: status, Status: http.StatusText(status), Body: io.NopCloser(strings.NewReader(body)), Header: http.Header{}}, nil
	})}}
	body, err := d.archive(context.Background(), "abc", "/etc/os release")
	if err != nil {
		t.Fatal(err)
	}
	data, _ := io.ReadAll(body)
	body.Close()
	if string(data) != "tar" || seen != "/containers/abc/archive?path=%2Fetc%2Fos+release" {
		t.Fatalf("data %q uri %q", data, seen)
	}
	if _, err := d.archive(context.Background(), "abc", "/missing"); !IsNotFound(err) {
		t.Fatalf("err %v", err)
	}
	if _, err := d.archive(context.Background(), "gone", "/etc/os-release"); err != ErrContainerGone {
		t.Fatalf("err %v", err)
	}
}
