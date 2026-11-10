package collect

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

var (
	ErrNoDocker      = errors.New("Docker is not installed")
	ErrContainerGone = errors.New("The container stopped during the scan")
)

type ContainerSettings struct {
	ID           string
	Name         string
	Running      bool
	Labels       map[string]string
	Privileged   bool
	NetworkMode  string
	PidMode      string
	CapAdd       []string
	User         string
	WorkingDir   string
	ImageRef     string
	ImageID      string
	MountSources []string
	Image        *ImageDetails
}

type ImageDetails struct {
	Tags    []string
	Digests []string
	Created *int64
}

type inspectedSettings struct {
	Name   string `json:"Name"`
	Image  string `json:"Image"`
	Config struct {
		Image      string `json:"Image"`
		User       string `json:"User"`
		WorkingDir string `json:"WorkingDir"`
	} `json:"Config"`
	HostConfig struct {
		Privileged  bool     `json:"Privileged"`
		NetworkMode string   `json:"NetworkMode"`
		PidMode     string   `json:"PidMode"`
		CapAdd      []string `json:"CapAdd"`
	} `json:"HostConfig"`
	Mounts []struct {
		Source string `json:"Source"`
	} `json:"Mounts"`
}

type inspectedImage struct {
	RepoTags    []string `json:"RepoTags"`
	RepoDigests []string `json:"RepoDigests"`
	Created     string   `json:"Created"`
}

func (c *Collector) ContainerSettings(ctx context.Context) ([]ContainerSettings, error) {
	if !dockerInstalled() {
		return nil, ErrNoDocker
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var listed []listedContainer
	if err := c.docker.get(ctx, "/containers/json?all=1", &listed); err != nil {
		return nil, errors.New(dockerErrorMessage(err))
	}
	settings := make([]ContainerSettings, len(listed))
	failures := make([]error, len(listed))
	limit := make(chan struct{}, 4)
	var wg sync.WaitGroup
	for i, item := range listed {
		settings[i] = ContainerSettings{ID: item.ID, Running: item.State == "running", Labels: item.Labels, ImageRef: item.Image, MountSources: []string{}}
		if len(item.Names) > 0 {
			settings[i].Name = strings.TrimPrefix(item.Names[0], "/")
		}
		wg.Add(1)
		go func(i int, id string) {
			defer wg.Done()
			limit <- struct{}{}
			defer func() { <-limit }()
			var inspected inspectedSettings
			if err := c.docker.get(ctx, "/containers/"+url.PathEscape(id)+"/json", &inspected); err != nil {
				failures[i] = err
				return
			}
			applySettings(&settings[i], inspected)
		}(i, item.ID)
	}
	wg.Wait()
	found := make([]ContainerSettings, 0, len(settings))
	for i, err := range failures {
		var apiErr *APIError
		switch {
		case err == nil:
			found = append(found, settings[i])
		case errors.As(err, &apiErr) && apiErr.Code == http.StatusNotFound:
		default:
			return nil, errors.New(dockerErrorMessage(err))
		}
	}
	c.addImageDetails(ctx, found)
	return found, nil
}

func applySettings(settings *ContainerSettings, inspected inspectedSettings) {
	if inspected.Name != "" {
		settings.Name = strings.TrimPrefix(inspected.Name, "/")
	}
	if inspected.Config.Image != "" {
		settings.ImageRef = inspected.Config.Image
	}
	settings.ImageID = inspected.Image
	settings.User = inspected.Config.User
	settings.WorkingDir = inspected.Config.WorkingDir
	settings.Privileged = inspected.HostConfig.Privileged
	settings.NetworkMode = inspected.HostConfig.NetworkMode
	settings.PidMode = inspected.HostConfig.PidMode
	settings.CapAdd = append([]string{}, inspected.HostConfig.CapAdd...)
	for _, mount := range inspected.Mounts {
		settings.MountSources = append(settings.MountSources, mount.Source)
	}
}

func (c *Collector) addImageDetails(ctx context.Context, settings []ContainerSettings) {
	details := map[string]*ImageDetails{}
	for _, container := range settings {
		if container.Running && container.ImageID != "" {
			details[container.ImageID] = nil
		}
	}
	var mu sync.Mutex
	limit := make(chan struct{}, 4)
	var wg sync.WaitGroup
	for id := range details {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			limit <- struct{}{}
			defer func() { <-limit }()
			var inspected inspectedImage
			if err := c.docker.get(ctx, "/images/"+url.PathEscape(id)+"/json", &inspected); err != nil {
				return
			}
			mu.Lock()
			details[id] = imageDetails(inspected)
			mu.Unlock()
		}(id)
	}
	wg.Wait()
	for i := range settings {
		if settings[i].Running {
			settings[i].Image = details[settings[i].ImageID]
		}
	}
}

func imageDetails(inspected inspectedImage) *ImageDetails {
	details := &ImageDetails{Tags: []string{}, Digests: []string{}}
	for _, tag := range inspected.RepoTags {
		if tag != "" && tag != "<none>:<none>" {
			details.Tags = append(details.Tags, tag)
		}
	}
	for _, digest := range inspected.RepoDigests {
		if digest != "" && digest != "<none>@<none>" {
			details.Digests = append(details.Digests, digest)
		}
	}
	if created := dockerTime(inspected.Created); created != nil && *created > 0 {
		details.Created = created
	}
	return details
}

const archiveErrorLimit = 64 << 10

func (c *Collector) ContainerArchive(ctx context.Context, id, path string) (io.ReadCloser, error) {
	if !dockerInstalled() {
		return nil, ErrNoDocker
	}
	return c.docker.archive(ctx, id, path)
}

func (d *dockerCollector) archive(ctx context.Context, id, path string) (io.ReadCloser, error) {
	target := "/containers/" + url.PathEscape(id) + "/archive?path=" + url.QueryEscape(path)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker"+target, nil)
	if err != nil {
		return nil, err
	}
	resp, err := d.client.Do(req)
	if err != nil {
		return nil, errors.New(dockerErrorMessage(err))
	}
	if resp.StatusCode != http.StatusOK {
		var message struct {
			Message string `json:"message"`
		}
		json.NewDecoder(io.LimitReader(resp.Body, archiveErrorLimit)).Decode(&message)
		resp.Body.Close()
		if resp.StatusCode == http.StatusNotFound && strings.HasPrefix(message.Message, "No such container") {
			return nil, ErrContainerGone
		}
		return nil, &APIError{Code: resp.StatusCode, Status: resp.Status, Path: "/containers/" + id + "/archive"}
	}
	return resp.Body, nil
}

func IsNotFound(err error) bool {
	var apiErr *APIError
	return errors.As(err, &apiErr) && apiErr.Code == http.StatusNotFound
}
