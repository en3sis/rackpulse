package security

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"github.com/en3sis/rackpulse/agent/internal/collect"
	"github.com/en3sis/rackpulse/agent/internal/config"
)

const (
	composeProjectLabel = "com.docker.compose.project"
	composeDirLabel     = "com.docker.compose.project.working_dir"
	projectLimit        = 20
	lockfileLimit       = 50
	dependencyLimit     = 50000
	lockfileSizeLimit   = 10 << 20
	walkDepth           = 3
	walkEntryLimit      = 20000
	dirEntryLimit       = 2000
)

var (
	errTooLarge   = errors.New("file is larger than 10 MB")
	errNotRegular = errors.New("not a regular file")
	skippedDirs   = map[string]bool{"node_modules": true, "vendor": true, "venv": true, "target": true, "dist": true, "build": true}
	systemDirs    = []string{"/proc", "/sys", "/dev", config.Dir, config.StateDir}
)

type composeProject struct {
	name string
	path string
}

func composeProjects(containers []collect.ContainerSettings) []composeProject {
	names := map[string]string{}
	for _, container := range containers {
		dir := container.Labels[composeDirLabel]
		if dir == "" {
			continue
		}
		if name := container.Labels[composeProjectLabel]; names[dir] == "" {
			names[dir] = name
		}
	}
	projects := make([]composeProject, 0, len(names))
	for dir, name := range names {
		if name == "" {
			name = path.Base(dir)
		}
		projects = append(projects, composeProject{name: name, path: dir})
	}
	sort.Slice(projects, func(i, j int) bool {
		if projects[i].name != projects[j].name {
			return projects[i].name < projects[j].name
		}
		return projects[i].path < projects[j].path
	})
	return projects
}

func projectsKey(projects []composeProject) string {
	parts := make([]string, len(projects))
	for i, project := range projects {
		parts[i] = project.name + "\x00" + project.path
	}
	return strings.Join(parts, "\x01")
}

func scanProjects(root string, projects []composeProject) []Project {
	result := []Project{}
	budget := dependencyLimit
	for _, project := range projects {
		if len(result) >= projectLimit {
			break
		}
		result = append(result, scanProject(root, project, &budget))
	}
	return result
}

func underSystemDir(dir string) bool {
	for _, blocked := range systemDirs {
		if dir == blocked || strings.HasPrefix(dir, blocked+"/") {
			return true
		}
	}
	return false
}

func allowedWorkingDir(dir string) bool {
	return filepath.IsAbs(dir) && filepath.Clean(dir) == dir && !underSystemDir(dir)
}

func scanProject(root string, project composeProject, budget *int) Project {
	result := Project{Name: project.name, Path: project.path, Lockfiles: []Lockfile{}}
	if !allowedWorkingDir(project.path) {
		result.Error = stringPointer("Folder is not allowed")
		return result
	}
	base := hostPath(root, project.path)
	info, err := os.Lstat(base)
	switch {
	case err != nil:
		result.Error = stringPointer(folderError(err))
		return result
	case info.Mode()&fs.ModeSymlink != 0:
		result.Error = stringPointer("Folder is a symbolic link")
		return result
	case !info.IsDir():
		result.Error = stringPointer("Not a folder")
		return result
	}
	found, err := findLockfiles(base, project.path)
	if err != nil {
		result.Error = stringPointer(folderError(err))
		return result
	}
	for _, relative := range found {
		if len(result.Lockfiles) >= lockfileLimit {
			break
		}
		lockfile, err := readLockfile(base, relative, budget)
		if errors.Is(err, errTooLarge) || errors.Is(err, errNotRegular) {
			continue
		}
		if err != nil {
			if result.Error == nil {
				result.Error = stringPointer(err.Error())
			}
			continue
		}
		result.Lockfiles = append(result.Lockfiles, lockfile)
	}
	return result
}

func folderError(err error) string {
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return "Folder not found"
	case errors.Is(err, fs.ErrPermission):
		return "Permission denied"
	}
	var pathError *fs.PathError
	if errors.As(err, &pathError) {
		return pathError.Err.Error()
	}
	return err.Error()
}

func findLockfiles(base, logical string) ([]string, error) {
	found := []string{}
	visited := 0
	queue := []string{""}
	for len(queue) > 0 && visited < walkEntryLimit {
		relative := queue[0]
		queue = queue[1:]
		entries, err := readDirLimited(filepath.Join(base, relative), min(dirEntryLimit, walkEntryLimit-visited))
		if err != nil {
			if relative == "" {
				return nil, err
			}
			continue
		}
		visited += len(entries)
		for _, entry := range entries {
			name := entry.Name()
			child := filepath.Join(relative, name)
			switch {
			case entry.IsDir():
				if !strings.HasPrefix(name, ".") && !skippedDirs[name] && strings.Count(child, string(filepath.Separator)) < walkDepth && !underSystemDir(path.Join(logical, filepath.ToSlash(child))) {
					queue = append(queue, child)
				}
			case entry.Type().IsRegular():
				if _, ok := lockfileParsers[name]; ok {
					found = append(found, child)
				}
			}
		}
	}
	sort.Strings(found)
	return found, nil
}

func readDirLimited(dir string, limit int) ([]fs.DirEntry, error) {
	handle, err := os.OpenFile(dir, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer handle.Close()
	entries := []fs.DirEntry{}
	for len(entries) < limit {
		batch, err := handle.ReadDir(min(256, limit-len(entries)))
		entries = append(entries, batch...)
		if err != nil {
			break
		}
	}
	return entries, nil
}

func readLimited(file string) ([]byte, error) {
	info, err := os.Lstat(file)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errNotRegular
	}
	if info.Size() > lockfileSizeLimit {
		return nil, errTooLarge
	}
	handle, err := os.OpenFile(file, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer handle.Close()
	stat, err := handle.Stat()
	if err != nil {
		return nil, err
	}
	if !stat.Mode().IsRegular() {
		return nil, errNotRegular
	}
	data, err := io.ReadAll(io.LimitReader(handle, lockfileSizeLimit+1))
	if err != nil {
		return nil, err
	}
	if len(data) > lockfileSizeLimit {
		return nil, errTooLarge
	}
	return data, nil
}

func readLockfile(base, relative string, budget *int) (Lockfile, error) {
	parser := lockfileParsers[filepath.Base(relative)]
	display := filepath.ToSlash(relative)
	if *budget <= 0 {
		return Lockfile{Path: display, Ecosystem: parser.ecosystem, Packages: []Dependency{}, Truncated: true}, nil
	}
	data, err := readLimited(filepath.Join(base, relative))
	if errors.Is(err, errTooLarge) || errors.Is(err, errNotRegular) {
		return Lockfile{}, err
	}
	if err != nil {
		return Lockfile{}, errors.New("Cannot read " + display + ": " + folderError(err))
	}
	dependencies, err := parser.parse(data)
	if err != nil {
		return Lockfile{}, errors.New("Cannot parse " + display)
	}
	dependencies = uniqueDependencies(dependencies)
	truncated := false
	if len(dependencies) > *budget {
		dependencies = dependencies[:*budget]
		truncated = true
	}
	*budget -= len(dependencies)
	return Lockfile{Path: display, Ecosystem: parser.ecosystem, Packages: dependencies, Truncated: truncated}, nil
}

func uniqueDependencies(dependencies []Dependency) []Dependency {
	seen := map[Dependency]bool{}
	unique := []Dependency{}
	for _, dependency := range dependencies {
		if dependency.Name == "" || dependency.Version == "" || seen[dependency] {
			continue
		}
		seen[dependency] = true
		unique = append(unique, dependency)
	}
	sort.Slice(unique, func(i, j int) bool {
		if unique[i].Name != unique[j].Name {
			return unique[i].Name < unique[j].Name
		}
		return unique[i].Version < unique[j].Version
	})
	return unique
}
