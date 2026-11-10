package security

import (
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/en3sis/rackpulse/agent/internal/collect"
	"github.com/en3sis/rackpulse/agent/internal/config"
)

const npmLockfile = `{"lockfileVersion":3,"packages":{"":{},"node_modules/lodash":{"version":"4.17.20"}}}`

func TestComposeProjects(t *testing.T) {
	containers := []collect.ContainerSettings{
		{Name: "web", Labels: map[string]string{composeProjectLabel: "app", composeDirLabel: "/srv/app"}},
		{Name: "db", Labels: map[string]string{composeProjectLabel: "app", composeDirLabel: "/srv/app"}},
		{Name: "solo", Labels: map[string]string{}},
		{Name: "blog", Labels: map[string]string{composeDirLabel: "/srv/blog"}},
	}
	got := composeProjects(containers)
	want := []composeProject{{name: "app", path: "/srv/app"}, {name: "blog", path: "/srv/blog"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v", got)
	}
}

func TestScanProject(t *testing.T) {
	root := writeTree(t, map[string]string{
		"srv/app/package-lock.json":                npmLockfile,
		"srv/app/web/package-lock.json":            npmLockfile,
		"srv/app/a/b/c/go.mod":                     "require golang.org/x/net v0.17.0\n",
		"srv/app/a/b/c/d/go.mod":                   "require golang.org/x/text v0.13.0\n",
		"srv/app/node_modules/x/package-lock.json": npmLockfile,
		"srv/app/.git/package-lock.json":           npmLockfile,
		"srv/app/.hidden/package-lock.json":        npmLockfile,
		"srv/app/vendor/Cargo.lock":                "",
		"srv/app/build/package-lock.json":          npmLockfile,
		"srv/app/notes.txt":                        "lodash==1.0\n",
		"srv/app/README-package-lock.json":         npmLockfile,
		"srv/secret/package-lock.json":             npmLockfile,
		"srv/app/huge/requirements.txt":            "",
		"etc/package-lock.json":                    npmLockfile,
	})
	if err := os.Truncate(filepath.Join(root, "srv/app/huge/requirements.txt"), lockfileSizeLimit+1); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "srv/secret"), filepath.Join(root, "srv/app/linked")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "srv/secret/package-lock.json"), filepath.Join(root, "srv/app/sub/package-lock.json")); err != nil {
		os.MkdirAll(filepath.Join(root, "srv/app/sub"), 0o755)
		if err := os.Symlink(filepath.Join(root, "srv/secret/package-lock.json"), filepath.Join(root, "srv/app/sub/package-lock.json")); err != nil {
			t.Fatal(err)
		}
	}
	budget := dependencyLimit
	project := scanProject(root, composeProject{name: "app", path: "/srv/app"}, &budget)
	if project.Error != nil {
		t.Fatalf("error %s", *project.Error)
	}
	paths := []string{}
	for _, lockfile := range project.Lockfiles {
		paths = append(paths, lockfile.Path+" "+lockfile.Ecosystem)
	}
	want := []string{"a/b/c/go.mod Go", "package-lock.json npm", "web/package-lock.json npm"}
	if !reflect.DeepEqual(paths, want) {
		t.Fatalf("lockfiles %v\nwant %v", paths, want)
	}
	if got := project.Lockfiles[1].Packages; !reflect.DeepEqual(got, deps("lodash 4.17.20")) {
		t.Fatalf("packages %+v", got)
	}
	if budget != dependencyLimit-3 {
		t.Fatalf("budget %d", budget)
	}
}

func TestScanProjectRefusesUnsafeFolders(t *testing.T) {
	root := writeTree(t, map[string]string{"srv/real/package-lock.json": npmLockfile, "srv/file": "x"})
	os.Symlink(filepath.Join(root, "srv/real"), filepath.Join(root, "srv/link"))
	cases := map[string]string{
		"srv/real":          "Folder is not allowed",
		"/srv/real/../real": "Folder is not allowed",
		"/srv/real/":        "Folder is not allowed",
		"/proc/1/root":      "Folder is not allowed",
		"/sys":              "Folder is not allowed",
		"/dev/shm":          "Folder is not allowed",
		config.StateDir:     "Folder is not allowed",
		config.Dir + "/x":   "Folder is not allowed",
		"/srv/link":         "Folder is a symbolic link",
		"/srv/missing":      "Folder not found",
		"/srv/file":         "Not a folder",
	}
	for path, want := range cases {
		budget := dependencyLimit
		project := scanProject(root, composeProject{name: "x", path: path}, &budget)
		if project.Error == nil || *project.Error != want || len(project.Lockfiles) != 0 {
			t.Errorf("%s: error %v lockfiles %d, want %q", path, project.Error, len(project.Lockfiles), want)
		}
	}
}

func TestScanProjectErrors(t *testing.T) {
	skipAsRoot(t)
	root := writeTree(t, map[string]string{
		"srv/app/package-lock.json":      npmLockfile,
		"srv/app/api/composer.lock":      "{broken",
		"srv/app/data/package-lock.json": npmLockfile,
		"srv/locked/package-lock.json":   npmLockfile,
		"srv/app/web/package-lock.json":  npmLockfile,
	})
	os.Chmod(filepath.Join(root, "srv/app/data"), 0)
	os.Chmod(filepath.Join(root, "srv/app/web/package-lock.json"), 0)
	os.Chmod(filepath.Join(root, "srv/locked"), 0)
	t.Cleanup(func() {
		os.Chmod(filepath.Join(root, "srv/app/data"), 0o755)
		os.Chmod(filepath.Join(root, "srv/locked"), 0o755)
	})
	budget := dependencyLimit
	project := scanProject(root, composeProject{name: "app", path: "/srv/app"}, &budget)
	if project.Error == nil || *project.Error != "Cannot parse api/composer.lock" || len(project.Lockfiles) != 1 {
		t.Fatalf("project %+v", project)
	}
	project = scanProject(root, composeProject{name: "locked", path: "/srv/locked"}, &budget)
	if project.Error == nil || *project.Error != "Permission denied" {
		t.Fatalf("locked %+v", project)
	}
	os.Chmod(filepath.Join(root, "srv/app/api/composer.lock"), 0)
	project = scanProject(root, composeProject{name: "app", path: "/srv/app"}, &budget)
	if project.Error == nil || *project.Error != "Cannot read api/composer.lock: Permission denied" {
		t.Fatalf("project %+v", project)
	}
}

func TestScanProjectsLimits(t *testing.T) {
	files := map[string]string{}
	var lock strings.Builder
	lock.WriteString(`{"lockfileVersion":3,"packages":{`)
	for i := 0; i < 30; i++ {
		if i > 0 {
			lock.WriteString(",")
		}
		lock.WriteString(`"node_modules/p` + string(rune('a'+i%26)) + string(rune('a'+i/26)) + `":{"version":"1.0.0"}`)
	}
	lock.WriteString("}}")
	for i := 0; i < 60; i++ {
		files["srv/app/d"+string(rune('a'+i/26))+string(rune('a'+i%26))+"/package-lock.json"] = lock.String()
	}
	root := writeTree(t, files)
	budget := 40
	project := scanProject(root, composeProject{name: "app", path: "/srv/app"}, &budget)
	if len(project.Lockfiles) != lockfileLimit {
		t.Fatalf("lockfiles %d", len(project.Lockfiles))
	}
	if first, second := project.Lockfiles[0], project.Lockfiles[1]; first.Truncated || len(first.Packages) != 30 || !second.Truncated || len(second.Packages) != 10 {
		t.Fatalf("first %d %v, second %d %v", len(first.Packages), first.Truncated, len(second.Packages), second.Truncated)
	}
	if third := project.Lockfiles[2]; !third.Truncated || third.Packages == nil || len(third.Packages) != 0 {
		t.Fatalf("third %+v", third)
	}
	projects := make([]composeProject, 25)
	for i := range projects {
		projects[i] = composeProject{name: "p", path: "/srv/none"}
	}
	if got := scanProjects(root, projects); len(got) != projectLimit {
		t.Fatalf("projects %d", len(got))
	}
}

func TestScanProjectSkipsAgentFolders(t *testing.T) {
	root := writeTree(t, map[string]string{
		"var/lib/rackpulse-agent/package-lock.json": npmLockfile,
		"var/lib/app/package-lock.json":             npmLockfile,
	})
	budget := dependencyLimit
	project := scanProject(root, composeProject{name: "x", path: "/var/lib"}, &budget)
	if project.Error != nil || len(project.Lockfiles) != 1 || project.Lockfiles[0].Path != "app/package-lock.json" {
		t.Fatalf("project %+v", project)
	}
}

func TestFindLockfilesBoundsLargeFolders(t *testing.T) {
	root := writeTree(t, map[string]string{"web/package-lock.json": npmLockfile})
	for i := 0; i < 2*dirEntryLimit; i++ {
		mustWrite(t, filepath.Join(root, "data", "f"+strconv.Itoa(i)), nil)
	}
	entries, err := readDirLimited(filepath.Join(root, "data"), dirEntryLimit)
	if err != nil || len(entries) != dirEntryLimit {
		t.Fatalf("entries %d err %v", len(entries), err)
	}
	found, err := findLockfiles(root, "/srv/app")
	if err != nil || !reflect.DeepEqual(found, []string{filepath.Join("web", "package-lock.json")}) {
		t.Fatalf("found %v err %v", found, err)
	}
}

func TestScanProjectStopsReadingWithoutBudget(t *testing.T) {
	root := writeTree(t, map[string]string{"srv/app/package-lock.json": "{broken"})
	budget := 0
	project := scanProject(root, composeProject{name: "app", path: "/srv/app"}, &budget)
	if project.Error != nil || len(project.Lockfiles) != 1 || !project.Lockfiles[0].Truncated || len(project.Lockfiles[0].Packages) != 0 {
		t.Fatalf("project %+v", project)
	}
}
