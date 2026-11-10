package security

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"
)

const (
	aptListsDir     = "/var/lib/apt/lists"
	aptSuccessStamp = "/var/lib/apt/periodic/update-success-stamp"
	aptTimeout      = 60 * time.Second
	aptOutputLimit  = 8 << 20
)

var aptArgs = []string{
	"-s",
	"-o", "Debug::NoLocking=1",
	"-o", "APT::Get::Show-User-Simulation-Note=false",
	"dist-upgrade",
}

var aptEnv = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}

type cappedBuffer struct {
	buffer   bytes.Buffer
	limit    int
	overflow bool
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	if room := b.limit - b.buffer.Len(); room > 0 {
		if len(p) > room {
			b.buffer.Write(p[:room])
			b.overflow = true
		} else {
			b.buffer.Write(p)
		}
	} else if len(p) > 0 {
		b.overflow = true
	}
	return len(p), nil
}

func findBinary(name string) string {
	for _, dir := range []string{"/usr/bin", "/bin"} {
		path := dir + "/" + name
		if info, err := os.Stat(path); err == nil && info.Mode().IsRegular() {
			return path
		}
	}
	return ""
}

func runAptGet(ctx context.Context) ([]byte, error) {
	return runTool(ctx, "apt-get", aptArgs)
}

func runAptConfig(ctx context.Context) ([]byte, error) {
	return runTool(ctx, "apt-config", []string{"dump", "APT::Periodic"})
}

func runTool(ctx context.Context, name string, args []string) ([]byte, error) {
	binary := findBinary(name)
	if binary == "" {
		return nil, errors.New(name + " not found")
	}
	ctx, cancel := context.WithTimeout(ctx, aptTimeout)
	defer cancel()
	stdout := &cappedBuffer{limit: aptOutputLimit}
	stderr := &cappedBuffer{limit: 64 << 10}
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Env = aptEnv
	cmd.Dir = "/"
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	cmd.WaitDelay = 5 * time.Second
	err := cmd.Run()
	switch {
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		return nil, errors.New(name + " did not finish in 60 seconds")
	case stdout.overflow:
		return nil, errors.New(name + " output is larger than 8 MB")
	case err != nil:
		if message := aptErrorLine(stderr.buffer.String()); message != "" {
			return nil, errors.New(name + " failed: " + message)
		}
		return nil, errors.New(name + " failed: " + err.Error())
	}
	return stdout.buffer.Bytes(), nil
}

func aptErrorLine(stderr string) string {
	lines := strings.Split(strings.TrimSpace(stderr), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if message, ok := strings.CutPrefix(strings.TrimSpace(lines[i]), "E: "); ok {
			return message
		}
	}
	return ""
}

func parseAptSimulation(output []byte) []Update {
	items := []Update{}
	scanner := bufio.NewScanner(bytes.NewReader(output))
	scanner.Buffer(make([]byte, 64<<10), 1<<20)
	seen := map[string]bool{}
	for scanner.Scan() {
		update, ok := parseInstLine(scanner.Text())
		if !ok || seen[update.Name] {
			continue
		}
		seen[update.Name] = true
		items = append(items, update)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Name < items[j].Name })
	return items
}

func parseInstLine(line string) (Update, bool) {
	rest, ok := strings.CutPrefix(line, "Inst ")
	if !ok {
		return Update{}, false
	}
	name, rest, _ := strings.Cut(strings.TrimSpace(rest), " ")
	if base, _, found := strings.Cut(name, ":"); found {
		name = base
	}
	if name == "" {
		return Update{}, false
	}
	update := Update{Name: name, Origins: []string{}}
	rest = strings.TrimSpace(rest)
	if strings.HasPrefix(rest, "[") {
		end := strings.IndexByte(rest, ']')
		if end < 0 {
			return Update{}, false
		}
		current := rest[1:end]
		update.Current = &current
		rest = strings.TrimSpace(rest[end+1:])
	}
	opening := strings.IndexByte(rest, '(')
	closing := strings.LastIndexByte(rest, ')')
	if opening < 0 || closing < opening {
		return Update{}, false
	}
	inner := strings.TrimSpace(rest[opening+1 : closing])
	available, origins, _ := strings.Cut(inner, " ")
	if available == "" {
		return Update{}, false
	}
	update.Available = available
	origins = strings.TrimSpace(origins)
	if index := strings.LastIndex(origins, " ["); index >= 0 && strings.HasSuffix(origins, "]") {
		origins = origins[:index]
	} else if strings.HasPrefix(origins, "[") && strings.HasSuffix(origins, "]") {
		origins = ""
	}
	for _, origin := range strings.Split(origins, ",") {
		if origin = strings.TrimSpace(origin); origin != "" {
			update.Origins = append(update.Origins, origin)
			if securityOrigin(origin) {
				update.Security = true
			}
		}
	}
	return update, true
}

func securityOrigin(origin string) bool {
	if strings.HasPrefix(origin, "Debian-Security:") {
		return true
	}
	slash := strings.LastIndexByte(origin, '/')
	return slash >= 0 && strings.HasSuffix(origin[slash+1:], "-security")
}

func aptListsTime(root string) *int64 {
	var newest time.Time
	entries, _ := os.ReadDir(hostPath(root, aptListsDir))
	for _, entry := range entries {
		if entry.Name() == "partial" || entry.Name() == "lock" || !entry.Type().IsRegular() {
			continue
		}
		if info, err := entry.Info(); err == nil && info.ModTime().After(newest) {
			newest = info.ModTime()
		}
	}
	if info, err := os.Stat(hostPath(root, aptSuccessStamp)); err == nil && info.ModTime().After(newest) {
		newest = info.ModTime()
	}
	if newest.IsZero() {
		return nil
	}
	unix := newest.Unix()
	return &unix
}

func modTime(root, path string) int64 {
	info, err := os.Stat(hostPath(root, path))
	if err != nil {
		return 0
	}
	return info.ModTime().UnixNano()
}
