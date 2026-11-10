package security

import (
	"os"
	"strings"
)

func readKernel(root string, packages []Package) Kernel {
	kernel := Kernel{}
	if data, err := os.ReadFile(hostPath(root, "/proc/sys/kernel/osrelease")); err == nil {
		kernel.Running = optionalString(strings.TrimSpace(string(data)))
	}
	kernel.LatestInstalled = latestKernel(packages)
	return kernel
}

func kernelRelease(name string) (string, bool) {
	release, ok := strings.CutPrefix(name, "linux-image-")
	if !ok || release == "" || !isDigit(release[0]) {
		return "", false
	}
	return release, true
}

func latestKernel(packages []Package) *string {
	best, bestVersion := "", ""
	for _, item := range packages {
		release, ok := kernelRelease(item.Name)
		if !ok {
			continue
		}
		if best == "" {
			best, bestVersion = release, item.Version
			continue
		}
		result := CompareVersions(item.Version, bestVersion)
		if result > 0 || result == 0 && CompareVersions(release, best) > 0 {
			best, bestVersion = release, item.Version
		}
	}
	return optionalString(best)
}

func kernelVersion(packages []Package, release string) (string, bool) {
	for _, item := range packages {
		if name, ok := kernelRelease(item.Name); ok && name == release {
			return item.Version, true
		}
	}
	return "", false
}

func kernelCheck(kernel Kernel, packages []Package) (Check, bool) {
	if kernel.Running == nil || kernel.LatestInstalled == nil {
		return Check{}, false
	}
	running, latest := *kernel.Running, *kernel.LatestInstalled
	check := Check{ID: "kernel.reboot", Status: statusPass, Title: "Running the newest installed kernel", Detail: "Running " + running}
	if running == latest {
		return check, true
	}
	newer := CompareVersions(latest, running) > 0
	if runningVersion, ok := kernelVersion(packages, running); ok {
		latestVersion, _ := kernelVersion(packages, latest)
		newer = CompareVersions(latestVersion, runningVersion) > 0
	}
	if newer {
		check.Status = statusFail
		check.Title = "Reboot needed to use the newer kernel"
		check.Detail = "Running " + running + ", installed " + latest
	}
	return check, true
}
