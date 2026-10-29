package collect

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type storage struct {
	Device string
	Kind   string
	Model  string
}

var virtualVendors = []string{"qemu", "vmware", "msft", "google", "amazon", "red hat", "virtio", "xen"}

func describeStorage(sysRoot, device string, dev uint64) storage {
	result := storage{Device: device}
	name := blockName(sysRoot, device, dev)
	if name == "" {
		return result
	}
	if device == "/dev/root" {
		result.Device = "/dev/" + name
	}
	disk := name
	if real, err := filepath.EvalSymlinks(filepath.Join(sysRoot, "class/block", name)); err == nil {
		if exists(filepath.Join(real, "partition")) {
			disk = filepath.Base(filepath.Dir(real))
		}
	}
	base := filepath.Join(sysRoot, "block", disk)
	real, _ := filepath.EvalSymlinks(base)
	read := func(file string) string {
		data, err := os.ReadFile(filepath.Join(base, file))
		if err != nil {
			return ""
		}
		return strings.TrimSpace(string(data))
	}
	model := read("device/model")
	switch {
	case strings.HasPrefix(disk, "zram"), strings.HasPrefix(disk, "ram"):
		result.Kind = "ram"
	case strings.HasPrefix(disk, "loop"):
		result.Kind = "image"
	case strings.HasPrefix(disk, "md"):
		result.Kind = "raid"
	case strings.HasPrefix(disk, "dm-"):
		result.Kind = "mapped"
	case strings.HasPrefix(disk, "mmcblk"):
		result.Kind = "sd"
		if read("device/type") == "MMC" {
			result.Kind = "emmc"
		}
		model = read("device/name")
	case strings.HasPrefix(disk, "nvme"):
		result.Kind = "nvme"
	case strings.Contains(real, "/usb"):
		result.Kind = "usb"
	case strings.HasPrefix(disk, "vd"), strings.HasPrefix(disk, "xvd"), isVirtual(read("device/vendor")):
		result.Kind = "virtual"
		model = ""
	case read("queue/rotational") == "1":
		result.Kind = "hdd"
	default:
		result.Kind = "ssd"
	}
	result.Model = model
	return result
}

func blockName(sysRoot, device string, dev uint64) string {
	if major, minor := deviceNumbers(dev); major != 0 {
		if real, err := filepath.EvalSymlinks(filepath.Join(sysRoot, "dev/block", fmt.Sprintf("%d:%d", major, minor))); err == nil {
			return filepath.Base(real)
		}
	}
	name := filepath.Base(device)
	if exists(filepath.Join(sysRoot, "class/block", name)) {
		return name
	}
	if real, err := filepath.EvalSymlinks(device); err == nil && exists(filepath.Join(sysRoot, "class/block", filepath.Base(real))) {
		return filepath.Base(real)
	}
	return ""
}

func deviceNumbers(dev uint64) (uint64, uint64) {
	major := (dev>>8)&0xfff | (dev>>32)&0xfffff000
	minor := dev&0xff | (dev>>12)&0xffffff00
	return major, minor
}

func isVirtual(vendor string) bool {
	vendor = strings.ToLower(vendor)
	for _, name := range virtualVendors {
		if vendor != "" && strings.HasPrefix(vendor, name) {
			return true
		}
	}
	return false
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
