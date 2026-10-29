package collect

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDescribeStorage(t *testing.T) {
	root := t.TempDir()
	disk := func(path, name string, files map[string]string, parts ...string) {
		dir := filepath.Join(root, "devices", path, "block", name)
		for file, value := range files {
			full := filepath.Join(dir, file)
			if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(full, []byte(value+"\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		link := func(target, at string) {
			if err := os.MkdirAll(filepath.Dir(at), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, at); err != nil {
				t.Fatal(err)
			}
		}
		os.MkdirAll(dir, 0o755)
		link(dir, filepath.Join(root, "block", name))
		link(dir, filepath.Join(root, "class/block", name))
		for _, part := range parts {
			partDir := filepath.Join(dir, part)
			os.MkdirAll(partDir, 0o755)
			os.WriteFile(filepath.Join(partDir, "partition"), []byte("1\n"), 0o644)
			link(partDir, filepath.Join(root, "class/block", part))
		}
	}
	disk("platform/mmc0", "mmcblk0", map[string]string{"device/type": "SD", "device/name": "SD64G"}, "mmcblk0p2")
	disk("platform/mmc1", "mmcblk1", map[string]string{"device/type": "MMC", "device/name": "A3A444"}, "mmcblk1p1")
	disk("platform/usb1/1-1", "sda", map[string]string{"device/model": "Expansion HDD", "queue/rotational": "1"}, "sda1")
	disk("pci0000:00/nvme0", "nvme0n1", map[string]string{"device/model": "Samsung 980"}, "nvme0n1p1")
	disk("pci0000:00/ata1", "sdb", map[string]string{"device/model": "WDC WD40", "device/vendor": "ATA", "queue/rotational": "1"})
	disk("pci0000:00/virtio1", "sdc", map[string]string{"device/model": "QEMU HARDDISK", "device/vendor": "QEMU", "queue/rotational": "1"}, "sdc1")
	disk("virtual", "zram1", map[string]string{})
	os.MkdirAll(filepath.Join(root, "dev/block"), 0o755)
	os.Symlink(filepath.Join(root, "devices/platform/mmc0/block/mmcblk0/mmcblk0p2"), filepath.Join(root, "dev/block/179:2"))

	rootDev := uint64(179<<8 | 2)
	cases := []struct {
		device string
		dev    uint64
		want   storage
	}{
		{"/dev/root", rootDev, storage{Device: "/dev/mmcblk0p2", Kind: "sd", Model: "SD64G"}},
		{"/dev/mmcblk1p1", 0, storage{Device: "/dev/mmcblk1p1", Kind: "emmc", Model: "A3A444"}},
		{"/dev/sda1", 0, storage{Device: "/dev/sda1", Kind: "usb", Model: "Expansion HDD"}},
		{"/dev/nvme0n1p1", 0, storage{Device: "/dev/nvme0n1p1", Kind: "nvme", Model: "Samsung 980"}},
		{"/dev/sdb", 0, storage{Device: "/dev/sdb", Kind: "hdd", Model: "WDC WD40"}},
		{"/dev/sdc1", 0, storage{Device: "/dev/sdc1", Kind: "virtual"}},
		{"/dev/zram1", 0, storage{Device: "/dev/zram1", Kind: "ram"}},
		{"/dev/unknown", 0, storage{Device: "/dev/unknown"}},
	}
	for _, c := range cases {
		if got := describeStorage(root, c.device, c.dev); got != c.want {
			t.Errorf("%s: got %+v, want %+v", c.device, got, c.want)
		}
	}
}
