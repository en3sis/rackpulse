package security

import (
	"bytes"
	"reflect"
	"testing"
)

func TestParseDpkgStatus(t *testing.T) {
	items, err := parseDpkgStatus(bytes.NewReader(readFixture(t, "dpkg/status")))
	if err != nil {
		t.Fatal(err)
	}
	want := []Package{
		{Name: "bash", Version: "5.2.21-2ubuntu4", Source: "bash", SourceVersion: "5.2.21-2ubuntu4", Arch: "arm64"},
		{Name: "liblzma5", Version: "5.6.1+really5.4.5-1ubuntu0.3", Source: "xz-utils", SourceVersion: "5.6.1+really5.4.5-1ubuntu0.3", Arch: "arm64"},
		{Name: "libssl3t64", Version: "3.0.13-0ubuntu3.4", Source: "openssl", SourceVersion: "3.0.13-0ubuntu3.4", Arch: "arm64"},
		{Name: "linux-image-6.8.0-85-generic", Version: "6.8.0-85.85", Source: "linux-signed", SourceVersion: "6.8.0-85.85", Arch: "arm64"},
		{Name: "linux-image-6.8.0-88-generic", Version: "6.8.0-88.89", Source: "linux-signed", SourceVersion: "6.8.0-88.89", Arch: "arm64"},
		{Name: "linux-image-generic", Version: "6.8.0-88.89", Source: "linux-meta", SourceVersion: "6.8.0-88.89", Arch: "arm64"},
		{Name: "unattended-upgrades", Version: "2.9.1+nmu4ubuntu1", Source: "unattended-upgrades", SourceVersion: "2.9.1+nmu4ubuntu1", Arch: "all"},
	}
	if !reflect.DeepEqual(items, want) {
		t.Fatalf("got %+v\nwant %+v", items, want)
	}
}

func TestParseDpkgSourceWithDifferentVersion(t *testing.T) {
	items, _ := parseDpkgStatus(bytes.NewBufferString("Package: libfoo1\nStatus: install ok installed\nArchitecture: amd64\nSource: foo (1.2-3)\nVersion: 1.2-3+b1\n"))
	if len(items) != 1 || items[0].Source != "foo" || items[0].SourceVersion != "1.2-3" || items[0].Version != "1.2-3+b1" {
		t.Fatalf("items %+v", items)
	}
}

func TestParseDpkgKeepsEpochs(t *testing.T) {
	status := "Package: vim\nStatus: install ok installed\nArchitecture: amd64\nVersion: 2:9.0.1378-2\n\nPackage: xxd\nStatus: install ok installed\nArchitecture: amd64\nSource: vim (2:9.0.1378-2)\nVersion: 2:9.0.1378-2+b1\n"
	items, _ := parseDpkgStatus(bytes.NewBufferString(status))
	if len(items) != 2 || items[0].SourceVersion != "2:9.0.1378-2" || items[0].Version != "2:9.0.1378-2" || items[1].SourceVersion != "2:9.0.1378-2" || items[1].Version != "2:9.0.1378-2+b1" {
		t.Fatalf("items %+v", items)
	}
}

func TestParseApkInstalled(t *testing.T) {
	items, err := parseApkInstalled(bytes.NewReader(readFixture(t, "apk/installed")))
	if err != nil {
		t.Fatal(err)
	}
	want := []Package{
		{Name: "busybox", Version: "1.36.1-r29", Source: "busybox", SourceVersion: "1.36.1-r29", Arch: "aarch64"},
		{Name: "libcrypto3", Version: "3.3.2-r0", Source: "openssl", SourceVersion: "3.3.2-r0", Arch: "aarch64"},
		{Name: "musl", Version: "1.2.5-r0", Source: "musl", SourceVersion: "1.2.5-r0", Arch: "aarch64"},
	}
	if !reflect.DeepEqual(items, want) {
		t.Fatalf("got %+v\nwant %+v", items, want)
	}
}

func TestParseOSRelease(t *testing.T) {
	info := parseOSRelease("PRETTY_NAME=\"Ubuntu 24.04.3 LTS\"\nNAME=\"Ubuntu\"\nVERSION_ID=\"24.04\"\nVERSION_CODENAME=noble\nID=ubuntu\nID_LIKE=debian\n# comment\n")
	if *info.ID != "ubuntu" || *info.VersionID != "24.04" || *info.Codename != "noble" || *info.Name != "Ubuntu 24.04.3 LTS" || !reflect.DeepEqual(info.Like, []string{"debian"}) {
		t.Fatalf("info %+v", info)
	}
	alpine := parseOSRelease("ID=alpine\nVERSION_ID=3.20.3\nPRETTY_NAME='Alpine Linux v3.20'\n")
	if *alpine.ID != "alpine" || alpine.Codename != nil || alpine.Like == nil || len(alpine.Like) != 0 || *alpine.Name != "Alpine Linux v3.20" {
		t.Fatalf("alpine %+v", alpine)
	}
	if empty := readOSRelease(t.TempDir()); empty.ID != nil || empty.Like == nil {
		t.Fatalf("empty %+v", empty)
	}
}
