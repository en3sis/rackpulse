package security

import (
	"archive/tar"
	"bytes"
	"context"
	"io"
	"path/filepath"
	"sort"
	"testing"
	"time"
)

func FuzzStanzas(f *testing.F) {
	f.Add([]byte("Package: a\nStatus: install ok installed\nVersion: 1\nSource: b (2)\n\nP:x\nV:1\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		parseDpkgStatus(bytes.NewReader(data))
		parseApkInstalled(bytes.NewReader(data))
	})
}

func FuzzAptSimulation(f *testing.F) {
	f.Add([]byte("Inst libssl3 [3.0.13-0ubuntu3.4] (3.0.13-0ubuntu3.5 Ubuntu:24.04/noble-security [arm64])\nInst x (1 [all])\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		for _, update := range parseAptSimulation(data) {
			if update.Name == "" || update.Available == "" || update.Origins == nil {
				t.Fatalf("bad update %+v", update)
			}
		}
	})
}

func FuzzAptConfig(f *testing.F) {
	f.Add(`APT::Periodic { Unattended-Upgrade "1"; }; /* x */ // y` + "\n#clear\n")
	f.Fuzz(func(t *testing.T, data string) {
		parseAptConfig(data)
	})
}

func FuzzProcNet(f *testing.F) {
	f.Add([]byte("  sl  local_address rem_address   st\n   0: 00000000:1F90 00000000:0000 0A 0\n   1: 0000000000000000FFFF00000100007F:0016 00 0A\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		for _, listener := range parseProcNet(bytes.NewReader(data)) {
			if listener.Address == "" || listener.Port < 0 || listener.Port > 65535 {
				t.Fatalf("bad listener %+v", listener)
			}
		}
	})
}

func FuzzLockfiles(f *testing.F) {
	f.Add([]byte(npmLockfile))
	f.Add([]byte("lockfileVersion: '6.0'\npackages:\n  /@a/b@1.0.0(c@2):\n  /d/1.0.0_e:\n"))
	f.Add([]byte("\"a@^1\", a@~1:\n  version \"1.0.0\"\n\"b@npm:2\":\n  version: 2.0.0\n  resolution: \"b@npm:2.0.0\"\n"))
	f.Add([]byte("a[b]==1.0 ; python_version>'3'\n[[package]]\nname = \"x\"\nversion = \"1\"\nsource = \"y\"\n"))
	f.Add([]byte("require (\n\tgolang.org/x/net v0.17.0 // indirect\n)\nreplace a v1 => b v2\n"))
	f.Add([]byte("GEM\n  specs:\n    rack (2.2.8-x86_64-linux)\n"))
	f.Add([]byte(`{"default":{"a":{"version":"==1"}},"packages":[{"name":"a","version":"v1"}]}`))
	names := make([]string, 0, len(lockfileParsers))
	for name := range lockfileParsers {
		names = append(names, name)
	}
	sort.Strings(names)
	f.Fuzz(func(t *testing.T, data []byte) {
		for _, name := range names {
			dependencies, err := lockfileParsers[name].parse(data)
			if err != nil {
				continue
			}
			for _, dependency := range uniqueDependencies(dependencies) {
				if dependency.Name == "" || dependency.Version == "" {
					t.Fatalf("%s: empty dependency %+v", name, dependency)
				}
			}
		}
	})
}

func FuzzCompareVersions(f *testing.F) {
	f.Add("1:2.0~rc1-1", "2.0-1")
	f.Add("6.8.0-88.89", "6.8.0-85.85")
	f.Fuzz(func(t *testing.T, a, b string) {
		ab, ba := CompareVersions(a, b), CompareVersions(b, a)
		if ab != -ba {
			t.Fatalf("Compare(%q, %q) = %d but reverse is %d", a, b, ab, ba)
		}
		if CompareVersions(a, a) != 0 {
			t.Fatalf("Compare(%q, %q) != 0", a, a)
		}
	})
}

func FuzzOSReleaseAndPasswd(f *testing.F) {
	f.Add("ID=ubuntu\nVERSION_ID=\"24.04\"\nID_LIKE='debian x'\nfoo:x:0:0::/:/bin/sh\n")
	f.Fuzz(func(t *testing.T, data string) {
		parseOSRelease(data)
		extraRootAccounts(data)
	})
}

func FuzzSSHConfig(f *testing.F) {
	f.Add([]byte("Include sshd_config.d/*.conf\nPasswordAuthentication=no\nMatch User x\n  PasswordAuthentication yes\nMatch all\nPermitRootLogin \"yes\"\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		root := t.TempDir()
		mustWrite(t, filepath.Join(root, sshdConfigPath), data)
		mustWrite(t, filepath.Join(root, sshDir, "sshd_config.d", "a.conf"), data)
		config, ok := readSSHConfig(root)
		if !ok {
			t.Fatal("config not found")
		}
		for _, check := range sshChecks(config) {
			if check.Title == "" || check.Status == "" {
				t.Fatalf("bad check %+v", check)
			}
		}
	})
}

func FuzzImageArchive(f *testing.F) {
	var seed bytes.Buffer
	writer := tar.NewWriter(&seed)
	writer.WriteHeader(&tar.Header{Name: "status.d/", Typeflag: tar.TypeDir})
	writer.WriteHeader(&tar.Header{Name: "status.d/a", Typeflag: tar.TypeReg, Size: 20})
	writer.Write([]byte("Package: a\nVersion: 1"))
	writer.Close()
	f.Add(seed.Bytes())
	limits := defaultScanLimits
	limits.packageBytes, limits.imageBytes, limits.entries = 4<<10, 8<<10, 16
	f.Fuzz(func(t *testing.T, data []byte) {
		docker := fakeDocker{archive: func(context.Context, string, string) (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(data)), nil
		}}
		result := scanImage(context.Background(), docker, imageJob{id: "x", container: "c", workingDir: "/app"}, limits, time.Unix(0, 0))
		if result.image.Packages.Items == nil || result.image.Lockfiles == nil || len(result.image.Packages.Items) > packageLimit {
			t.Fatalf("result %+v", result.image)
		}
	})
}
