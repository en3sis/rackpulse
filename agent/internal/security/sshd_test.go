package security

import (
	"os"
	"path/filepath"
	"testing"
)

type checkResult struct {
	status, detail, source string
}

func resultOf(check Check) checkResult {
	source := ""
	if check.Source != nil {
		source = *check.Source
	}
	return checkResult{check.Status, check.Detail, source}
}

func TestSSHChecks(t *testing.T) {
	const main = "etc/ssh/sshd_config"
	const cloud = "etc/ssh/sshd_config.d/50-cloud-init.conf"
	cases := []struct {
		name       string
		files      map[string]string
		unreadable []string
		password   checkResult
		root       checkResult
	}{
		{
			name:     "defaults",
			files:    map[string]string{main: "Port 22\n"},
			password: checkResult{statusFail, "PasswordAuthentication is not set, the default is yes", sshdConfigPath},
			root:     checkResult{statusPass, "PermitRootLogin is not set, the default is prohibit-password", ""},
		},
		{
			name: "include comes first and wins",
			files: map[string]string{
				main:  "Include /etc/ssh/sshd_config.d/*.conf\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nPermitRootLogin no\n",
				cloud: "passwordauthentication yes\n",
			},
			password: checkResult{statusFail, "PasswordAuthentication yes", "/etc/ssh/sshd_config.d/50-cloud-init.conf"},
			root:     checkResult{statusPass, "PermitRootLogin no", sshdConfigPath},
		},
		{
			name: "include globs skip dotfiles",
			files: map[string]string{
				main:                              "Include sshd_config.d/*.conf\nPasswordAuthentication no\nKbdInteractiveAuthentication no\n",
				"etc/ssh/sshd_config.d/.old.conf": "PasswordAuthentication yes\n",
			},
			password: checkResult{statusPass, "PasswordAuthentication no", sshdConfigPath},
			root:     checkResult{statusPass, "PermitRootLogin is not set, the default is prohibit-password", ""},
		},
		{
			name: "relative include in lexical order",
			files: map[string]string{
				main:                                 "Include sshd_config.d/*.conf\n",
				"etc/ssh/sshd_config.d/10-a.conf":    "PasswordAuthentication=no\nKbdInteractiveAuthentication no\n",
				"etc/ssh/sshd_config.d/20-b.conf":    "PasswordAuthentication yes\nPermitRootLogin yes\n",
				"etc/ssh/sshd_config.d/30-c.conf.no": "PermitRootLogin no\n",
			},
			password: checkResult{statusPass, "PasswordAuthentication no", "/etc/ssh/sshd_config.d/10-a.conf"},
			root:     checkResult{statusFail, "PermitRootLogin yes", "/etc/ssh/sshd_config.d/20-b.conf"},
		},
		{
			name: "match blocks are ignored",
			files: map[string]string{
				main:                 "PasswordAuthentication no\nKbdInteractiveAuthentication no\nMatch User deploy\n  PermitRootLogin yes\n  Include /etc/ssh/extra.conf\nMatch all\nPermitRootLogin without-password\n",
				"etc/ssh/extra.conf": "PermitRootLogin yes\n",
			},
			password: checkResult{statusPass, "PasswordAuthentication no", sshdConfigPath},
			root:     checkResult{statusPass, "PermitRootLogin without-password", sshdConfigPath},
		},
		{
			name: "match all overrides earlier global values",
			files: map[string]string{
				main:                 "PasswordAuthentication no\nKbdInteractiveAuthentication no\nPermitRootLogin no\nMatch all # back to global\n  Include /etc/ssh/extra.conf\nPasswordAuthentication yes\n",
				"etc/ssh/extra.conf": "PermitRootLogin yes\n",
			},
			password: checkResult{statusFail, "PasswordAuthentication yes", sshdConfigPath},
			root:     checkResult{statusFail, "PermitRootLogin yes", "/etc/ssh/extra.conf"},
		},
		{
			name: "match ends with the included file",
			files: map[string]string{
				main:  "Include /etc/ssh/sshd_config.d/*.conf\nPermitRootLogin yes\nPasswordAuthentication no\nChallengeResponseAuthentication no\n",
				cloud: "Match Address 10.0.0.0/8\n  PermitRootLogin no\n",
			},
			password: checkResult{statusPass, "PasswordAuthentication no", sshdConfigPath},
			root:     checkResult{statusFail, "PermitRootLogin yes", sshdConfigPath},
		},
		{
			name: "keyboard interactive with PAM accepts passwords",
			files: map[string]string{
				main: "PasswordAuthentication no\nUsePAM yes\n",
			},
			password: checkResult{statusFail, "KbdInteractiveAuthentication is not set, the default is yes, UsePAM yes", sshdConfigPath},
			root:     checkResult{statusPass, "PermitRootLogin is not set, the default is prohibit-password", ""},
		},
		{
			name: "legacy challenge response keyword",
			files: map[string]string{
				main: "PasswordAuthentication no\nChallengeResponseAuthentication yes\nUsePAM yes\n",
			},
			password: checkResult{statusFail, "ChallengeResponseAuthentication yes, UsePAM yes", sshdConfigPath},
			root:     checkResult{statusPass, "PermitRootLogin is not set, the default is prohibit-password", ""},
		},
		{
			name: "includes outside /etc/ssh are ignored",
			files: map[string]string{
				main:             "Include /tmp/evil.conf\nInclude ../../tmp/evil.conf\nPasswordAuthentication no\nKbdInteractiveAuthentication no\n",
				"tmp/evil.conf":  "PasswordAuthentication yes\n",
				"etc/tmp/x.conf": "PasswordAuthentication yes\n",
			},
			password: checkResult{statusPass, "PasswordAuthentication no", sshdConfigPath},
			root:     checkResult{statusPass, "PermitRootLogin is not set, the default is prohibit-password", ""},
		},
		{
			name: "unreadable include makes later values unknown",
			files: map[string]string{
				main:  "Include /etc/ssh/sshd_config.d/*.conf\nPasswordAuthentication no\nPermitRootLogin no\n",
				cloud: "PasswordAuthentication yes\n",
			},
			unreadable: []string{cloud},
			password:   checkResult{statusUnknown, "Cannot read /etc/ssh/sshd_config.d/50-cloud-init.conf", "/etc/ssh/sshd_config.d/50-cloud-init.conf"},
			root:       checkResult{statusUnknown, "Cannot read /etc/ssh/sshd_config.d/50-cloud-init.conf", "/etc/ssh/sshd_config.d/50-cloud-init.conf"},
		},
		{
			name: "unreadable include after a decided value",
			files: map[string]string{
				main:  "PasswordAuthentication no\nKbdInteractiveAuthentication no\nInclude /etc/ssh/sshd_config.d/*.conf\nPermitRootLogin no\n",
				cloud: "PasswordAuthentication yes\n",
			},
			unreadable: []string{cloud},
			password:   checkResult{statusPass, "PasswordAuthentication no", sshdConfigPath},
			root:       checkResult{statusUnknown, "Cannot read /etc/ssh/sshd_config.d/50-cloud-init.conf", "/etc/ssh/sshd_config.d/50-cloud-init.conf"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			root := writeTree(t, c.files)
			if len(c.unreadable) > 0 {
				skipAsRoot(t)
			}
			for _, name := range c.unreadable {
				os.Chmod(filepath.Join(root, name), 0)
			}
			config, ok := readSSHConfig(root)
			if !ok {
				t.Fatal("config not found")
			}
			checks := sshChecks(config)
			if got := resultOf(checks[0]); checks[0].ID != "ssh.passwordLogin" || got != c.password {
				t.Errorf("password %+v\nwant %+v", got, c.password)
			}
			if got := resultOf(checks[1]); checks[1].ID != "ssh.rootLogin" || got != c.root {
				t.Errorf("root %+v\nwant %+v", got, c.root)
			}
		})
	}
}

func TestSSHMissingConfigOmitsChecks(t *testing.T) {
	if _, ok := readSSHConfig(t.TempDir()); ok {
		t.Fatal("missing sshd_config must omit SSH checks")
	}
}

func TestSSHIncludeLimits(t *testing.T) {
	files := map[string]string{"etc/ssh/sshd_config": "Include /etc/ssh/loop.conf\n", "etc/ssh/loop.conf": "Include /etc/ssh/loop.conf\n"}
	config, _ := readSSHConfig(writeTree(t, files))
	if config.includes > sshDepthLimit {
		t.Fatalf("followed %d includes", config.includes)
	}
	files = map[string]string{"etc/ssh/sshd_config": ""}
	for i := 0; i < 30; i++ {
		files["etc/ssh/sshd_config"] += "Include /etc/ssh/one.conf\n"
	}
	files["etc/ssh/one.conf"] = "Port 22\n"
	config, _ = readSSHConfig(writeTree(t, files))
	if config.includes != sshIncludeLimit {
		t.Fatalf("followed %d includes", config.includes)
	}
}
