package install

import (
	"strings"
	"testing"

	"github.com/en3sis/rackpulse/agent/internal/config"
)

func TestUFWRule(t *testing.T) {
	cases := []struct {
		listen string
		want   string
	}{
		{"", "allow 7311/tcp"},
		{"100.101.102.103", "allow in on tailscale0 to any port 7311 proto tcp"},
		{"10.0.0.2", "allow in to 10.0.0.2 port 7311 proto tcp"},
	}
	for _, c := range cases {
		got := strings.Join(ufwRule(config.Config{Port: 7311, Listen: c.listen}), " ")
		if got != c.want {
			t.Errorf("listen %q: got %q, want %q", c.listen, got, c.want)
		}
	}
}
