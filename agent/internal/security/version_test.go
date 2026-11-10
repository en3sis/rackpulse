package security

import "testing"

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0", "1.0", 0},
		{"0:1.0", "1.0", 0},
		{"1.0-0", "1.0", 0},
		{"1.002", "1.2", 0},
		{"1.0~rc1", "1.0", -1},
		{"1.0~~", "1.0~~a", -1},
		{"1.0~~a", "1.0~", -1},
		{"1.0~", "1.0", -1},
		{"1.0", "1.0a", -1},
		{"1.0", "1.0.", -1},
		{"1.0", "1.0+dfsg", -1},
		{"1:0.1", "2.0", 1},
		{"2:1.0", "1:9.9", 1},
		{"1.0-1", "1.0-2", -1},
		{"1.0-1", "1.0-1ubuntu1", -1},
		{"1.0-10", "1.0-9", 1},
		{"2.30", "2.3", 1},
		{"1.0.0", "1.0", 1},
		{"a", "b", -1},
		{"7.6p2-4", "7.6-0", 1},
		{"1.0.3-3", "1.0-1", 1},
		{"1.3", "1.2.2-2", 1},
		{"0-pre", "0-pre", 0},
		{"0-pre", "0-pree", -1},
		{"1.1.6r2-2", "1.1.6r-1", 1},
		{"2.6b2-1", "2.6b-2", 1},
		{"98.1p5-1", "98.1-pre2-b6-2", -1},
		{"0.4a6-2", "0.4-1", 1},
		{"1:3.0.5-2", "1:3.0.5.1", -1},
		{"3.0.13-0ubuntu3.4", "3.0.13-0ubuntu3.5", -1},
		{"5.6.1+really5.4.5-1ubuntu0.3", "5.6.1+really5.4.5-1ubuntu0.4", -1},
		{"2.39-0ubuntu8.3", "2.39-0ubuntu8.10", -1},
		{"6.8.0-88-generic", "6.8.0-100-generic", -1},
	}
	for _, c := range cases {
		if got := CompareVersions(c.a, c.b); got != c.want {
			t.Errorf("CompareVersions(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
		if got := CompareVersions(c.b, c.a); got != -c.want {
			t.Errorf("CompareVersions(%q, %q) = %d, want %d", c.b, c.a, got, -c.want)
		}
	}
}
