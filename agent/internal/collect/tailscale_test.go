package collect

import "testing"

func TestTailscaleName(t *testing.T) {
	status := []byte(`{"Self":{"DNSName":"web-1.tail0000.ts.net.","TailscaleIPs":["100.64.0.7"]}}`)
	if got := TailscaleName(status); got != "web-1.tail0000.ts.net" {
		t.Fatalf("got %q", got)
	}
	if got := TailscaleName([]byte("not json")); got != "" {
		t.Fatalf("got %q for bad input", got)
	}
	if got := TailscaleName([]byte(`{"Self":{}}`)); got != "" {
		t.Fatalf("got %q without a name", got)
	}
}
