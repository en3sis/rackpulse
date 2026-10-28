package collect

import (
	"testing"
	"time"
)

func TestParseCPU(t *testing.T) {
	busy, total, ok := parseCPU("cpu  100 0 50 800 50 0 0 0 0 0\ncpu0 1 2 3 4 5 6 7 8 9 10\n")
	if !ok || busy != 150 || total != 1000 {
		t.Fatalf("got busy %d total %d ok %v", busy, total, ok)
	}
}

func TestParseDiskstatsCountsWholeDisksOnly(t *testing.T) {
	data := "   8       0 sda 100 0 2000 0 50 0 800 0 0 0 0\n" +
		"   8       1 sda1 90 0 1800 0 40 0 700 0 0 0 0\n" +
		"   7       0 loop0 5 0 10 0 0 0 0 0 0 0 0\n"
	reads, writes, readSectors, written := parseDiskstats(data, func(name string) bool { return name == "sda" })
	if reads != 100 || writes != 50 || readSectors != 2000 || written != 800 {
		t.Fatalf("got %d %d %d %d", reads, writes, readSectors, written)
	}
}

func TestParseNetDevSkipsOtherInterfaces(t *testing.T) {
	data := "Inter-|   Receive |  Transmit\n face |bytes packets errs drop fifo frame compressed multicast|bytes\n" +
		"    lo: 500 5 0 0 0 0 0 0 500 5 0 0 0 0 0 0\n" +
		"  eth0: 1000 10 0 0 0 0 0 0 4000 20 0 0 0 0 0 0\n" +
		"docker0: 300 3 0 0 0 0 0 0 300 3 0 0 0 0 0 0\n"
	in, out := parseNetDev(data, func(name string) bool { return name == "eth0" })
	if in != 1000 || out != 4000 {
		t.Fatalf("got in %d out %d", in, out)
	}
}

func TestRates(t *testing.T) {
	start := time.Unix(1_000, 0)
	before := counters{at: start, cpuBusy: 100, cpuTotal: 1000, reads: 10, writes: 20, readSectors: 100, written: 200, netIn: 1000, netOut: 2000}
	after := counters{at: start.Add(60 * time.Second), cpuBusy: 400, cpuTotal: 4000, reads: 70, writes: 140, readSectors: 220, written: 320, netIn: 7000, netOut: 2000}
	got := rates(before, after)
	if got == nil || got.CPU != 10 || got.DiskReadIOPS != 1 || got.DiskWriteIOPS != 2 || got.DiskReadBytes != 1024 || got.NetInBytes != 100 || got.NetOutBytes != 0 {
		t.Fatalf("got %+v", got)
	}
	if rates(after, before) != nil {
		t.Fatal("a counter that went back must give no rates")
	}
}
