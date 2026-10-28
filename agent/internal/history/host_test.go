package history

import "testing"

func TestUptimeMinutesAcrossHours(t *testing.T) {
	const hour = int64(1761476400)
	now := hour + 2*3600
	h := NewHost(hour)
	h.MarkRange(hour+50*60+30, hour+3600+9*60+59, now)
	h.MarkMinute(hour + 59*60)
	h.MarkMinute(hour + 59*60 + 45)
	h.MarkMinute(hour + 3600 + 9*60 + 10)

	got := h.Query(0, now).Hours
	if got["1761476400"] != 10 || got["1761480000"] != 10 || len(got) != 2 {
		t.Fatalf("hours %v", got)
	}
	if got := h.Query(hour+1, now).Hours; len(got) != 1 || got["1761480000"] != 10 {
		t.Fatalf("since filter %v", got)
	}
}

func TestUptimeRetentionAndCoverage(t *testing.T) {
	const day = int64(86400)
	now := int64(1761480000) + 1800
	h := NewHost(now - 40*day)
	h.MarkMinute(now - 35*day)
	h.MarkMinute(now - 30*day)
	h.MarkMinute(now)
	h.Prune(now)
	response := h.Query(0, now)
	if len(response.Hours) != 2 {
		t.Fatalf("hours after retention %v", response.Hours)
	}
	if want := retentionCutoff(now); response.CoverageStart != want {
		t.Fatalf("coverage %d, want %d", response.CoverageStart, want)
	}
	if response.Step != coarseStep {
		t.Fatalf("step %d", response.Step)
	}
}

func TestSamplesRollUpToFiveMinutes(t *testing.T) {
	start := int64(1761480000)
	h := NewHost(start)
	for i := range 11 {
		t0 := start + int64(i)*60 + 7
		h.AddSample(Sample{T: t0, Memory: float64(i), Load: 1}, t0)
	}
	now := start + 11*60
	if r := h.Query(now-3600, now); r.Step != fineStep || len(r.Samples) != 11 || r.Samples[0].T != start {
		t.Fatalf("minute samples %+v", r)
	}
	r := h.Query(now-2*86400, now)
	if r.Step != coarseStep || len(r.Samples) != 2 {
		t.Fatalf("five minute samples %+v", r)
	}
	if r.Samples[0].T != start || r.Samples[0].Memory != 2 || r.Samples[1].Memory != 7 {
		t.Fatalf("five minute values %+v", r.Samples)
	}
}

func TestFiveMinuteAverageKeepsActivity(t *testing.T) {
	const bucket = int64(1761480000)
	cpu := func(v float64) *float64 { return &v }
	group := []Sample{{T: bucket, CPU: cpu(10)}, {T: bucket + 60, CPU: cpu(30)}, {T: bucket + 120}}
	got := averageSamples(bucket, group)
	if got.CPU == nil || *got.CPU != 20 {
		t.Fatalf("cpu %v", got.CPU)
	}
	if got.NetInBytes != nil {
		t.Fatalf("missing fields must stay missing, got %v", *got.NetInBytes)
	}
}
