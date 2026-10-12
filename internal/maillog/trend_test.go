package maillog

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestAutoBucketSize(t *testing.T) {
	cases := []struct {
		span time.Duration
		want time.Duration
	}{
		{30 * time.Minute, 15 * time.Minute},
		{3 * time.Hour, 30 * time.Minute},
		{12 * time.Hour, time.Hour},
		{48 * time.Hour, 4 * time.Hour},
		{7 * 24 * time.Hour, 12 * time.Hour},
		{30 * 24 * time.Hour, 24 * time.Hour},
		{0, time.Hour},
	}
	for _, c := range cases {
		if got := AutoBucketSize(c.span); got != c.want {
			t.Errorf("AutoBucketSize(%v)=%v want %v", c.span, got, c.want)
		}
	}
	if FormatBucketSize(15*time.Minute) != "15m" || FormatBucketSize(time.Hour) != "1h" || FormatBucketSize(4*time.Hour) != "4h" || FormatBucketSize(24*time.Hour) != "1d" {
		t.Fatalf("FormatBucketSize labels wrong")
	}
}

func TestDirection(t *testing.T) {
	if Direction(10, 10, 18, 2, 5) != DirectionImproving {
		t.Fatal("expected improving")
	}
	if Direction(18, 2, 10, 10, 5) != DirectionWorsening {
		t.Fatal("expected worsening")
	}
	if Direction(10, 5, 12, 6, 5) != DirectionFlat {
		t.Fatal("expected flat")
	}
	if Direction(2, 1, 20, 20, 5) != DirectionInsufficient {
		t.Fatal("expected insufficient")
	}
}

func synLine(t time.Time, domain, status string, n int) string {
	detail := "250 OK"
	if status == "deferred" {
		detail = "host mx said: 421-4.7.28 rate limited"
	}
	if status == "bounced" {
		detail = "host mx said: 550 5.1.1 user unknown"
	}
	return fmt.Sprintf("%s mail postfix/smtp[1]: %08X: to=<u%d@%s>, relay=mx, delay=1, dsn=2.0.0, status=%s (%s)",
		t.Format("2006-01-02T15:04:05-07:00"), n, n, domain, status, detail)
}

func TestTrendBucketsAndDirection(t *testing.T) {
	loc := cst
	base := time.Date(2026, 10, 12, 0, 0, 0, 0, loc)
	agg := NewTrendAggregator("", time.Hour)
	agg.WindowStart = base
	agg.WindowEnd = base.Add(4 * time.Hour)

	// gmail: early half heavy deferrals, late half mostly sent → improving
	for i := 0; i < 10; i++ {
		line := synLine(base.Add(30*time.Minute), "gmail.com", "deferred", 100+i)
		ev, ok := ParseLine(line, now)
		if !ok {
			t.Fatalf("parse %s", line)
		}
		agg.Add(ev)
	}
	for i := 0; i < 10; i++ {
		line := synLine(base.Add(3*time.Hour+10*time.Minute), "gmail.com", "sent", 200+i)
		ev, _ := ParseLine(line, now)
		agg.Add(ev)
	}
	// outlook: opposite → worsening
	for i := 0; i < 10; i++ {
		line := synLine(base.Add(20*time.Minute), "outlook.com", "sent", 300+i)
		ev, _ := ParseLine(line, now)
		agg.Add(ev)
	}
	for i := 0; i < 10; i++ {
		line := synLine(base.Add(3*time.Hour), "outlook.com", "deferred", 400+i)
		ev, _ := ParseLine(line, now)
		agg.Add(ev)
	}
	// tiny domain → insufficient
	line := synLine(base.Add(time.Hour), "tiny.example", "deferred", 500)
	ev, _ := ParseLine(line, now)
	agg.Add(ev)

	tr := agg.Result(0)
	if tr.Bucket != "1h" || len(tr.Domains) != 3 {
		t.Fatalf("trend %+v", tr)
	}
	by := map[string]DomainTrend{}
	for _, d := range tr.Domains {
		by[d.Domain] = d
	}
	g := by["gmail.com"]
	if g.Direction != DirectionImproving || g.Sent != 10 || g.Deferred != 10 {
		t.Fatalf("gmail %+v", g)
	}
	if len(g.Buckets) != 5 { // 0,1,2,3,4h inclusive of end at +4h → buckets at 0,1,2,3,4 = 5
		t.Fatalf("gmail buckets %d: %+v", len(g.Buckets), g.Buckets)
	}
	o := by["outlook.com"]
	if o.Direction != DirectionWorsening {
		t.Fatalf("outlook %+v", o)
	}
	if by["tiny.example"].Direction != DirectionInsufficient {
		t.Fatalf("tiny %+v", by["tiny.example"])
	}
}

func TestTrendFromFixture(t *testing.T) {
	agg := NewTrendAggregator("", 0)
	agg.WindowStart = now.Add(-24 * time.Hour)
	agg.WindowEnd = now
	scanFixture(t, now.Add(-24*time.Hour), agg.Add, nil)
	tr := agg.Result(5)
	if tr.Bucket == "" || len(tr.Domains) == 0 {
		t.Fatalf("empty trend %+v", tr)
	}
	if tr.BucketSize != time.Hour {
		t.Fatalf("auto bucket for 24h window: %v", tr.BucketSize)
	}
	found := false
	for _, d := range tr.Domains {
		if d.Domain == "gmail.com" && d.Deferred > 0 {
			found = true
			if len(d.Buckets) < 2 {
				t.Fatalf("gmail buckets %+v", d.Buckets)
			}
		}
		if d.Direction == "" {
			t.Fatalf("missing direction %+v", d)
		}
	}
	if !found {
		t.Fatalf("gmail missing: %+v", tr.Domains)
	}
	// domain filter
	one := NewTrendAggregator("gmail.com", time.Hour)
	scanFixture(t, time.Time{}, one.Add, nil)
	r := one.Result(0)
	for _, d := range r.Domains {
		if d.Domain != "gmail.com" {
			t.Fatalf("filter: %s", d.Domain)
		}
	}
	if len(r.Domains) != 1 {
		t.Fatalf("want one domain, got %d", len(r.Domains))
	}
}

func TestTrendRate(t *testing.T) {
	if deferralRate(0, 0) != 0 || deferralRate(3, 1) != 0.25 {
		t.Fatal(deferralRate(3, 1))
	}
	_ = strings.Builder{}
}
