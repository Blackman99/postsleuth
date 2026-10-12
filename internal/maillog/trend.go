package maillog

import (
	"sort"
	"strconv"
	"strings"
	"time"
)

// Trend direction labels for early-vs-late deferral rate comparison.
const (
	DirectionImproving    = "improving"
	DirectionWorsening    = "worsening"
	DirectionFlat         = "flat"
	DirectionInsufficient = "insufficient_data"
)

// Bucket is one time slice of delivery outcomes for a domain.
type Bucket struct {
	Start    time.Time `json:"start"`
	End      time.Time `json:"end"`
	Sent     int       `json:"sent"`
	Deferred int       `json:"deferred_attempts"`
	Bounced  int       `json:"bounced"`
	Rate     float64   `json:"deferral_rate"` // deferred / (sent+deferred); 0 when none
}

// DomainTrend is the per-destination trend over the window.
type DomainTrend struct {
	Domain    string   `json:"domain"`
	Sent      int      `json:"sent"`
	Deferred  int      `json:"deferred_attempts"`
	Bounced   int      `json:"bounced"`
	Rate      float64  `json:"deferral_rate"`
	Direction string   `json:"direction"`
	EarlyRate float64  `json:"early_rate"`
	LateRate  float64  `json:"late_rate"`
	Buckets   []Bucket `json:"buckets"`
}

// Trend is the result of bucketing delivery outcomes by recipient domain.
type Trend struct {
	First      time.Time     `json:"first_event,omitempty"`
	Last       time.Time     `json:"last_event,omitempty"`
	BucketSize time.Duration `json:"bucket_size_ns"`
	Bucket     string        `json:"bucket"` // human label, e.g. "1h"
	Domains    []DomainTrend `json:"domains"`
}

type timedHit struct {
	t      time.Time
	status string // sent, deferred, bounced
}

// TrendAggregator accumulates timed sent/deferred/bounced events into buckets.
type TrendAggregator struct {
	Domain     string // optional recipient-domain filter
	BucketSize time.Duration
	// WindowStart/End bound empty buckets and the early/late split.
	// Zero means derive from observed events.
	WindowStart time.Time
	WindowEnd   time.Time

	first, last time.Time
	hits        map[string][]timedHit
}

// NewTrendAggregator returns an empty aggregator. bucketSize 0 means auto-size
// from the observed (or window) span when Result is called.
func NewTrendAggregator(domain string, bucketSize time.Duration) *TrendAggregator {
	return &TrendAggregator{
		Domain:     strings.ToLower(domain),
		BucketSize: bucketSize,
		hits:       map[string][]timedHit{},
	}
}

func (a *TrendAggregator) match(d string) bool {
	if a.Domain == "" {
		return true
	}
	if strings.HasPrefix(a.Domain, ".") {
		return strings.HasSuffix(d, a.Domain) || d == a.Domain[1:]
	}
	return d == a.Domain
}

// AutoBucketSize chooses a bucket width from the span of the analysis window.
func AutoBucketSize(span time.Duration) time.Duration {
	switch {
	case span <= 0:
		return time.Hour
	case span <= 2*time.Hour:
		return 15 * time.Minute
	case span <= 6*time.Hour:
		return 30 * time.Minute
	case span <= 24*time.Hour:
		return time.Hour
	case span <= 3*24*time.Hour:
		return 4 * time.Hour
	case span <= 14*24*time.Hour:
		return 12 * time.Hour
	default:
		return 24 * time.Hour
	}
}

// FormatBucketSize returns a short label for a duration (15m, 1h, 4h, 1d, …).
func FormatBucketSize(d time.Duration) string {
	switch {
	case d <= 0:
		return "0"
	case d%(24*time.Hour) == 0:
		return strconv.Itoa(int(d/(24*time.Hour))) + "d"
	case d%time.Hour == 0:
		return strconv.Itoa(int(d/time.Hour)) + "h"
	case d%time.Minute == 0:
		return strconv.Itoa(int(d/time.Minute)) + "m"
	default:
		return d.String()
	}
}

func deferralRate(sent, deferred int) float64 {
	den := sent + deferred
	if den == 0 {
		return 0
	}
	return float64(deferred) / float64(den)
}

// Add consumes one event (only sent/delivered/deferred/bounced with a recipient).
func (a *TrendAggregator) Add(ev Event) {
	to, ok := ev.Fields["to"]
	if !ok || ev.Status == "" || ev.Time.IsZero() {
		return
	}
	var status string
	switch ev.Status {
	case "sent", "delivered":
		status = "sent"
	case "deferred":
		status = "deferred"
	case "bounced":
		status = "bounced"
	default:
		return
	}
	d := domainOf(to)
	if !a.match(d) {
		return
	}
	if a.first.IsZero() || ev.Time.Before(a.first) {
		a.first = ev.Time
	}
	if ev.Time.After(a.last) {
		a.last = ev.Time
	}
	a.hits[d] = append(a.hits[d], timedHit{t: ev.Time, status: status})
}

// Direction compares early vs late half deferral rates.
// Needs at least minAttempts delivery attempts (sent+deferred) in each half.
func Direction(earlySent, earlyDef, lateSent, lateDef, minAttempts int) string {
	if earlySent+earlyDef < minAttempts || lateSent+lateDef < minAttempts {
		return DirectionInsufficient
	}
	diff := deferralRate(lateSent, lateDef) - deferralRate(earlySent, earlyDef)
	const absThresh = 0.05 // 5 percentage points
	if diff >= absThresh {
		return DirectionWorsening
	}
	if diff <= -absThresh {
		return DirectionImproving
	}
	return DirectionFlat
}

func truncateTo(t time.Time, bs time.Duration) time.Time {
	sec := int64(bs / time.Second)
	if sec < 1 {
		sec = 1
	}
	u := t.Unix()
	return time.Unix(u/sec*sec, 0).In(t.Location())
}

// Result finalizes buckets. top limits domains (0 = all).
func (a *TrendAggregator) Result(top int) Trend {
	start, end := a.WindowStart, a.WindowEnd
	if start.IsZero() {
		start = a.first
	}
	if end.IsZero() {
		end = a.last
	}
	bs := a.BucketSize
	if bs <= 0 {
		span := time.Duration(0)
		if !start.IsZero() && !end.IsZero() {
			span = end.Sub(start)
		}
		bs = AutoBucketSize(span)
	}
	if bs < time.Second {
		bs = time.Second
	}

	outDomains := make([]DomainTrend, 0, len(a.hits))
	for dom, hits := range a.hits {
		counts := map[int64]struct{ sent, deferred, bounced int }{}
		var totS, totD, totB int
		var earlyS, earlyD, lateS, lateD int
		mid := start
		if !start.IsZero() && !end.IsZero() {
			mid = start.Add(end.Sub(start) / 2)
		} else if !a.first.IsZero() {
			mid = a.first.Add(a.last.Sub(a.first) / 2)
		}
		for _, h := range hits {
			key := truncateTo(h.t, bs).Unix()
			c := counts[key]
			switch h.status {
			case "sent":
				c.sent++
				totS++
			case "deferred":
				c.deferred++
				totD++
			case "bounced":
				c.bounced++
				totB++
			}
			counts[key] = c
			if h.status == "sent" || h.status == "deferred" {
				if !mid.IsZero() && h.t.After(mid) {
					if h.status == "sent" {
						lateS++
					} else {
						lateD++
					}
				} else {
					if h.status == "sent" {
						earlyS++
					} else {
						earlyD++
					}
				}
			}
		}

		loc := time.Local
		if !start.IsZero() {
			loc = start.Location()
		} else if !a.first.IsZero() {
			loc = a.first.Location()
		}
		var buckets []Bucket
		if !start.IsZero() && !end.IsZero() && !end.Before(start) {
			for t := truncateTo(start, bs); !t.After(end); t = t.Add(bs) {
				c := counts[t.Unix()]
				bStart := t.In(loc)
				buckets = append(buckets, Bucket{
					Start: bStart, End: bStart.Add(bs),
					Sent: c.sent, Deferred: c.deferred, Bounced: c.bounced,
					Rate: deferralRate(c.sent, c.deferred),
				})
			}
		} else {
			keys := make([]int64, 0, len(counts))
			for k := range counts {
				keys = append(keys, k)
			}
			sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
			for _, k := range keys {
				c := counts[k]
				bStart := time.Unix(k, 0).In(loc)
				buckets = append(buckets, Bucket{
					Start: bStart, End: bStart.Add(bs),
					Sent: c.sent, Deferred: c.deferred, Bounced: c.bounced,
					Rate: deferralRate(c.sent, c.deferred),
				})
			}
		}

		outDomains = append(outDomains, DomainTrend{
			Domain:    dom,
			Sent:      totS,
			Deferred:  totD,
			Bounced:   totB,
			Rate:      deferralRate(totS, totD),
			EarlyRate: deferralRate(earlyS, earlyD),
			LateRate:  deferralRate(lateS, lateD),
			Direction: Direction(earlyS, earlyD, lateS, lateD, 5),
			Buckets:   buckets,
		})
	}

	sort.Slice(outDomains, func(i, j int) bool {
		bi := outDomains[i].Deferred + outDomains[i].Sent
		bj := outDomains[j].Deferred + outDomains[j].Sent
		if bi != bj {
			return bi > bj
		}
		if outDomains[i].Deferred != outDomains[j].Deferred {
			return outDomains[i].Deferred > outDomains[j].Deferred
		}
		return outDomains[i].Domain < outDomains[j].Domain
	})
	if top > 0 && len(outDomains) > top {
		outDomains = outDomains[:top]
	}
	return Trend{
		First: a.first, Last: a.last,
		BucketSize: bs, Bucket: FormatBucketSize(bs),
		Domains: outDomains,
	}
}
