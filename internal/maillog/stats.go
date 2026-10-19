package maillog

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Blackman99/postsleuth/internal/provider"
	"github.com/Blackman99/postsleuth/internal/reason"
)

// DomainStat counts delivery outcomes for one recipient domain.
type DomainStat struct {
	Domain     string    `json:"domain"`
	Sent       int       `json:"sent"`
	Deferred   int       `json:"deferred_attempts"`
	Bounced    int       `json:"bounced"`
	LastStatus string    `json:"last_status"`
	LastDetail string    `json:"last_detail,omitempty"`
	LastTime   time.Time `json:"last_time"`
}

// ReasonStat groups failure texts.
type ReasonStat struct {
	Reason   string   `json:"reason"`
	Category string   `json:"category"`
	Hint     string   `json:"hint"`
	Count    int      `json:"count"`
	Domains  []string `json:"domains,omitempty"`
	Remotes  []string `json:"remote_hosts,omitempty"`
	Example  string   `json:"example"`
	// Provider is gmail, microsoft or yahoo when the reply came from one of
	// them; Playbook is the id of the matching provider playbook, if any
	// (postsleuth playbook ID).
	Provider string `json:"provider,omitempty"`
	Playbook string `json:"playbook,omitempty"`
}

// DKIMSeen is a selector observed in opendkim/rspamd signing log lines.
type DKIMSeen struct {
	Selector string `json:"selector"`
	Domain   string `json:"domain"`
	Count    int    `json:"count"`
}

// Totals counts outcomes.
type Totals struct {
	Received int `json:"received"`
	Sent     int `json:"sent"`
	Deferred int `json:"deferred_attempts"`
	Bounced  int `json:"bounced"`
	Expired  int `json:"expired"`
	Rejected int `json:"rejected"`
}

// Stats is the result of aggregating a log.
type Stats struct {
	First        time.Time    `json:"first_event,omitempty"`
	Last         time.Time    `json:"last_event,omitempty"`
	Events       int          `json:"postfix_lines"`
	Totals       Totals       `json:"totals"`
	Domains      []DomainStat `json:"domains"`
	StillFailing []DomainStat `json:"still_failing"`
	Deferrals    []ReasonStat `json:"deferral_reasons"`
	Bounces      []ReasonStat `json:"bounce_causes"`
	Rejects      []ReasonStat `json:"smtpd_rejects"`
	DKIM         []DKIMSeen   `json:"dkim_selectors_seen,omitempty"`
}

type reasonAgg struct {
	rs      ReasonStat
	domains map[string]bool
	remotes map[string]bool
}

// Aggregator accumulates events into Stats.
type Aggregator struct {
	Domain    string // optional recipient-domain filter (suffix with leading ".")
	stats     Stats
	domains   map[string]*DomainStat
	deferrals map[string]*reasonAgg
	bounces   map[string]*reasonAgg
	rejects   map[string]*reasonAgg
	dkim      map[string]*DKIMSeen
}

// NewAggregator returns an empty aggregator.
func NewAggregator(domain string) *Aggregator {
	return &Aggregator{Domain: strings.ToLower(domain), domains: map[string]*DomainStat{}, deferrals: map[string]*reasonAgg{},
		bounces: map[string]*reasonAgg{}, rejects: map[string]*reasonAgg{}, dkim: map[string]*DKIMSeen{}}
}

func domainOf(addr string) string {
	addr = strings.Trim(addr, "<>")
	if i := strings.LastIndexByte(addr, '@'); i >= 0 {
		return strings.ToLower(addr[i+1:])
	}
	if addr == "" {
		return "<>"
	}
	return "localhost"
}

func (a *Aggregator) match(d string) bool {
	if a.Domain == "" {
		return true
	}
	if strings.HasPrefix(a.Domain, ".") {
		return strings.HasSuffix(d, a.Domain) || d == a.Domain[1:]
	}
	return d == a.Domain
}

func addReason(m map[string]*reasonAgg, text, domain string) {
	key := reason.Normalize(text)
	ag := m[key]
	if ag == nil {
		c := reason.Classify(text)
		pm := provider.Lookup(text, domain)
		ag = &reasonAgg{rs: ReasonStat{Reason: key, Category: c.ID, Hint: c.Hint, Example: text, Provider: pm.Provider, Playbook: pm.ID}, domains: map[string]bool{}, remotes: map[string]bool{}}
		m[key] = ag
	}
	ag.rs.Count++
	if domain != "" {
		ag.domains[domain] = true
	}
	if r := reason.Remote(text); r != "" {
		ag.remotes[r] = true
	}
}

// Add consumes one event.
func (a *Aggregator) Add(ev Event) {
	s := &a.stats
	s.Events++
	if !ev.Time.IsZero() {
		if s.First.IsZero() || ev.Time.Before(s.First) {
			s.First = ev.Time
		}
		if ev.Time.After(s.Last) {
			s.Last = ev.Time
		}
	}
	if ev.Reject {
		d := domainOf(ev.Fields["to"])
		if a.Domain != "" && !a.match(d) {
			return
		}
		s.Totals.Rejected++
		addReason(a.rejects, ev.Detail, "")
		return
	}
	if strings.HasSuffix(ev.Program, "/cleanup") && strings.Contains(ev.Raw, "message-id=") {
		s.Totals.Received++
		return
	}
	if strings.HasSuffix(ev.Program, "/qmgr") {
		if ev.Status == "expired" {
			s.Totals.Expired++
		}
		return
	}
	to, ok := ev.Fields["to"]
	if !ok || ev.Status == "" {
		return
	}
	d := domainOf(to)
	if !a.match(d) {
		return
	}
	ds := a.domains[d]
	if ds == nil {
		ds = &DomainStat{Domain: d}
		a.domains[d] = ds
	}
	switch ev.Status {
	case "sent", "delivered":
		s.Totals.Sent++
		ds.Sent++
	case "deferred":
		s.Totals.Deferred++
		ds.Deferred++
		addReason(a.deferrals, ev.Detail, d)
	case "bounced":
		s.Totals.Bounced++
		ds.Bounced++
		addReason(a.bounces, ev.Detail, d)
	default:
		return
	}
	if !ev.Time.Before(ds.LastTime) {
		ds.LastTime, ds.LastStatus, ds.LastDetail = ev.Time, ev.Status, ev.Detail
	}
}

// AddDKIM records a signing selector.
func (a *Aggregator) AddDKIM(d DKIMSignature) {
	k := d.Selector + "._domainkey." + d.Domain
	if a.dkim[k] == nil {
		a.dkim[k] = &DKIMSeen{Selector: d.Selector, Domain: d.Domain}
	}
	a.dkim[k].Count++
}

func finish(m map[string]*reasonAgg, top int) []ReasonStat {
	out := []ReasonStat{}
	for _, ag := range m {
		for d := range ag.domains {
			ag.rs.Domains = append(ag.rs.Domains, d)
		}
		for r := range ag.remotes {
			ag.rs.Remotes = append(ag.rs.Remotes, r)
		}
		sort.Strings(ag.rs.Domains)
		sort.Strings(ag.rs.Remotes)
		if len(ag.rs.Domains) > 8 {
			ag.rs.Domains = append(ag.rs.Domains[:8], fmt.Sprintf("+%d more", len(ag.domains)-8))
		}
		if len(ag.rs.Remotes) > 5 {
			ag.rs.Remotes = ag.rs.Remotes[:5]
		}
		out = append(out, ag.rs)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Reason < out[j].Reason
	})
	if top > 0 && len(out) > top {
		out = out[:top]
	}
	return out
}

// Result returns the aggregated stats; top limits list lengths (0 = all).
func (a *Aggregator) Result(top int) Stats {
	s := a.stats
	s.Domains = []DomainStat{}
	s.StillFailing = []DomainStat{}
	for _, d := range a.domains {
		s.Domains = append(s.Domains, *d)
		if d.LastStatus == "deferred" {
			s.StillFailing = append(s.StillFailing, *d)
		}
	}
	bad := func(d DomainStat) int { return d.Deferred + d.Bounced }
	sort.Slice(s.Domains, func(i, j int) bool {
		if bad(s.Domains[i]) != bad(s.Domains[j]) {
			return bad(s.Domains[i]) > bad(s.Domains[j])
		}
		if s.Domains[i].Sent != s.Domains[j].Sent {
			return s.Domains[i].Sent > s.Domains[j].Sent
		}
		return s.Domains[i].Domain < s.Domains[j].Domain
	})
	sort.Slice(s.StillFailing, func(i, j int) bool { return s.StillFailing[i].Deferred > s.StillFailing[j].Deferred })
	if top > 0 && len(s.Domains) > top {
		s.Domains = s.Domains[:top]
	}
	s.Deferrals = finish(a.deferrals, top)
	s.Bounces = finish(a.bounces, top)
	s.Rejects = finish(a.rejects, top)
	for _, d := range a.dkim {
		s.DKIM = append(s.DKIM, *d)
	}
	sort.Slice(s.DKIM, func(i, j int) bool { return s.DKIM[i].Count > s.DKIM[j].Count })
	return s
}

// Top returns a copy with every list cut to at most n entries (0 = all).
func (s Stats) Top(n int) Stats {
	if n <= 0 {
		return s
	}
	cut := func(l []ReasonStat) []ReasonStat {
		if len(l) > n {
			return l[:n]
		}
		return l
	}
	if len(s.Domains) > n {
		s.Domains = s.Domains[:n]
	}
	s.Deferrals, s.Bounces, s.Rejects = cut(s.Deferrals), cut(s.Bounces), cut(s.Rejects)
	return s
}

// Trace collects every event for queue IDs matching a query (a queue ID or an
// email address, matched against to=, orig_to= and from=).
type Trace struct {
	Query  string
	byID   map[string][]Event
	order  []string
	hits   map[string]bool
	parent map[string]string
}

// NewTrace starts a trace.
func NewTrace(query string) *Trace {
	return &Trace{Query: strings.Trim(strings.TrimSpace(query), "<>"), byID: map[string][]Event{}, hits: map[string]bool{}, parent: map[string]string{}}
}

// Add consumes one event.
func (t *Trace) Add(ev Event) {
	if ev.QueueID == "" {
		return
	}
	if _, ok := t.byID[ev.QueueID]; !ok {
		t.order = append(t.order, ev.QueueID)
	}
	ev.Fields = nil
	t.byID[ev.QueueID] = append(t.byID[ev.QueueID], ev)
	q := strings.ToLower(t.Query)
	if ev.QueueID == t.Query {
		t.hits[ev.QueueID] = true
	} else if strings.Contains(q, "@") && strings.Contains(strings.ToLower(ev.Raw), "<"+q+">") {
		t.hits[ev.QueueID] = true
	}
	// "sender non-delivery notification: 4ABC123" links a bounce to its parent.
	if i := strings.Index(ev.Raw, "notification: "); i >= 0 {
		child := strings.TrimSpace(ev.Raw[i+len("notification: "):])
		t.parent[child] = ev.QueueID
	}
}

// TracedMessage is the timeline of one queue ID.
type TracedMessage struct {
	QueueID     string   `json:"queue_id"`
	BounceOf    string   `json:"bounce_of,omitempty"`
	FinalStatus string   `json:"final_status"`
	Events      []string `json:"lines"`
}

// Result returns timelines for matching queue IDs (at most limit, newest last).
func (t *Trace) Result(limit int) []TracedMessage {
	out := []TracedMessage{}
	for _, id := range t.order {
		if !t.hits[id] && !t.hits[t.parent[id]] {
			continue
		}
		tm := TracedMessage{QueueID: id, BounceOf: t.parent[id], FinalStatus: "in progress"}
		for _, ev := range t.byID[id] {
			tm.Events = append(tm.Events, ev.Raw)
			switch {
			case ev.Status != "":
				tm.FinalStatus = ev.Status
			case ev.Detail == "removed":
				if tm.FinalStatus == "in progress" {
					tm.FinalStatus = "removed"
				}
			}
		}
		out = append(out, tm)
	}
	if limit > 0 && len(out) > limit {
		out = out[len(out)-limit:]
	}
	return out
}
