// Package provider recognises which large mailbox provider (Gmail, Microsoft,
// Yahoo) produced a deferral or bounce, and maps the provider's own codes to a
// recovery playbook: ordered next steps plus the provider's official pages.
//
// It only reads reply texts. It never contacts a provider, files a request or
// changes anything.
package provider

import (
	"regexp"
	"sort"
	"strings"

	"github.com/Blackman99/postsleuth/internal/reason"
)

// Provider ids.
const (
	Gmail     = "gmail"
	Microsoft = "microsoft"
	Yahoo     = "yahoo"
)

// Info describes a provider.
type Info struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	// Hosts are MX / relay host suffixes the provider answers from.
	Hosts []string `json:"mx_hosts"`
}

// Providers lists every provider postsleuth knows, in display order.
var Providers = []Info{
	{Gmail, "Gmail / Google Workspace", []string{"google.com", "googlemail.com"}},
	{Microsoft, "Microsoft (Outlook.com / Microsoft 365)", []string{"protection.outlook.com", "outlook.com", "hotmail.com", "office365.com"}},
	{Yahoo, "Yahoo / AOL", []string{"yahoodns.net", "yahoo.com", "aol.com"}},
}

// Name returns the display name of a provider id ("" if unknown).
func Name(id string) string {
	for _, p := range Providers {
		if p.ID == id {
			return p.Name
		}
	}
	return ""
}

// Short returns a compact display name: Gmail, Microsoft, Yahoo.
func Short(id string) string {
	switch id {
	case Gmail:
		return "Gmail"
	case Microsoft:
		return "Microsoft"
	case Yahoo:
		return "Yahoo"
	}
	return id
}

// Ref is an official reference page.
type Ref struct {
	Title string `json:"title"`
	URL   string `json:"url"`
}

// Playbook is an ordered recovery procedure for one provider failure.
type Playbook struct {
	ID       string `json:"id"`
	Provider string `json:"provider"`
	// Codes is the family of reply codes this playbook covers, for display.
	Codes   string   `json:"codes"`
	Title   string   `json:"title"`
	Meaning string   `json:"meaning"`
	Steps   []string `json:"steps"`
	Refs    []Ref    `json:"references"`
	// CodeNotes holds the provider's own one-line explanation per code,
	// where the provider publishes one (e.g. Outlook.com SC-001..OU-002).
	CodeNotes map[string]string `json:"code_notes,omitempty"`

	re *regexp.Regexp
	// permanent: retrying cannot succeed even when the reply is a 4xx.
	permanent bool
}

// Match is the result of looking up one reply text.
type Match struct {
	Provider string `json:"provider,omitempty"` // gmail, microsoft, yahoo; "" if not recognised
	// Playbook is nil when the provider was recognised but has no playbook
	// for this reply (e.g. a plain "user unknown").
	Playbook *Playbook `json:"-"`
	ID       string    `json:"playbook,omitempty"`
	Code     string    `json:"code,omitempty"`      // the provider code seen, e.g. 4.7.28, S3150, TSS04
	Note     string    `json:"code_note,omitempty"` // provider's explanation of Code, if published
	// Temporary is true when Postfix's own retries can succeed.
	Temporary bool `json:"temporary"`

	classKnown bool // the text had a 4xx/5xx status, so Temporary is from the reply itself
}

var (
	reAddrs   = regexp.MustCompile(`<[^<>\s]*@[^<>\s]*>|\b[\w.+\-=]+@[\w.\-]+\.[A-Za-z]{2,}\b`)
	reGoogle  = regexp.MustCompile(`(?i)\bgsmtp\b|\bgmail\b|support\.google\.com|google\.com`)
	reMS      = regexp.MustCompile(`(?i)protection\.outlook\.com|outlook\.com|hotmail\.com|aka\.ms/postmaster|postmaster\.live\.com|sender\.office\.com|delist@microsoft\.com|\(S\d{3,4}\)|\b(?:RP|SC|DY|OU)-00\d\b|\bbanned sending ip\b|5\.7\.6(?:0[6-9]|[1-4]\d)\b`)
	reYahoo   = regexp.MustCompile(`(?i)yahoodns\.net|yahooinc\.com|postmaster\.yahoo|yahoo\.com|\[(?:TSS?|BL|PH)\d+\]`)
	reStatus  = regexp.MustCompile(`(?:^|said: |\s)([45])\d\d[ -]`)
	reEnhCode = regexp.MustCompile(`\b([45])\.\d{1,3}\.\d{1,3}\b`)
)

func hostIs(h string, suffixes ...string) bool {
	for _, s := range suffixes {
		if h == s || strings.HasSuffix(h, "."+s) {
			return true
		}
	}
	return false
}

// Detect names the provider behind a failure text: first from the remote
// host Postfix talked to ("host gmail-smtp-in.l.google.com[...] said:"), then
// from provider-specific markers in the reply (gsmtp, S3150, [TSS04], ...),
// then from the recipient domain. It returns "" when nothing matches.
func Detect(text, rcptDomain string) string {
	h := strings.ToLower(strings.TrimSuffix(reason.Remote(text), "."))
	switch {
	case h == "":
	case hostIs(h, "google.com", "googlemail.com", "gmail.com"):
		return Gmail
	case hostIs(h, "outlook.com", "hotmail.com", "live.com", "msn.com", "office365.com", "microsoft.com"):
		return Microsoft
	case hostIs(h, "yahoodns.net", "yahoo.com", "yahoo.net", "aol.com", "yahooinc.com"):
		return Yahoo
	}
	// Markers in the reply itself. Recipient addresses are removed first so
	// "<bob@gmail.com>" quoted by some other server does not count.
	t := reAddrs.ReplaceAllString(text, " ")
	switch {
	case reMS.MatchString(t):
		return Microsoft
	case reYahoo.MatchString(t):
		return Yahoo
	case reGoogle.MatchString(t):
		return Gmail
	}
	if h != "" {
		return "" // a known, non-provider host answered
	}
	return byDomain(rcptDomain)
}

func byDomain(d string) string {
	d = strings.ToLower(strings.TrimSpace(d))
	switch {
	case d == "":
		return ""
	case d == "gmail.com" || d == "googlemail.com":
		return Gmail
	case d == "msn.com" || d == "windowslive.com" ||
		strings.HasPrefix(d, "outlook.") || strings.HasPrefix(d, "hotmail.") || strings.HasPrefix(d, "live."):
		return Microsoft
	case d == "ymail.com" || d == "rocketmail.com" || d == "aim.com" ||
		strings.HasPrefix(d, "yahoo.") || strings.HasPrefix(d, "aol."):
		return Yahoo
	}
	return ""
}

// Lookup detects the provider of a failure text and finds its playbook.
// rcptDomain is optional and only used when the text itself is ambiguous.
func Lookup(text, rcptDomain string) Match {
	m := Match{Provider: Detect(text, rcptDomain)}
	if m.Provider == "" {
		return m
	}
	for i := range playbooks {
		pb := &playbooks[i]
		if pb.Provider != m.Provider {
			continue
		}
		sm := pb.re.FindStringSubmatch(text)
		if sm == nil {
			continue
		}
		m.Playbook, m.ID = pb, pb.ID
		for _, g := range sm[1:] {
			if g != "" {
				m.Code = g
				break
			}
		}
		if m.Code == "" {
			m.Code = statusCode(text)
		}
		m.Note = pb.CodeNotes[strings.ToUpper(m.Code)]
		var known bool
		m.Temporary, known = temporary(text)
		m.Temporary = m.Temporary && !pb.permanent
		m.classKnown = known
		return m
	}
	return m
}

// statusCode returns the enhanced status code of a reply (e.g. 5.7.1), if any.
func statusCode(text string) string {
	if c := reEnhCode.FindString(text); c != "" {
		return c
	}
	return ""
}

// temporary reports whether a reply is a 4xx (Postfix retries) rather than 5xx.
// The second result is false when the text carries no SMTP status at all
// (e.g. a delay reason without the reply code).
func temporary(text string) (bool, bool) {
	if m := reStatus.FindStringSubmatch(text); m != nil {
		return m[1] == "4", true
	}
	if m := reEnhCode.FindStringSubmatch(text); m != nil {
		return m[1] == "4", true
	}
	return false, false
}

// All returns every built-in playbook, grouped by provider.
func All() []Playbook {
	out := make([]Playbook, len(playbooks))
	copy(out, playbooks)
	return out
}

// Get returns the playbook with the given id.
func Get(id string) (Playbook, bool) {
	for _, p := range playbooks {
		if strings.EqualFold(p.ID, id) {
			return p, true
		}
	}
	return Playbook{}, false
}

// Hit is a playbook that applies to failures seen on this server, with the
// evidence: how often, for which domains, and one example reply.
type Hit struct {
	Playbook  Playbook `json:"playbook"`
	Codes     []string `json:"codes_seen"`
	Notes     []string `json:"code_notes,omitempty"`
	Temporary bool     `json:"temporary"`
	Deferrals int      `json:"deferred_attempts"`
	Bounces   int      `json:"bounces"`
	Queued    int      `json:"queued_recipients"`
	Domains   []string `json:"domains"`
	Example   string   `json:"example"`
}

// Collector merges failures from the queue and the log into playbook hits.
type Collector struct {
	hits map[string]*hitAgg
}

type hitAgg struct {
	h       Hit
	codes   map[string]bool
	notes   map[string]bool
	domains map[string]bool
}

// NewCollector returns an empty collector.
func NewCollector() *Collector { return &Collector{hits: map[string]*hitAgg{}} }

// Kinds of evidence for Collector.Add.
const (
	KindDeferral = "deferral"
	KindBounce   = "bounce"
	KindQueued   = "queued"
)

// Add records n failures of the given kind with this reply text.
func (c *Collector) Add(kind, text string, domains []string, n int) Match {
	first := ""
	if len(domains) > 0 {
		first = domains[0]
	}
	m := Lookup(text, first)
	if m.Playbook == nil {
		return m
	}
	a := c.hits[m.ID]
	if a == nil {
		a = &hitAgg{h: Hit{Playbook: *m.Playbook, Example: text}, codes: map[string]bool{}, notes: map[string]bool{}, domains: map[string]bool{}}
		c.hits[m.ID] = a
	}
	switch kind {
	case KindDeferral:
		a.h.Deferrals += n
	case KindBounce:
		a.h.Bounces += n
	case KindQueued:
		a.h.Queued += n
	}
	// Postfix deferred it and the text has no status code: trust Postfix,
	// unless the playbook is for a provider's permanent block.
	if !m.classKnown && kind != KindBounce && !m.Playbook.permanent {
		m.Temporary = true
	}
	if m.Temporary {
		a.h.Temporary = true
	}
	if m.Code != "" {
		a.codes[m.Code] = true
	}
	if m.Note != "" {
		a.notes[m.Code+": "+m.Note] = true
	}
	for _, d := range domains {
		if !strings.HasPrefix(d, "+") {
			a.domains[d] = true
		}
	}
	return m
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Result returns hits, the most affected first.
func (c *Collector) Result() []Hit {
	out := []Hit{}
	for _, a := range c.hits {
		h := a.h
		h.Codes, h.Notes, h.Domains = keys(a.codes), keys(a.notes), keys(a.domains)
		if len(h.Notes) == 0 {
			h.Notes = nil
		}
		out = append(out, h)
	}
	weight := func(h Hit) int { return h.Deferrals + h.Bounces + h.Queued }
	sort.Slice(out, func(i, j int) bool {
		if weight(out[i]) != weight(out[j]) {
			return weight(out[i]) > weight(out[j])
		}
		return out[i].Playbook.ID < out[j].Playbook.ID
	})
	return out
}
