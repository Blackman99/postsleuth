package message

import (
	"fmt"
	"net/mail"
	"regexp"
	"sort"
	"strings"
	"time"

	"golang.org/x/net/publicsuffix"

	"github.com/Blackman99/postsleuth/internal/provider"
	"github.com/Blackman99/postsleuth/internal/queue"
	"github.com/Blackman99/postsleuth/internal/reason"
)

// Note levels (the same words the doctor uses).
const (
	Problem = "problem"
	Warning = "warning"
	Info    = "info"
)

// Recipient is one envelope recipient with its delivery state.
type Recipient struct {
	Address     string `json:"address"`
	Domain      string `json:"domain"`
	Status      string `json:"status"` // pending, delivered, canceled
	Original    string `json:"original_recipient,omitempty"`
	DelayReason string `json:"delay_reason,omitempty"`
	Category    string `json:"category,omitempty"`
	Hint        string `json:"hint,omitempty"`
	Provider    string `json:"provider,omitempty"`
	Playbook    string `json:"playbook,omitempty"`
	Temporary   *bool  `json:"temporary,omitempty"`
}

// Hop is one Received header, oldest first.
type Hop struct {
	From string `json:"from,omitempty"` // the client's HELO name
	// FromHost is the client's reverse DNS name as the receiving host saw it
	// ("unknown" when it has none).
	FromHost string `json:"from_host,omitempty"`
	FromIP   string `json:"from_ip,omitempty"`
	By       string `json:"by,omitempty"`
	With     string `json:"with,omitempty"`
	TLS      string `json:"tls,omitempty"`
	ID       string `json:"id,omitempty"`
	Time     string `json:"time,omitempty"` // RFC 3339
	// Authenticated: a SMTP AUTH submission (the client is a person's device;
	// its name and address are hidden when redacting).
	Authenticated bool `json:"authenticated,omitempty"`
	// Local: submitted on the host itself (sendmail/pickup).
	Local bool `json:"local,omitempty"`
}

// Signature is one DKIM-Signature header.
type Signature struct {
	Domain    string `json:"d"`
	Selector  string `json:"s"`
	Algorithm string `json:"a,omitempty"`
	// Aligned: d= shares the organizational domain of the From header
	// (relaxed DMARC alignment).
	Aligned bool `json:"aligned_with_from"`
}

// Note is one observation about the message.
type Note struct {
	Level string `json:"level"`
	ID    string `json:"id"`
	Text  string `json:"text"`
	Fix   string `json:"fix,omitempty"`
}

// Count is a domain with a number of recipients.
type Count = queue.Count

// Report is everything postsleuth shows about one queued message.
type Report struct {
	QueueID string `json:"queue_id"`
	// Queue: incoming, active, deferred, hold or corrupt.
	Queue        string      `json:"queue"`
	Arrival      string      `json:"arrival_time,omitempty"` // RFC 3339
	Age          string      `json:"age,omitempty"`
	AgeSeconds   int64       `json:"age_seconds,omitempty"`
	Size         int64       `json:"message_size"`
	Sender       string      `json:"sender"` // "<>" is the null sender (a bounce)
	SenderDomain string      `json:"sender_domain"`
	FromDomain   string      `json:"from_domain,omitempty"` // domain of the From: header
	Recipients   []Recipient `json:"recipients"`
	Domains      []Count     `json:"recipient_domains"`
	Hops         []Hop       `json:"hops"`
	DKIM         []Signature `json:"dkim"`
	Headers      []Header    `json:"headers"`
	Notes        []Note      `json:"notes"`
	// Redacted is true unless the CLI was run with --unredacted. Secret-like
	// headers are removed either way and the body is never read.
	Redacted bool   `json:"redacted"`
	Source   string `json:"source"`
}

// Options for Build.
type Options struct {
	Redact bool
	Now    time.Time
	// Entry is this message's postqueue -j entry, if available: it carries
	// the delay reasons and the authoritative queue name and arrival time.
	Entry  *queue.Message
	Source string
}

// Build turns parsed postcat output into a report.
func Build(p Parsed, o Options) Report {
	r := newRedactor(o.Redact)
	rep := Report{QueueID: p.QueueID, Queue: p.Queue, Size: p.Size, Redacted: o.Redact, Source: o.Source,
		Recipients: []Recipient{}, Domains: []Count{}, Hops: []Hop{}, DKIM: []Signature{}, Headers: []Header{}, Notes: []Note{}}
	arrival := p.Arrival
	sender, hasSender := p.Sender, p.HasSender
	reasons := map[string]string{}
	if e := o.Entry; e != nil {
		if rep.QueueID == "" {
			rep.QueueID = e.QueueID
		}
		if e.QueueName != "" {
			rep.Queue = e.QueueName
		}
		if e.ArrivalTime > 0 {
			arrival = e.Arrival()
		}
		if rep.Size == 0 {
			rep.Size = e.MessageSize
		}
		if !hasSender {
			sender, hasSender = e.Sender, true
		}
		for _, rc := range e.Recipients {
			reasons[strings.ToLower(rc.Address)] = rc.DelayReason
		}
		if len(p.Recipients) == 0 {
			for _, rc := range e.Recipients {
				p.Recipients = append(p.Recipients, RawRecipient{Address: rc.Address, Status: Pending})
			}
		}
	}
	if !arrival.IsZero() {
		if !o.Now.IsZero() {
			arrival = arrival.In(o.Now.Location())
		}
		rep.Arrival = arrival.Format(time.RFC3339)
		if !o.Now.IsZero() {
			age := o.Now.Sub(arrival)
			rep.Age, rep.AgeSeconds = queue.HumanAge(age), int64(age.Seconds())
		}
	}
	rep.Sender = r.addr(sender)
	rep.SenderDomain = queue.Domain(sender)

	byDomain := map[string]int{}
	for _, rc := range p.Recipients {
		d := queue.Domain(rc.Address)
		out := Recipient{Address: r.addr(rc.Address), Domain: d, Status: rc.Status}
		if rc.Original != "" && !strings.EqualFold(rc.Original, rc.Address) {
			out.Original = r.addr(rc.Original)
		}
		if why := reasons[strings.ToLower(rc.Address)]; why != "" && rc.Status == Pending {
			c := reason.Classify(why)
			pm := provider.Lookup(why, d)
			out.DelayReason, out.Category, out.Hint = r.text(why), c.ID, c.Hint
			out.Provider, out.Playbook = pm.Provider, pm.ID
			if pm.ID != "" {
				t := pm.Temporary
				out.Temporary = &t
			}
		}
		rep.Recipients = append(rep.Recipients, out)
		byDomain[d]++
	}
	for d, n := range byDomain {
		rep.Domains = append(rep.Domains, Count{Key: d, Count: n})
	}
	sort.Slice(rep.Domains, func(i, j int) bool {
		if rep.Domains[i].Count != rep.Domains[j].Count {
			return rep.Domains[i].Count > rep.Domains[j].Count
		}
		return rep.Domains[i].Key < rep.Domains[j].Key
	})

	// Headers, hops, signatures.
	froms := p.Get("From")
	var fromAddrs []string
	for _, f := range froms {
		for _, m := range emailRe.FindAllStringSubmatch(f, -1) {
			fromAddrs = append(fromAddrs, m[0])
		}
	}
	if len(fromAddrs) > 0 {
		rep.FromDomain = queue.Domain(fromAddrs[0])
	}
	for _, h := range p.Headers {
		rep.Headers = append(rep.Headers, r.header(h))
		switch strings.ToLower(h.Name) {
		case "received":
			rep.Hops = append(rep.Hops, parseHop(h.Value, o.Redact))
		case "dkim-signature":
			tags := dkimTags(h.Value)
			s := Signature{Domain: strings.ToLower(tags["d"]), Selector: tags["s"], Algorithm: tags["a"]}
			s.Aligned = rep.FromDomain != "" && orgDomain(s.Domain) == orgDomain(rep.FromDomain)
			rep.DKIM = append(rep.DKIM, s)
		}
	}
	// Received headers are prepended: the first one is the newest hop.
	for i, j := 0, len(rep.Hops)-1; i < j; i, j = i+1, j-1 {
		rep.Hops[i], rep.Hops[j] = rep.Hops[j], rep.Hops[i]
	}
	rep.Notes = notes(p, rep, len(froms), hasSender && sender == "")
	return rep
}

var (
	reHopFrom   = regexp.MustCompile(`(?i)^from\s+(\S+)(?:\s+\(([^()]*)\))?`)
	reHopIP     = regexp.MustCompile(`\[(?:IPv6:)?([0-9A-Fa-f:.]+)\]`)
	reHopBy     = regexp.MustCompile(`(?i)\bby\s+([^\s;()]+)`)
	reHopWith   = regexp.MustCompile(`(?i)\bwith\s+([A-Za-z0-9-]+)`)
	reHopCipher = regexp.MustCompile(`(?i)^(cipher|no)$`)
	reHopID     = regexp.MustCompile(`(?i)\bid\s+<?([^\s;>]+)`)
	reHopTLS    = regexp.MustCompile(`(?i)\(using\s+(TLSv?[0-9.]+|SSLv[0-9.]+)`)
	reHopGTLS   = regexp.MustCompile(`(?i)version=TLS1_([0-9])`)
	reHopUserID = regexp.MustCompile(`(?i)\bfrom userid\b`)
)

func parseHop(v string, redact bool) Hop {
	var h Hop
	if m := reHopFrom.FindStringSubmatch(v); m != nil {
		h.From = m[1]
		inner := m[2]
		if ip := reHopIP.FindStringSubmatch(inner); ip != nil {
			h.FromIP = ip[1]
			if host := strings.TrimSpace(inner[:strings.Index(inner, "[")]); host != "" {
				h.FromHost = strings.TrimSuffix(host, ".")
			}
		} else if ip := reHopIP.FindStringSubmatch(m[1]); ip != nil {
			h.FromIP, h.From = ip[1], ""
		}
	}
	if m := reHopBy.FindStringSubmatch(v); m != nil {
		h.By = m[1]
	}
	for _, m := range reHopWith.FindAllStringSubmatch(v, -1) {
		if !reHopCipher.MatchString(m[1]) {
			h.With = m[1]
			break
		}
	}
	if m := reHopID.FindStringSubmatch(v); m != nil {
		h.ID = m[1]
	}
	if m := reHopTLS.FindStringSubmatch(v); m != nil {
		h.TLS = m[1]
	} else if m := reHopGTLS.FindStringSubmatch(v); m != nil {
		h.TLS = "TLSv1." + m[1]
	} else if w := strings.ToUpper(h.With); strings.HasSuffix(w, "SMTPS") || strings.HasSuffix(w, "SMTPSA") || strings.HasSuffix(w, "LMTPS") {
		h.TLS = "TLS"
	}
	if i := strings.LastIndexByte(v, ';'); i >= 0 {
		if t, err := mail.ParseDate(strings.TrimSpace(v[i+1:])); err == nil {
			h.Time = t.Format(time.RFC3339)
		}
	}
	h.Authenticated = authenticatedHop(v)
	h.Local = h.From == "" && h.FromIP == "" && reHopUserID.MatchString(v)
	if h.Authenticated && redact {
		h.From, h.FromHost, h.FromIP = "", "", ""
	}
	return h
}

func dkimTags(v string) map[string]string {
	out := map[string]string{}
	for _, m := range reTag.FindAllStringSubmatch(v, -1) {
		out[strings.ToLower(m[1])] = strings.Join(strings.Fields(m[2]), "")
	}
	return out
}

// orgDomain is the registrable domain (example.co.uk for mail.example.co.uk).
func orgDomain(d string) string {
	d = strings.TrimSuffix(strings.ToLower(d), ".")
	if o, err := publicsuffix.EffectiveTLDPlusOne(d); err == nil {
		return o
	}
	return d
}

func notes(p Parsed, rep Report, nFrom int, nullSender bool) []Note {
	var out []Note
	add := func(level, id, text, fix string) { out = append(out, Note{level, id, text, fix}) }
	has := func(name string) bool { return len(p.Get(name)) > 0 }
	if len(p.Headers) == 0 {
		add(Info, "no_headers", "postcat returned no headers for this message", "it may still be in the maildrop or incoming queue; try again in a few seconds")
		return out
	}
	switch {
	case nFrom == 0:
		add(Problem, "no_from", "no From: header", "RFC 5322 requires one and Gmail, Microsoft and Yahoo reject or junk mail without it; fix the sending application")
	case nFrom > 1:
		add(Problem, "multiple_from", fmt.Sprintf("%d From: headers", nFrom), "receivers (Gmail, Microsoft) reject messages with more than one From:; fix the sending application")
	}
	if !has("Message-ID") {
		add(Warning, "no_message_id", "no Message-ID: header", "Gmail rejects mail without one (550 5.7.1 ... missing a valid Message-ID); let Postfix add it for local clients (always_add_missing_headers = yes) or fix the application")
	}
	if !has("Date") {
		add(Warning, "no_date", "no Date: header", "some receivers score or reject mail without a Date:; let Postfix add it (always_add_missing_headers = yes)")
	}
	early := rep.Queue == "maildrop" || rep.Queue == "incoming"
	switch {
	case len(rep.DKIM) == 0 && !early:
		add(Warning, "no_dkim", "not DKIM-signed",
			"Gmail, Yahoo and Microsoft require DKIM for bulk senders and DMARC relies on it; check the signing milter (smtpd_milters / non_smtpd_milters) (unless a content_filter signs it later)")
	case len(rep.DKIM) > 0 && rep.FromDomain != "":
		aligned := false
		var ds []string
		for _, s := range rep.DKIM {
			aligned = aligned || s.Aligned
			ds = append(ds, "d="+s.Domain)
		}
		if !aligned {
			add(Problem, "dkim_not_aligned", fmt.Sprintf("DKIM %s does not align with From: %s", strings.Join(ds, ", "), rep.FromDomain),
				"DMARC needs a signature from the From: domain (or a subdomain); sign with d="+orgDomain(rep.FromDomain))
		}
	}
	if rep.FromDomain != "" && !nullSender && rep.SenderDomain != "" && rep.SenderDomain != "<>" &&
		orgDomain(rep.SenderDomain) != orgDomain(rep.FromDomain) {
		add(Info, "spf_not_aligned", fmt.Sprintf("envelope sender domain %s differs from From: %s, so SPF cannot align", rep.SenderDomain, rep.FromDomain),
			"fine if DKIM aligns; otherwise DMARC fails")
	}
	bulk := has("List-Id")
	for _, v := range p.Get("Precedence") {
		if v := strings.ToLower(strings.TrimSpace(v)); v == "bulk" || v == "list" || v == "junk" {
			bulk = true
		}
	}
	httpsUnsub := false
	for _, v := range p.Get("List-Unsubscribe") {
		httpsUnsub = httpsUnsub || strings.Contains(strings.ToLower(v), "<https:")
	}
	oneClick := httpsUnsub && has("List-Unsubscribe-Post")
	level := Info
	if bulk {
		level = Warning
	}
	const rfc8058 = "Gmail and Yahoo require one-click unsubscribe from bulk senders (RFC 8058): List-Unsubscribe with an https URL plus List-Unsubscribe-Post: List-Unsubscribe=One-Click"
	switch {
	case bulk && !has("List-Unsubscribe"):
		add(Warning, "no_list_unsubscribe", "bulk mail (Precedence/List-Id) without List-Unsubscribe:", rfc8058)
	case has("List-Unsubscribe") && !httpsUnsub:
		add(level, "no_one_click", "List-Unsubscribe is mailto: only, so there is no one-click unsubscribe", rfc8058)
	case has("List-Unsubscribe") && !oneClick:
		add(level, "no_one_click", "List-Unsubscribe without List-Unsubscribe-Post, so there is no one-click unsubscribe", rfc8058)
	}
	if nullSender {
		add(Info, "null_sender", "null sender <>: this is a bounce or delivery notification",
			"many of these to outside domains can be backscatter; check what sent the original (postsleuth trace)")
	}
	if rep.Queue == "hold" {
		add(Info, "on_hold", "on hold: Postfix will not try to deliver it until it is released",
			"postsleuth release --allow-mutations "+rep.QueueID)
	}
	if rep.Queue == "corrupt" {
		add(Problem, "corrupt", "the queue file is in the corrupt queue", "Postfix will not deliver it; inspect it and check the disk and file system")
	}
	if p.BodyDropped > 0 {
		add(Info, "body_ignored", fmt.Sprintf("%d body line(s) in the input were ignored", p.BodyDropped), "postsleuth never shows message bodies")
	}
	return out
}
