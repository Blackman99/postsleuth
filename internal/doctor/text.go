package doctor

import (
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/Blackman99/postsleuth/internal/dnsauth"
	"github.com/Blackman99/postsleuth/internal/maillog"
	"github.com/Blackman99/postsleuth/internal/provider"
	"github.com/Blackman99/postsleuth/internal/queue"
	"github.com/Blackman99/postsleuth/internal/reason"
)

// Style colours terminal output.
type Style struct{ Color bool }

func (s Style) c(code, text string) string {
	if !s.Color {
		return text
	}
	return "\x1b[" + code + "m" + text + "\x1b[0m"
}

// Bold text.
func (s Style) Bold(t string) string { return s.c("1", t) }

// Dim text.
func (s Style) Dim(t string) string { return s.c("2", t) }

// Mark returns a coloured status glyph.
func (s Style) Mark(status string) string {
	switch status {
	case dnsauth.OK:
		return s.c("32", "✓")
	case dnsauth.Warn, SevWarn:
		return s.c("33", "!")
	case dnsauth.Fail, SevProblem:
		return s.c("31", "✗")
	default:
		return s.c("2", "·")
	}
}

func head(s Style, label string) string { return s.Bold(fmt.Sprintf("%-8s", label)) }

// WriteQueue prints a queue summary.
func WriteQueue(w io.Writer, s Style, q queue.Summary) { writeQueue(w, s, q, true) }

func writeQueue(w io.Writer, s Style, q queue.Summary, pointers bool) {
	var parts []string
	for _, c := range q.ByQueue {
		parts = append(parts, fmt.Sprintf("%s %d", c.Key, c.Count))
	}
	line := fmt.Sprintf("%d messages", q.Total)
	if len(parts) > 0 {
		line += " · " + strings.Join(parts, " · ")
	}
	if q.OldestID != "" {
		line += fmt.Sprintf(" · oldest %s (%s)", q.OldestAge, q.OldestID)
	}
	fmt.Fprintf(w, "%s %s\n", head(s, "QUEUE"), line)
	for _, r := range q.Reasons {
		mark := s.Mark(SevProblem)
		if r.Category == "greylisting" {
			mark = s.Mark(SevWarn)
		}
		fmt.Fprintf(w, "  %s %4d  %-17s %s\n", mark, r.Count, r.Category, strings.Join(r.Domains, ", "))
		fmt.Fprintf(w, "         %s\n", s.Dim(trim(r.Reason, 96)))
		for i, l := range wrap(r.Hint, 100) {
			lead := "         → "
			if i > 0 {
				lead = "           "
			}
			fmt.Fprintf(w, "%s%s\n", lead, l)
		}
		if pointers && r.Playbook != "" {
			fmt.Fprintf(w, "         → %s\n", playbookPointer(s, r.Provider, r.Playbook))
		}
	}
}

func playbookPointer(s Style, prov, id string) string {
	return provider.Short(prov) + " playbook: " + s.Bold("postsleuth playbook "+id)
}

// WriteShape prints a qshape matrix.
func WriteShape(w io.Writer, s Style, sh queue.Shape) {
	fmt.Fprintf(w, "%s %s queue by %s domain, age in minutes\n", head(s, "SHAPE"), sh.Queue, sh.By)
	for _, l := range strings.Split(strings.TrimRight(sh.Text(), "\n"), "\n") {
		fmt.Fprintf(w, "  %s\n", l)
	}
}

// WriteLog prints log stats.
func WriteLog(w io.Writer, s Style, lr LogResult) { writeLog(w, s, lr, true) }

func writeLog(w io.Writer, s Style, lr LogResult, pointers bool) {
	t := lr.Stats.Totals
	fmt.Fprintf(w, "%s %s · %d sent · %d deferred attempts · %d bounced · %d expired · %d rejected\n", head(s, "LOG"),
		s.Dim(lr.Source), t.Sent, t.Deferred, t.Bounced, t.Expired, t.Rejected)
	if len(lr.Stats.StillFailing) > 0 {
		var d []string
		for i, f := range lr.Stats.StillFailing {
			if i >= 4 {
				break
			}
			d = append(d, fmt.Sprintf("%s (%d)", f.Domain, f.Deferred))
		}
		fmt.Fprintf(w, "  %s still failing: %s\n", s.Mark(SevWarn), strings.Join(d, ", "))
	}
	sec := func(name string, list []maillog.ReasonStat) {
		for i, r := range list {
			if i >= 3 {
				break
			}
			doms := strings.Join(r.Domains, ", ")
			if doms != "" {
				doms = " · " + doms
			}
			fmt.Fprintf(w, "  %s %-8s %4d  %-17s %s%s\n", s.Mark(SevProblem), name, r.Count, r.Category, s.Dim(trim(r.Reason, 70)), doms)
			if pointers && r.Playbook != "" {
				fmt.Fprintf(w, "%19s→ %s\n", "", playbookPointer(s, r.Provider, r.Playbook))
			}
		}
	}
	sec("bounce", lr.Stats.Bounces)
	sec("deferral", lr.Stats.Deferrals)
	sec("reject", lr.Stats.Rejects)
}

// WriteTrend prints per-destination deferral trends.
func WriteTrend(w io.Writer, s Style, tr TrendResult) {
	t := tr.Trend
	win := ""
	if !tr.Since.IsZero() {
		win = " since " + tr.Since.Format("Jan 2 15:04")
	}
	fmt.Fprintf(w, "%s %s · buckets %s%s · %d destination(s)\n", head(s, "TREND"), s.Dim(tr.Source), t.Bucket, win, len(t.Domains))
	if len(t.Domains) == 0 {
		fmt.Fprintf(w, "  %s no sent/deferred events in window\n", s.Mark("info"))
		return
	}
	fmt.Fprintf(w, "  %-28s %6s %9s %7s  %-18s %s\n", "domain", "sent", "deferred", "rate", "direction", "early→late")
	for _, d := range t.Domains {
		mark := s.Mark("info")
		switch d.Direction {
		case maillog.DirectionWorsening:
			mark = s.Mark(SevWarn)
		case maillog.DirectionImproving:
			mark = s.Mark(dnsauth.OK)
		}
		fmt.Fprintf(w, "  %s %-26s %6d %9d %6.0f%%  %-18s %.0f%%→%.0f%%\n",
			mark, d.Domain, d.Sent, d.Deferred, d.Rate*100, d.Direction, d.EarlyRate*100, d.LateRate*100)
		var parts []string
		for _, b := range d.Buckets {
			if b.Sent+b.Deferred == 0 {
				continue
			}
			parts = append(parts, fmt.Sprintf("%s %.0f%%(%d/%d)", b.Start.Format("15:04"), b.Rate*100, b.Deferred, b.Sent+b.Deferred))
		}
		if len(parts) > 8 {
			parts = parts[len(parts)-8:]
		}
		if len(parts) > 0 {
			fmt.Fprintf(w, "         %s\n", s.Dim(strings.Join(parts, " · ")))
		}
	}
}

// WriteDNS prints DNS checks.
func WriteDNS(w io.Writer, s Style, r dnsauth.Report) {
	extra := ""
	if len(r.IPs) > 0 {
		extra = " · sending IP " + strings.Join(r.IPs, ", ")
	}
	fmt.Fprintf(w, "%s %s%s\n", head(s, "DNS"), r.Domain, extra)
	for _, c := range r.Checks {
		rec := ""
		if c.Record != "" && c.Name != "spf" && c.Name != "dmarc" {
			rec = s.Dim(trim(c.Record, 44)) + "  "
		}
		fmt.Fprintf(w, "  %s %-6s %s%s\n", s.Mark(c.Status), c.Name, rec, trim(c.Message, 120))
	}
}

func wrap(t string, n int) []string {
	var out []string
	line := ""
	for _, w := range strings.Fields(t) {
		if line != "" && len([]rune(line))+1+len([]rune(w)) > n {
			out = append(out, line)
			line = w
			continue
		}
		if line != "" {
			line += " "
		}
		line += w
	}
	if line != "" {
		out = append(out, line)
	}
	return out
}

func trim(t string, n int) string {
	r := []rune(t)
	if len(r) <= n {
		return t
	}
	return string(r[:n-1]) + "…"
}

// WriteReport prints the doctor report.
func WriteReport(w io.Writer, s Style, r Report) {
	who := r.Identity.Hostname
	if who == "" {
		who = "postfix"
	}
	fmt.Fprintf(w, "%s %s\n\n", s.Bold("postsleuth doctor"), s.Dim("· "+who+" · "+r.GeneratedAt.Format("2006-01-02 15:04 MST")))
	if r.Queue != nil {
		writeQueue(w, s, *r.Queue, false)
		if r.Shape != nil && r.Shape.Total.Total > 0 {
			fmt.Fprintln(w)
			WriteShape(w, s, *r.Shape)
		}
		fmt.Fprintln(w)
	} else if r.QueueError != "" {
		fmt.Fprintf(w, "%s %s %s\n\n", head(s, "QUEUE"), s.Mark(SevWarn), r.QueueError)
	}
	if r.Log != nil {
		writeLog(w, s, *r.Log, false)
		fmt.Fprintln(w)
	} else if r.LogError != "" {
		fmt.Fprintf(w, "%s %s %s\n\n", head(s, "LOG"), s.Mark("info"), r.LogError)
	}
	if r.Trend != nil && len(r.Trend.Trend.Domains) > 0 {
		var shown int
		for _, d := range r.Trend.Trend.Domains {
			if d.Direction != maillog.DirectionWorsening && d.Direction != maillog.DirectionImproving {
				continue
			}
			if d.Sent+d.Deferred < 10 {
				continue
			}
			if shown == 0 {
				fmt.Fprintf(w, "%s buckets %s\n", head(s, "TREND"), r.Trend.Trend.Bucket)
			}
			mark := s.Mark(SevWarn)
			if d.Direction == maillog.DirectionImproving {
				mark = s.Mark(dnsauth.OK)
			}
			fmt.Fprintf(w, "  %s %s %s (%.0f%% → %.0f%%)\n", mark, d.Domain, d.Direction, d.EarlyRate*100, d.LateRate*100)
			shown++
			if shown >= 4 {
				break
			}
		}
		if shown > 0 {
			fmt.Fprintln(w)
		}
	}
	if len(r.Playbooks) > 0 {
		writePlaybookHeader(w, s, len(r.Playbooks), "what is failing here")
		for _, h := range r.Playbooks {
			writeHit(w, s, h, hitView{})
		}
		fmt.Fprintln(w)
	}
	if r.DNS != nil {
		WriteDNS(w, s, *r.DNS)
		fmt.Fprintln(w)
	} else if r.DNSError != "" {
		fmt.Fprintf(w, "%s %s %s\n\n", head(s, "DNS"), s.Mark("info"), r.DNSError)
	}
	verdict := s.c("32", "no problems found")
	if r.Problems > 0 {
		verdict = s.c("31", fmt.Sprintf("%d problem(s)", r.Problems))
	}
	fmt.Fprintf(w, "%s %s, %d warning(s)\n", head(s, "RESULT"), verdict, r.Warnings)
}

// Playbook output. Body text starts in column 9, like the rest of the report;
// steps are numbered in the gutter.

const body = "         "

func writePlaybookHeader(w io.Writer, s Style, n int, what string) {
	noun := "provider playbook"
	verb := "matches"
	if n != 1 {
		noun += "s"
		verb = "match"
	}
	fmt.Fprintf(w, "%s %d %s %s %s\n", head(s, "PLAYBOOK"), n, noun, verb, what)
}

func writeWrapped(w io.Writer, first, rest, text string, width int, style func(string) string) {
	for i, l := range wrap(text, width) {
		lead := first
		if i > 0 {
			lead = rest
		}
		fmt.Fprintf(w, "%s%s\n", lead, style(l))
	}
}

func plain(t string) string { return t }

func retryLabel(s Style, temporary bool) string {
	if temporary {
		return s.c("33", "temporary") + s.Dim(" (Postfix retries)")
	}
	return s.c("31", "permanent") + s.Dim(" (retrying won't help)")
}

var reANSI = regexp.MustCompile(`\x1b\[[0-9;]*m`)

func stripANSI(t string) string { return reANSI.ReplaceAllString(t, "") }

func evidence(h provider.Hit) []string {
	var ev []string
	if h.Deferrals > 0 {
		ev = append(ev, fmt.Sprintf("%d deferred attempts", h.Deferrals))
	}
	if h.Bounces > 0 {
		ev = append(ev, fmt.Sprintf("%d bounced", h.Bounces))
	}
	if h.Queued > 0 {
		ev = append(ev, fmt.Sprintf("%d queued", h.Queued))
	}
	doms := h.Domains
	if len(doms) > 4 {
		doms = append(doms[:4:4], fmt.Sprintf("+%d more", len(h.Domains)-4))
	}
	if len(doms) > 0 {
		ev = append(ev, strings.Join(doms, ", "))
	}
	return ev
}

type hitView struct {
	full   bool // meaning, every step, code notes, references
	static bool // a playbook on its own: no retry verdict, no evidence
	id     bool // append the playbook id to the title line
}

// writeHit prints one playbook. Compact view: the first three steps and a
// pointer to the full playbook.
func writeHit(w io.Writer, s Style, h provider.Hit, v hitView) {
	p := h.Playbook
	mark := s.Mark(SevProblem)
	switch {
	case v.static:
		mark = s.Mark("info")
	case h.Temporary:
		mark = s.Mark(SevWarn)
	}
	codes := strings.Join(h.Codes, "/")
	if codes == "" {
		codes = p.Codes
	}
	id := ""
	if v.id {
		id = " " + s.Dim("· "+p.ID)
	}
	fmt.Fprintf(w, "  %s %s %s · %s%s\n", mark, s.Bold(provider.Short(p.Provider)), s.Bold(codes), p.Title, id)
	if !v.static {
		// verdict, then counts and domains; the domains move to their own
		// line when everything doesn't fit in ~100 columns
		line := retryLabel(s, h.Temporary)
		width := len([]rune(stripANSI(line)))
		for _, part := range evidence(h) {
			n := len([]rune(part)) + 3
			if width+n > 100 {
				fmt.Fprintf(w, "%s%s\n", body, line)
				line, width = part, len([]rune(part))
				continue
			}
			line += " · " + part
			width += n
		}
		fmt.Fprintf(w, "%s%s\n", body, line)
	}
	if v.full {
		writeWrapped(w, body, body, p.Meaning, 96, s.Dim)
		for _, n := range h.Notes {
			writeWrapped(w, body+"· ", body+"  ", n, 94, s.Dim)
		}
	} else if len(h.Notes) > 0 {
		writeWrapped(w, body, body, strings.Join(h.Notes, "; "), 96, s.Dim)
	}
	steps := p.Steps
	if !v.full && len(steps) > 1 {
		steps = steps[:1] // doctor is the overview; the playbook has the rest
	}
	for i, st := range steps {
		writeWrapped(w, fmt.Sprintf("%7d  ", i+1), body, st, 96, plain)
	}
	if !v.full {
		more := []string{}
		if n := len(p.Steps) - len(steps); n > 0 {
			more = append(more, fmt.Sprintf("%d more step%s", n, plural(n)))
		}
		if n := len(p.Refs); n > 0 {
			more = append(more, fmt.Sprintf("%d official link%s", n, plural(n)))
		}
		fmt.Fprintf(w, "%s%s %s\n", body, s.Dim("+ "+strings.Join(more, ", ")+":"), s.Bold("postsleuth playbook "+p.ID))
		return
	}
	for i, r := range p.Refs {
		lead := "    ref  "
		if i > 0 {
			lead = body
		}
		title := fmt.Sprintf("%-36s", trim(r.Title, 36))
		if len(body)+36+2+len(r.URL) > 112 {
			fmt.Fprintf(w, "%s%s\n%s%s\n", s.Dim(lead), strings.TrimRight(title, " "), body, r.URL)
			continue
		}
		fmt.Fprintf(w, "%s%s  %s\n", s.Dim(lead), title, r.URL)
	}
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// WritePlaybooks prints the provider playbooks for what is failing on this server.
func WritePlaybooks(w io.Writer, s Style, r PlaybookResult) {
	src := []string{}
	if r.LogSource != "" {
		l := r.LogSource
		if !r.Since.IsZero() {
			l += " since " + r.Since.Format("Jan 2 15:04")
		}
		src = append(src, l)
	}
	if r.QueueError == "" {
		src = append(src, "queue")
	}
	if len(r.Playbooks) == 0 {
		who := "Gmail, Microsoft or Yahoo"
		if r.Provider != "" {
			who = provider.Short(r.Provider)
		}
		fmt.Fprintf(w, "%s %s nothing failing at %s that has a playbook %s\n", head(s, "PLAYBOOK"), s.Mark(dnsauth.OK), who, s.Dim("("+strings.Join(src, " + ")+")"))
	} else {
		writePlaybookHeader(w, s, len(r.Playbooks), s.Dim("("+strings.Join(src, " + ")+")"))
	}
	if r.QueueError != "" {
		fmt.Fprintf(w, "  %s queue not read: %s\n", s.Mark("info"), trim(r.QueueError, 100))
	}
	if r.LogError != "" {
		fmt.Fprintf(w, "  %s log not read: %s\n", s.Mark("info"), trim(r.LogError, 100))
	}
	for i, h := range r.Playbooks {
		if i > 0 {
			fmt.Fprintln(w)
		}
		writeHit(w, s, h, hitView{full: true, id: true})
	}
	if len(r.Playbooks) == 0 {
		fmt.Fprintf(w, "%s%s\n", body, s.Dim("look up a single reply with postsleuth playbook --reply \"TEXT\", or list them all with --list"))
	}
}

// WritePlaybook prints one playbook in full, without evidence.
func WritePlaybook(w io.Writer, s Style, p provider.Playbook) {
	fmt.Fprintf(w, "%s %s %s\n", head(s, "PLAYBOOK"), s.Bold(p.ID), s.Dim("· "+provider.Name(p.Provider)))
	h := provider.Hit{Playbook: p, Codes: []string{p.Codes}, Notes: sortedNotes(p.CodeNotes)}
	writeHit(w, s, h, hitView{full: true, static: true})
}

func sortedNotes(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k, v := range m {
		out = append(out, k+": "+v)
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

// WritePlaybookIndex lists every built-in playbook.
func WritePlaybookIndex(w io.Writer, s Style) {
	all := provider.All()
	fmt.Fprintf(w, "%s %d built-in provider playbooks · postsleuth playbook ID for the steps\n", head(s, "PLAYBOOK"), len(all))
	last := ""
	for _, p := range all {
		if p.Provider != last {
			fmt.Fprintf(w, "\n  %s\n", s.Bold(provider.Name(p.Provider)))
			last = p.Provider
		}
		if 4+22+1+len([]rune(p.Title))+3+len(p.Codes) > 104 {
			fmt.Fprintf(w, "    %-22s %s\n    %-22s %s\n", p.ID, p.Title, "", s.Dim(p.Codes))
			continue
		}
		fmt.Fprintf(w, "    %-22s %s %s\n", p.ID, p.Title, s.Dim("· "+p.Codes))
	}
}

// WriteReplyLookup prints the result of looking up one reply text.
func WriteReplyLookup(w io.Writer, s Style, r ReplyLookup) {
	if r.Playbook == nil {
		who := "no playbook: not a Gmail, Microsoft or Yahoo reply"
		if r.Provider != "" {
			who = "no playbook: " + r.ProviderName + " reply, but not one with provider-specific steps"
		}
		fmt.Fprintf(w, "%s %s %s\n", head(s, "PLAYBOOK"), s.Mark("info"), who)
		fmt.Fprintf(w, "%s%s %s\n", body, s.Bold(r.Category), s.Dim(trim(reason.Normalize(r.Reply), 90)))
		writeWrapped(w, body+"→ ", body+"  ", r.Hint, 94, plain)
		return
	}
	h := provider.Hit{Playbook: *r.Playbook, Temporary: r.Temporary}
	if r.Code != "" {
		h.Codes = []string{r.Code}
	}
	if r.CodeNote != "" {
		h.Notes = []string{r.Code + ": " + r.CodeNote}
	}
	fmt.Fprintf(w, "%s %s %s\n", head(s, "PLAYBOOK"), s.Bold(r.Playbook.ID), s.Dim("· "+r.ProviderName+" · category "+r.Category))
	writeHit(w, s, h, hitView{full: true})
}
