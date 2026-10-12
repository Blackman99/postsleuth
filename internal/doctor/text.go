package doctor

import (
	"fmt"
	"io"
	"strings"

	"github.com/Blackman99/postsleuth/internal/dnsauth"
	"github.com/Blackman99/postsleuth/internal/maillog"
	"github.com/Blackman99/postsleuth/internal/queue"
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

func head(s Style, label string) string { return s.Bold(fmt.Sprintf("%-7s", label)) }

// WriteQueue prints a queue summary.
func WriteQueue(w io.Writer, s Style, q queue.Summary) {
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
	}
}

// WriteShape prints a qshape matrix.
func WriteShape(w io.Writer, s Style, sh queue.Shape) {
	fmt.Fprintf(w, "%s %s queue by %s domain, age in minutes\n", head(s, "SHAPE"), sh.Queue, sh.By)
	for _, l := range strings.Split(strings.TrimRight(sh.Text(), "\n"), "\n") {
		fmt.Fprintf(w, "  %s\n", l)
	}
}

// WriteLog prints log stats.
func WriteLog(w io.Writer, s Style, lr LogResult) {
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
		WriteQueue(w, s, *r.Queue)
		if r.Shape != nil && r.Shape.Total.Total > 0 {
			fmt.Fprintln(w)
			WriteShape(w, s, *r.Shape)
		}
		fmt.Fprintln(w)
	} else if r.QueueError != "" {
		fmt.Fprintf(w, "%s %s %s\n\n", head(s, "QUEUE"), s.Mark(SevWarn), r.QueueError)
	}
	if r.Log != nil {
		WriteLog(w, s, *r.Log)
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
