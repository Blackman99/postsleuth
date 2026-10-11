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
		fmt.Fprintf(w, "         → %s\n", trim(r.Hint, 110))
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
