package doctor

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/Blackman99/postsleuth/internal/dnsauth"
	"github.com/Blackman99/postsleuth/internal/message"
	"github.com/Blackman99/postsleuth/internal/queue"
)

// HumanSize formats a byte count: 812 B, 36.8 KB, 4.1 MB.
func HumanSize(n int64) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(n)/(1<<10))
	default:
		return fmt.Sprintf("%d B", n)
	}
}

// WriteMessage prints one queued message: where it is, who is still
// waiting and why, the route it took, its authentication and its headers.
func WriteMessage(w io.Writer, s Style, r message.Report) {
	line := []string{s.Bold(r.QueueID), r.Queue}
	if t, err := time.Parse(time.RFC3339, r.Arrival); err == nil {
		a := "arrived " + t.Format("2006-01-02 15:04 MST")
		if r.Age != "" {
			a += " (" + r.Age + " ago)"
		}
		line = append(line, a)
	}
	line = append(line, HumanSize(r.Size))
	fmt.Fprintf(w, "%s %s\n", head(s, "MESSAGE"), strings.Join(line, " · "))
	fmt.Fprintf(w, "  %s %-10s %s\n", s.Dim("·"), "sender", r.Sender)
	for _, rc := range r.Recipients {
		mark := s.Mark(SevInfo)
		switch {
		case rc.Status == message.Delivered:
			mark = s.Mark(dnsauth.OK)
		case rc.Status == message.Pending && rc.Category == "greylisting":
			mark = s.Mark(SevWarn)
		case rc.Status == message.Pending && rc.DelayReason != "":
			mark = s.Mark(SevProblem)
		}
		cat := ""
		if rc.Category != "" {
			cat = "  " + rc.Category
		}
		fmt.Fprintf(w, "  %s %-10s %s%s\n", mark, rc.Status, rc.Address, cat)
		if rc.Original != "" {
			fmt.Fprintf(w, "%15s%s\n", "", s.Dim("originally "+rc.Original))
		}
		if rc.DelayReason != "" {
			writeWrapped(w, strings.Repeat(" ", 15), strings.Repeat(" ", 15), rc.DelayReason, 92, s.Dim)
			writeWrapped(w, strings.Repeat(" ", 15)+"→ ", strings.Repeat(" ", 17), rc.Hint, 90, plain)
			if rc.Playbook != "" {
				fmt.Fprintf(w, "%15s→ %s\n", "", playbookPointer(s, rc.Provider, rc.Playbook))
			}
		}
	}

	if len(r.Hops) > 0 {
		fmt.Fprintf(w, "%s %d hop%s, oldest first\n", head(s, "ROUTE"), len(r.Hops), plural(len(r.Hops)))
		var prev time.Time
		for i, h := range r.Hops {
			var parts []string
			switch {
			case h.Local:
				parts = append(parts, "local submission on "+h.By+s.Dim(" (sendmail/pickup)"))
			default:
				from := h.FromHost
				if from == "" {
					from = h.From
				}
				if h.FromIP != "" {
					from = strings.TrimSpace(from + " [" + h.FromIP + "]")
				}
				if h.Authenticated && h.FromIP == "" && h.From == "" {
					from = s.Dim("[authenticated client hidden]")
				}
				if from == "" {
					from = "?"
				}
				parts = append(parts, from+" → "+h.By)
			}
			if h.With != "" {
				parts = append(parts, h.With)
			}
			if h.TLS != "" {
				parts = append(parts, h.TLS)
			}
			if h.ID != "" {
				parts = append(parts, "id "+h.ID)
			}
			if t, err := time.Parse(time.RFC3339, h.Time); err == nil {
				ts := t.Format("15:04:05")
				if !prev.IsZero() {
					ts += s.Dim(" (+" + hopDelay(t.Sub(prev)) + ")")
				}
				parts = append(parts, ts)
				prev = t
			}
			fmt.Fprintf(w, "  %d  %s\n", i+1, strings.Join(parts, " · "))
		}
	}

	auth := []string{}
	if r.FromDomain != "" {
		auth = append(auth, "From: "+r.FromDomain)
	} else {
		auth = append(auth, "From: "+s.Mark(SevProblem)+" none")
	}
	if len(r.DKIM) == 0 {
		auth = append(auth, "DKIM "+s.Mark(SevWarn)+" unsigned")
	}
	for _, d := range r.DKIM {
		m, word := s.Mark(dnsauth.OK), "aligned"
		if !d.Aligned {
			m, word = s.Mark(SevProblem), "not aligned"
		}
		auth = append(auth, fmt.Sprintf("DKIM d=%s s=%s %s %s", d.Domain, d.Selector, m, word))
	}
	auth = append(auth, "envelope "+r.SenderDomain)
	fmt.Fprintf(w, "%s %s\n", head(s, "AUTH"), strings.Join(auth, " · "))

	var shown []message.Header
	width := 0
	for _, h := range r.Headers {
		switch strings.ToLower(h.Name) {
		case "received", "dkim-signature":
			continue
		}
		shown = append(shown, h)
		if n := len(h.Name) + 1; n > width && n <= 26 {
			width = n
		}
	}
	note := "as stored"
	if r.Redacted {
		note = "personal values redacted"
	}
	fmt.Fprintf(w, "%s %d more (Received in ROUTE, DKIM in AUTH) · %s · body never read\n", head(s, "HEADERS"), len(shown), note)
	for _, h := range shown {
		v := trim(h.Value, 96-width)
		if h.Redacted || h.Removed {
			v = s.Dim(v)
		}
		fmt.Fprintf(w, "  %-*s %s\n", width, h.Name+":", v)
	}

	if len(r.Notes) > 0 {
		fmt.Fprintf(w, "%s\n", s.Bold("NOTES"))
		for _, n := range r.Notes {
			fmt.Fprintf(w, "  %s %s\n", s.Mark(n.Level), n.Text)
			if n.Fix != "" {
				writeWrapped(w, "    → ", "      ", n.Fix, 96, plain)
			}
		}
	}
	if r.Redacted {
		fmt.Fprintf(w, "%s\n", s.Dim("redacted: local parts → [user-N] · domains kept · credentials removed · --unredacted for raw values (CLI only)"))
	} else {
		fmt.Fprintf(w, "%s\n", s.Dim("unredacted: addresses and subject shown as stored · credential-like headers still removed · body never read"))
	}
}

func hopDelay(d time.Duration) string {
	if d < 0 {
		return "clock skew " + (-d).String()
	}
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm%02ds", int(d.Minutes()), int(d.Seconds())%60)
	default:
		return queue.HumanAge(d)
	}
}
