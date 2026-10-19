package doctor

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Blackman99/postsleuth/internal/dnsauth"
	"github.com/Blackman99/postsleuth/internal/maillog"
	"github.com/Blackman99/postsleuth/internal/provider"
	"github.com/Blackman99/postsleuth/internal/queue"
)

// Severity of a finding.
const (
	SevProblem = "problem"
	SevWarn    = "warning"
	SevInfo    = "info"
)

// Finding is one thing the operator should know.
type Finding struct {
	Severity string `json:"severity"`
	Area     string `json:"area"` // queue, log, dns, config
	Title    string `json:"title"`
	Detail   string `json:"detail,omitempty"`
	Next     string `json:"next_step,omitempty"`
	// Provider playbook findings (area "provider") carry the full ordered
	// steps and the provider's official references.
	Playbook   string         `json:"playbook,omitempty"`
	Steps      []string       `json:"steps,omitempty"`
	References []provider.Ref `json:"references,omitempty"`
}

// Report is the combined diagnosis.
type Report struct {
	GeneratedAt time.Time         `json:"generated_at"`
	Identity    SenderIdentity    `json:"identity"`
	Queue       *queue.Summary    `json:"queue,omitempty"`
	QueueError  string            `json:"queue_error,omitempty"`
	Shape       *queue.Shape      `json:"shape,omitempty"`
	Log         *LogResult        `json:"log,omitempty"`
	LogError    string            `json:"log_error,omitempty"`
	Trend       *TrendResult      `json:"trend,omitempty"`
	Playbooks   []provider.Hit    `json:"provider_playbooks,omitempty"`
	DNS         *dnsauth.Report   `json:"dns,omitempty"`
	DNSError    string            `json:"dns_error,omitempty"`
	Config      map[string]string `json:"config,omitempty"`
	Findings    []Finding         `json:"findings"`
	Problems    int               `json:"problems"`
	Warnings    int               `json:"warnings"`
}

// Options for Run.
type Options struct {
	Window    time.Duration
	Domain    string
	IPs       []string
	Selectors []string
	SkipDNS   bool
	SkipLog   bool
	Top       int
}

// Run produces a diagnosis. Individual sources may fail; their errors are
// recorded and the rest of the report is still produced.
func (e *Env) Run(ctx context.Context, o Options) Report {
	if o.Top == 0 {
		o.Top = 5
	}
	now := e.now()
	r := Report{GeneratedAt: now}
	if cfg, err := e.Config(ctx); err == nil {
		r.Config = ConfigView(cfg)
	}
	r.Identity = e.Identity(ctx)
	var fullQueue *queue.Summary
	var fullLog *maillog.Stats
	if msgs, err := e.Queue(ctx); err != nil {
		r.QueueError = err.Error()
		r.add(SevWarn, "queue", "could not read the queue", err.Error(), "run as a user allowed to run postqueue (authorized_mailq_users), or pass --queue-file")
	} else {
		s := queue.Summarize(msgs, now, o.Top)
		r.Queue = &s
		all := queue.Summarize(msgs, now, 0)
		fullQueue = &all
		sh := queue.BuildShape(msgs, now, "deferred", "recipient", o.Top)
		r.Shape = &sh
		r.queueFindings(s, msgs, now)
	}
	if !o.SkipLog {
		if lr, err := e.LogStats(ctx, o.Window, "", 0); err != nil {
			r.LogError = err.Error()
			r.add(SevInfo, "log", "mail log not analysed", err.Error(), "")
		} else {
			all := lr.Stats
			fullLog = &all
			lr.Stats = lr.Stats.Top(o.Top)
			r.Log = &lr
			r.logFindings(lr)
			if tr, err := e.LogTrend(ctx, o.Window, 0, "", o.Top); err == nil && len(tr.Trend.Domains) > 0 {
				r.Trend = &tr
				r.trendFindings(tr)
			}
		}
	}
	if fullQueue != nil || fullLog != nil {
		r.Playbooks = CollectPlaybooks(fullQueue, fullLog, "")
		r.playbookFindings()
	}
	if !o.SkipDNS {
		dom := o.Domain
		ips := o.IPs
		var sel []string = o.Selectors
		if len(sel) == 0 && r.Log != nil {
			d := dom
			if d == "" {
				d = r.Identity.Domain
			}
			for _, k := range r.Log.Stats.DKIM {
				if strings.EqualFold(k.Domain, d) {
					sel = append(sel, k.Selector)
				}
			}
		}
		rep, err := e.DNS(ctx, DNSOptions{Domain: dom, IPs: ips, Selectors: sel})
		if err != nil {
			r.DNSError = err.Error()
			r.add(SevInfo, "dns", "DNS checks skipped", err.Error(), "pass --domain example.com --ip YOUR.SENDING.IP")
		} else {
			r.DNS = &rep
			for _, c := range rep.Checks {
				switch c.Status {
				case dnsauth.Fail:
					r.add(SevProblem, "dns", strings.ToUpper(c.Name)+": "+c.Message, c.Record, "")
				case dnsauth.Warn:
					r.add(SevWarn, "dns", strings.ToUpper(c.Name)+": "+c.Message, c.Record, "")
				}
			}
		}
	}
	return r
}

func (r *Report) add(sev, area, title, detail, next string) {
	r.Findings = append(r.Findings, Finding{Severity: sev, Area: area, Title: title, Detail: detail, Next: next})
	switch sev {
	case SevProblem:
		r.Problems++
	case SevWarn:
		r.Warnings++
	}
}

func (r *Report) queueFindings(s queue.Summary, msgs []queue.Message, now time.Time) {
	byQ := map[string]int{}
	for _, c := range s.ByQueue {
		byQ[c.Key] = c.Count
	}
	if d := byQ["deferred"]; d > 0 {
		var oldest time.Duration
		for _, m := range msgs {
			if m.QueueName == "deferred" {
				if a := now.Sub(m.Arrival()); a > oldest {
					oldest = a
				}
			}
		}
		sev := SevWarn
		if oldest > 24*time.Hour || d >= 100 {
			sev = SevProblem
		}
		r.add(sev, "queue", fmt.Sprintf("%d deferred message(s), oldest %s", d, queue.HumanAge(oldest)), "", "")
		for i, rc := range s.Reasons {
			if i >= 3 {
				break
			}
			if rc.Category == "greylisting" {
				r.add(SevInfo, "queue", fmt.Sprintf("%d recipient(s) greylisted at %s", rc.Count, strings.Join(rc.Domains, ", ")), rc.Reason, rc.Hint)
				continue
			}
			r.add(sev, "queue", fmt.Sprintf("%d recipient(s) stuck: %s at %s", rc.Count, rc.Category, strings.Join(rc.Domains, ", ")), rc.Reason, rc.Hint)
		}
	}
	if h := byQ["hold"]; h > 0 {
		r.add(SevInfo, "queue", fmt.Sprintf("%d message(s) on hold", h), "held mail is never delivered until released (postsuper -H)", "")
	}
	if c := byQ["corrupt"]; c > 0 {
		r.add(SevProblem, "queue", fmt.Sprintf("%d corrupt queue file(s)", c), "", "check disk health and run postsuper -s")
	}
	if a := byQ["active"]; a > 500 {
		r.add(SevWarn, "queue", fmt.Sprintf("active queue holds %d messages", a), "a large active queue usually means delivery agents cannot keep up", "")
	}
}

func (r *Report) logFindings(lr LogResult) {
	st := lr.Stats
	if st.Events == 0 {
		r.add(SevInfo, "log", "no Postfix lines in the selected window", "source: "+lr.Source, "")
		return
	}
	tried := st.Totals.Sent + st.Totals.Bounced
	if tried > 0 && st.Totals.Bounced*100/tried >= 5 {
		r.add(SevProblem, "log", fmt.Sprintf("bounce rate %d%% (%d of %d)", st.Totals.Bounced*100/tried, st.Totals.Bounced, tried), "", "")
	}
	for i, b := range st.Bounces {
		if i >= 2 {
			break
		}
		sev := SevWarn
		switch b.Category {
		case "auth", "ptr", "blocklist", "policy":
			sev = SevProblem
		}
		r.add(sev, "log", fmt.Sprintf("%d bounce(s): %s at %s", b.Count, b.Category, strings.Join(b.Domains, ", ")), b.Reason, b.Hint)
	}
	for i, d := range st.StillFailing {
		if i >= 3 {
			break
		}
		r.add(SevWarn, "log", fmt.Sprintf("%s still failing (%d deferred attempts, last %s)", d.Domain, d.Deferred, d.LastTime.Format("Jan 2 15:04")), d.LastDetail, "")
	}
	if st.Totals.Expired > 0 {
		r.add(SevProblem, "log", fmt.Sprintf("%d message(s) expired and were returned to sender", st.Totals.Expired), "they sat in the queue past maximal_queue_lifetime", "")
	}
}

func (r *Report) trendFindings(tr TrendResult) {
	for _, d := range tr.Trend.Domains {
		attempts := d.Sent + d.Deferred
		if d.Direction != maillog.DirectionWorsening || attempts < 20 || d.LateRate < 0.2 {
			continue
		}
		r.add(SevWarn, "log",
			fmt.Sprintf("%s deferral rate worsening (%.0f%% → %.0f%%, %s buckets)",
				d.Domain, d.EarlyRate*100, d.LateRate*100, tr.Trend.Bucket),
			fmt.Sprintf("%d sent · %d deferred in window", d.Sent, d.Deferred),
			"see postsleuth trend --domain "+d.Domain+"; check reputation and destination rate limits before flushing")
	}
}

// ExitCode is 0 when no problems were found, 1 otherwise.
func (r Report) ExitCode() int {
	if r.Problems > 0 {
		return 1
	}
	return 0
}
