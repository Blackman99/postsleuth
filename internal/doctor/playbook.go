package doctor

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Blackman99/postsleuth/internal/maillog"
	"github.com/Blackman99/postsleuth/internal/provider"
	"github.com/Blackman99/postsleuth/internal/queue"
	"github.com/Blackman99/postsleuth/internal/reason"
)

// CollectPlaybooks matches queue delay reasons and log deferral/bounce texts
// against the provider playbooks. Either source may be nil.
func CollectPlaybooks(q *queue.Summary, st *maillog.Stats, only string) []provider.Hit {
	c := provider.NewCollector()
	if q != nil {
		for _, r := range q.Reasons {
			if r.Playbook != "" {
				c.Add(provider.KindQueued, r.Example, r.Domains, r.Count)
			}
		}
	}
	if st != nil {
		for _, r := range st.Deferrals {
			if r.Playbook != "" {
				c.Add(provider.KindDeferral, r.Example, r.Domains, r.Count)
			}
		}
		for _, r := range st.Bounces {
			if r.Playbook != "" {
				c.Add(provider.KindBounce, r.Example, r.Domains, r.Count)
			}
		}
	}
	hits := c.Result()
	if only == "" {
		return hits
	}
	out := []provider.Hit{}
	for _, h := range hits {
		if h.Playbook.Provider == only {
			out = append(out, h)
		}
	}
	return out
}

// PlaybookResult is the provider playbooks that apply to this server.
type PlaybookResult struct {
	LogSource  string         `json:"log_source,omitempty"`
	Since      time.Time      `json:"since,omitempty"`
	LogError   string         `json:"log_error,omitempty"`
	QueueError string         `json:"queue_error,omitempty"`
	Provider   string         `json:"provider_filter,omitempty"`
	Playbooks  []provider.Hit `json:"playbooks"`
}

// ProviderPlaybooks reads the queue and the mail log (window, 0 = all) and
// returns the provider playbooks for what is failing. It fails only when
// neither source can be read.
func (e *Env) ProviderPlaybooks(ctx context.Context, window time.Duration, only string) (PlaybookResult, error) {
	res := PlaybookResult{Provider: only}
	var q *queue.Summary
	if msgs, err := e.Queue(ctx); err != nil {
		res.QueueError = err.Error()
	} else {
		s := queue.Summarize(msgs, e.now(), 0)
		q = &s
	}
	var st *maillog.Stats
	if lr, err := e.LogStats(ctx, window, "", 0); err != nil {
		res.LogError = err.Error()
	} else {
		res.LogSource, res.Since, st = lr.Source, lr.Since, &lr.Stats
	}
	if q == nil && st == nil {
		return res, fmt.Errorf("could not read the queue (%s) or the mail log (%s)", res.QueueError, res.LogError)
	}
	res.Playbooks = CollectPlaybooks(q, st, only)
	if res.Playbooks == nil {
		res.Playbooks = []provider.Hit{}
	}
	return res, nil
}

// ReplyLookup is the playbook lookup for one pasted reply text.
type ReplyLookup struct {
	Reply        string             `json:"reply"`
	Provider     string             `json:"provider,omitempty"`
	ProviderName string             `json:"provider_name,omitempty"`
	Code         string             `json:"code,omitempty"`
	CodeNote     string             `json:"code_note,omitempty"`
	Temporary    bool               `json:"temporary"`
	Category     string             `json:"category"`
	Hint         string             `json:"hint"`
	Playbook     *provider.Playbook `json:"playbook"`
}

// LookupReply classifies one SMTP reply or delay reason (as found in the log
// or in postqueue output) and finds its provider playbook. rcptDomain is an
// optional hint used when the reply names no host.
func LookupReply(text, rcptDomain string) ReplyLookup {
	text = strings.TrimSpace(text)
	m := provider.Lookup(text, rcptDomain)
	c := reason.Classify(text)
	return ReplyLookup{Reply: text, Provider: m.Provider, ProviderName: provider.Name(m.Provider), Code: m.Code, CodeNote: m.Note,
		Temporary: m.Temporary, Category: c.ID, Hint: c.Hint, Playbook: m.Playbook}
}

func (r *Report) playbookFindings() {
	for _, h := range r.Playbooks {
		var ev []string
		if h.Deferrals > 0 {
			ev = append(ev, fmt.Sprintf("%d deferred attempts", h.Deferrals))
		}
		if h.Bounces > 0 {
			ev = append(ev, fmt.Sprintf("%d bounced", h.Bounces))
		}
		if h.Queued > 0 {
			ev = append(ev, fmt.Sprintf("%d queued recipients", h.Queued))
		}
		detail := h.Playbook.Meaning
		if len(h.Notes) > 0 {
			detail += " (" + strings.Join(h.Notes, "; ") + ")"
		}
		next := ""
		if len(h.Playbook.Steps) > 0 {
			next = h.Playbook.Steps[0]
		}
		f := Finding{Severity: SevInfo, Area: "provider",
			Title: fmt.Sprintf("%s %s: %s (%s) at %s", provider.Short(h.Playbook.Provider), strings.Join(h.Codes, "/"),
				h.Playbook.Title, strings.Join(ev, ", "), strings.Join(h.Domains, ", ")),
			Detail: detail, Next: next, Playbook: h.Playbook.ID, Steps: h.Playbook.Steps, References: h.Playbook.Refs}
		r.Findings = append(r.Findings, f)
	}
}
