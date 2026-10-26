// Package doctor ties the queue, log, config and DNS checks together. Both the
// CLI and the MCP server call into it.
package doctor

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"github.com/Blackman99/postsleuth/internal/dnsauth"
	"github.com/Blackman99/postsleuth/internal/maillog"
	"github.com/Blackman99/postsleuth/internal/message"
	"github.com/Blackman99/postsleuth/internal/postfix"
	"github.com/Blackman99/postsleuth/internal/queue"
)

// Env is the shared runtime configuration.
type Env struct {
	Runner    postfix.Runner
	Logs      postfix.LogSource
	QueueFile string // read postqueue -j output from this file instead of running postqueue
	// MessageFile: read saved "postcat -e -h -q ID" output instead of running postcat.
	MessageFile string
	Resolver    dnsauth.Resolver
	Now         func() time.Time
}

func (e *Env) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now()
}

// Queue loads the queue.
func (e *Env) Queue(ctx context.Context) ([]queue.Message, error) {
	var data []byte
	var err error
	if e.QueueFile != "" {
		if e.QueueFile == "-" {
			data, err = io.ReadAll(os.Stdin)
		} else {
			data, err = os.ReadFile(e.QueueFile)
		}
	} else {
		data, err = e.Runner.QueueJSON(ctx)
	}
	if err != nil {
		return nil, err
	}
	return queue.Parse(bytes.NewReader(data))
}

// Message reads the envelope and headers of one queued message (postcat
// -e -h -q ID; never the body) and joins them with its postqueue -j entry for
// the delay reasons. With redact (always on over MCP) local parts, display
// names, subjects and other free text are hidden; secret-like headers are
// removed either way.
func (e *Env) Message(ctx context.Context, id string, redact bool) (message.Report, error) {
	if !postfix.ValidQueueID(id) {
		return message.Report{}, fmt.Errorf("invalid queue ID %q: %s", id, postfix.QueueIDHelp)
	}
	var raw, src string
	if e.MessageFile != "" {
		var data []byte
		var err error
		if e.MessageFile == "-" {
			data, err = io.ReadAll(os.Stdin)
		} else {
			data, err = os.ReadFile(e.MessageFile)
		}
		if err != nil {
			return message.Report{}, err
		}
		raw, src = string(data), e.MessageFile
	} else {
		out, err := e.Runner.QueueMessage(ctx, id)
		if err != nil {
			return message.Report{}, err
		}
		raw, src = out, "postcat -e -h -q "+id
	}
	now := e.now()
	p := message.Parse(raw, now.Location())
	if p.QueueID != "" && p.QueueID != id {
		return message.Report{}, fmt.Errorf("%s holds message %s, not %s", src, p.QueueID, id)
	}
	if p.QueueID == "" {
		p.QueueID = id
	}
	var entry *queue.Message
	if msgs, err := e.Queue(ctx); err == nil {
		for i := range msgs {
			if msgs[i].QueueID == id {
				entry = &msgs[i]
				break
			}
		}
	}
	return message.Build(p, message.Options{Redact: redact, Now: now, Entry: entry, Source: src}), nil
}

// Config returns `postconf -n` (empty map when Postfix is not reachable).
func (e *Env) Config(ctx context.Context) (map[string]string, error) {
	return e.Runner.Config(ctx)
}

func (e *Env) mailLogFile(ctx context.Context) string {
	if len(e.Logs.Files) > 0 || e.Logs.Cmd != "" {
		return ""
	}
	p, err := e.Runner.Params(ctx, "maillog_file")
	if err != nil {
		return ""
	}
	return p["maillog_file"]
}

// LogResult is log statistics plus where they came from.
type LogResult struct {
	Source string        `json:"source"`
	Since  time.Time     `json:"since"`
	Stats  maillog.Stats `json:"stats"`
}

// LogStats aggregates the log since now-window.
func (e *Env) LogStats(ctx context.Context, window time.Duration, domain string, top int) (LogResult, error) {
	now := e.now()
	since := time.Time{}
	if window > 0 {
		since = now.Add(-window)
	}
	rcs, src, err := e.Runner.OpenLogs(ctx, e.Logs, e.mailLogFile(ctx), since)
	if err != nil {
		return LogResult{}, err
	}
	agg := maillog.NewAggregator(domain)
	for _, rc := range rcs {
		err := maillog.Scan(rc, now, since, agg.Add, agg.AddDKIM)
		rc.Close()
		if err != nil {
			return LogResult{}, err
		}
	}
	return LogResult{Source: src, Since: since, Stats: agg.Result(top)}, nil
}

// TrendResult is per-destination deferral trends plus where they came from.
type TrendResult struct {
	Source string        `json:"source"`
	Since  time.Time     `json:"since"`
	Trend  maillog.Trend `json:"trend"`
}

// LogTrend aggregates per-destination deferral rates over time buckets.
// bucketSize 0 selects an automatic width from the window.
func (e *Env) LogTrend(ctx context.Context, window, bucketSize time.Duration, domain string, top int) (TrendResult, error) {
	now := e.now()
	since := time.Time{}
	if window > 0 {
		since = now.Add(-window)
	}
	rcs, src, err := e.Runner.OpenLogs(ctx, e.Logs, e.mailLogFile(ctx), since)
	if err != nil {
		return TrendResult{}, err
	}
	agg := maillog.NewTrendAggregator(domain, bucketSize)
	agg.WindowStart = since
	agg.WindowEnd = now
	if since.IsZero() {
		// leave WindowStart zero so Result uses first/last events
		agg.WindowEnd = time.Time{}
	}
	for _, rc := range rcs {
		err := maillog.Scan(rc, now, since, agg.Add, nil)
		rc.Close()
		if err != nil {
			return TrendResult{}, err
		}
	}
	tr := agg.Result(top)
	if since.IsZero() && !tr.First.IsZero() {
		// re-run Result with observed span as window so buckets are contiguous
		agg.WindowStart = tr.First
		agg.WindowEnd = tr.Last
		if agg.WindowEnd.IsZero() {
			agg.WindowEnd = now
		}
		tr = agg.Result(top)
	}
	return TrendResult{Source: src, Since: since, Trend: tr}, nil
}

// Trace follows a queue ID or address through the log.
func (e *Env) Trace(ctx context.Context, query string, window time.Duration, limit int) ([]maillog.TracedMessage, string, error) {
	now := e.now()
	since := time.Time{}
	if window > 0 {
		since = now.Add(-window)
	}
	rcs, src, err := e.Runner.OpenLogs(ctx, e.Logs, e.mailLogFile(ctx), since)
	if err != nil {
		return nil, "", err
	}
	t := maillog.NewTrace(query)
	for _, rc := range rcs {
		err := maillog.Scan(rc, now, since, t.Add, nil)
		rc.Close()
		if err != nil {
			return nil, src, err
		}
	}
	return t.Result(limit), src, nil
}

// DNSOptions for DNS.
type DNSOptions struct {
	Domain    string
	IPs       []string
	Selectors []string
	HELO      string
	// SelectorsFromLog: if no selectors are given, look for opendkim signing lines in the log.
	SelectorsFromLog bool
}

// SenderIdentity is what Postfix presents to the world, from postconf.
type SenderIdentity struct {
	Hostname string   `json:"myhostname"`
	Domain   string   `json:"sending_domain"`
	IPs      []string `json:"sending_ips"`
}

// Identity derives the sending domain/IPs from postconf (best effort).
func (e *Env) Identity(ctx context.Context) SenderIdentity {
	var id SenderIdentity
	p, err := e.Runner.Params(ctx, "myhostname", "mydomain", "myorigin", "smtp_bind_address", "smtp_bind_address6", "relayhost")
	if err != nil {
		return id
	}
	id.Hostname = p["myhostname"]
	id.Domain = p["myorigin"]
	if id.Domain == "" || strings.HasPrefix(id.Domain, "/") {
		id.Domain = p["mydomain"]
	}
	for _, k := range []string{"smtp_bind_address", "smtp_bind_address6"} {
		if ip := net.ParseIP(p[k]); ip != nil && !ip.IsUnspecified() {
			id.IPs = append(id.IPs, ip.String())
		}
	}
	if len(id.IPs) == 0 && id.Hostname != "" && p["relayhost"] == "" && e.Resolver != nil {
		rctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		if ips, err := e.Resolver.LookupIP(rctx, "ip", id.Hostname); err == nil {
			for _, ip := range ips {
				if !ip.IsLoopback() && !ip.IsPrivate() {
					id.IPs = append(id.IPs, ip.String())
				}
			}
		}
	}
	return id
}

// DNS runs the authentication checks. Missing domain/IPs are filled from postconf.
func (e *Env) DNS(ctx context.Context, o DNSOptions) (dnsauth.Report, error) {
	if o.Domain == "" || o.HELO == "" {
		id := e.Identity(ctx)
		if o.Domain == "" {
			o.Domain = id.Domain
			if len(o.IPs) == 0 {
				o.IPs = id.IPs
			}
		}
		if o.HELO == "" {
			o.HELO = id.Hostname
		}
	}
	if o.Domain == "" {
		return dnsauth.Report{}, fmt.Errorf("no domain given and none found in postconf (myorigin/mydomain)")
	}
	if len(o.Selectors) == 0 && o.SelectorsFromLog {
		if lr, err := e.LogStats(ctx, 7*24*time.Hour, "", 0); err == nil {
			for _, d := range lr.Stats.DKIM {
				if strings.EqualFold(d.Domain, o.Domain) {
					o.Selectors = append(o.Selectors, d.Selector)
				}
			}
		}
	}
	res := e.Resolver
	if res == nil {
		res = dnsauth.NewResolver("")
	}
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	return dnsauth.Run(ctx, res, dnsauth.Options{Domain: o.Domain, IPs: o.IPs, Selectors: o.Selectors, HELO: o.HELO}), nil
}

// ConfigView returns the subset of postconf -n that matters for delivery.
func ConfigView(all map[string]string) map[string]string {
	keep := []string{"myhostname", "mydomain", "myorigin", "mydestination", "relayhost", "inet_interfaces", "inet_protocols",
		"smtp_tls_security_level", "smtp_tls_policy_maps", "smtp_tls_CAfile", "smtp_sasl_auth_enable", "smtp_sasl_password_maps",
		"smtp_bind_address", "smtp_helo_name", "default_destination_concurrency_limit", "smtp_destination_concurrency_limit",
		"smtp_destination_rate_delay", "maximal_queue_lifetime", "bounce_queue_lifetime", "message_size_limit", "transport_maps",
		"relay_domains", "virtual_mailbox_domains", "virtual_alias_domains", "smtpd_milters", "non_smtpd_milters", "maillog_file",
		"mail_version", "compatibility_level"}
	out := map[string]string{}
	for _, k := range keep {
		if v, ok := all[k]; ok {
			out[k] = v
		}
	}
	return out
}
