// Package mcpserver exposes postsleuth over the Model Context Protocol (stdio).
// Every tool is read-only unless the server was started with mutations enabled.
package mcpserver

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Blackman99/postsleuth/internal/dnsauth"
	"github.com/Blackman99/postsleuth/internal/doctor"
	"github.com/Blackman99/postsleuth/internal/maillog"
	"github.com/Blackman99/postsleuth/internal/provider"
	"github.com/Blackman99/postsleuth/internal/queue"
	"github.com/Blackman99/postsleuth/internal/reason"
)

// Options configure the server.
type Options struct {
	Version        string
	AllowMutations bool
}

func ptr[T any](v T) *T { return &v }

var readOnly = &mcp.ToolAnnotations{ReadOnlyHint: true, OpenWorldHint: ptr(false)}

const instructions = `postsleuth inspects a Postfix mail server: the queue (postqueue -j), a qshape-style age-by-domain matrix, the mail log (deferral reasons, bounce causes, per-domain outcomes, per-destination deferral trends, message traces) and the DNS records receivers check (MX, SPF, DKIM, DMARC, PTR/FCrDNS).
Start with postfix_doctor for an overview, then drill down. Every failure is classified (rate_limit, auth, ptr, blocklist, timeout, tls, dns, recipient_unknown, ...) with a hint. When Gmail, Microsoft (Outlook.com / Microsoft 365) or Yahoo/AOL is the receiver that is refusing or throttling mail, postfix_provider_playbook returns that provider's ordered recovery steps and official links (e.g. Gmail 421 4.7.28, Outlook.com S3150 / SNDS, Yahoo [TSS04]). Tools that change the queue only exist when the operator started the server with --allow-mutations, and even then require confirm=true.`

func parseWindow(s string, def time.Duration) (time.Duration, error) {
	if s == "" {
		return def, nil
	}
	if s == "all" {
		return 0, nil
	}
	if strings.HasSuffix(s, "d") {
		var n int
		if _, err := fmt.Sscanf(s, "%dd", &n); err == nil {
			return time.Duration(n) * 24 * time.Hour, nil
		}
	}
	return time.ParseDuration(s)
}

// QueueSummaryIn are arguments.
type QueueSummaryIn struct {
	Queue string `json:"queue,omitempty" jsonschema:"only this queue: active, deferred, hold, incoming, maildrop or corrupt (default all)"`
	Top   int    `json:"top,omitempty" jsonschema:"max entries per list (default 10)"`
}

// QueueListIn are arguments.
type QueueListIn struct {
	Queue          string `json:"queue,omitempty" jsonschema:"queue name filter, e.g. deferred"`
	Domain         string `json:"domain,omitempty" jsonschema:"recipient domain; a leading dot matches subdomains too"`
	Sender         string `json:"sender,omitempty" jsonschema:"substring of the envelope sender"`
	ReasonContains string `json:"reason_contains,omitempty" jsonschema:"case-insensitive substring of the delay reason"`
	Category       string `json:"category,omitempty" jsonschema:"reason category id, e.g. rate_limit, auth, ptr, timeout"`
	MinAge         string `json:"min_age,omitempty" jsonschema:"only messages older than this, e.g. 2h or 3d"`
	Limit          int    `json:"limit,omitempty" jsonschema:"max messages returned (default 50)"`
}

// QueueListOut is the result.
type QueueListOut struct {
	Matched  int             `json:"matched"`
	Returned int             `json:"returned"`
	Messages []queue.Message `json:"messages"`
}

// ShapeIn are arguments.
type ShapeIn struct {
	Queue string `json:"queue,omitempty" jsonschema:"queue to shape (default deferred; 'all' for every queue)"`
	By    string `json:"by,omitempty" jsonschema:"recipient (default) or sender domain"`
	Top   int    `json:"top,omitempty" jsonschema:"max domains (default 20)"`
}

// ShapeOut wraps the matrix with a text rendering.
type ShapeOut struct {
	queue.Shape
	Text string `json:"text"`
}

// LogStatsIn are arguments.
type LogStatsIn struct {
	Since  string `json:"since,omitempty" jsonschema:"time window, e.g. 1h, 24h (default), 7d, or all"`
	Domain string `json:"domain,omitempty" jsonschema:"only this recipient domain (leading dot = include subdomains)"`
	Top    int    `json:"top,omitempty" jsonschema:"max entries per list (default 15)"`
}

// LogTrendIn are arguments.
type LogTrendIn struct {
	Since  string `json:"since,omitempty" jsonschema:"time window, e.g. 1h, 24h (default), 7d, or all"`
	Domain string `json:"domain,omitempty" jsonschema:"only this recipient domain (leading dot = include subdomains)"`
	Bucket string `json:"bucket,omitempty" jsonschema:"bucket size, e.g. 15m, 1h, 4h, 12h, 1d (default: auto from window)"`
	Top    int    `json:"top,omitempty" jsonschema:"max destinations (default 15)"`
}

// TraceIn are arguments.
type TraceIn struct {
	Query string `json:"query" jsonschema:"a queue ID (e.g. 4F2A1C3B9) or an email address"`
	Since string `json:"since,omitempty" jsonschema:"time window (default 7d)"`
	Limit int    `json:"limit,omitempty" jsonschema:"max messages (default 20, newest kept)"`
}

// TraceOut is the result.
type TraceOut struct {
	Source   string                  `json:"source"`
	Messages []maillog.TracedMessage `json:"messages"`
}

// DNSIn are arguments.
type DNSIn struct {
	Domain    string   `json:"domain,omitempty" jsonschema:"sending domain (default: myorigin/mydomain from postconf)"`
	IPs       []string `json:"ips,omitempty" jsonschema:"sending IPs to check SPF authorisation and PTR/FCrDNS for (default: smtp_bind_address or myhostname's public A/AAAA)"`
	Selectors []string `json:"selectors,omitempty" jsonschema:"DKIM selectors (default: taken from opendkim log lines, else common names are probed)"`
}

// DoctorIn are arguments.
type DoctorIn struct {
	Since   string   `json:"since,omitempty" jsonschema:"log window (default 24h)"`
	Domain  string   `json:"domain,omitempty" jsonschema:"sending domain for DNS checks"`
	IPs     []string `json:"ips,omitempty" jsonschema:"sending IPs"`
	SkipDNS bool     `json:"skip_dns,omitempty" jsonschema:"do not run DNS checks"`
}

// PlaybookIn are arguments.
type PlaybookIn struct {
	Reply    string `json:"reply,omitempty" jsonschema:"one SMTP reply or delay reason to look up, as it appears in the log or postqueue (e.g. 'host gmail-smtp-in.l.google.com[...] said: 421-4.7.28 ...'); when set the queue and log are not read"`
	Domain   string `json:"domain,omitempty" jsonschema:"recipient domain of reply, used to recognise the provider when the reply names no host (e.g. outlook.com)"`
	ID       string `json:"id,omitempty" jsonschema:"return this one playbook, e.g. gmail-4.7.28, microsoft-s3150, yahoo-deferred (see available)"`
	Provider string `json:"provider,omitempty" jsonschema:"only this provider when scanning the server: gmail, microsoft or yahoo"`
	Since    string `json:"since,omitempty" jsonschema:"log window when scanning the server, e.g. 1h, 24h (default), 7d, or all"`
}

// PlaybookSummary names one built-in playbook.
type PlaybookSummary struct {
	ID       string `json:"id"`
	Provider string `json:"provider"`
	Codes    string `json:"codes"`
	Title    string `json:"title"`
}

// PlaybookOut is the result; which field is set depends on mode.
type PlaybookOut struct {
	Mode      string                 `json:"mode" jsonschema:"server (queue and log were scanned), reply (one reply was looked up) or id (one playbook by id)"`
	Server    *doctor.PlaybookResult `json:"server,omitempty" jsonschema:"mode server: playbooks for what is failing, with evidence counts, codes seen and affected domains, most deliveries affected first"`
	Lookup    *doctor.ReplyLookup    `json:"lookup,omitempty" jsonschema:"mode reply: provider, code, whether Postfix retries, category, and the playbook (null if none applies)"`
	Playbook  *provider.Playbook     `json:"playbook,omitempty" jsonschema:"mode id: the playbook"`
	Available []PlaybookSummary      `json:"available,omitempty" jsonschema:"every built-in playbook id; included when nothing matched"`
}

func available() []PlaybookSummary {
	out := []PlaybookSummary{}
	for _, p := range provider.All() {
		out = append(out, PlaybookSummary{ID: p.ID, Provider: p.Provider, Codes: p.Codes, Title: p.Title})
	}
	return out
}

// ConfigOut is the result.
type ConfigOut struct {
	Settings map[string]string `json:"settings"`
	Note     string            `json:"note"`
}

// CategoriesOut lists classification categories.
type CategoriesOut struct {
	Categories []reason.Category `json:"categories"`
}

// IDsIn are arguments for mutating tools.
type IDsIn struct {
	QueueIDs []string `json:"queue_ids" jsonschema:"explicit queue IDs (bulk ALL is not supported)"`
	Confirm  bool     `json:"confirm" jsonschema:"must be true; confirms the operator asked for this change"`
}

// FlushIn are arguments.
type FlushIn struct {
	QueueIDs []string `json:"queue_ids,omitempty" jsonschema:"retry these queue IDs now (postqueue -i)"`
	Site     string   `json:"site,omitempty" jsonschema:"retry everything queued for this destination domain (postqueue -s)"`
	All      bool     `json:"all,omitempty" jsonschema:"retry the whole deferred queue (postqueue -f); avoid while a receiver is throttling you"`
	Confirm  bool     `json:"confirm" jsonschema:"must be true; confirms the operator asked for this change"`
}

// ActionOut reports what was run.
type ActionOut struct {
	Ran []string `json:"ran"`
}

// New builds the MCP server.
func New(env *doctor.Env, o Options) *mcp.Server {
	s := mcp.NewServer(&mcp.Implementation{Name: "postsleuth", Version: o.Version}, &mcp.ServerOptions{Instructions: instructions})

	mcp.AddTool(s, &mcp.Tool{Name: "postfix_doctor", Annotations: readOnly,
		Description: "One-call diagnosis of a Postfix server: queue summary, qshape of the deferred queue, log outcomes for the window, DNS authentication checks, and a list of findings with next steps."},
		func(ctx context.Context, _ *mcp.CallToolRequest, in DoctorIn) (*mcp.CallToolResult, doctor.Report, error) {
			w, err := parseWindow(in.Since, 24*time.Hour)
			if err != nil {
				return nil, doctor.Report{}, err
			}
			r := env.Run(ctx, doctor.Options{Window: w, Domain: in.Domain, IPs: in.IPs, SkipDNS: in.SkipDNS})
			return nil, r, nil
		})

	mcp.AddTool(s, &mcp.Tool{Name: "postfix_queue_summary", Annotations: readOnly,
		Description: "Summarise the Postfix queue (postqueue -j): counts per queue, top recipient and sender domains, delay reasons grouped and classified with hints, oldest message."},
		func(ctx context.Context, _ *mcp.CallToolRequest, in QueueSummaryIn) (*mcp.CallToolResult, queue.Summary, error) {
			msgs, err := env.Queue(ctx)
			if err != nil {
				return nil, queue.Summary{}, err
			}
			if in.Top == 0 {
				in.Top = 10
			}
			now := time.Now()
			if env.Now != nil {
				now = env.Now()
			}
			msgs = queue.Filter{Queue: in.Queue}.Apply(msgs, now)
			return nil, queue.Summarize(msgs, now, in.Top), nil
		})

	mcp.AddTool(s, &mcp.Tool{Name: "postfix_queue_list", Annotations: readOnly,
		Description: "List queued messages (queue ID, queue, arrival time, size, sender, recipients with delay reasons), filtered by queue, recipient domain, sender, reason text, reason category or minimum age."},
		func(ctx context.Context, _ *mcp.CallToolRequest, in QueueListIn) (*mcp.CallToolResult, QueueListOut, error) {
			msgs, err := env.Queue(ctx)
			if err != nil {
				return nil, QueueListOut{}, err
			}
			minAge, err := parseWindow(in.MinAge, 0)
			if err != nil {
				return nil, QueueListOut{}, err
			}
			now := time.Now()
			if env.Now != nil {
				now = env.Now()
			}
			f := queue.Filter{Queue: in.Queue, Domain: in.Domain, Sender: in.Sender, ReasonContains: in.ReasonContains, Category: in.Category, MinAge: minAge}
			got := f.Apply(msgs, now)
			if in.Limit <= 0 {
				in.Limit = 50
			}
			out := QueueListOut{Matched: len(got)}
			if len(got) > in.Limit {
				got = got[:in.Limit]
			}
			out.Returned, out.Messages = len(got), got
			if out.Messages == nil {
				out.Messages = []queue.Message{}
			}
			return nil, out, nil
		})

	mcp.AddTool(s, &mcp.Tool{Name: "postfix_queue_shape", Annotations: readOnly,
		Description: "qshape-style matrix of a queue: rows are recipient (or sender) domains, columns are message age buckets in minutes (5,10,20,...,1280+). Shows which destination is backing up and since when."},
		func(ctx context.Context, _ *mcp.CallToolRequest, in ShapeIn) (*mcp.CallToolResult, ShapeOut, error) {
			msgs, err := env.Queue(ctx)
			if err != nil {
				return nil, ShapeOut{}, err
			}
			if in.Queue == "" {
				in.Queue = "deferred"
			}
			if in.Top == 0 {
				in.Top = 20
			}
			now := time.Now()
			if env.Now != nil {
				now = env.Now()
			}
			sh := queue.BuildShape(msgs, now, in.Queue, in.By, in.Top)
			return nil, ShapeOut{sh, sh.Text()}, nil
		})

	mcp.AddTool(s, &mcp.Tool{Name: "postfix_log_stats", Annotations: readOnly,
		Description: "Aggregate the Postfix mail log over a time window: totals (received, sent, deferred attempts, bounced, expired, smtpd rejects), per-domain outcomes, domains still failing, grouped deferral reasons and bounce causes with category and hint, and DKIM selectors seen in signing logs."},
		func(ctx context.Context, _ *mcp.CallToolRequest, in LogStatsIn) (*mcp.CallToolResult, doctor.LogResult, error) {
			w, err := parseWindow(in.Since, 24*time.Hour)
			if err != nil {
				return nil, doctor.LogResult{}, err
			}
			if in.Top == 0 {
				in.Top = 15
			}
			r, err := env.LogStats(ctx, w, in.Domain, in.Top)
			return nil, r, err
		})

	mcp.AddTool(s, &mcp.Tool{Name: "postfix_log_trend", Annotations: readOnly,
		Description: "Per-destination deferral rate over time buckets from the mail log: sent/deferred counts and rate per bucket, plus a direction (improving / worsening / flat / insufficient_data) comparing the early vs late half of the window. Use to see whether Gmail/Outlook/etc. is getting better or worse."},
		func(ctx context.Context, _ *mcp.CallToolRequest, in LogTrendIn) (*mcp.CallToolResult, doctor.TrendResult, error) {
			w, err := parseWindow(in.Since, 24*time.Hour)
			if err != nil {
				return nil, doctor.TrendResult{}, err
			}
			var bs time.Duration
			if in.Bucket != "" {
				bs, err = parseWindow(in.Bucket, 0)
				if err != nil {
					return nil, doctor.TrendResult{}, fmt.Errorf("bad bucket %q", in.Bucket)
				}
			}
			if in.Top == 0 {
				in.Top = 15
			}
			r, err := env.LogTrend(ctx, w, bs, in.Domain, in.Top)
			return nil, r, err
		})

	mcp.AddTool(s, &mcp.Tool{Name: "postfix_log_trace", Annotations: readOnly,
		Description: "Follow one message through the log by queue ID or email address: every line for each matching queue ID (smtpd, cleanup, qmgr, smtp/local, bounce notifications) and its final status."},
		func(ctx context.Context, _ *mcp.CallToolRequest, in TraceIn) (*mcp.CallToolResult, TraceOut, error) {
			if strings.TrimSpace(in.Query) == "" {
				return nil, TraceOut{}, fmt.Errorf("query is required")
			}
			w, err := parseWindow(in.Since, 7*24*time.Hour)
			if err != nil {
				return nil, TraceOut{}, err
			}
			if in.Limit == 0 {
				in.Limit = 20
			}
			msgs, src, err := env.Trace(ctx, in.Query, w, in.Limit)
			return nil, TraceOut{Source: src, Messages: msgs}, err
		})

	mcp.AddTool(s, &mcp.Tool{Name: "mail_dns_check", Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, OpenWorldHint: ptr(true)},
		Description: "Check the DNS records receivers use to accept or reject your mail: MX, SPF (syntax, 10-lookup limit, whether the sending IP is authorised), DKIM selector keys (presence, key size), DMARC policy and reporting, PTR with forward confirmation (FCrDNS) against myhostname."},
		func(ctx context.Context, _ *mcp.CallToolRequest, in DNSIn) (*mcp.CallToolResult, dnsauth.Report, error) {
			r, err := env.DNS(ctx, doctor.DNSOptions{Domain: in.Domain, IPs: in.IPs, Selectors: in.Selectors, SelectorsFromLog: true})
			return nil, r, err
		})

	mcp.AddTool(s, &mcp.Tool{Name: "postfix_config", Annotations: readOnly,
		Description: "Delivery-relevant non-default Postfix settings from postconf -n (relayhost, TLS policy, SASL, concurrency/rate limits, queue lifetimes, domains, milters). Secret-looking values are redacted."},
		func(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, ConfigOut, error) {
			cfg, err := env.Config(ctx)
			if err != nil {
				return nil, ConfigOut{}, err
			}
			return nil, ConfigOut{Settings: doctor.ConfigView(cfg), Note: "subset of postconf -n; unset parameters use Postfix defaults"}, nil
		})

	mcp.AddTool(s, &mcp.Tool{Name: "postfix_provider_playbook", Annotations: readOnly,
		Description: "Recovery playbooks for the big mailbox providers: Gmail / Google Workspace (421 4.7.28 rate limit, 5.7.26-5.7.32 SPF/DKIM/DMARC, PTR, TLS, reputation), Microsoft Outlook.com / Microsoft 365 (S3150 block list with SNDS/JMRP, 5.7.606-649 banned IP, 5.7.511, 4.7.650, SC/DY/OU/RP codes, 5.7.515, 5.7.705-750) and Yahoo / AOL ([TSS04]/[TS*] deferrals, [TSS09], [BL21]/[BL23], 5.7.9). " +
			"Each playbook says what the code means, whether Postfix will retry or retrying is pointless, ordered steps (Postfix-specific, e.g. a dedicated transport with destination_concurrency_limit = 1 for Gmail 4.7.28; never flush the queue at a throttling receiver), and the provider's official pages. " +
			"Modes: with no arguments, scans the queue and the mail log (since, default 24h) and returns the playbooks for what is failing here with evidence counts and affected domains; with reply, looks up one pasted SMTP reply without reading the server; with id, returns one playbook. Read-only: it never contacts the providers or changes the queue."},
		func(ctx context.Context, _ *mcp.CallToolRequest, in PlaybookIn) (*mcp.CallToolResult, PlaybookOut, error) {
			switch {
			case strings.TrimSpace(in.ID) != "":
				p, ok := provider.Get(strings.ToLower(strings.TrimSpace(in.ID)))
				if !ok {
					ids := []string{}
					for _, a := range available() {
						ids = append(ids, a.ID)
					}
					return nil, PlaybookOut{}, fmt.Errorf("unknown playbook id %q; valid ids: %s", in.ID, strings.Join(ids, ", "))
				}
				return nil, PlaybookOut{Mode: "id", Playbook: &p}, nil
			case strings.TrimSpace(in.Reply) != "":
				r := doctor.LookupReply(in.Reply, in.Domain)
				out := PlaybookOut{Mode: "reply", Lookup: &r}
				if r.Playbook == nil {
					out.Available = available()
				}
				return nil, out, nil
			}
			only := strings.ToLower(strings.TrimSpace(in.Provider))
			if only != "" && provider.Name(only) == "" {
				return nil, PlaybookOut{}, fmt.Errorf("unknown provider %q; use gmail, microsoft or yahoo", in.Provider)
			}
			w, err := parseWindow(in.Since, 24*time.Hour)
			if err != nil {
				return nil, PlaybookOut{}, err
			}
			r, err := env.ProviderPlaybooks(ctx, w, only)
			if err != nil {
				return nil, PlaybookOut{}, err
			}
			out := PlaybookOut{Mode: "server", Server: &r}
			if len(r.Playbooks) == 0 {
				out.Available = available()
			}
			return nil, out, nil
		})

	mcp.AddTool(s, &mcp.Tool{Name: "postfix_reason_categories", Annotations: readOnly,
		Description: "List the failure categories postsleuth assigns to delay/bounce reasons, with the hint for each."},
		func(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, CategoriesOut, error) {
			return nil, CategoriesOut{reason.Categories()}, nil
		})

	if o.AllowMutations {
		addMutations(s, env)
	}
	return s
}

func addMutations(s *mcp.Server, env *doctor.Env) {
	destructive := &mcp.ToolAnnotations{ReadOnlyHint: false, DestructiveHint: ptr(true), OpenWorldHint: ptr(false)}
	changing := &mcp.ToolAnnotations{ReadOnlyHint: false, DestructiveHint: ptr(false), OpenWorldHint: ptr(false)}
	need := func(c bool) error {
		if !c {
			return fmt.Errorf("refused: set confirm=true only after the operator explicitly asked for this change")
		}
		return nil
	}
	mcp.AddTool(s, &mcp.Tool{Name: "postfix_queue_flush", Annotations: changing,
		Description: "CHANGES THE QUEUE. Retry delivery now for given queue IDs (postqueue -i), one destination (postqueue -s), or everything (postqueue -f). Requires confirm=true."},
		func(ctx context.Context, _ *mcp.CallToolRequest, in FlushIn) (*mcp.CallToolResult, ActionOut, error) {
			if err := need(in.Confirm); err != nil {
				return nil, ActionOut{}, err
			}
			ran, err := env.Runner.Flush(ctx, in.QueueIDs, in.Site, in.All)
			return nil, ActionOut{ran}, err
		})
	for _, t := range []struct {
		name, op, desc string
		ann            *mcp.ToolAnnotations
	}{
		{"postfix_queue_requeue", "r", "CHANGES THE QUEUE. Requeue messages (postsuper -r) so they are re-processed with current settings (e.g. after fixing transport or relayhost). Requires confirm=true.", changing},
		{"postfix_queue_hold", "h", "CHANGES THE QUEUE. Put messages on hold (postsuper -h): they stay queued but are not delivered. Requires confirm=true.", changing},
		{"postfix_queue_release", "H", "CHANGES THE QUEUE. Release held messages (postsuper -H). Requires confirm=true.", changing},
		{"postfix_queue_delete", "d", "DELETES MAIL PERMANENTLY. Delete messages by queue ID (postsuper -d). No bulk ALL. Requires confirm=true.", destructive},
	} {
		op := t.op
		mcp.AddTool(s, &mcp.Tool{Name: t.name, Annotations: t.ann, Description: t.desc},
			func(ctx context.Context, _ *mcp.CallToolRequest, in IDsIn) (*mcp.CallToolResult, ActionOut, error) {
				if err := need(in.Confirm); err != nil {
					return nil, ActionOut{}, err
				}
				ran, err := env.Runner.Super(ctx, op, in.QueueIDs)
				return nil, ActionOut{ran}, err
			})
	}
}
