// Command postsleuth diagnoses Postfix mail delivery: queue, qshape, mail log,
// SPF/DKIM/DMARC/PTR. It is also an MCP server (postsleuth mcp).
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime/debug"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Blackman99/postsleuth/internal/dnsauth"
	"github.com/Blackman99/postsleuth/internal/doctor"
	"github.com/Blackman99/postsleuth/internal/mcpserver"
	"github.com/Blackman99/postsleuth/internal/postfix"
	"github.com/Blackman99/postsleuth/internal/provider"
	"github.com/Blackman99/postsleuth/internal/queue"
)

var version = "dev"

func init() {
	if version != "dev" {
		return
	}
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		version = strings.TrimPrefix(bi.Main.Version, "v")
	}
}

const usage = `postsleuth: find out why Postfix is not delivering mail (read-only by default)

Usage:
  postsleuth doctor              queue + qshape + log + DNS in one report (exit 1 if problems)
  postsleuth queue               summarise the queue; --list to print messages
  postsleuth shape [QUEUE]       qshape-style age x domain matrix (default: deferred)
  postsleuth log                 outcomes, deferral reasons, bounce causes from the mail log
  postsleuth trend               per-destination deferral rate over time (is it getting better?)
  postsleuth playbook [ID]       Gmail / Microsoft / Yahoo recovery steps for what is failing here
                                 (gmail|microsoft|yahoo to filter, --reply "TEXT" for one reply, --list)
  postsleuth message ID          one queued message: who is still waiting and why, route, DKIM,
                                 headers (postcat -e -h; body never read; personal data redacted)
  postsleuth trace ID|ADDRESS    every log line for a message
  postsleuth dns [DOMAIN]        MX, SPF, DKIM, DMARC, PTR/FCrDNS checks
  postsleuth config              delivery-relevant postconf -n settings
  postsleuth mcp                 run as an MCP server on stdio
  postsleuth version

Changing the queue (off unless --allow-mutations is given):
  postsleuth flush   --allow-mutations [--site DOMAIN | --all | ID...]
  postsleuth requeue --allow-mutations ID...
  postsleuth hold    --allow-mutations ID...
  postsleuth release --allow-mutations ID...
  postsleuth delete  --allow-mutations ID...

Common flags:
  --wrap CMD        run postqueue/postconf/postsuper through CMD, e.g. "docker exec -i mailserver" or "ssh mx sudo"
  --log FILE        mail log to read (repeatable, .gz ok, - for stdin); default: maillog_file, /var/log/mail.log, /var/log/maillog, journald
  --log-cmd CMD     command whose output is the log, e.g. "journalctl -u postfix@- -o short-iso"
  --queue-file FILE read saved "postqueue -j" output instead of running postqueue
  --message-file F  (message) read saved "postcat -e -h -q ID" output instead of running postcat
  --unredacted      (message) show addresses and subject as stored; credentials stay hidden
  --since DUR       log window: 1h, 24h, 7d, all
  --resolver IP     DNS server for checks (default: system resolver)
  --json            machine-readable output
  --no-color        plain output (also NO_COLOR=1)

Docs: https://blackman99.github.io/postsleuth/docs/
`

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error { *m = append(*m, splitList(v)...); return nil }

func splitList(v string) []string {
	var out []string
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

type common struct {
	wrap, logCmd, queueFile, resolver, since string
	logs                                     multi
	jsonOut, noColor, allowMut               bool
}

func (c *common) register(fs *flag.FlagSet, defSince string) {
	fs.StringVar(&c.wrap, "wrap", os.Getenv("POSTSLEUTH_WRAP"), "command prefix for Postfix tools")
	fs.Var(&c.logs, "log", "mail log file (repeatable)")
	fs.StringVar(&c.logCmd, "log-cmd", "", "command that prints the mail log")
	fs.StringVar(&c.queueFile, "queue-file", "", "saved postqueue -j output")
	fs.StringVar(&c.resolver, "resolver", "", "DNS server")
	fs.StringVar(&c.since, "since", defSince, "log window (1h, 24h, 7d, all)")
	fs.BoolVar(&c.jsonOut, "json", false, "JSON output")
	fs.BoolVar(&c.noColor, "no-color", os.Getenv("NO_COLOR") != "", "no colours")
	fs.BoolVar(&c.allowMut, "allow-mutations", false, "allow commands that change the queue")
}

func (c *common) env() *doctor.Env {
	return &doctor.Env{
		Runner:    postfix.Runner{Wrap: strings.Fields(c.wrap)},
		Logs:      postfix.LogSource{Files: c.logs, Cmd: c.logCmd},
		QueueFile: c.queueFile,
		Resolver:  dnsauth.NewResolver(c.resolver),
	}
}

func (c *common) style() doctor.Style {
	if c.noColor {
		return doctor.Style{}
	}
	fi, err := os.Stdout.Stat()
	return doctor.Style{Color: err == nil && fi.Mode()&os.ModeCharDevice != 0}
}

func parseWindow(s string) (time.Duration, error) {
	switch s {
	case "", "all":
		return 0, nil
	}
	if strings.HasSuffix(s, "d") {
		var n int
		if _, err := fmt.Sscanf(s, "%dd", &n); err == nil && n > 0 {
			return time.Duration(n) * 24 * time.Hour, nil
		}
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("bad --since %q (use 1h, 24h, 7d, all)", s)
	}
	return d, nil
}

// parseAll parses flags that may appear before or after positional arguments.
func parseAll(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		rest := fs.Args()
		if len(rest) == 0 {
			return pos, nil
		}
		pos = append(pos, rest[0])
		args = rest[1:]
	}
}

func printJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		fmt.Fprint(stdout, usage)
		return 0
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	cmd, args := args[0], args[1:]
	fs := flag.NewFlagSet("postsleuth "+cmd, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, usage) }
	var c common
	defSince := "24h"
	if cmd == "trace" {
		defSince = "7d"
	}
	c.register(fs, defSince)
	err := func() error {
		switch cmd {
		case "version", "--version":
			fmt.Fprintln(stdout, "postsleuth", version)
			return nil
		case "doctor":
			return cmdDoctor(ctx, fs, &c, args, stdout)
		case "queue":
			return cmdQueue(ctx, fs, &c, args, stdout)
		case "shape":
			return cmdShape(ctx, fs, &c, args, stdout)
		case "log":
			return cmdLog(ctx, fs, &c, args, stdout)
		case "trend":
			return cmdTrend(ctx, fs, &c, args, stdout)
		case "message", "msg":
			return cmdMessage(ctx, fs, &c, args, stdout)
		case "playbook", "playbooks":
			return cmdPlaybook(ctx, fs, &c, args, stdout)
		case "trace":
			return cmdTrace(ctx, fs, &c, args, stdout)
		case "dns":
			return cmdDNS(ctx, fs, &c, args, stdout)
		case "config":
			return cmdConfig(ctx, fs, &c, args, stdout)
		case "mcp":
			return cmdMCP(ctx, fs, &c, args)
		case "flush", "requeue", "hold", "release", "delete":
			return cmdMutate(ctx, fs, &c, cmd, args, stdout)
		default:
			return fmt.Errorf("unknown command %q (see postsleuth --help)", cmd)
		}
	}()
	var ec exitCode
	switch {
	case err == nil:
		return 0
	case errors.As(err, &ec):
		return int(ec)
	case errors.Is(err, flag.ErrHelp):
		return 0
	default:
		fmt.Fprintln(stderr, "postsleuth:", err)
		return 2
	}
}

type exitCode int

func (e exitCode) Error() string { return fmt.Sprintf("exit %d", int(e)) }

func cmdDoctor(ctx context.Context, fs *flag.FlagSet, c *common, args []string, w io.Writer) error {
	var ips, sels multi
	var domain string
	var noDNS, noLog bool
	fs.StringVar(&domain, "domain", "", "sending domain for DNS checks (default: myorigin)")
	fs.Var(&ips, "ip", "sending IP (repeatable)")
	fs.Var(&sels, "selector", "DKIM selector (repeatable)")
	fs.BoolVar(&noDNS, "no-dns", false, "skip DNS checks")
	fs.BoolVar(&noLog, "no-log", false, "skip the mail log")
	if _, err := parseAll(fs, args); err != nil {
		return err
	}
	win, err := parseWindow(c.since)
	if err != nil {
		return err
	}
	r := c.env().Run(ctx, doctor.Options{Window: win, Domain: domain, IPs: ips, Selectors: sels, SkipDNS: noDNS, SkipLog: noLog})
	if c.jsonOut {
		if err := printJSON(w, r); err != nil {
			return err
		}
	} else {
		doctor.WriteReport(w, c.style(), r)
	}
	if ec := r.ExitCode(); ec != 0 {
		return exitCode(ec)
	}
	return nil
}

func cmdQueue(ctx context.Context, fs *flag.FlagSet, c *common, args []string, w io.Writer) error {
	var f queue.Filter
	var list bool
	var limit, top int
	var minAge string
	fs.StringVar(&f.Queue, "queue", "", "only this queue (active, deferred, hold, ...)")
	fs.StringVar(&f.Domain, "domain", "", "recipient domain (leading dot = subdomains)")
	fs.StringVar(&f.Sender, "sender", "", "sender substring")
	fs.StringVar(&f.ReasonContains, "reason", "", "delay reason substring")
	fs.StringVar(&f.Category, "category", "", "reason category (rate_limit, auth, timeout, ...)")
	fs.StringVar(&minAge, "min-age", "", "older than (e.g. 2h)")
	fs.BoolVar(&list, "list", false, "list messages instead of a summary")
	fs.IntVar(&limit, "limit", 50, "max messages with --list")
	fs.IntVar(&top, "top", 10, "max entries per summary list")
	if _, err := parseAll(fs, args); err != nil {
		return err
	}
	if minAge != "" {
		d, err := parseWindow(minAge)
		if err != nil {
			return err
		}
		f.MinAge = d
	}
	msgs, err := c.env().Queue(ctx)
	if err != nil {
		return err
	}
	now := time.Now()
	msgs = f.Apply(msgs, now)
	if list {
		if len(msgs) > limit {
			msgs = msgs[:limit]
		}
		if c.jsonOut {
			return printJSON(w, msgs)
		}
		s := c.style()
		for _, m := range msgs {
			fmt.Fprintf(w, "%s %-8s %s %7d  %s\n", s.Bold(m.QueueID), m.QueueName, queue.HumanAge(now.Sub(m.Arrival())), m.MessageSize, m.Sender)
			for _, r := range m.Recipients {
				fmt.Fprintf(w, "    → %s\n", r.Address)
				if r.DelayReason != "" {
					fmt.Fprintf(w, "      %s\n", s.Dim(r.DelayReason))
				}
			}
		}
		if len(msgs) == 0 {
			fmt.Fprintln(w, "no matching messages")
		}
		return nil
	}
	sum := queue.Summarize(msgs, now, top)
	if c.jsonOut {
		return printJSON(w, sum)
	}
	doctor.WriteQueue(w, c.style(), sum)
	return nil
}

func cmdShape(ctx context.Context, fs *flag.FlagSet, c *common, args []string, w io.Writer) error {
	var by string
	var top int
	fs.StringVar(&by, "by", "recipient", "recipient or sender")
	fs.IntVar(&top, "top", 20, "max domains")
	pos, err := parseAll(fs, args)
	if err != nil {
		return err
	}
	q := "deferred"
	if len(pos) > 0 {
		q = pos[0]
	}
	msgs, err := c.env().Queue(ctx)
	if err != nil {
		return err
	}
	sh := queue.BuildShape(msgs, time.Now(), q, by, top)
	if c.jsonOut {
		return printJSON(w, sh)
	}
	doctor.WriteShape(w, c.style(), sh)
	return nil
}

func cmdLog(ctx context.Context, fs *flag.FlagSet, c *common, args []string, w io.Writer) error {
	var domain string
	var top int
	fs.StringVar(&domain, "domain", "", "only this recipient domain")
	fs.IntVar(&top, "top", 15, "max entries per list")
	if _, err := parseAll(fs, args); err != nil {
		return err
	}
	win, err := parseWindow(c.since)
	if err != nil {
		return err
	}
	r, err := c.env().LogStats(ctx, win, domain, top)
	if err != nil {
		return err
	}
	if c.jsonOut {
		return printJSON(w, r)
	}
	s := c.style()
	doctor.WriteLog(w, s, r)
	if len(r.Stats.Domains) > 0 {
		fmt.Fprintf(w, "\n  %-32s %6s %9s %8s  %s\n", "domain", "sent", "deferred", "bounced", "last")
		for _, d := range r.Stats.Domains {
			fmt.Fprintf(w, "  %-32s %6d %9d %8d  %s\n", d.Domain, d.Sent, d.Deferred, d.Bounced, d.LastStatus)
		}
	}
	return nil
}

func cmdTrend(ctx context.Context, fs *flag.FlagSet, c *common, args []string, w io.Writer) error {
	var domain, bucket string
	var top int
	fs.StringVar(&domain, "domain", "", "only this recipient domain")
	fs.StringVar(&bucket, "bucket", "", "bucket size (15m, 1h, 4h, 12h, 1d); default auto from --since")
	fs.IntVar(&top, "top", 15, "max destinations")
	if _, err := parseAll(fs, args); err != nil {
		return err
	}
	win, err := parseWindow(c.since)
	if err != nil {
		return err
	}
	var bs time.Duration
	if bucket != "" {
		bs, err = parseWindow(bucket)
		if err != nil {
			return fmt.Errorf("bad --bucket %q (use 15m, 1h, 4h, 12h, 1d)", bucket)
		}
	}
	r, err := c.env().LogTrend(ctx, win, bs, domain, top)
	if err != nil {
		return err
	}
	if c.jsonOut {
		return printJSON(w, r)
	}
	doctor.WriteTrend(w, c.style(), r)
	return nil
}

func cmdPlaybook(ctx context.Context, fs *flag.FlagSet, c *common, args []string, w io.Writer) error {
	var reply, domain string
	var list bool
	fs.StringVar(&reply, "reply", "", "look up one SMTP reply or delay reason instead of reading the queue and log")
	fs.StringVar(&domain, "domain", "", "recipient domain of --reply, when the reply names no host")
	fs.BoolVar(&list, "list", false, "list every built-in playbook")
	pos, err := parseAll(fs, args)
	if err != nil {
		return err
	}
	if len(pos) > 1 {
		return fmt.Errorf("usage: postsleuth playbook [ID|gmail|microsoft|yahoo] [--reply TEXT] [--list]")
	}
	st := c.style()
	switch {
	case list:
		if c.jsonOut {
			return printJSON(w, map[string]any{"providers": provider.Providers, "playbooks": provider.All()})
		}
		doctor.WritePlaybookIndex(w, st)
		return nil
	case strings.TrimSpace(reply) != "":
		r := doctor.LookupReply(reply, domain)
		if c.jsonOut {
			return printJSON(w, r)
		}
		doctor.WriteReplyLookup(w, st, r)
		return nil
	}
	only := ""
	if len(pos) == 1 {
		arg := strings.ToLower(pos[0])
		if p, ok := provider.Get(arg); ok {
			if c.jsonOut {
				return printJSON(w, p)
			}
			doctor.WritePlaybook(w, st, p)
			return nil
		}
		if provider.Name(arg) == "" {
			return fmt.Errorf("unknown playbook or provider %q (see postsleuth playbook --list)", pos[0])
		}
		only = arg
	}
	win, err := parseWindow(c.since)
	if err != nil {
		return err
	}
	r, err := c.env().ProviderPlaybooks(ctx, win, only)
	if err != nil {
		return err
	}
	if c.jsonOut {
		return printJSON(w, r)
	}
	doctor.WritePlaybooks(w, st, r)
	return nil
}

func cmdTrace(ctx context.Context, fs *flag.FlagSet, c *common, args []string, w io.Writer) error {
	var limit int
	fs.IntVar(&limit, "limit", 20, "max messages")
	pos, err := parseAll(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return fmt.Errorf("usage: postsleuth trace QUEUE_ID|ADDRESS")
	}
	win, err := parseWindow(c.since)
	if err != nil {
		return err
	}
	msgs, src, err := c.env().Trace(ctx, pos[0], win, limit)
	if err != nil {
		return err
	}
	if c.jsonOut {
		return printJSON(w, map[string]any{"source": src, "messages": msgs})
	}
	s := c.style()
	if len(msgs) == 0 {
		fmt.Fprintf(w, "no log lines for %s in %s (window %s)\n", pos[0], src, c.since)
		return nil
	}
	for _, m := range msgs {
		extra := ""
		if m.BounceOf != "" {
			extra = " (bounce notice for " + m.BounceOf + ")"
		}
		fmt.Fprintf(w, "%s  %s%s\n", s.Bold(m.QueueID), m.FinalStatus, extra)
		for _, l := range m.Events {
			fmt.Fprintf(w, "  %s\n", s.Dim(l))
		}
	}
	return nil
}

func cmdMessage(ctx context.Context, fs *flag.FlagSet, c *common, args []string, w io.Writer) error {
	var file string
	var unredacted bool
	fs.StringVar(&file, "message-file", "", "saved postcat -e -h -q ID output")
	fs.BoolVar(&unredacted, "unredacted", false, "show addresses and subject as stored")
	pos, err := parseAll(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return fmt.Errorf("usage: postsleuth message QUEUE_ID  (find IDs with: postsleuth queue --list)")
	}
	env := c.env()
	env.MessageFile = file
	r, err := env.Message(ctx, pos[0], !unredacted)
	if err != nil {
		return err
	}
	if c.jsonOut {
		return printJSON(w, r)
	}
	doctor.WriteMessage(w, c.style(), r)
	return nil
}

func cmdDNS(ctx context.Context, fs *flag.FlagSet, c *common, args []string, w io.Writer) error {
	var ips, sels multi
	var helo string
	fs.Var(&ips, "ip", "sending IP (repeatable)")
	fs.Var(&sels, "selector", "DKIM selector (repeatable)")
	fs.StringVar(&helo, "helo", "", "HELO name to compare with PTR (default: myhostname)")
	pos, err := parseAll(fs, args)
	if err != nil {
		return err
	}
	o := doctor.DNSOptions{IPs: ips, Selectors: sels, HELO: helo, SelectorsFromLog: true}
	if len(pos) > 0 {
		o.Domain = pos[0]
	}
	r, err := c.env().DNS(ctx, o)
	if err != nil {
		return err
	}
	if c.jsonOut {
		if err := printJSON(w, r); err != nil {
			return err
		}
	} else {
		doctor.WriteDNS(w, c.style(), r)
	}
	if r.Worst() == dnsauth.Fail {
		return exitCode(1)
	}
	return nil
}

func cmdConfig(ctx context.Context, fs *flag.FlagSet, c *common, args []string, w io.Writer) error {
	if _, err := parseAll(fs, args); err != nil {
		return err
	}
	cfg, err := c.env().Config(ctx)
	if err != nil {
		return err
	}
	v := doctor.ConfigView(cfg)
	if c.jsonOut {
		return printJSON(w, v)
	}
	for _, k := range sortedKeys(v) {
		fmt.Fprintf(w, "%s = %s\n", k, v[k])
	}
	return nil
}

func sortedKeys(m map[string]string) []string {
	k := make([]string, 0, len(m))
	for x := range m {
		k = append(k, x)
	}
	for i := 1; i < len(k); i++ {
		for j := i; j > 0 && k[j] < k[j-1]; j-- {
			k[j], k[j-1] = k[j-1], k[j]
		}
	}
	return k
}

func cmdMCP(ctx context.Context, fs *flag.FlagSet, c *common, args []string) error {
	if _, err := parseAll(fs, args); err != nil {
		return err
	}
	srv := mcpserver.New(c.env(), mcpserver.Options{Version: version, AllowMutations: c.allowMut})
	return srv.Run(ctx, &mcp.StdioTransport{})
}

func cmdMutate(ctx context.Context, fs *flag.FlagSet, c *common, cmd string, args []string, w io.Writer) error {
	var site string
	var all bool
	if cmd == "flush" {
		fs.StringVar(&site, "site", "", "retry everything for this destination (postqueue -s)")
		fs.BoolVar(&all, "all", false, "retry the whole queue (postqueue -f)")
	}
	ids, err := parseAll(fs, args)
	if err != nil {
		return err
	}
	if !c.allowMut {
		return fmt.Errorf("%s changes the mail queue; re-run with --allow-mutations if you mean it", cmd)
	}
	r := postfix.Runner{Wrap: strings.Fields(c.wrap)}
	var ran []string
	switch cmd {
	case "flush":
		ran, err = r.Flush(ctx, ids, site, all)
	case "requeue":
		ran, err = r.Super(ctx, "r", ids)
	case "hold":
		ran, err = r.Super(ctx, "h", ids)
	case "release":
		ran, err = r.Super(ctx, "H", ids)
	case "delete":
		ran, err = r.Super(ctx, "d", ids)
	}
	for _, x := range ran {
		fmt.Fprintln(w, "ran:", x)
	}
	return err
}
