// Package dnsauth checks the DNS records that decide whether other mail
// servers accept your mail: MX, SPF, DKIM, DMARC and PTR/FCrDNS.
package dnsauth

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"
)

// Resolver is the subset of *net.Resolver used here (mockable in tests).
type Resolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
	LookupMX(ctx context.Context, name string) ([]*net.MX, error)
	LookupAddr(ctx context.Context, addr string) ([]string, error)
	LookupIP(ctx context.Context, network, host string) ([]net.IP, error)
}

// NewResolver returns the system resolver, or one that queries server
// ("1.1.1.1" or "1.1.1.1:53") directly.
func NewResolver(server string) Resolver {
	if server == "" {
		return net.DefaultResolver
	}
	if _, _, err := net.SplitHostPort(server); err != nil {
		server = net.JoinHostPort(server, "53")
	}
	return &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		d := net.Dialer{Timeout: 5 * time.Second}
		return d.DialContext(ctx, network, server)
	}}
}

// Status of one check.
const (
	OK   = "ok"
	Warn = "warn"
	Fail = "fail"
	Info = "info"
)

// Check is one finding.
type Check struct {
	Name    string `json:"check"`
	Status  string `json:"status"`
	Record  string `json:"record,omitempty"`
	Message string `json:"message"`
}

// Report is the result for one domain.
type Report struct {
	Domain string   `json:"domain"`
	IPs    []string `json:"sending_ips,omitempty"`
	Checks []Check  `json:"checks"`
}

// Worst returns the most severe status in the report.
func (r Report) Worst() string {
	w := OK
	for _, c := range r.Checks {
		if c.Status == Fail {
			return Fail
		}
		if c.Status == Warn {
			w = Warn
		}
	}
	return w
}

// Options for Run.
type Options struct {
	Domain    string
	IPs       []string // sending IPs to check SPF authorisation and PTR for
	HELO      string   // myhostname, compared against PTR
	Selectors []string // DKIM selectors; if empty, CommonSelectors are probed
}

// CommonSelectors are probed when no selector is known.
var CommonSelectors = []string{"default", "mail", "dkim", "s1", "s2", "selector1", "selector2", "google", "k1", "smtp", "postfix", "key1", "sig1"}

func notFound(err error) bool {
	var de *net.DNSError
	return errors.As(err, &de) && de.IsNotFound
}

// Run performs all checks.
func Run(ctx context.Context, res Resolver, o Options) Report {
	d := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(o.Domain)), ".")
	r := Report{Domain: d, IPs: o.IPs}
	r.Checks = append(r.Checks, checkMX(ctx, res, d))
	r.Checks = append(r.Checks, checkSPF(ctx, res, d, o.IPs)...)
	r.Checks = append(r.Checks, checkDKIM(ctx, res, d, o.Selectors)...)
	r.Checks = append(r.Checks, checkDMARC(ctx, res, d))
	for _, ip := range o.IPs {
		r.Checks = append(r.Checks, checkPTR(ctx, res, ip, o.HELO))
	}
	if len(o.IPs) == 0 {
		r.Checks = append(r.Checks, Check{Name: "ptr", Status: Info, Message: "no sending IP given (--ip): PTR/FCrDNS and SPF authorisation not checked"})
	}
	return r
}

func checkMX(ctx context.Context, res Resolver, d string) Check {
	mx, err := res.LookupMX(ctx, d)
	if err != nil {
		if notFound(err) {
			return Check{Name: "mx", Status: Warn, Message: "no MX record: bounces and replies to this domain fall back to its A record"}
		}
		return Check{Name: "mx", Status: Warn, Message: "MX lookup failed: " + err.Error()}
	}
	if len(mx) == 1 && (mx[0].Host == "." || mx[0].Host == "") {
		return Check{Name: "mx", Status: Warn, Record: "0 .", Message: "null MX: this domain says it accepts no mail (bounces to it will fail)"}
	}
	var hosts []string
	for _, m := range mx {
		hosts = append(hosts, fmt.Sprintf("%d %s", m.Pref, strings.TrimSuffix(m.Host, ".")))
	}
	return Check{Name: "mx", Status: OK, Record: strings.Join(hosts, ", "), Message: fmt.Sprintf("%d MX host(s)", len(mx))}
}

func spfRecords(ctx context.Context, res Resolver, d string) ([]string, error) {
	txt, err := res.LookupTXT(ctx, d)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, t := range txt {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(t)), "v=spf1") && (len(t) == 6 || t[6] == ' ') {
			out = append(out, strings.TrimSpace(t))
		}
	}
	return out, nil
}

func checkSPF(ctx context.Context, res Resolver, d string, ips []string) []Check {
	recs, err := spfRecords(ctx, res, d)
	if err != nil && !notFound(err) {
		return []Check{{Name: "spf", Status: Warn, Message: "TXT lookup failed: " + err.Error()}}
	}
	if len(recs) == 0 {
		return []Check{{Name: "spf", Status: Fail, Message: "no SPF record: Gmail, Yahoo and Microsoft reject or spam-folder unauthenticated mail"}}
	}
	if len(recs) > 1 {
		return []Check{{Name: "spf", Status: Fail, Record: strings.Join(recs, " | "), Message: "multiple SPF records: receivers treat this as a permanent error (permerror); merge them into one"}}
	}
	rec := recs[0]
	e := &spfEval{ctx: ctx, res: res}
	lookups, err := e.countLookups(d, rec, 0)
	var out []Check
	c := Check{Name: "spf", Status: OK, Record: rec}
	lower := strings.ToLower(rec)
	switch {
	case err != nil:
		c.Status, c.Message = Fail, err.Error()
	case lookups > 10:
		c.Status, c.Message = Fail, fmt.Sprintf("%d DNS lookups: SPF allows at most 10, receivers return permerror", lookups)
	case strings.Contains(lower, "+all") || strings.HasSuffix(lower, " all"):
		c.Status, c.Message = Fail, "+all authorises the whole internet to send as this domain"
	case strings.Contains(lower, "?all"):
		c.Status, c.Message = Warn, fmt.Sprintf("?all (neutral) gives no protection; use ~all or -all (%d DNS lookups)", lookups)
	case !strings.Contains(lower, "all") && !strings.Contains(lower, "redirect="):
		c.Status, c.Message = Warn, fmt.Sprintf("no 'all' mechanism: result for other senders is neutral (%d DNS lookups)", lookups)
	default:
		c.Message = fmt.Sprintf("one record, %d of 10 DNS lookups", lookups)
	}
	out = append(out, c)
	for _, ipS := range ips {
		ip := net.ParseIP(ipS)
		if ip == nil {
			out = append(out, Check{Name: "spf-ip", Status: Warn, Message: "not an IP: " + ipS})
			continue
		}
		e := &spfEval{ctx: ctx, res: res}
		result, why := e.check(ip, d, 0)
		cc := Check{Name: "spf-ip", Record: ipS}
		switch result {
		case "pass":
			cc.Status, cc.Message = OK, fmt.Sprintf("%s is authorised (%s)", ipS, why)
		case "fail", "softfail":
			cc.Status, cc.Message = Fail, fmt.Sprintf("%s is NOT authorised: SPF %s (%s). Add it (ip4:/ip6:) or send through an authorised relay", ipS, result, why)
		default:
			cc.Status, cc.Message = Warn, fmt.Sprintf("SPF result for %s: %s (%s)", ipS, result, why)
		}
		out = append(out, cc)
	}
	return out
}

type spfEval struct {
	ctx     context.Context
	res     Resolver
	lookups int
}

func (e *spfEval) countLookups(d, rec string, depth int) (int, error) {
	if depth > 10 {
		return 0, fmt.Errorf("SPF include loop or too deep")
	}
	n := 0
	for _, term := range strings.Fields(rec)[1:] {
		t := strings.ToLower(strings.TrimLeft(term, "+-~?"))
		switch {
		case strings.HasPrefix(t, "include:"), strings.HasPrefix(t, "redirect="):
			n++
			target := term[strings.IndexAny(term, ":=")+1:]
			sub, err := spfRecords(e.ctx, e.res, target)
			if err != nil || len(sub) != 1 {
				return n, fmt.Errorf("%s: target has %d SPF records (permerror)", t, len(sub))
			}
			m, err := e.countLookups(target, sub[0], depth+1)
			n += m
			if err != nil {
				return n, err
			}
		case t == "a" || strings.HasPrefix(t, "a:") || strings.HasPrefix(t, "a/") ||
			t == "mx" || strings.HasPrefix(t, "mx:") || strings.HasPrefix(t, "mx/") ||
			t == "ptr" || strings.HasPrefix(t, "ptr:") || strings.HasPrefix(t, "exists:"):
			n++
		}
	}
	return n, nil
}

func cidr(term string, def4, def6 int) (string, int, int) {
	host, c4, c6 := term, def4, def6
	if i := strings.Index(term, "//"); i >= 0 {
		fmt.Sscanf(term[i+2:], "%d", &c6)
		host = term[:i]
	}
	if i := strings.Index(host, "/"); i >= 0 {
		fmt.Sscanf(host[i+1:], "%d", &c4)
		host = host[:i]
	}
	return host, c4, c6
}

func inNet(ip net.IP, other net.IP, c4, c6 int) bool {
	if ip4 := ip.To4(); ip4 != nil {
		o4 := other.To4()
		if o4 == nil {
			return false
		}
		m := net.CIDRMask(c4, 32)
		return ip4.Mask(m).Equal(o4.Mask(m))
	}
	if other.To4() != nil {
		return false
	}
	m := net.CIDRMask(c6, 128)
	return ip.Mask(m).Equal(other.Mask(m))
}

// check is a simplified SPF evaluation (RFC 7208) without macros.
func (e *spfEval) check(ip net.IP, d string, depth int) (string, string) {
	if depth > 10 {
		return "permerror", "too deep"
	}
	recs, err := spfRecords(e.ctx, e.res, d)
	if err != nil && !notFound(err) {
		return "temperror", err.Error()
	}
	if len(recs) != 1 {
		return "permerror", fmt.Sprintf("%s has %d SPF records", d, len(recs))
	}
	var redirect string
	for _, term := range strings.Fields(recs[0])[1:] {
		q := "pass"
		switch term[0] {
		case '+':
			term = term[1:]
		case '-':
			q, term = "fail", term[1:]
		case '~':
			q, term = "softfail", term[1:]
		case '?':
			q, term = "neutral", term[1:]
		}
		lt := strings.ToLower(term)
		match := false
		switch {
		case lt == "all":
			match = true
		case strings.HasPrefix(lt, "ip4:") || strings.HasPrefix(lt, "ip6:"):
			v := term[4:]
			if !strings.Contains(v, "/") {
				if strings.HasPrefix(lt, "ip4:") {
					v += "/32"
				} else {
					v += "/128"
				}
			}
			if _, n, err := net.ParseCIDR(v); err == nil && n.Contains(ip) {
				match = true
			}
		case lt == "a" || strings.HasPrefix(lt, "a:") || strings.HasPrefix(lt, "a/"):
			host, c4, c6 := cidr(strings.TrimPrefix(strings.TrimPrefix(term, "a"), ":"), 32, 128)
			if host == "" {
				host = d
			}
			addrs, _ := e.res.LookupIP(e.ctx, "ip", host)
			for _, a := range addrs {
				if inNet(ip, a, c4, c6) {
					match = true
				}
			}
		case lt == "mx" || strings.HasPrefix(lt, "mx:") || strings.HasPrefix(lt, "mx/"):
			host, c4, c6 := cidr(strings.TrimPrefix(strings.TrimPrefix(term, "mx"), ":"), 32, 128)
			if host == "" {
				host = d
			}
			mxs, _ := e.res.LookupMX(e.ctx, host)
			for _, m := range mxs {
				addrs, _ := e.res.LookupIP(e.ctx, "ip", m.Host)
				for _, a := range addrs {
					if inNet(ip, a, c4, c6) {
						match = true
					}
				}
			}
		case strings.HasPrefix(lt, "include:"):
			r, _ := e.check(ip, term[8:], depth+1)
			if r == "pass" {
				match = true
				q = q + " via " + term
			} else if r == "permerror" || r == "temperror" {
				return r, "include " + term[8:]
			}
		case strings.HasPrefix(lt, "redirect="):
			redirect = term[9:]
		case strings.HasPrefix(lt, "ptr") || strings.HasPrefix(lt, "exists:"):
			// not evaluated; rarely decisive and discouraged by RFC 7208
		}
		if match {
			res, _, _ := strings.Cut(q, " ")
			return res, "matched " + term + " in " + d
		}
	}
	if redirect != "" {
		return e.check(ip, redirect, depth+1)
	}
	return "neutral", "no mechanism matched in " + d
}

func checkDKIM(ctx context.Context, res Resolver, d string, selectors []string) []Check {
	probing := len(selectors) == 0
	if probing {
		selectors = CommonSelectors
	}
	var out []Check
	for _, sel := range selectors {
		name := sel + "._domainkey." + d
		txt, err := res.LookupTXT(ctx, name)
		if err != nil || len(txt) == 0 {
			if !probing {
				msg := "no DKIM key published at " + name
				if err != nil && !notFound(err) {
					msg = "lookup failed for " + name + ": " + err.Error()
				}
				out = append(out, Check{Name: "dkim", Status: Fail, Record: name, Message: msg + ": receivers cannot verify signatures made with this selector"})
			}
			continue
		}
		rec := strings.Join(txt, "")
		out = append(out, dkimKey(name, rec))
	}
	if probing && len(out) == 0 {
		out = append(out, Check{Name: "dkim", Status: Warn, Message: "no DKIM key found under common selectors; pass --selector (or point --log at a log with opendkim lines so it is detected)"})
	}
	return out
}

func tags(rec string) map[string]string {
	m := map[string]string{}
	for _, p := range strings.Split(rec, ";") {
		k, v, ok := strings.Cut(p, "=")
		if ok {
			m[strings.ToLower(strings.TrimSpace(k))] = strings.Join(strings.Fields(v), "")
		}
	}
	return m
}

func dkimKey(name, rec string) Check {
	t := tags(rec)
	c := Check{Name: "dkim", Record: name}
	p, ok := t["p"]
	if !ok {
		c.Status, c.Message = Fail, "TXT record has no p= key"
		return c
	}
	if p == "" {
		c.Status, c.Message = Fail, "key revoked (empty p=)"
		return c
	}
	k := strings.ToLower(t["k"])
	if k == "" {
		k = "rsa"
	}
	if k == "ed25519" {
		c.Status, c.Message = OK, "ed25519 key published (also publish an RSA selector: not every receiver verifies ed25519)"
		return c
	}
	der, err := base64.StdEncoding.DecodeString(p)
	if err != nil {
		c.Status, c.Message = Fail, "p= is not valid base64"
		return c
	}
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		if rk, err2 := x509.ParsePKCS1PublicKey(der); err2 == nil {
			pub = rk
		} else {
			c.Status, c.Message = Fail, "cannot parse public key: "+err.Error()
			return c
		}
	}
	rk, ok := pub.(*rsa.PublicKey)
	if !ok {
		c.Status, c.Message = Warn, "non-RSA key"
		return c
	}
	bits := rk.N.BitLen()
	switch {
	case bits < 1024:
		c.Status, c.Message = Fail, fmt.Sprintf("RSA %d-bit key: too short, receivers ignore it; use 2048", bits)
	case bits < 2048:
		c.Status, c.Message = Warn, fmt.Sprintf("RSA %d-bit key: works, but 2048 is recommended", bits)
	default:
		c.Status, c.Message = OK, fmt.Sprintf("RSA %d-bit key published", bits)
	}
	if t["t"] == "y" {
		c.Status, c.Message = Warn, c.Message+"; t=y (testing mode) is set"
	}
	return c
}

func checkDMARC(ctx context.Context, res Resolver, d string) Check {
	name := "_dmarc." + d
	txt, err := res.LookupTXT(ctx, name)
	if err != nil && !notFound(err) {
		return Check{Name: "dmarc", Status: Warn, Record: name, Message: "lookup failed: " + err.Error()}
	}
	var recs []string
	for _, t := range txt {
		if strings.HasPrefix(strings.ToUpper(strings.TrimSpace(t)), "V=DMARC1") {
			recs = append(recs, t)
		}
	}
	if len(recs) == 0 {
		return Check{Name: "dmarc", Status: Fail, Record: name, Message: "no DMARC record: Gmail and Yahoo require one for bulk senders; start with v=DMARC1; p=none; rua=mailto:..."}
	}
	if len(recs) > 1 {
		return Check{Name: "dmarc", Status: Fail, Record: strings.Join(recs, " | "), Message: "multiple DMARC records: receivers ignore DMARC entirely"}
	}
	t := tags(recs[0])
	c := Check{Name: "dmarc", Status: OK, Record: recs[0]}
	p := strings.ToLower(t["p"])
	var notes []string
	switch p {
	case "reject", "quarantine":
		notes = append(notes, "policy p="+p)
	case "none":
		notes = append(notes, "policy p=none (monitoring only)")
	default:
		c.Status = Fail
		notes = append(notes, "missing or invalid p= tag")
	}
	if t["rua"] == "" {
		if c.Status == OK {
			c.Status = Warn
		}
		notes = append(notes, "no rua= so you receive no aggregate reports")
	}
	if pct := t["pct"]; pct != "" && pct != "100" {
		notes = append(notes, "pct="+pct)
	}
	c.Message = strings.Join(notes, "; ")
	return c
}

func checkPTR(ctx context.Context, res Resolver, ipS, helo string) Check {
	c := Check{Name: "ptr", Record: ipS}
	ip := net.ParseIP(ipS)
	if ip == nil {
		c.Status, c.Message = Warn, "not an IP address"
		return c
	}
	names, err := res.LookupAddr(ctx, ipS)
	if err != nil || len(names) == 0 {
		c.Status, c.Message = Fail, "no PTR record: many receivers (Gmail, Outlook) reject mail from IPs without reverse DNS. Ask your hosting provider to set one"
		return c
	}
	sort.Strings(names)
	var confirmed []string
	for _, n := range names {
		addrs, err := res.LookupIP(ctx, "ip", n)
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if a.Equal(ip) {
				confirmed = append(confirmed, strings.TrimSuffix(n, "."))
				break
			}
		}
	}
	if len(confirmed) == 0 {
		c.Status, c.Message = Fail, fmt.Sprintf("PTR %s does not resolve back to %s (FCrDNS fails)", strings.Join(names, ", "), ipS)
		return c
	}
	c.Status, c.Message = OK, fmt.Sprintf("PTR %s, forward-confirmed", strings.Join(confirmed, ", "))
	if helo != "" {
		match := false
		for _, n := range confirmed {
			if strings.EqualFold(n, strings.TrimSuffix(helo, ".")) {
				match = true
			}
		}
		if !match {
			c.Status = Warn
			c.Message += fmt.Sprintf("; but myhostname (HELO) is %s: some receivers want them to match", helo)
		}
	}
	return c
}
