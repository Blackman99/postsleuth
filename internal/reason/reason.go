// Package reason normalises and classifies Postfix delivery failure texts
// (delay_reason in the queue, status=deferred/bounced text in the log).
package reason

import (
	"regexp"
	"strings"
)

// Category is a coarse cause of a delivery failure.
type Category struct {
	ID   string `json:"id"`
	Hint string `json:"hint"`
}

type rule struct {
	re  *regexp.Regexp
	cat Category
}

// Order matters: first match wins.
var rules = []rule{
	{regexp.MustCompile(`(?i)loops back to myself`), Category{"loop", "Postfix thinks it is the destination: check mydestination, myhostname and virtual domains, or the MX points back at this host."}},
	{regexp.MustCompile(`(?i)(relay access denied|relaying denied|not permitted to relay|5\.7\.1 .*relay)`), Category{"relay_denied", "The next hop refuses to relay for you: check relayhost, SASL credentials, or the recipient domain is not hosted there."}},
	{regexp.MustCompile(`(?i)(sasl authentication failed|authentication failed|5\.7\.8|535[ -])`), Category{"sasl_auth", "Login to the relay host failed: check smtp_sasl_password_maps (and run postmap after editing it)."}},
	{regexp.MustCompile(`(?i)(spamhaus|blocked using|block ?list|black ?list|\brbl\b|\bdnsbl\b|listed (at|on|in)|banned sending ip|S3150|5\.7\.606|5\.7\.511|ip .* blocked|has been blocked)`), Category{"blocklist", "The receiver rejects your IP or domain because of a blocklist entry: look the IP up (Spamhaus, Microsoft SNDS) and request delisting after fixing the cause."}},
	{regexp.MustCompile(`(?i)(5\.7\.25|reverse dns|ptr record|reverse (lookup|mapping)|does not have a ptr|no ptr)`), Category{"ptr", "The receiver requires reverse DNS: set a PTR for your sending IP that resolves back to the same IP (FCrDNS), ideally matching myhostname."}},
	{regexp.MustCompile(`(?i)(5\.7\.26|5\.7\.27|5\.7\.23|5\.7\.24|\bdmarc\b|\bdkim\b|\bspf\b|unauthenticated|not authenticated|authentication (results|checks)|sender (address|domain)? ?(is )?not authorized)`), Category{"auth", "The receiver could not authenticate your mail: check SPF covers this IP, DKIM signs with a published selector, and DMARC aligns (postsleuth dns DOMAIN)."}},
	{regexp.MustCompile(`(?i)(greylist|grey-list|graylist)`), Category{"greylisting", "Greylisting: normal, Postfix retries automatically. Only a problem if it persists for hours."}},
	{regexp.MustCompile(`(?i)(rate limit|ratelimit|too many (messages|connections|recipients|concurrent)|throttl|4\.7\.28|4\.7\.0 .*try again later|try again later|temporarily (rate|deferred)|421 4\.7\.0|TSS04|exceeded the (message|rate))`), Category{"rate_limit", "The receiver is throttling you: lower smtp_destination_concurrency_limit / add smtp_destination_rate_delay for that domain, and check your sending reputation."}},
	{regexp.MustCompile(`(?i)(5\.1\.1|5\.1\.0|user unknown|unknown user|no such user|does not exist|recipient address rejected: (user|undeliverable|unknown)|mailbox unavailable|invalid recipient|address rejected|no mailbox here|unrouteable address)`), Category{"recipient_unknown", "The mailbox does not exist: fix or remove the address (check for typos)."}},
	{regexp.MustCompile(`(?i)(5\.2\.2|4\.2\.2|over quota|quota exceeded|mailbox (is )?full|insufficient (system )?storage)`), Category{"mailbox_full", "The recipient's mailbox is full: nothing to fix on your side; the sender should use another channel."}},
	{regexp.MustCompile(`(?i)(5\.3\.4|message (size|file too big)|too large|exceeds .*size)`), Category{"size", "The message is larger than the receiver accepts."}},
	{regexp.MustCompile(`(?i)(tls is required|cannot start tls|starttls|tls (handshake|library problem)|ssl_|certificate verif|server certificate not (trusted|verified)|no common cipher|handshake failure)`), Category{"tls", "TLS negotiation failed: check smtp_tls_security_level / smtp_tls_policy_maps for that destination and the system CA bundle (smtp_tls_CAfile)."}},
	{regexp.MustCompile(`(?i)(host or domain name not found|name service error|host not found|no mx host|nxdomain|domain not found|malformed dns|dns lookup|unable to look up)`), Category{"dns", "DNS lookup for the destination failed: check the domain exists and has MX/A records, and that this server's resolver works (dig MX domain)."}},
	{regexp.MustCompile(`(?i)(connection timed out|timed out while|conversation with .* timed out|lost connection)`), Category{"timeout", "Connections to port 25 time out: many providers block outbound port 25, so test with nc -vz MX 25 and use a relayhost if blocked."}},
	{regexp.MustCompile(`(?i)(connection refused|no route to host|network is unreachable|connect to .*:\d+:)`), Category{"connect", "Could not connect to the destination: the remote server is down or unreachable, or outbound port 25 is blocked."}},
	{regexp.MustCompile(`(?i)(spam|junk|5\.7\.1 .*(message|content|rejected)|policy|refused to accept|content rejected|5\.7\.0|5\.7\.1)`), Category{"policy", "The receiver's policy rejected the message (spam or content filter). Read the full reply text; check authentication and the message content."}},
}

var other = Category{"other", "Read the full reply text from the remote server."}

// Classify returns the category of a failure text.
func Classify(text string) Category {
	for _, r := range rules {
		if r.re.MatchString(text) {
			return r.cat
		}
	}
	return other
}

// Categories lists every category id, for documentation and tests.
func Categories() []Category {
	out := make([]Category, 0, len(rules)+1)
	seen := map[string]bool{}
	for _, r := range rules {
		if !seen[r.cat.ID] {
			seen[r.cat.ID] = true
			out = append(out, r.cat)
		}
	}
	return append(out, other)
}

var (
	reAddr     = regexp.MustCompile(`<[^<>\s]*@[^<>\s]*>`)
	reBareAdr  = regexp.MustCompile(`\b[\w.+\-=]+@[\w.\-]+\.[A-Za-z]{2,}\b`)
	reHostIP   = regexp.MustCompile(`\[[0-9a-fA-F:.]+\](:\d+)?`)
	reIPv4     = regexp.MustCompile(`\b\d{1,3}(\.\d{1,3}){3}\b`)
	reIPv6     = regexp.MustCompile(`\b[0-9a-fA-F]{1,4}(:[0-9a-fA-F]{0,4}){3,7}\b`)
	reLongTok  = regexp.MustCompile(`\b[0-9A-Za-z_\-]*\d[0-9A-Za-z_\-]{11,}\b`)
	reHostSaid = regexp.MustCompile(`(?i)^host \S+ said: `)
	reInReply  = regexp.MustCompile(`(?i)\s*\(in reply to [^)]*\)\s*$`)
	reSpaces   = regexp.MustCompile(`\s+`)
	reMXHost   = regexp.MustCompile(`(?i)\b(?:[a-z0-9-]+\.)+(?:[a-z0-9-]+\.)(?:[a-z]{2,})\b`)
)

// Normalize turns a failure text into a stable key for grouping: addresses,
// IPs and long tokens (tracking IDs) are replaced, the "host X said:" prefix
// and "(in reply to ...)" suffix are removed.
func Normalize(text string) string {
	s := strings.TrimSpace(text)
	s = reHostSaid.ReplaceAllString(s, "")
	s = reInReply.ReplaceAllString(s, "")
	s = reAddr.ReplaceAllString(s, "<addr>")
	s = reBareAdr.ReplaceAllString(s, "addr")
	s = reHostIP.ReplaceAllString(s, "[ip]")
	s = reIPv4.ReplaceAllString(s, "ip")
	s = reIPv6.ReplaceAllString(s, "ip")
	s = reLongTok.ReplaceAllString(s, "…")
	s = reSpaces.ReplaceAllString(s, " ")
	if len(s) > 220 {
		s = s[:220] + "…"
	}
	return s
}

// Remote extracts the remote host from "host mx.example.com[1.2.3.4] said:" or
// "connect to mx.example.com[1.2.3.4]:25:" style texts, if present.
func Remote(text string) string {
	for _, p := range []string{"host ", "connect to "} {
		if i := strings.Index(strings.ToLower(text), p); i >= 0 {
			rest := text[i+len(p):]
			if j := strings.IndexAny(rest, "[ "); j > 0 {
				h := rest[:j]
				if reMXHost.MatchString(h) || strings.Count(h, ".") >= 1 {
					return h
				}
			}
		}
	}
	return ""
}
