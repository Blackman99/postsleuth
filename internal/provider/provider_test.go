package provider

import (
	"net/url"
	"strings"
	"testing"
)

// Anonymised replies as Postfix logs them (status=... detail). Hosts are the
// providers' public MX names; addresses use example.com/example.net and IPs
// come from the documentation ranges (RFC 5737).
var fixtures = []struct {
	name, text, domain string
	provider, id, code string
	temporary          bool
}{
	{"gmail 421 4.7.28 IP", "host gmail-smtp-in.l.google.com[192.0.2.27] said: 421-4.7.28 Gmail has detected an unusual rate of unsolicited mail originating from your IP address. To protect our users from spam, mail sent from your IP address has been temporarily rate limited. For more information, go to 421-4.7.28 https://support.google.com/mail/answer/81126 - gsmtp (in reply to end of DATA command)", "gmail.com",
		Gmail, "gmail-4.7.28", "4.7.28", true},
	{"gmail 4.7.28 DKIM domain, Workspace MX", "host aspmx.l.google.com[192.0.2.28] said: 421-4.7.28 Gmail has detected an unusual rate of unsolicited email originating from your DKIM domain example.com. - gsmtp (in reply to end of DATA command)", "example.net",
		Gmail, "gmail-4.7.28", "4.7.28", true},
	{"gmail 550 5.7.26 DMARC", "host gmail-smtp-in.l.google.com[192.0.2.27] said: 550-5.7.26 Unauthenticated email from example.com is not accepted due to domain's DMARC policy. Please contact the administrator of example.com domain if this was a legitimate mail. - gsmtp (in reply to end of DATA command)", "gmail.com",
		Gmail, "gmail-auth", "5.7.26", false},
	{"gmail 421 4.7.26 unauthenticated", "host gmail-smtp-in.l.google.com[192.0.2.27] said: 421-4.7.26 This email has been rate limited because it is unauthenticated. Gmail requires all senders to authenticate with either SPF or DKIM. - gsmtp (in reply to end of DATA command)", "gmail.com",
		Gmail, "gmail-auth", "4.7.26", true},
	{"gmail 5.7.40 no DMARC", "host gmail-smtp-in.l.google.com[192.0.2.27] said: 550-5.7.40 Your message was blocked because the sending domain doesn't have a DMARC record or the DMARC record doesn't specify a DMARC policy. - gsmtp (in reply to end of DATA command)", "gmail.com",
		Gmail, "gmail-auth", "5.7.40", false},
	{"gmail 550 5.7.25 PTR", "host gmail-smtp-in.l.google.com[192.0.2.27] said: 550-5.7.25 [203.0.113.7] The IP address sending this message does not have a PTR record setup, or the corresponding forward DNS entry does not point to the sending IP. - gsmtp (in reply to end of DATA command)", "gmail.com",
		Gmail, "gmail-ptr", "5.7.25", false},
	{"gmail 421 4.7.0 PTR", "host gmail-smtp-in.l.google.com[192.0.2.27] said: 421-4.7.0 [203.0.113.7] The IP address sending this message does not have a PTR record, or the corresponding forward DNS entry does not point to the sending IP. - gsmtp (in reply to MAIL FROM command)", "gmail.com",
		Gmail, "gmail-ptr", "4.7.0", true},
	{"gmail 550 5.7.1 IPv6", "host gmail-smtp-in.l.google.com[2001:db8::1b] said: 550-5.7.1 This message does not meet IPv6 sending guidelines regarding PTR records and authentication. - gsmtp (in reply to end of DATA command)", "gmail.com",
		Gmail, "gmail-ptr", "5.7.1", false},
	{"gmail 4.7.29 TLS", "host gmail-smtp-in.l.google.com[192.0.2.27] said: 421-4.7.29 Your email has been rate limited because you're not using a TLS connection. - gsmtp (in reply to end of DATA command)", "gmail.com",
		Gmail, "gmail-tls", "4.7.29", true},
	{"gmail 550 5.7.1 unsolicited", "host gmail-smtp-in.l.google.com[192.0.2.27] said: 550-5.7.1 [203.0.113.7] Our system has detected that this message is likely unsolicited mail. To reduce the amount of spam sent to Gmail, this message has been blocked. - gsmtp (in reply to end of DATA command)", "gmail.com",
		Gmail, "gmail-reputation", "5.7.1", false},
	{"gmail 421 4.7.0 low IP reputation", "host gmail-smtp-in.l.google.com[192.0.2.27] said: 421-4.7.0 This message is suspicious due to the very low reputation of the sending IP address. - gsmtp (in reply to end of DATA command)", "gmail.com",
		Gmail, "gmail-reputation", "4.7.0", true},
	{"gmail 550 5.7.28 blocked", "host gmail-smtp-in.l.google.com[192.0.2.27] said: 550-5.7.28 There is an unusual rate of unsolicited email originating from your IP address. - gsmtp (in reply to end of DATA command)", "gmail.com",
		Gmail, "gmail-reputation", "5.7.28", false},
	{"gmail not authorized IP", "host gmail-smtp-in.l.google.com[192.0.2.27] said: 550-5.7.1 [198.51.100.9] The IP you're using to send mail is not authorized to send email directly to our servers. Please use the SMTP relay at your service provider instead. - gsmtp (in reply to end of DATA command)", "gmail.com",
		Gmail, "gmail-relay-required", "5.7.1", false},

	{"outlook S3150", "host outlook-com.olc.protection.outlook.com[192.0.2.42] said: 550 5.7.1 Unfortunately, messages from [203.0.113.7] weren't sent. Please contact your Internet service provider since part of their network is on our block list (S3150). You can also refer your provider to http://mail.live.com/mail/troubleshooting.aspx#errors. [AM0EUR02FT012.eop-EUR02.prod.protection.outlook.com] (in reply to MAIL FROM command)", "outlook.com",
		Microsoft, "microsoft-s3150", "S3150", false},
	{"hotmail S3140", "host hotmail-com.olc.protection.outlook.com[192.0.2.43] said: 550 5.7.1 Unfortunately, messages from [203.0.113.7] weren't sent. Please contact your Internet service provider since part of their network is on our block list (S3140). (in reply to MAIL FROM command)", "hotmail.com",
		Microsoft, "microsoft-s3150", "S3140", false},
	{"M365 banned sending IP", "host example-net.mail.protection.outlook.com[192.0.2.44] said: 550 5.7.606 Access denied, banned sending IP [203.0.113.7]. To request removal from this list please visit https://sender.office.com/ and follow the directions. (in reply to RCPT TO command)", "example.net",
		Microsoft, "microsoft-banned-ip", "5.7.606", false},
	{"M365 5.7.511", "host example-net.mail.protection.outlook.com[192.0.2.44] said: 550 5.7.511 Access denied, banned sender[203.0.113.7]. To request removal from this list, forward this message to delist@microsoft.com. (in reply to RCPT TO command)", "example.net",
		Microsoft, "microsoft-5.7.511", "5.7.511", false},
	{"outlook 4.7.650", "host outlook-com.olc.protection.outlook.com[192.0.2.42] said: 451 4.7.650 The mail server [203.0.113.7] has been temporarily rate limited due to IP reputation. For e-mail delivery information, see https://aka.ms/postmaster (S775) (in reply to MAIL FROM command)", "outlook.com",
		Microsoft, "microsoft-rate-limit", "4.7.650", true},
	{"outlook RP-001", "host hotmail-com.olc.protection.outlook.com[192.0.2.43] said: 421 RP-001 (BAY004-MC1F3) Unfortunately, some messages from 203.0.113.7 weren't sent. Please try again. We have limits for how many messages can be sent per hour and per day. (in reply to MAIL FROM command)", "hotmail.com",
		Microsoft, "microsoft-rate-limit", "RP-001", true},
	{"outlook SC-001 relay text", "host outlook-com.olc.protection.outlook.com[192.0.2.42] said: 550 SC-001 (DM1NAM02FT0123) Unfortunately, messages from 203.0.113.7 weren't sent. Please contact your Internet service provider. (in reply to MAIL FROM command)", "outlook.com",
		Microsoft, "microsoft-policy", "SC-001", false},
	{"outlook DY-001", "host outlook-com.olc.protection.outlook.com[192.0.2.42] said: 550 DY-001 (SNT004-MC1F43) Unfortunately, messages from 203.0.113.7 weren't sent. (in reply to MAIL FROM command)", "outlook.com",
		Microsoft, "microsoft-policy", "DY-001", false},
	{"outlook 5.7.515", "host outlook-com.olc.protection.outlook.com[192.0.2.42] said: 550 5.7.515 Access denied, sending domain example.com does not meet the required authentication level. (in reply to end of DATA command)", "outlook.com",
		Microsoft, "microsoft-5.7.515", "5.7.515", false},
	{"EXO 5.7.708 via relay", "host smtp.office365.com[192.0.2.45] said: 550 5.7.708 Service unavailable. Access denied, traffic not accepted from this IP. (in reply to MAIL FROM command)", "example.net",
		Microsoft, "microsoft-exo-relay", "5.7.708", false},
	{"EXO 5.7.750", "host smtp.office365.com[192.0.2.45] said: 550 5.7.750 Service unavailable. Client blocked from sending from unregistered domains. (in reply to MAIL FROM command)", "example.net",
		Microsoft, "microsoft-exo-relay", "5.7.750", false},

	{"yahoo TSS04", "host mta6.am0.yahoodns.net[192.0.2.72] said: 421 4.7.0 [TSS04] Messages from 203.0.113.7 temporarily deferred due to unexpected volume or user complaints - 4.16.55.1; see https://postmaster.yahooinc.com/error-codes (in reply to MAIL FROM command)", "yahoo.com",
		Yahoo, "yahoo-deferred", "TSS04", true},
	{"aol TSS04", "host mx-aol.mail.gm0.yahoodns.net[192.0.2.73] said: 421 4.7.0 [TSS04] Messages from 203.0.113.7 temporarily deferred due to unexpected volume or user complaints (in reply to MAIL FROM command)", "aol.com",
		Yahoo, "yahoo-deferred", "TSS04", true},
	{"yahoo TSS09", "host mta5.am0.yahoodns.net[192.0.2.72] said: 421 4.7.0 [TSS09] All messages from 203.0.113.7 will be permanently deferred; Retrying will NOT succeed. See https://postmaster.yahooinc.com/error-codes (in reply to MAIL FROM command)", "yahoo.com",
		Yahoo, "yahoo-tss09", "TSS09", false},
	{"yahoo BL21", "host mta7.am0.yahoodns.net[192.0.2.72] said: 553 5.7.1 [BL21] Connections will not be accepted from 203.0.113.7, because the ip is in Spamhaus's list; see https://postmaster.yahooinc.com/error-codes (in reply to MAIL FROM command)", "yahoo.com",
		Yahoo, "yahoo-blocklist", "BL21", false},
	{"yahoo BL23", "host mta7.am0.yahoodns.net[192.0.2.72] said: 553 5.7.1 [BL23] Connections not accepted from IP addresses on Spamhaus XBL; see https://postmaster.yahooinc.com/error-codes (in reply to MAIL FROM command)", "yahoo.com",
		Yahoo, "yahoo-blocklist", "BL23", false},
	{"yahoo 550 5.7.9 unauthenticated", "host mta7.am0.yahoodns.net[192.0.2.72] said: 550 5.7.9 This mail has been blocked because the sender is unauthenticated. Yahoo requires all senders to authenticate with either SPF or DKIM. (in reply to end of DATA command)", "yahoo.com",
		Yahoo, "yahoo-auth", "5.7.9", false},
	{"yahoo 554 5.7.9 policy", "host mta7.am0.yahoodns.net[192.0.2.72] said: 554 5.7.9 Message not accepted for policy reasons.  See https://postmaster.yahooinc.com/error-codes (in reply to end of DATA command)", "yahoo.com",
		Yahoo, "yahoo-policy", "5.7.9", false},
}

func TestLookupFixtures(t *testing.T) {
	for _, f := range fixtures {
		m := Lookup(f.text, f.domain)
		if m.Provider != f.provider || m.ID != f.id || m.Code != f.code || m.Temporary != f.temporary {
			t.Errorf("%s: got provider=%q id=%q code=%q temporary=%v, want %q %q %q %v",
				f.name, m.Provider, m.ID, m.Code, m.Temporary, f.provider, f.id, f.code, f.temporary)
		}
	}
}

func TestDetect(t *testing.T) {
	cases := []struct{ text, domain, want string }{
		{"connect to gmail-smtp-in.l.google.com[192.0.2.27]:25: Connection timed out", "gmail.com", Gmail},
		{"host alt1.aspmx.l.google.com[192.0.2.28] said: 452-4.2.2 The email account that you tried to reach is over quota.", "example.com", Gmail},
		{"host example-com.mail.protection.outlook.com[192.0.2.44] said: 550 5.4.1 Recipient address rejected: Access denied", "example.com", Microsoft},
		{"host mx-aol.mail.gm0.yahoodns.net[192.0.2.73] said: 554 5.1.1 <old@aol.com>: Recipient address rejected", "aol.com", Yahoo},
		// marker in the reply, no host (e.g. through a relay or a retry: transport)
		{"4.7.28 Gmail has detected an unusual rate of mail originating from your IP address. - gsmtp", "", Gmail},
		{"Unfortunately, messages from [203.0.113.7] weren't sent ... block list (S3150)", "", Microsoft},
		{"[TSS04] Messages from 203.0.113.7 temporarily deferred", "", Yahoo},
		// a non-provider host that quotes a Gmail address is not Gmail
		{"host mx.example.net[198.51.100.20] said: 550 5.1.1 <bob@gmail.com>: Recipient address rejected: User unknown", "gmail.com", ""},
		// recipient domain fallback when there is no host and no marker
		{"Host or domain name not found. Name service error for name=example.net type=MX", "hotmail.co.uk", Microsoft},
		{"Host or domain name not found", "ymail.com", Yahoo},
		{"Host or domain name not found", "example.org", ""},
	}
	for _, c := range cases {
		if got := Detect(c.text, c.domain); got != c.want {
			t.Errorf("Detect(%q, %q) = %q, want %q", c.text, c.domain, got, c.want)
		}
	}
}

func TestNoPlaybookForOrdinaryFailures(t *testing.T) {
	for _, text := range []string{
		"host gmail-smtp-in.l.google.com[192.0.2.27] said: 550-5.1.1 The email account that you tried to reach does not exist. - gsmtp (in reply to RCPT TO command)",
		"host mta7.am0.yahoodns.net[192.0.2.72] said: 554 5.1.1 <old.user@example.com>: Recipient address rejected: User unknown (in reply to RCPT TO command)",
		"connect to outlook-com.olc.protection.outlook.com[192.0.2.42]:25: Connection timed out",
		"host mx.example.net[198.51.100.20] said: 421 4.7.28 too busy (in reply to MAIL FROM command)",
	} {
		if m := Lookup(text, ""); m.Playbook != nil {
			t.Errorf("unexpected playbook %s for %q", m.ID, text)
		}
	}
}

func TestPlaybooksWellFormed(t *testing.T) {
	seen := map[string]bool{}
	for _, p := range All() {
		if seen[p.ID] {
			t.Fatalf("duplicate id %s", p.ID)
		}
		seen[p.ID] = true
		if Name(p.Provider) == "" || !strings.HasPrefix(p.ID, p.Provider+"-") {
			t.Errorf("%s: bad provider %q", p.ID, p.Provider)
		}
		if p.Title == "" || p.Meaning == "" || p.Codes == "" || len(p.Steps) < 2 || len(p.Refs) == 0 {
			t.Errorf("%s: incomplete playbook", p.ID)
		}
		for _, r := range p.Refs {
			u, err := url.Parse(r.URL)
			if err != nil || u.Scheme != "https" || r.Title == "" {
				t.Errorf("%s: bad reference %+v", p.ID, r)
			}
		}
		for _, s := range p.Steps {
			if strings.TrimSpace(s) == "" || strings.HasSuffix(s, " ") {
				t.Errorf("%s: sloppy step %q", p.ID, s)
			}
		}
		if _, ok := Get(p.ID); !ok {
			t.Errorf("Get(%s) failed", p.ID)
		}
	}
	for _, id := range []string{"gmail-4.7.28", "microsoft-s3150", "yahoo-deferred"} {
		if !seen[id] {
			t.Errorf("missing %s", id)
		}
	}
}

func TestCollector(t *testing.T) {
	c := NewCollector()
	g := fixtures[0].text
	c.Add(KindDeferral, g, []string{"gmail.com"}, 82)
	c.Add(KindQueued, g, []string{"gmail.com", "+3 more"}, 141)
	c.Add(KindBounce, fixtures[13].text, []string{"outlook.com"}, 14)
	c.Add(KindDeferral, "host mx.example.net[198.51.100.20] said: 450 4.7.1 Greylisted", []string{"example.net"}, 3)
	hits := c.Result()
	if len(hits) != 2 {
		t.Fatalf("hits: %+v", hits)
	}
	h := hits[0]
	if h.Playbook.ID != "gmail-4.7.28" || h.Deferrals != 82 || h.Queued != 141 || !h.Temporary || len(h.Domains) != 1 || h.Codes[0] != "4.7.28" {
		t.Fatalf("gmail hit: %+v", h)
	}
	if hits[1].Playbook.ID != "microsoft-s3150" || hits[1].Bounces != 14 || hits[1].Temporary {
		t.Fatalf("outlook hit: %+v", hits[1])
	}
}

// A delay reason that lost its reply code (Postfix's retry transport, some
// relays) still finds the playbook, and a deferral without a code is
// treated as temporary because Postfix deferred it.
func TestCodelessDeferral(t *testing.T) {
	text := "Gmail has detected an unusual rate of unsolicited mail originating from your IP address. - gsmtp"
	m := Lookup(text, "example.net")
	if m.ID != "gmail-4.7.28" || m.Temporary {
		t.Fatalf("lookup %+v", m)
	}
	c := NewCollector()
	c.Add(KindQueued, text, []string{"example.net"}, 1)
	c.Add(KindDeferral, "host mta5.am0.yahoodns.net[192.0.2.70] said: [TSS09] All messages from 203.0.113.7 will be permanently deferred; Retrying will NOT succeed.", []string{"yahoo.com"}, 2)
	got := map[string]Hit{}
	for _, h := range c.Result() {
		got[h.Playbook.ID] = h
	}
	if h := got["gmail-4.7.28"]; !h.Temporary || h.Queued != 1 {
		t.Errorf("gmail %+v", h)
	}
	if h := got["yahoo-tss09"]; h.Temporary || h.Deferrals != 2 {
		t.Errorf("tss09 must stay permanent: %+v", h)
	}
}
