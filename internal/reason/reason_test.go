package reason

import "testing"

func TestClassify(t *testing.T) {
	cases := map[string]string{
		"host gmail-smtp-in.l.google.com[1.2.3.4] said: 421-4.7.28 Gmail has detected an unusual rate":   "rate_limit",
		"connect to mx.example.com[1.2.3.4]:25: Connection timed out":                                    "timeout",
		"connect to mx.example.com[1.2.3.4]:25: Connection refused":                                      "connect",
		"Host or domain name not found. Name service error for name=x.example type=MX":                   "dns",
		"550 5.7.1 ... part of their network is on our block list (S3150)":                               "blocklist",
		"550 5.7.25 [1.2.3.4] The IP address sending this message does not have a PTR record setup":      "ptr",
		"550-5.7.26 Unauthenticated email from example.com is not accepted due to domain's DMARC policy": "auth",
		"554 5.1.1 <a@b.c>: Recipient address rejected: User unknown":                                    "recipient_unknown",
		"552 5.2.2 Mailbox full": "mailbox_full",
		"450 4.7.1 <a@b>: Recipient address rejected: Greylisted, see http://postgrey":         "greylisting",
		"554 5.7.1 <a@b>: Relay access denied":                                                 "relay_denied",
		"SASL authentication failed; server smtp.relay.example[1.2.3.4] said: 535 5.7.8 Error": "sasl_auth",
		"TLS is required, but was not offered by host mx.example.com[1.2.3.4]":                 "tls",
		"mail for example.com loops back to myself":                                            "loop",
		// provider-specific replies (see internal/provider for the playbooks)
		"host aspmx.l.google.com[192.0.2.28] said: 421-4.7.28 Gmail has detected an unusual rate of unsolicited email originating from your DKIM domain example.com. - gsmtp":        "rate_limit",
		"host gmail-smtp-in.l.google.com[192.0.2.27] said: 421-4.7.29 Your email has been rate limited because you're not using a TLS connection. - gsmtp":                           "tls",
		"host gmail-smtp-in.l.google.com[192.0.2.27] said: 421-4.7.0 This message is suspicious due to the very low reputation of the sending IP address. - gsmtp":                   "policy",
		"host gmail-smtp-in.l.google.com[192.0.2.27] said: 550-5.7.28 There is an unusual rate of unsolicited email originating from your IP address. - gsmtp":                       "policy",
		"host gmail-smtp-in.l.google.com[192.0.2.27] said: 550-5.7.1 [203.0.113.7] The IP you're using to send mail is not authorized to send email directly to our servers.":        "relay_denied",
		"550 5.7.1 Unfortunately, messages from [203.0.113.7] weren't sent. Please contact your Internet service provider since part of their network is on our block list (S3140).": "blocklist",
		"451 4.7.650 The mail server [203.0.113.7] has been temporarily rate limited due to IP reputation.":                                                                          "rate_limit",
		"421 RP-001 (BAY004-MC1F3) Unfortunately, some messages from 203.0.113.7 weren't sent. Please try again.":                                                                    "rate_limit",
		"550 SC-001 (DM1NAM02FT0123) Unfortunately, messages from 203.0.113.7 weren't sent. Please contact your Internet service provider.":                                          "blocklist",
		"550 DY-001 (SNT004-MC1F43) Unfortunately, messages from 203.0.113.7 weren't sent.":                                                                                          "blocklist",
		"550 5.7.515 Access denied, sending domain example.com does not meet the required authentication level.":                                                                     "auth",
		"550 5.7.708 Service unavailable. Access denied, traffic not accepted from this IP.":                                                                                         "relay_denied",
		"421 4.7.0 [TSS04] Messages from 203.0.113.7 temporarily deferred due to unexpected volume or user complaints":                                                               "rate_limit",
		"421 4.7.0 [TSS09] All messages from 203.0.113.7 will be permanently deferred; Retrying will NOT succeed.":                                                                   "blocklist",
		"553 5.7.1 [BL21] Connections will not be accepted from 203.0.113.7, because the ip is in Spamhaus's list":                                                                   "blocklist",
		"550 5.7.9 This mail has been blocked because the sender is unauthenticated. Yahoo requires all senders to authenticate with either SPF or DKIM.":                            "auth",
		"something nobody has seen before": "other",
	}
	for in, want := range cases {
		if got := Classify(in).ID; got != want {
			t.Errorf("Classify(%q) = %s, want %s", in, got, want)
		}
	}
}

func TestNormalize(t *testing.T) {
	a := Normalize("host mx.a.example[192.0.2.1] said: 550 5.1.1 <bob@a.example>: User unknown (in reply to RCPT TO command)")
	b := Normalize("host mx.a.example[192.0.2.9] said: 550 5.1.1 <ann@a.example>: User unknown (in reply to RCPT TO command)")
	if a != b {
		t.Fatalf("not grouped: %q vs %q", a, b)
	}
	if a != "550 5.1.1 <addr>: User unknown" {
		t.Fatalf("got %q", a)
	}
	if r := Remote("host mx.a.example[192.0.2.1] said: 550"); r != "mx.a.example" {
		t.Fatalf("Remote = %q", r)
	}
}

func TestCategoriesUnique(t *testing.T) {
	seen := map[string]bool{}
	for _, c := range Categories() {
		if seen[c.ID] || c.Hint == "" {
			t.Fatalf("bad category %+v", c)
		}
		seen[c.ID] = true
	}
}
