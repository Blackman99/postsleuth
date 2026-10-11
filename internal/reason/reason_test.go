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
		"something nobody has seen before":                                                     "other",
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
