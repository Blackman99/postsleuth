package message

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Blackman99/postsleuth/internal/queue"
)

var cst = time.FixedZone("CST", 8*3600)
var now = time.Unix(1791759600, 0).In(cst)

func fixture(t *testing.T) Parsed {
	b, err := os.ReadFile("../../testdata/postcat-F543B5DFCE.txt")
	if err != nil {
		t.Fatal(err)
	}
	return Parse(string(b), cst)
}

func entry(t *testing.T) *queue.Message {
	f, err := os.Open("../../testdata/queue.json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	msgs, err := queue.Parse(f)
	if err != nil {
		t.Fatal(err)
	}
	for i := range msgs {
		if msgs[i].QueueID == "F543B5DFCE" {
			return &msgs[i]
		}
	}
	t.Fatal("F543B5DFCE not in queue.json")
	return nil
}

func TestParse(t *testing.T) {
	p := fixture(t)
	if p.Queue != "deferred" || p.QueueID != "F543B5DFCE" || p.Path != "deferred/F/F543B5DFCE" {
		t.Fatalf("path %+v", p)
	}
	if p.Size != 37649 || p.Sender != "alerts@example.com" || !p.HasSender {
		t.Fatalf("envelope %+v", p)
	}
	if want := time.Date(2026, 10, 12, 2, 3, 0, 0, cst); !p.Arrival.Equal(want) {
		t.Fatalf("arrival %v", p.Arrival)
	}
	if len(p.Recipients) != 2 || p.Recipients[0].Status != Pending || p.Recipients[1].Status != Delivered || p.Recipients[1].Original != "oncall@example.org" {
		t.Fatalf("recipients %+v", p.Recipients)
	}
	if len(p.Headers) != 14 || p.Headers[0].Name != "Received" || !strings.Contains(p.Headers[0].Value, "(No client certificate requested) by mail.example.com") {
		t.Fatalf("headers %d %+v", len(p.Headers), p.Headers[0])
	}
	if got := p.Get("x-mailer"); len(got) != 1 || got[0] != "alertd 4.2.1" {
		t.Fatalf("Get %v", got)
	}
}

func TestBuildRedacted(t *testing.T) {
	r := Build(fixture(t), Options{Redact: true, Now: now, Entry: entry(t), Source: "test"})
	if r.Queue != "deferred" || r.Age != "4h57m" || r.Arrival != "2026-10-12T02:03:00+08:00" || r.Size != 37649 {
		t.Fatalf("header %+v", r)
	}
	if r.Sender != "[user-1]@example.com" || r.SenderDomain != "example.com" || r.FromDomain != "example.com" {
		t.Fatalf("sender %q %q %q", r.Sender, r.SenderDomain, r.FromDomain)
	}
	g := r.Recipients[0]
	if g.Address != "[user-2]@gmail.com" || g.Domain != "gmail.com" || g.Status != Pending || g.Category != "rate_limit" ||
		g.Playbook != "gmail-4.7.28" || g.Temporary == nil || !*g.Temporary {
		t.Fatalf("pending %+v", g)
	}
	if d := r.Recipients[1]; d.Address != "[user-3]@example.org" || d.Status != Delivered || d.DelayReason != "" {
		t.Fatalf("delivered %+v", d)
	}
	if len(r.Domains) != 2 {
		t.Fatalf("domains %+v", r.Domains)
	}
	// Hops oldest first: pickup on the app host, then the relay into this server.
	if len(r.Hops) != 2 || !r.Hops[0].Local || r.Hops[0].By != "app01.internal" || r.Hops[0].ID != "4bNqJx2rG9z1Hk" {
		t.Fatalf("hop 1 %+v", r.Hops)
	}
	if h := r.Hops[1]; h.FromIP != "10.0.0.12" || h.FromHost != "app01.internal" || h.By != "mail.example.com" || h.With != "ESMTPS" || h.TLS != "TLSv1.3" || h.ID != "F543B5DFCE" || h.Time != "2026-10-12T02:03:00+08:00" {
		t.Fatalf("hop 2 %+v", h)
	}
	if len(r.DKIM) != 1 || r.DKIM[0].Domain != "example.com" || r.DKIM[0].Selector != "mail" || !r.DKIM[0].Aligned {
		t.Fatalf("dkim %+v", r.DKIM)
	}
	if !hasNote(r, "no_one_click", Warning) || len(r.Notes) != 1 {
		t.Fatalf("notes %+v", r.Notes)
	}
	hdr := map[string]Header{}
	for _, h := range r.Headers {
		hdr[h.Name] = h
	}
	for name, want := range map[string]string{
		"From":             "[user-1]@example.com",
		"To":               "[user-2]@gmail.com, [user-3]@example.org",
		"Subject":          "[redacted, 48 chars]",
		"Message-ID":       "<[id]@app01.example.com>",
		"Content-Type":     "multipart/alternative",
		"List-Unsubscribe": "[present: mailto; values hidden]",
		"X-Mailer":         "alertd 4.2.1",
		"Precedence":       "bulk",
		"X-Api-Key":        "[removed: looks like a credential]",
	} {
		if hdr[name].Value != want {
			t.Errorf("%s = %q, want %q", name, hdr[name].Value, want)
		}
	}
	if !strings.HasPrefix(hdr["DKIM-Signature"].Value, "v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=mail") {
		t.Errorf("dkim header %q", hdr["DKIM-Signature"].Value)
	}
	b, _ := json.Marshal(r)
	for _, leak := range []string{"yuki342", "oncall@", "alerts@", "Jamie", "Smith", "Example Alerts", "On-call", "db-3", "alertd-demo-key", "c2lnbmF0dXJl", "Zm9vYmFy", "4bNqJx2rG9@", "unsub-", "unsubscribe@"} {
		if strings.Contains(string(b), leak) {
			t.Errorf("redacted report leaks %q", leak)
		}
	}
	if !r.Redacted {
		t.Error("Redacted flag not set")
	}
}

func hasNote(r Report, id, level string) bool {
	for _, n := range r.Notes {
		if n.ID == id && n.Level == level {
			return true
		}
	}
	return false
}

func TestBuildUnredactedStillHidesSecrets(t *testing.T) {
	r := Build(fixture(t), Options{Redact: false, Now: now, Entry: entry(t)})
	b, _ := json.Marshal(r)
	for _, want := range []string{"yuki342@gmail.com", "alerts@example.com", "Jamie Smith", "db-3 disk usage"} {
		if !strings.Contains(string(b), want) {
			t.Errorf("unredacted report misses %q", want)
		}
	}
	if strings.Contains(string(b), "alertd-demo-key") {
		t.Error("credential header shown with redaction off")
	}
	if r.Redacted {
		t.Error("Redacted flag set")
	}
}

func TestBuildWithoutQueueEntry(t *testing.T) {
	// postqueue unavailable: the queue file alone still gives queue, arrival and recipients.
	r := Build(fixture(t), Options{Redact: true, Now: now})
	if r.Queue != "deferred" || r.Age != "4h57m" || len(r.Recipients) != 2 || r.Recipients[0].DelayReason != "" {
		t.Fatalf("%+v", r)
	}
}

const minimal = `*** ENVELOPE RECORDS hold/A/ABCDEF1234 ***
message_size:             900             300               1               0             900               0
message_arrival_time: Sun Oct 11 22:00:00 2026
sender: 
recipient: someone@partner.example
*** MESSAGE CONTENTS hold/A/ABCDEF1234 ***
Received: from laptop.home (cpe-203-0-113-9.isp.example [203.0.113.9])
	(Authenticated sender: jane.doe@example.com)
	by mail.example.com (Postfix) with ESMTPSA id ABCDEF1234
	for <someone@partner.example>; Sun, 11 Oct 2026 22:00:00 +0800 (CST)
DKIM-Signature: v=1; a=rsa-sha256; d=esp.example; s=s1; i=@esp.example; bh=AAAA; b=BBBB
From: Jane Doe <jane.doe@shop.example>
From: other@shop.example
Authentication-Results: mail.example.com; spf=pass smtp.mailfrom=jane.doe@example.com
Cookie: session=abcdef
X-Session-Token: 12345
List-Id: Offers <offers.shop.example>
X-Custom-Note: call Jane on +1 555 0100

this is the body and must never show up
SECRET BODY LINE
*** HEADER EXTRACTED hold/A/ABCDEF1234 ***
*** MESSAGE FILE END hold/A/ABCDEF1234 ***
`

func TestRedactionEdgeCases(t *testing.T) {
	p := Parse(minimal, cst)
	if p.BodyDropped != 2 {
		t.Fatalf("body lines: %d", p.BodyDropped)
	}
	r := Build(p, Options{Redact: true, Now: now})
	if r.Sender != "<>" || r.SenderDomain != "<>" || r.Queue != "hold" {
		t.Fatalf("%+v", r)
	}
	h := r.Hops[0]
	if !h.Authenticated || h.FromIP != "" || h.From != "" || h.FromHost != "" || h.With != "ESMTPSA" || h.TLS != "TLS" {
		t.Fatalf("authenticated hop not hidden: %+v", h)
	}
	if len(r.DKIM) != 1 || r.DKIM[0].Aligned {
		t.Fatalf("dkim %+v", r.DKIM)
	}
	for _, id := range []string{"multiple_from", "no_message_id", "no_date", "dkim_not_aligned", "no_list_unsubscribe", "null_sender", "on_hold", "body_ignored"} {
		found := false
		for _, n := range r.Notes {
			found = found || n.ID == id
		}
		if !found {
			t.Errorf("missing note %s in %+v", id, r.Notes)
		}
	}
	b, _ := json.Marshal(r)
	s := string(b)
	for _, leak := range []string{"jane.doe", "Jane", "203.0.113.9", "laptop.home", "cpe-203", "session=abcdef", "12345", "555 0100", "this is the body", "SECRET", "BBBB", "AAAA"} {
		if strings.Contains(s, leak) {
			t.Errorf("leaks %q: %s", leak, s)
		}
	}
	for _, want := range []string{"[user-1]@partner.example", "[user-2]@shop.example", "smtp.mailfrom=[user-4]@example.com", "Offers \u003coffers.shop.example\u003e", "from [authenticated client hidden]", "(Authenticated sender: [redacted])"} {
		if !strings.Contains(s, want) && !strings.Contains(s, strings.NewReplacer("<", `\u003c`, ">", `\u003e`).Replace(want)) {
			t.Errorf("missing %q in %s", want, s)
		}
	}
	// Even unredacted, credentials and the body stay out.
	r = Build(p, Options{Redact: false, Now: now})
	b, _ = json.Marshal(r)
	for _, leak := range []string{"session=abcdef", "12345", "SECRET"} {
		if strings.Contains(string(b), leak) {
			t.Errorf("unredacted leaks %q", leak)
		}
	}
}

func TestOrgDomainAlignment(t *testing.T) {
	for _, c := range []struct {
		a, b string
		same bool
	}{
		{"example.com", "mail.example.com", true},
		{"news.example.co.uk", "example.co.uk", true},
		{"example.co.uk", "other.co.uk", false},
		{"esp.example", "shop.example", false},
		{"Example.COM.", "example.com", true},
	} {
		if (orgDomain(c.a) == orgDomain(c.b)) != c.same {
			t.Errorf("%s vs %s", c.a, c.b)
		}
	}
}

func TestSecretHeaderNames(t *testing.T) {
	for _, n := range []string{"Authorization", "Cookie", "Set-Cookie", "X-Api-Key", "X-API-KEY", "X-Auth-Token", "X-Session-Id", "X-Reset-Password-Link", "X-Client-Secret", "X-Credentials"} {
		if !secretHeader.MatchString(n) {
			t.Errorf("%s not treated as secret", n)
		}
	}
	for _, n := range []string{"DKIM-Signature", "From", "Subject", "X-Mailer", "Authentication-Results", "X-Authenticated-Sender", "List-Unsubscribe"} {
		if secretHeader.MatchString(n) && n != "DKIM-Signature" {
			t.Errorf("%s treated as secret", n)
		}
	}
}
