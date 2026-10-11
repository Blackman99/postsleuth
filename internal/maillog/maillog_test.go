package maillog

import (
	"os"
	"strings"
	"testing"
	"time"
)

var cst = time.FixedZone("CST", 8*3600)
var now = time.Unix(1791759600, 0).In(cst)

func TestParseLineFormats(t *testing.T) {
	lines := []string{
		"Oct 12 06:58:01 mail postfix/smtp[2211]: 4F2A1C3B9: to=<a@gmail.com>, relay=gmail-smtp-in.l.google.com[1.2.3.4]:25, delay=1, delays=0/0/0.5/0.5, dsn=4.7.28, status=deferred (host gmail-smtp-in.l.google.com[1.2.3.4] said: 421-4.7.28 rate limited (in reply to end of DATA command))",
		"2026-10-12T06:58:01.123456+08:00 mail postfix/smtp[2211]: 4F2A1C3B9: to=<a@gmail.com>, relay=x, dsn=4.7.28, status=deferred (host x[1.2.3.4] said: 421-4.7.28 rate limited (in reply to end of DATA command))",
		"2026-10-12T06:58:01+0800 mail postfix-out/smtp[2211]: 4F2A1C3B9: to=<a@gmail.com>, relay=x, dsn=4.7.28, status=deferred (host x[1.2.3.4] said: 421-4.7.28 rate limited (in reply to end of DATA command))",
	}
	for _, l := range lines {
		ev, ok := ParseLine(l, now)
		if !ok {
			t.Fatalf("not parsed: %s", l)
		}
		if ev.QueueID != "4F2A1C3B9" || ev.Status != "deferred" || ev.Fields["to"] != "a@gmail.com" || ev.Fields["dsn"] != "4.7.28" {
			t.Fatalf("bad event %+v", ev)
		}
		if !strings.HasSuffix(ev.Detail, "(in reply to end of DATA command)") || !strings.HasPrefix(ev.Detail, "host x") && !strings.HasPrefix(ev.Detail, "host gmail") {
			t.Fatalf("detail %q", ev.Detail)
		}
		want := time.Date(2026, 10, 12, 6, 58, 1, 0, cst)
		if ev.Time.Truncate(time.Second).Unix() != want.Unix() {
			t.Fatalf("time %v want %v", ev.Time, want)
		}
	}
	if _, ok := ParseLine("Oct 12 06:58:01 mail sshd[1]: hello", now); ok {
		t.Fatal("non-postfix line parsed")
	}
	ev, ok := ParseLine("Oct 12 06:58:01 mail postfix/smtpd[1]: NOQUEUE: reject: RCPT from unknown[1.2.3.4]: 554 5.7.1 <x@y.com>: Relay access denied; from=<s@b.example> to=<x@y.com> proto=ESMTP helo=<h>", now)
	if !ok || !ev.Reject || ev.Detail != "554 5.7.1 <x@y.com>: Relay access denied" || ev.Fields["to"] != "x@y.com" {
		t.Fatalf("reject %+v", ev)
	}
	ev, _ = ParseLine("Oct 12 06:58:01 mail postfix/qmgr[1]: ABCDE12345: from=<a@b.c>, status=expired, returned to sender", now)
	if ev.Status != "expired" || ev.Detail != "returned to sender" {
		t.Fatalf("expired %+v", ev)
	}
}

func TestYearRollover(t *testing.T) {
	jan := time.Date(2027, 1, 1, 0, 10, 0, 0, cst)
	ev, _ := ParseLine("Dec 31 23:59:00 mail postfix/qmgr[1]: ABCDE12345: removed", jan)
	if ev.Time.Year() != 2026 {
		t.Fatalf("year %d", ev.Time.Year())
	}
}

func scanFixture(t *testing.T, since time.Time, fn func(Event), dk func(DKIMSignature)) {
	f, err := os.Open("../../testdata/mail.log")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := Scan(f, now, since, fn, dk); err != nil {
		t.Fatal(err)
	}
}

func TestStats(t *testing.T) {
	a := NewAggregator("")
	scanFixture(t, time.Time{}, a.Add, a.AddDKIM)
	s := a.Result(10)
	if s.Totals.Sent == 0 || s.Totals.Bounced != 26 || s.Totals.Rejected != 30 || s.Totals.Expired != 1 {
		t.Fatalf("totals %+v", s.Totals)
	}
	if s.Totals.Received != s.Totals.Sent+s.Totals.Bounced+(s.Totals.Deferred) {
		t.Logf("received %d (each message is received once)", s.Totals.Received)
	}
	if s.Deferrals[0].Category != "rate_limit" || s.Deferrals[0].Domains[0] != "gmail.com" {
		t.Fatalf("deferrals %+v", s.Deferrals[0])
	}
	if len(s.Deferrals[0].Remotes) == 0 || s.Deferrals[0].Remotes[0] != "gmail-smtp-in.l.google.com" {
		t.Fatalf("remotes %+v", s.Deferrals[0].Remotes)
	}
	cats := map[string]int{}
	for _, b := range s.Bounces {
		cats[b.Category] += b.Count
	}
	if cats["recipient_unknown"] != 12 || cats["blocklist"] != 14 {
		t.Fatalf("bounces %+v", cats)
	}
	if s.Rejects[0].Category != "relay_denied" {
		t.Fatalf("rejects %+v", s.Rejects)
	}
	failing := map[string]bool{}
	for _, d := range s.StillFailing {
		failing[d.Domain] = true
	}
	if !failing["gmail.com"] || !failing["oldcorp.example"] || failing["fastmail.com"] {
		t.Fatalf("still failing %+v", s.StillFailing)
	}
	if len(s.DKIM) != 1 || s.DKIM[0].Selector != "mail" || s.DKIM[0].Domain != "example.com" {
		t.Fatalf("dkim %+v", s.DKIM)
	}
}

func TestStatsWindowAndDomain(t *testing.T) {
	all := NewAggregator("")
	scanFixture(t, time.Time{}, all.Add, nil)
	recent := NewAggregator("yahoo.com")
	scanFixture(t, now.Add(-2*time.Hour), recent.Add, nil)
	ra, rr := all.Result(0), recent.Result(0)
	if rr.Events >= ra.Events || rr.Events == 0 {
		t.Fatalf("window not applied: %d vs %d", rr.Events, ra.Events)
	}
	for _, d := range rr.Domains {
		if d.Domain != "yahoo.com" {
			t.Fatalf("domain filter: %s", d.Domain)
		}
	}
}

func TestTrace(t *testing.T) {
	tr := NewTrace("old.user3@yahoo.com")
	scanFixture(t, time.Time{}, tr.Add, nil)
	res := tr.Result(0)
	if len(res) != 2 {
		t.Fatalf("want message + bounce notice, got %+v", res)
	}
	if res[0].FinalStatus != "bounced" || res[1].BounceOf != res[0].QueueID {
		t.Fatalf("trace %+v", res)
	}
	byID := NewTrace(res[0].QueueID)
	scanFixture(t, time.Time{}, byID.Add, nil)
	if r := byID.Result(0); len(r) < 1 || r[0].QueueID != res[0].QueueID || len(r[0].Events) < 4 {
		t.Fatalf("by id %+v", r)
	}
}
