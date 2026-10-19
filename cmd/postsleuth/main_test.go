package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestMutationsRefusedWithoutFlag(t *testing.T) {
	for _, cmd := range []string{"delete", "requeue", "hold", "release", "flush"} {
		var out, errb bytes.Buffer
		if ec := run([]string{cmd, "ABCDE12345"}, &out, &errb); ec != 2 || !strings.Contains(errb.String(), "--allow-mutations") {
			t.Fatalf("%s: exit %d, %q", cmd, ec, errb.String())
		}
	}
}

func TestQueueAndDoctorFromFiles(t *testing.T) {
	var out, errb bytes.Buffer
	ec := run([]string{"queue", "--queue-file", "../../testdata/queue.json", "--no-color"}, &out, &errb)
	if ec != 0 || !strings.Contains(out.String(), "rate_limit") {
		t.Fatalf("queue: %d %s %s", ec, out.String(), errb.String())
	}
	out.Reset()
	ec = run([]string{"doctor", "--queue-file", "../../testdata/queue.json", "--log", "../../testdata/mail.log", "--since", "all", "--no-dns", "--no-color"}, &out, &errb)
	if ec != 1 || !strings.Contains(out.String(), "SHAPE") || !strings.Contains(out.String(), "still failing") {
		t.Fatalf("doctor: %d\n%s\n%s", ec, out.String(), errb.String())
	}
	out.Reset()
	ec = run([]string{"trace", "old.user3@yahoo.com", "--log", "../../testdata/mail.log", "--since", "all", "--no-color"}, &out, &errb)
	if ec != 0 || !strings.Contains(out.String(), "bounced") {
		t.Fatalf("trace: %d %s", ec, out.String())
	}
	out.Reset()
	ec = run([]string{"trend", "--log", "../../testdata/mail.log", "--since", "all", "--no-color", "--top", "5"}, &out, &errb)
	if ec != 0 || !strings.Contains(out.String(), "TREND") || !strings.Contains(out.String(), "gmail.com") {
		t.Fatalf("trend: %d %s %s", ec, out.String(), errb.String())
	}
}

func TestBadInput(t *testing.T) {
	var out, errb bytes.Buffer
	if ec := run([]string{"nope"}, &out, &errb); ec != 2 {
		t.Fatal(ec)
	}
	if ec := run([]string{"log", "--since", "yesterday", "--log", "../../testdata/mail.log"}, &out, &errb); ec != 2 {
		t.Fatal(ec)
	}
	if ec := run([]string{"version"}, &out, &errb); ec != 0 || !strings.Contains(out.String(), "postsleuth") {
		t.Fatal(ec)
	}
}

func TestPlaybookCommand(t *testing.T) {
	files := []string{"--queue-file", "../../testdata/queue.json", "--log", "../../testdata/mail.log", "--since", "all", "--no-color"}
	cases := []struct {
		args []string
		want []string
		not  []string
	}{
		{append([]string{"playbook"}, files...), []string{"2 provider playbooks match", "gmail-4.7.28", "microsoft-s3150", "temporary (Postfix retries)", "permanent (retrying won't help)", "https://support.google.com/mail/answer/81126"}, nil},
		{append([]string{"playbook", "microsoft"}, files...), []string{"microsoft-s3150", "SNDS"}, []string{"gmail-4.7.28"}},
		{append([]string{"playbook", "yahoo"}, files...), []string{"nothing failing at Yahoo", "--list"}, nil},
		{[]string{"playbook", "--list", "--no-color"}, []string{"18 built-in", "gmail-4.7.28", "microsoft-s3150", "yahoo-tss09"}, nil},
		{[]string{"playbook", "Gmail-4.7.28", "--no-color"}, []string{"PLAYBOOK gmail-4.7.28", "gmail_destination_concurrency_limit = 1"}, []string{"temporary"}},
		{[]string{"playbook", "--no-color", "--reply", "host mta5.am0.yahoodns.net[192.0.2.70] said: 421 4.7.0 [TSS04] Messages from 203.0.113.7 temporarily deferred due to unexpected volume or user complaints"}, []string{"yahoo-deferred", "Yahoo TSS04", "temporary"}, nil},
		{[]string{"playbook", "--no-color", "--reply", "550 5.1.1 <a@example.net>: User unknown"}, []string{"no playbook", "recipient_unknown"}, nil},
	}
	for _, c := range cases {
		var out, errb bytes.Buffer
		if ec := run(c.args, &out, &errb); ec != 0 {
			t.Fatalf("%v: exit %d %s", c.args, ec, errb.String())
		}
		for _, w := range c.want {
			if !strings.Contains(out.String(), w) {
				t.Errorf("%v: missing %q in\n%s", c.args, w, out.String())
			}
		}
		for _, w := range c.not {
			if strings.Contains(out.String(), w) {
				t.Errorf("%v: unexpected %q in\n%s", c.args, w, out.String())
			}
		}
	}
	var out, errb bytes.Buffer
	if ec := run(append([]string{"playbook", "--json"}, files...), &out, &errb); ec != 0 || !strings.Contains(out.String(), `"playbooks"`) || !strings.Contains(out.String(), `"codes_seen"`) {
		t.Fatalf("json: %d %s %s", ec, out.String(), errb.String())
	}
	out.Reset()
	errb.Reset()
	if ec := run([]string{"playbook", "hotmail"}, &out, &errb); ec != 2 || !strings.Contains(errb.String(), "postsleuth playbook --list") {
		t.Fatalf("unknown: %d %q", ec, errb.String())
	}
	out.Reset()
	if ec := run(append([]string{"doctor", "--no-dns", "--json"}, files...), &out, &errb); ec != 1 || !strings.Contains(out.String(), `"provider_playbooks"`) || !strings.Contains(out.String(), `"area": "provider"`) {
		t.Fatalf("doctor json: %d", ec)
	}
	out.Reset()
	run(append([]string{"doctor", "--no-dns"}, files...), &out, &errb)
	if !strings.Contains(out.String(), "PLAYBOOK 2 provider playbooks match what is failing here") || !strings.Contains(out.String(), "+ 5 more steps") {
		t.Fatalf("doctor text:\n%s", out.String())
	}
}
