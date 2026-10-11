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
