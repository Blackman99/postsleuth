package postfix

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidQueueID(t *testing.T) {
	good := []string{
		"F543B5DFCE", "4F2A1C3B9", "ABCDE12345", "CAF4941D40", "1A2B3C", // short: hex
		"4bNqJx2rG9z1Hk", "3zPVgK0lLzz4y8V", "4XrB9q0QwDz7cy", // long: base52 time, z, base51 inode
	}
	bad := []string{
		"", "ALL", "all", "AlL", "-d", "--help", "-q", "ABCDE", // too short
		"abcde12345",     // lower-case is not short form and has no z separator
		"4bNqJx2rG9z1Hz", // 'z' is not a base-51 inode digit
		"4bNqJx2rGaz1Hk", // vowel
		"ABC DEF123", "ABCDEF;rm", "ABCDEF|x", "$(id)", "ABCDEF`id`", "ABCDEF\n", "../../etc", "ABCDEF*",
		"ÄBCDEF123",
		strings.Repeat("A", 33),
	}
	for _, id := range good {
		if !ValidQueueID(id) {
			t.Errorf("rejected valid queue ID %q", id)
		}
	}
	for _, id := range bad {
		if ValidQueueID(id) {
			t.Errorf("accepted invalid queue ID %q", id)
		}
	}
	if err := checkIDs([]string{"ALL"}); err == nil || !strings.Contains(err.Error(), "ALL is never accepted") {
		t.Fatalf("ALL: %v", err)
	}
	if err := checkIDs(nil); err == nil {
		t.Fatal("empty ID list accepted")
	}
}

// stub puts a fake postcat on PATH that records its arguments.
func stub(t *testing.T, body string) string {
	dir := t.TempDir()
	rec := filepath.Join(dir, "calls.log")
	script := "#!/bin/sh\necho \"postcat $*\" >> " + rec + "\n" + body
	if err := os.WriteFile(filepath.Join(dir, "postcat"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return rec
}

func TestQueueMessage(t *testing.T) {
	rec := stub(t, "echo '*** ENVELOPE RECORDS deferred/F/F543B5DFCE ***'\n")
	out, err := Runner{}.QueueMessage(context.Background(), "F543B5DFCE")
	if err != nil || !strings.Contains(out, "ENVELOPE RECORDS") {
		t.Fatalf("%q %v", out, err)
	}
	b, _ := os.ReadFile(rec)
	if strings.TrimSpace(string(b)) != "postcat -e -h -q F543B5DFCE" {
		t.Fatalf("ran %q (the body flag -b must never be used)", b)
	}
	for _, id := range []string{"ALL", "-b", "F543B5DFCE; cat /etc/shadow"} {
		if _, err := (Runner{}).QueueMessage(context.Background(), id); err == nil || !strings.Contains(err.Error(), "invalid queue ID") {
			t.Fatalf("%q: %v", id, err)
		}
	}
	b, _ = os.ReadFile(rec)
	if strings.Count(string(b), "\n") != 1 {
		t.Fatalf("postcat ran for an invalid ID: %q", b)
	}
}

func TestQueueMessageNotQueued(t *testing.T) {
	stub(t, "echo 'postcat: fatal: open queue file F543B5DFCE: No such file or directory' >&2\nexit 1\n")
	_, err := Runner{}.QueueMessage(context.Background(), "F543B5DFCE")
	if !errors.Is(err, ErrNotQueued) || !strings.Contains(err.Error(), "postsleuth trace F543B5DFCE") {
		t.Fatalf("%v", err)
	}
}
