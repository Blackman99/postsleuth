package mcpserver

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Blackman99/postsleuth/internal/doctor"
	"github.com/Blackman99/postsleuth/internal/postfix"
)

// fakePostfix puts stub postqueue/postsuper/postconf scripts on PATH that
// record their arguments.
func fakePostfix(t *testing.T) string {
	dir := t.TempDir()
	rec := filepath.Join(dir, "calls.log")
	for _, n := range []string{"postqueue", "postsuper", "postconf"} {
		script := "#!/bin/sh\necho \"" + n + " $*\" >> " + rec + "\n"
		if n == "postconf" {
			script += "echo 'myhostname = mail.example.com'\necho 'relayhost = [smtp.relay.example]:587'\necho 'smtp_sasl_password = hunter2'\n"
		}
		if err := os.WriteFile(filepath.Join(dir, n), []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return rec
}

func connect(t *testing.T, allow bool) *mcp.ClientSession {
	env := &doctor.Env{
		Runner:    postfix.Runner{},
		Logs:      postfix.LogSource{Files: []string{"../../testdata/mail.log"}},
		QueueFile: "../../testdata/queue.json",
		Now:       func() time.Time { return time.Unix(1791759600, 0).In(time.FixedZone("CST", 8*3600)) },
	}
	srv := New(env, Options{Version: "test", AllowMutations: allow})
	st, ct := mcp.NewInMemoryTransports()
	ctx := context.Background()
	if _, err := srv.Connect(ctx, st, nil); err != nil {
		t.Fatal(err)
	}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "test"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cs.Close() })
	return cs
}

func tools(t *testing.T, cs *mcp.ClientSession) map[string]*mcp.Tool {
	res, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	m := map[string]*mcp.Tool{}
	for _, tl := range res.Tools {
		m[tl.Name] = tl
	}
	return m
}

func call(t *testing.T, cs *mcp.ClientSession, name string, args map[string]any) (map[string]any, *mcp.CallToolResult) {
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if res.StructuredContent != nil {
		b, _ := json.Marshal(res.StructuredContent)
		_ = json.Unmarshal(b, &out)
	}
	return out, res
}

func TestReadOnlyByDefault(t *testing.T) {
	fakePostfix(t)
	cs := connect(t, false)
	ts := tools(t, cs)
	for _, n := range []string{"postfix_doctor", "postfix_queue_summary", "postfix_queue_list", "postfix_queue_shape", "postfix_log_stats", "postfix_log_trend", "postfix_log_trace", "mail_dns_check", "postfix_config", "postfix_reason_categories"} {
		tl, ok := ts[n]
		if !ok {
			t.Fatalf("missing tool %s", n)
		}
		if tl.Annotations == nil || !tl.Annotations.ReadOnlyHint {
			t.Errorf("%s not annotated read-only", n)
		}
	}
	for n := range ts {
		if strings.Contains(n, "flush") || strings.Contains(n, "delete") || strings.Contains(n, "requeue") || strings.Contains(n, "hold") || strings.Contains(n, "release") {
			t.Fatalf("mutating tool %s exposed without --allow-mutations", n)
		}
	}
}

func TestQueueAndLogTools(t *testing.T) {
	fakePostfix(t)
	cs := connect(t, false)
	out, res := call(t, cs, "postfix_queue_summary", map[string]any{"queue": "deferred", "top": 3})
	if res.IsError || out["messages"].(float64) != 205 {
		t.Fatalf("summary %v %v", out, res.Content)
	}
	out, _ = call(t, cs, "postfix_queue_list", map[string]any{"category": "dns", "limit": 2})
	if out["matched"].(float64) != 4 || out["returned"].(float64) != 2 {
		t.Fatalf("list %v", out)
	}
	out, _ = call(t, cs, "postfix_queue_shape", map[string]any{"top": 3})
	if !strings.Contains(out["text"].(string), "gmail.com") {
		t.Fatalf("shape %v", out)
	}
	out, _ = call(t, cs, "postfix_log_stats", map[string]any{"since": "all"})
	st := out["stats"].(map[string]any)
	if st["totals"].(map[string]any)["bounced"].(float64) != 26 {
		t.Fatalf("log %v", st["totals"])
	}
	out, _ = call(t, cs, "postfix_log_trend", map[string]any{"since": "all", "top": 5})
	tr := out["trend"].(map[string]any)
	if tr["bucket"] == "" || len(tr["domains"].([]any)) == 0 {
		t.Fatalf("trend %v", out)
	}
	out, _ = call(t, cs, "postfix_log_trace", map[string]any{"query": "old.user3@yahoo.com", "since": "all"})
	if len(out["messages"].([]any)) != 2 {
		t.Fatalf("trace %v", out)
	}
	out, _ = call(t, cs, "postfix_config", map[string]any{})
	set := out["settings"].(map[string]any)
	if set["relayhost"] != "[smtp.relay.example]:587" {
		t.Fatalf("config %v", out)
	}
	if _, leaked := set["smtp_sasl_password"]; leaked {
		t.Fatal("secret leaked")
	}
	out, _ = call(t, cs, "postfix_doctor", map[string]any{"since": "all", "skip_dns": true})
	if out["problems"].(float64) == 0 {
		t.Fatalf("doctor found nothing: %v", out["findings"])
	}
}

func TestMutationsNeedFlagAndConfirm(t *testing.T) {
	rec := fakePostfix(t)
	cs := connect(t, true)
	ts := tools(t, cs)
	del, ok := ts["postfix_queue_delete"]
	if !ok || del.Annotations.ReadOnlyHint || del.Annotations.DestructiveHint == nil || !*del.Annotations.DestructiveHint {
		t.Fatalf("delete tool: %+v", del)
	}
	_, res := call(t, cs, "postfix_queue_delete", map[string]any{"queue_ids": []string{"ABCDE12345"}})
	if !res.IsError {
		t.Fatal("delete without confirm succeeded")
	}
	_, res = call(t, cs, "postfix_queue_delete", map[string]any{"queue_ids": []string{"ALL"}, "confirm": true})
	if !res.IsError {
		t.Fatal("delete ALL succeeded")
	}
	_, res = call(t, cs, "postfix_queue_delete", map[string]any{"queue_ids": []string{"-d"}, "confirm": true})
	if !res.IsError {
		t.Fatal("flag injection accepted")
	}
	if b, _ := os.ReadFile(rec); strings.Contains(string(b), "postsuper") {
		t.Fatalf("postsuper ran: %s", b)
	}
	out, res := call(t, cs, "postfix_queue_requeue", map[string]any{"queue_ids": []string{"ABCDE12345"}, "confirm": true})
	if res.IsError {
		t.Fatalf("requeue failed: %v", res.Content)
	}
	if ran := out["ran"].([]any); len(ran) != 1 || ran[0] != "postsuper -r ABCDE12345" {
		t.Fatalf("ran %v", out)
	}
	_, _ = call(t, cs, "postfix_queue_flush", map[string]any{"site": "gmail.com", "confirm": true})
	b, _ := os.ReadFile(rec)
	if !strings.Contains(string(b), "postsuper -r ABCDE12345") || !strings.Contains(string(b), "postqueue -s gmail.com") {
		t.Fatalf("calls: %s", b)
	}
}
