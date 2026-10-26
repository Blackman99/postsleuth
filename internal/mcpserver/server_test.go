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
	for _, n := range []string{"postqueue", "postsuper", "postconf", "postcat"} {
		script := "#!/bin/sh\necho \"" + n + " $*\" >> " + rec + "\n"
		if n == "postcat" {
			fixture, _ := filepath.Abs("../../testdata/postcat-F543B5DFCE.txt")
			script += "cat " + fixture + "\n"
		}
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
	for _, n := range []string{"postfix_doctor", "postfix_queue_summary", "postfix_queue_list", "postfix_queue_shape", "postfix_log_stats", "postfix_log_trend", "postfix_log_trace", "mail_dns_check", "postfix_config", "postfix_reason_categories", "postfix_provider_playbook", "postfix_queue_message"} {
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

func TestProviderPlaybookTool(t *testing.T) {
	fakePostfix(t)
	cs := connect(t, false)
	if d := tools(t, cs)["postfix_provider_playbook"].Description; !strings.Contains(d, "4.7.28") || !strings.Contains(d, "S3150") || !strings.Contains(d, "TSS04") {
		t.Fatalf("description: %s", d)
	}
	out, res := call(t, cs, "postfix_provider_playbook", map[string]any{"since": "all"})
	if res.IsError || out["mode"] != "server" {
		t.Fatalf("server %v %v", out, res.Content)
	}
	pbs := out["server"].(map[string]any)["playbooks"].([]any)
	if len(pbs) != 2 || pbs[0].(map[string]any)["playbook"].(map[string]any)["id"] != "gmail-4.7.28" {
		t.Fatalf("playbooks %v", pbs)
	}
	out, _ = call(t, cs, "postfix_provider_playbook", map[string]any{"since": "all", "provider": "yahoo"})
	if len(out["server"].(map[string]any)["playbooks"].([]any)) != 0 || len(out["available"].([]any)) != 18 {
		t.Fatalf("yahoo filter %v", out)
	}
	out, _ = call(t, cs, "postfix_provider_playbook", map[string]any{"reply": "550 5.7.1 Unfortunately, messages from [203.0.113.7] weren't sent. Please contact your Internet service provider since part of their network is on our block list (S3150).", "domain": "outlook.com"})
	lk := out["lookup"].(map[string]any)
	if lk["code"] != "S3150" || lk["temporary"] != false || lk["playbook"].(map[string]any)["id"] != "microsoft-s3150" {
		t.Fatalf("reply %v", lk)
	}
	out, _ = call(t, cs, "postfix_provider_playbook", map[string]any{"id": "yahoo-tss09"})
	if out["playbook"].(map[string]any)["provider"] != "yahoo" {
		t.Fatalf("id %v", out)
	}
	if _, res = call(t, cs, "postfix_provider_playbook", map[string]any{"id": "gmail-9.9.9"}); !res.IsError {
		t.Fatal("unknown id accepted")
	}
	if _, res = call(t, cs, "postfix_provider_playbook", map[string]any{"provider": "aol"}); !res.IsError {
		t.Fatal("unknown provider accepted")
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

func TestQueueMessageTool(t *testing.T) {
	rec := fakePostfix(t)
	cs := connect(t, false)
	tl := tools(t, cs)["postfix_queue_message"]
	if tl == nil || tl.Annotations == nil || !tl.Annotations.ReadOnlyHint || tl.Annotations.DestructiveHint != nil && *tl.Annotations.DestructiveHint {
		t.Fatalf("tool %+v", tl)
	}
	schema, _ := json.Marshal(tl.InputSchema)
	if strings.Contains(string(schema), "redact") {
		t.Fatalf("MCP must not offer a way to turn redaction off: %s", schema)
	}
	out, res := call(t, cs, "postfix_queue_message", map[string]any{"queue_id": "F543B5DFCE"})
	if res.IsError {
		t.Fatalf("%v", res.Content)
	}
	if out["queue"] != "deferred" || out["redacted"] != true || len(out["hops"].([]any)) != 2 {
		t.Fatalf("%v", out)
	}
	b, _ := json.Marshal(out)
	for _, leak := range []string{"yuki342", "alerts@", "Jamie", "db-3", "alertd-demo-key"} {
		if strings.Contains(string(b), leak) {
			t.Errorf("MCP output leaks %q", leak)
		}
	}
	rc := out["recipients"].([]any)[0].(map[string]any)
	if rc["address"] != "[user-2]@gmail.com" || rc["playbook"] != "gmail-4.7.28" {
		t.Fatalf("recipient %v", rc)
	}
	for _, bad := range []string{"ALL", "-b", "F543B5DFCE --body", "../F543B5DFCE"} {
		if _, res := call(t, cs, "postfix_queue_message", map[string]any{"queue_id": bad}); !res.IsError {
			t.Errorf("%q accepted", bad)
		}
	}
	calls, _ := os.ReadFile(rec)
	if n := strings.Count(string(calls), "postcat "); n != 1 || !strings.Contains(string(calls), "postcat -e -h -q F543B5DFCE\n") {
		t.Fatalf("postcat calls: %q", calls)
	}
}
