package queue

import (
	"os"
	"strings"
	"testing"
	"time"
)

var now = time.Unix(1791759600, 0)

func load(t *testing.T) []Message {
	f, err := os.Open("../../testdata/queue.json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	m, err := Parse(f)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestParseAndSummarize(t *testing.T) {
	msgs := load(t)
	if len(msgs) != 212 {
		t.Fatalf("parsed %d messages", len(msgs))
	}
	s := Summarize(msgs, now, 5)
	if s.ByQueue[0].Key != "deferred" || s.ByQueue[0].Count != 205 {
		t.Fatalf("by queue: %+v", s.ByQueue)
	}
	if s.Reasons[0].Category != "rate_limit" || s.Reasons[0].Count != 150 {
		t.Fatalf("top reason: %+v", s.Reasons[0])
	}
	if got := strings.Join(s.Reasons[0].Domains, ","); got != "gmail.com,googlemail.com" {
		t.Fatalf("domains %s", got)
	}
	if s.OldestAgeSecs < 40*3600 {
		t.Fatalf("oldest %s", s.OldestAge)
	}
}

func TestParseEmptyQueue(t *testing.T) {
	m, err := Parse(strings.NewReader("Mail queue is empty\n"))
	if err != nil || len(m) != 0 {
		t.Fatal(m, err)
	}
	if _, err := Parse(strings.NewReader("{bad json\n")); err == nil {
		t.Fatal("expected error")
	}
}

func TestFilter(t *testing.T) {
	msgs := load(t)
	got := Filter{Domain: ".outlook.com"}.Apply(msgs, now)
	if len(got) != 23 {
		t.Fatalf("outlook: %d", len(got))
	}
	got = Filter{Category: "timeout", MinAge: 10 * time.Hour}.Apply(msgs, now)
	for _, m := range got {
		if Domain(m.Recipients[0].Address) != "oldcorp.example" || now.Sub(m.Arrival()) < 10*time.Hour {
			t.Fatalf("bad match %+v", m)
		}
	}
	if len(Filter{Queue: "hold"}.Apply(msgs, now)) != 1 {
		t.Fatal("hold")
	}
}

func TestShape(t *testing.T) {
	msgs := []Message{
		{QueueName: "deferred", ArrivalTime: now.Unix() - 60, Recipients: []Recipient{{Address: "a@x.com"}, {Address: "b@x.com"}}},
		{QueueName: "deferred", ArrivalTime: now.Unix() - 7*60, Recipients: []Recipient{{Address: "a@y.com"}}},
		{QueueName: "deferred", ArrivalTime: now.Unix() - 3000*60, Recipients: []Recipient{{Address: "a@x.com"}}},
		{QueueName: "active", ArrivalTime: now.Unix(), Recipients: []Recipient{{Address: "a@z.com"}}},
	}
	sh := BuildShape(msgs, now, "deferred", "", 0)
	if sh.Total.Total != 3 || len(sh.Rows) != 2 || sh.Rows[0].Domain != "x.com" || sh.Rows[0].Total != 2 {
		t.Fatalf("%+v", sh)
	}
	if sh.Rows[0].Cells[0] != 1 || sh.Rows[0].Cells[len(BucketEdges)] != 1 || sh.Rows[1].Cells[1] != 1 {
		t.Fatalf("cells %+v", sh.Rows)
	}
	if !strings.Contains(sh.Text(), "1280+") {
		t.Fatal(sh.Text())
	}
}

func TestDomainAndAge(t *testing.T) {
	if Domain("<Bob@Example.COM>") != "example.com" || Domain("") != "<>" || Domain("root") != "localhost" {
		t.Fatal("Domain")
	}
	if HumanAge(26*time.Hour) != "1d2h" || HumanAge(90*time.Minute) != "1h30m" || HumanAge(5*time.Minute) != "5m" {
		t.Fatal("HumanAge")
	}
}
