// Package queue parses `postqueue -j` output and summarises the Postfix queue,
// including a qshape-style age-by-domain matrix.
package queue

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/Blackman99/postsleuth/internal/provider"
	"github.com/Blackman99/postsleuth/internal/reason"
)

// Recipient is one undelivered recipient of a queued message.
type Recipient struct {
	Address     string `json:"address"`
	DelayReason string `json:"delay_reason,omitempty"`
}

// Message is one line of `postqueue -j` output.
type Message struct {
	QueueName    string      `json:"queue_name"`
	QueueID      string      `json:"queue_id"`
	ArrivalTime  int64       `json:"arrival_time"`
	MessageSize  int64       `json:"message_size"`
	ForcedExpire bool        `json:"forced_expire"`
	Sender       string      `json:"sender"`
	Recipients   []Recipient `json:"recipients"`
}

// Arrival returns the arrival time.
func (m Message) Arrival() time.Time { return time.Unix(m.ArrivalTime, 0) }

// Parse reads newline-delimited JSON objects as written by `postqueue -j`.
func Parse(r io.Reader) ([]Message, error) {
	var out []Message
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 64*1024*1024)
	n := 0
	for sc.Scan() {
		n++
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		if line[0] != '{' {
			// "Mail queue is empty" or a wrapper's banner.
			continue
		}
		var m Message
		if err := json.Unmarshal(line, &m); err != nil {
			return out, fmt.Errorf("postqueue -j line %d: %w", n, err)
		}
		out = append(out, m)
	}
	return out, sc.Err()
}

// Domain returns the lower-cased domain part of an address ("" -> "<>", no @ -> "localhost").
func Domain(addr string) string {
	addr = strings.Trim(strings.TrimSpace(addr), "<>")
	if addr == "" {
		return "<>"
	}
	i := strings.LastIndexByte(addr, '@')
	if i < 0 {
		return "localhost"
	}
	return strings.ToLower(addr[i+1:])
}

// Filter selects messages.
type Filter struct {
	Queue          string // active, deferred, hold, incoming, maildrop, corrupt; "" = all
	Domain         string // recipient domain (exact, or suffix with leading ".")
	Sender         string // substring of sender
	ReasonContains string // case-insensitive substring of any delay_reason
	Category       string // reason category id
	MinAge         time.Duration
}

func domainMatch(d, want string) bool {
	want = strings.ToLower(want)
	if strings.HasPrefix(want, ".") {
		return strings.HasSuffix(d, want) || d == want[1:]
	}
	return d == want
}

// Apply returns the messages matching f.
func (f Filter) Apply(msgs []Message, now time.Time) []Message {
	var out []Message
	for _, m := range msgs {
		if f.Queue != "" && m.QueueName != f.Queue {
			continue
		}
		if f.Sender != "" && !strings.Contains(strings.ToLower(m.Sender), strings.ToLower(f.Sender)) {
			continue
		}
		if f.MinAge > 0 && now.Sub(m.Arrival()) < f.MinAge {
			continue
		}
		if f.Domain != "" || f.ReasonContains != "" || f.Category != "" {
			ok := false
			for _, r := range m.Recipients {
				if f.Domain != "" && !domainMatch(Domain(r.Address), f.Domain) {
					continue
				}
				if f.ReasonContains != "" && !strings.Contains(strings.ToLower(r.DelayReason), strings.ToLower(f.ReasonContains)) {
					continue
				}
				if f.Category != "" && reason.Classify(r.DelayReason).ID != f.Category {
					continue
				}
				ok = true
				break
			}
			if !ok {
				continue
			}
		}
		out = append(out, m)
	}
	return out
}

// Count is a labelled counter.
type Count struct {
	Key   string `json:"key"`
	Count int    `json:"count"`
}

// ReasonCount groups recipients by normalised delay reason.
type ReasonCount struct {
	Reason   string   `json:"reason"`
	Category string   `json:"category"`
	Hint     string   `json:"hint"`
	Count    int      `json:"recipients"`
	Domains  []string `json:"domains"`
	Example  string   `json:"example"`
	// Provider (gmail, microsoft, yahoo) and provider playbook id, if any.
	Provider string `json:"provider,omitempty"`
	Playbook string `json:"playbook,omitempty"`
}

// Summary is an overview of the queue.
type Summary struct {
	Total         int           `json:"messages"`
	Recipients    int           `json:"recipients"`
	Bytes         int64         `json:"bytes"`
	ByQueue       []Count       `json:"by_queue"`
	TopDomains    []Count       `json:"top_recipient_domains"`
	TopSenders    []Count       `json:"top_sender_domains"`
	Reasons       []ReasonCount `json:"reasons"`
	OldestID      string        `json:"oldest_queue_id,omitempty"`
	OldestAge     string        `json:"oldest_age,omitempty"`
	OldestAgeSecs int64         `json:"oldest_age_seconds,omitempty"`
	ForcedExpire  int           `json:"forced_expire"`
}

func sortedCounts(m map[string]int, top int) []Count {
	out := make([]Count, 0, len(m))
	for k, v := range m {
		out = append(out, Count{k, v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Key < out[j].Key
	})
	if top > 0 && len(out) > top {
		out = out[:top]
	}
	return out
}

// Summarize builds a Summary; top limits the per-list length (0 = no limit).
func Summarize(msgs []Message, now time.Time, top int) Summary {
	s := Summary{Total: len(msgs)}
	byQ, byD, byS := map[string]int{}, map[string]int{}, map[string]int{}
	type agg struct {
		rc      ReasonCount
		domains map[string]bool
	}
	reasons := map[string]*agg{}
	var oldest *Message
	for i := range msgs {
		m := &msgs[i]
		byQ[m.QueueName]++
		byS[Domain(m.Sender)]++
		s.Bytes += m.MessageSize
		if m.ForcedExpire {
			s.ForcedExpire++
		}
		if oldest == nil || m.ArrivalTime < oldest.ArrivalTime {
			oldest = m
		}
		for _, r := range m.Recipients {
			s.Recipients++
			d := Domain(r.Address)
			byD[d]++
			if r.DelayReason == "" {
				continue
			}
			key := reason.Normalize(r.DelayReason)
			a := reasons[key]
			if a == nil {
				c := reason.Classify(r.DelayReason)
				pm := provider.Lookup(r.DelayReason, d)
				a = &agg{rc: ReasonCount{Reason: key, Category: c.ID, Hint: c.Hint, Example: r.DelayReason, Provider: pm.Provider, Playbook: pm.ID}, domains: map[string]bool{}}
				reasons[key] = a
			}
			a.rc.Count++
			a.domains[d] = true
		}
	}
	s.ByQueue = sortedCounts(byQ, 0)
	s.TopDomains = sortedCounts(byD, top)
	s.TopSenders = sortedCounts(byS, top)
	for _, a := range reasons {
		for d := range a.domains {
			a.rc.Domains = append(a.rc.Domains, d)
		}
		sort.Strings(a.rc.Domains)
		if len(a.rc.Domains) > 8 {
			a.rc.Domains = append(a.rc.Domains[:8], fmt.Sprintf("+%d more", len(a.domains)-8))
		}
		s.Reasons = append(s.Reasons, a.rc)
	}
	sort.Slice(s.Reasons, func(i, j int) bool {
		if s.Reasons[i].Count != s.Reasons[j].Count {
			return s.Reasons[i].Count > s.Reasons[j].Count
		}
		return s.Reasons[i].Reason < s.Reasons[j].Reason
	})
	if top > 0 && len(s.Reasons) > top {
		s.Reasons = s.Reasons[:top]
	}
	if oldest != nil {
		age := now.Sub(oldest.Arrival())
		s.OldestID = oldest.QueueID
		s.OldestAge = HumanAge(age)
		s.OldestAgeSecs = int64(age.Seconds())
	}
	return s
}

// HumanAge formats a duration as 3d4h, 5h12m, 7m.
func HumanAge(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	switch {
	case d >= 24*time.Hour:
		return fmt.Sprintf("%dd%dh", int(d.Hours())/24, int(d.Hours())%24)
	case d >= time.Hour:
		return fmt.Sprintf("%dh%dm", int(d.Hours()), int(d.Minutes())%60)
	default:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	}
}
