// Package maillog parses Postfix syslog / journald / maillog_file lines and
// aggregates delivery outcomes per domain.
package maillog

import (
	"bufio"
	"compress/gzip"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Event is one parsed Postfix log line.
type Event struct {
	Time    time.Time         `json:"time"`
	Host    string            `json:"host,omitempty"`
	Program string            `json:"program"` // e.g. postfix/smtp
	QueueID string            `json:"queue_id,omitempty"`
	Fields  map[string]string `json:"fields,omitempty"`
	Status  string            `json:"status,omitempty"` // sent, deferred, bounced, expired, ...
	Detail  string            `json:"detail,omitempty"` // text after status=xxx, without parentheses
	Reject  bool              `json:"reject,omitempty"` // NOQUEUE: reject / milter-reject
	Raw     string            `json:"raw"`
}

// DKIMSignature is an "opendkim: ID: DKIM-Signature field added (s=sel, d=dom)" line.
type DKIMSignature struct {
	Selector string
	Domain   string
}

var (
	reLine = regexp.MustCompile(`^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d\d:\d\d:\d\d(?:\.\d+)?|\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:?\d\d)?)\s+(?P<host>\S+)\s+(?P<prog>[\w.\-]+(?:/[\w.\-]+)*)(?:\[\d+\])?:\s+(?P<msg>.*)$`)
	reQID  = regexp.MustCompile(`^([0-9A-Za-z]{5,32}):\s+(.*)$`)
	reKV   = regexp.MustCompile(`(\w+)=(<[^>]*>|[^,\s]+)`)
	reStat = regexp.MustCompile(`status=(\w+)(?:\s+\((.*)\)\s*$|,?\s*(.*)$)`)
	reDKIM = regexp.MustCompile(`DKIM-Signature (?:field|header) added \(s=([^,\s]+), d=([^)\s]+)\)`)
)

// tsLayouts are tried in order for ISO-like timestamps.
var tsLayouts = []string{
	time.RFC3339Nano, "2006-01-02T15:04:05.999999999-0700", "2006-01-02T15:04:05-0700",
	"2006-01-02 15:04:05.999999999-07:00", "2006-01-02 15:04:05", "2006-01-02T15:04:05",
}

// parseTime parses traditional "Oct 12 07:00:01" (assumed within the last year
// relative to now, local zone) or ISO timestamps.
func parseTime(s string, now time.Time) (time.Time, bool) {
	if len(s) > 0 && s[0] >= 'A' && s[0] <= 'Z' {
		f := strings.Fields(s)
		t, err := time.ParseInLocation("Jan 2 15:04:05.999999 2006", strings.Join(f, " ")+" "+strconv.Itoa(now.Year()), now.Location())
		if err != nil {
			return time.Time{}, false
		}
		if t.After(now.Add(48 * time.Hour)) {
			t = t.AddDate(-1, 0, 0)
		}
		return t, true
	}
	for _, l := range tsLayouts {
		if t, err := time.ParseInLocation(l, s, now.Location()); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

// ParseLine parses a single line. ok is false for non-Postfix lines.
func ParseLine(line string, now time.Time) (Event, bool) {
	m := reLine.FindStringSubmatch(line)
	if m == nil {
		return Event{}, false
	}
	prog := m[3]
	if !strings.HasPrefix(prog, "postfix") {
		return Event{}, false
	}
	t, _ := parseTime(m[1], now)
	ev := Event{Time: t, Host: m[2], Program: prog, Raw: line}
	msg := m[4]
	if strings.HasPrefix(msg, "NOQUEUE: ") {
		rest := strings.TrimPrefix(msg, "NOQUEUE: ")
		if strings.HasPrefix(rest, "reject:") || strings.HasPrefix(rest, "milter-reject:") {
			ev.Reject = true
			ev.Detail = rejectText(rest)
			ev.Fields = kv(rest)
		}
		return ev, true
	}
	if q := reQID.FindStringSubmatch(msg); q != nil {
		ev.QueueID = q[1]
		msg = q[2]
		if strings.HasPrefix(msg, "reject:") || strings.HasPrefix(msg, "milter-reject:") {
			ev.Reject = true
			ev.Detail = rejectText(msg)
		}
	}
	ev.Fields = kv(msg)
	if s := reStat.FindStringSubmatch(msg); s != nil {
		ev.Status = s[1]
		ev.Detail = strings.TrimSpace(s[2] + s[3])
	}
	if ev.Detail == "" && ev.Status == "" && !ev.Reject {
		ev.Detail = msg
	}
	return ev, true
}

// rejectText extracts "554 5.7.1 <x@y>: Relay access denied" from a reject line.
func rejectText(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(s, "milter-reject:"), "reject:"))
	s = reCmdFrom.ReplaceAllString(s, "")
	if j := strings.Index(s, "; from="); j >= 0 {
		s = s[:j]
	}
	return strings.TrimSpace(s)
}

var reCmdFrom = regexp.MustCompile(`^[A-Z][A-Z\-]* from \S+: `)

func kv(s string) map[string]string {
	out := map[string]string{}
	for _, m := range reKV.FindAllStringSubmatch(s, -1) {
		k := m[1]
		if k == "status" {
			continue
		}
		if _, dup := out[k]; dup {
			continue
		}
		out[k] = strings.Trim(m[2], "<>")
	}
	return out
}

// Source is something we can read lines from.
type Source struct {
	Name string
	R    io.Reader
}

// OpenFile opens a log file, transparently decompressing .gz. "-" is stdin.
func OpenFile(path string) (io.ReadCloser, error) {
	if path == "-" {
		return io.NopCloser(os.Stdin), nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	if strings.HasSuffix(path, ".gz") {
		gz, err := gzip.NewReader(f)
		if err != nil {
			f.Close()
			return nil, err
		}
		return struct {
			io.Reader
			io.Closer
		}{gz, f}, nil
	}
	return f, nil
}

// Scan reads r line by line, calling fn for every Postfix event whose time is
// at or after since (zero since = everything). DKIM signature lines are passed
// to dkim if non-nil.
func Scan(r io.Reader, now, since time.Time, fn func(Event), dkim func(DKIMSignature)) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if dkim != nil && strings.Contains(line, "DKIM-Signature") {
			if m := reDKIM.FindStringSubmatch(line); m != nil {
				dkim(DKIMSignature{Selector: m[1], Domain: strings.ToLower(m[2])})
			}
		}
		ev, ok := ParseLine(line, now)
		if !ok {
			continue
		}
		if !since.IsZero() && !ev.Time.IsZero() && ev.Time.Before(since) {
			continue
		}
		fn(ev)
	}
	return sc.Err()
}
