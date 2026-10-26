// Package message reads one queued message: the envelope records and the
// primary headers that `postcat -e -h -q ID` prints. The body is never read.
// Build turns that into a delivery-focused report and, by default, redacts
// personal data: local parts become stable pseudonyms, domains stay, and
// free-text headers are hidden.
package message

import (
	"bufio"
	"strconv"
	"strings"
	"time"
)

// RecordKind is the envelope record a recipient came from.
const (
	Pending   = "pending"   // recipient: not delivered yet
	Delivered = "delivered" // done_recipient: already delivered (or bounced)
	Canceled  = "canceled"  // canceled_recipient: dropped as a duplicate
)

// RawRecipient is one envelope recipient as stored in the queue file.
type RawRecipient struct {
	Address  string
	Original string // original_recipient, before aliasing/virtual mapping
	Status   string
}

// RawHeader is one primary header, unfolded.
type RawHeader struct {
	Name  string
	Value string
}

// Parsed is the postcat output split into its parts.
type Parsed struct {
	Path        string // e.g. deferred/C/CAF4941D40
	Queue       string // first path component: incoming, active, deferred, hold, corrupt
	QueueID     string // last path component
	Size        int64  // message_size: content length
	Arrival     time.Time
	Sender      string // "" is the null sender
	HasSender   bool
	Recipients  []RawRecipient
	Headers     []RawHeader
	BodyDropped int // lines after the headers that were ignored
}

// Parse reads postcat output. loc is the time zone of the mail server, used
// for message_arrival_time (postcat prints asctime without a zone).
func Parse(text string, loc *time.Location) Parsed {
	if loc == nil {
		loc = time.Local
	}
	var p Parsed
	const (
		secNone = iota
		secEnvelope
		secHeaders
		secBody
		secEnd
	)
	sec := secNone
	sawMarker := false
	orig := ""
	sc := bufio.NewScanner(strings.NewReader(text))
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		if strings.HasPrefix(line, "*** ") && strings.HasSuffix(line, " ***") {
			inner := strings.TrimSuffix(strings.TrimPrefix(line, "*** "), " ***")
			kind, path := inner, ""
			if i := strings.LastIndexByte(inner, ' '); i > 0 {
				kind, path = inner[:i], inner[i+1:]
			}
			sawMarker = true
			switch kind {
			case "ENVELOPE RECORDS", "HEADER EXTRACTED":
				sec = secEnvelope
			case "MESSAGE CONTENTS":
				sec = secHeaders
			case "MESSAGE FILE END":
				sec = secEnd
			default:
				continue
			}
			if p.Path == "" && path != "" {
				p.setPath(path)
			}
			continue
		}
		if !sawMarker && sec == secNone {
			// Plain headers (postcat -h) without the envelope.
			sec = secHeaders
		}
		switch sec {
		case secEnvelope:
			name, val, ok := strings.Cut(line, ": ")
			if !ok {
				name, val, ok = strings.Cut(line, ":")
				if !ok {
					continue
				}
			}
			val = strings.TrimSpace(val)
			switch name {
			case "message_size":
				if f := strings.Fields(val); len(f) > 0 {
					p.Size, _ = strconv.ParseInt(f[0], 10, 64)
				}
			case "message_arrival_time":
				if t, err := time.ParseInLocation(time.ANSIC, val, loc); err == nil {
					p.Arrival = t
				}
			case "sender":
				p.Sender, p.HasSender = val, true
			case "original_recipient":
				orig = val
			case "recipient", "done_recipient", "canceled_recipient":
				st := Pending
				if name == "done_recipient" {
					st = Delivered
				} else if name == "canceled_recipient" {
					st = Canceled
				}
				p.Recipients = append(p.Recipients, RawRecipient{Address: val, Original: orig, Status: st})
				orig = ""
			}
		case secHeaders:
			if line == "" {
				// End of the primary headers; anything after it is body.
				sec = secBody
				continue
			}
			if (line[0] == ' ' || line[0] == '\t') && len(p.Headers) > 0 {
				h := &p.Headers[len(p.Headers)-1]
				h.Value += " " + strings.TrimSpace(line)
				continue
			}
			name, val, ok := strings.Cut(line, ":")
			if !ok || name == "" || strings.ContainsAny(name, " \t") {
				continue
			}
			p.Headers = append(p.Headers, RawHeader{Name: name, Value: strings.TrimSpace(val)})
		case secBody:
			p.BodyDropped++
		}
	}
	return p
}

func (p *Parsed) setPath(path string) {
	p.Path = path
	parts := strings.Split(path, "/")
	if len(parts) >= 2 {
		p.Queue = parts[0]
		p.QueueID = parts[len(parts)-1]
	}
}

// Get returns the values of all headers with this name (case-insensitive).
func (p Parsed) Get(name string) []string {
	var out []string
	for _, h := range p.Headers {
		if strings.EqualFold(h.Name, name) {
			out = append(out, h.Value)
		}
	}
	return out
}
