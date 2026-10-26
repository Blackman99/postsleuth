package message

import (
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"
)

// secretHeader matches header names whose values are never shown, even with
// redaction off: credentials, cookies and session tokens sometimes leak into
// headers added by web apps and API gateways.
var secretHeader = regexp.MustCompile(`(?i)^(authorization|proxy-authorization|cookie|set-cookie|x-api-?key|x-auth-(token|key|pass).*|x-authorization|.*(token|secret|passw(or)?d|passwd|session|credential|api-?key|signature-input|x-csrf).*)$`)

// emailRe finds addresses in free text. '=' is not part of the local part so
// that "smtp.mailfrom=user@example.com" keeps its key.
var emailRe = regexp.MustCompile(`(?i)([a-z0-9!#$%&'*+/?^_` + "`" + `{|}~.-]+)@([a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+)`)

// roleLocals are not personal: keeping them makes bounces and reports readable.
var roleLocals = map[string]bool{
	"mailer-daemon": true, "postmaster": true, "double-bounce": true, "abuse": true,
	"noreply": true, "no-reply": true, "donotreply": true, "do-not-reply": true, "root": true,
	"bounce": true, "bounces": true, "hostmaster": true, "webmaster": true,
}

// redactor replaces local parts with stable pseudonyms ([user-1]@gmail.com);
// the same address always gets the same pseudonym within one report.
type redactor struct {
	on   bool
	seen map[string]string
}

func newRedactor(on bool) *redactor { return &redactor{on: on, seen: map[string]string{}} }

func (r *redactor) local(local, domain string) string {
	if !r.on || roleLocals[strings.ToLower(local)] {
		return local
	}
	key := strings.ToLower(local + "@" + domain)
	if t, ok := r.seen[key]; ok {
		return t
	}
	t := fmt.Sprintf("[user-%d]", len(r.seen)+1)
	r.seen[key] = t
	return t
}

// addr redacts one bare envelope address. "" is the null sender.
func (r *redactor) addr(a string) string {
	if a == "" {
		return "<>"
	}
	i := strings.LastIndexByte(a, '@')
	if i < 0 {
		if !r.on || roleLocals[strings.ToLower(a)] {
			return a
		}
		return r.local(a, "")
	}
	return r.local(a[:i], a[i+1:]) + a[i:]
}

// text redacts every address inside free text.
func (r *redactor) text(s string) string {
	if !r.on {
		return s
	}
	return emailRe.ReplaceAllStringFunc(s, func(m string) string {
		sub := emailRe.FindStringSubmatch(m)
		return r.local(sub[1], sub[2]) + "@" + sub[2]
	})
}

// addressList keeps only the addresses of an address header (From, To, ...):
// display names are personal and dropped when redacting.
func (r *redactor) addressList(v string) string {
	if !r.on {
		return v
	}
	ms := emailRe.FindAllStringSubmatch(v, -1)
	if len(ms) == 0 {
		if strings.TrimSpace(v) == "" || strings.Contains(v, "undisclosed-recipients") {
			return strings.TrimSpace(v)
		}
		return "[redacted]"
	}
	out := make([]string, 0, len(ms))
	for _, m := range ms {
		out = append(out, r.local(m[1], m[2])+"@"+m[2])
	}
	return strings.Join(out, ", ")
}

var (
	reAuthSender = regexp.MustCompile(`(?i)\(Authenticated sender:[^)]*\)`)
	reAuthWith   = regexp.MustCompile(`(?i)\bwith\s+(E?SMTPS?A|LMTPS?A|ESMTPSA|UTF8SMTPS?A)\b`)
	reFromClause = regexp.MustCompile(`(?i)^from\s+\S+(\s+\([^()]*\))?`)
	reTagB       = regexp.MustCompile(`(?i)(^|;)\s*(b|bh)\s*=[^;]*`)
	reTag        = regexp.MustCompile(`(?i)(?:^|;)\s*([a-z]+)\s*=\s*([^;]*)`)
	reMsgID      = regexp.MustCompile(`<([^<>@\s]+)@([^<>\s]+)>`)
	reSchemes    = regexp.MustCompile(`(?i)<\s*(mailto|https?):`)
)

// authenticatedHop reports whether a Received header records an
// authenticated submission (a person's client, not a server).
func authenticatedHop(v string) bool {
	return reAuthSender.MatchString(v) || reAuthWith.MatchString(v)
}

// received redacts one Received header: addresses go, and for authenticated
// submissions the client name and IP (a person's home or office) are hidden.
func (r *redactor) received(v string) string {
	if !r.on {
		return v
	}
	if authenticatedHop(v) {
		v = reFromClause.ReplaceAllString(v, "from [authenticated client hidden]")
		v = reAuthSender.ReplaceAllString(v, "(Authenticated sender: [redacted])")
	}
	return r.text(v)
}

// dkim keeps the tags that matter for diagnosis and drops the signature and
// body hash; the i= identity is redacted like any address.
func (r *redactor) dkim(v string) string {
	v = reTagB.ReplaceAllString(v, "$1")
	var keep []string
	for _, m := range reTag.FindAllStringSubmatch(v, -1) {
		tag := strings.ToLower(m[1])
		switch tag {
		case "v", "a", "c", "d", "s", "t", "x", "i", "cv", "q":
			keep = append(keep, tag+"="+r.text(strings.Join(strings.Fields(m[2]), "")))
		case "h":
			keep = append(keep, "h="+strings.Join(strings.Fields(m[2]), ""))
		}
	}
	return strings.Join(keep, "; ")
}

func (r *redactor) msgID(v string) string {
	if !r.on {
		return v
	}
	if m := reMsgID.FindStringSubmatch(v); m != nil {
		return "<[id]@" + m[2] + ">"
	}
	return "[redacted]"
}

// keepHeaders are shown as they are (addresses inside still redacted): they
// describe the mail system, not the person.
var keepHeaders = map[string]bool{
	"date": true, "mime-version": true, "content-transfer-encoding": true, "precedence": true,
	"auto-submitted": true, "list-unsubscribe-post": true, "list-id": true, "x-mailer": true,
	"user-agent": true, "feedback-id": true, "x-priority": true, "importance": true,
	"authentication-results": true, "arc-authentication-results": true, "received-spf": true,
	"x-spam-flag": true, "x-spam-score": true, "x-spam-level": true, "x-spam-status": true,
	"x-virus-scanned": true, "x-original-authentication-results": true, "x-ms-exchange-organization-scl": true,
	"x-auto-response-suppress": true, "x-report-abuse": true, "x-csa-complaints": true, "x-mailgun-sid": true,
	"x-ses-outgoing": true, "x-sg-eid": true, "x-entity-id": true, "content-language": true,
}

var addressHeaders = map[string]bool{
	"from": true, "to": true, "cc": true, "bcc": true, "sender": true, "reply-to": true,
	"return-path": true, "delivered-to": true, "x-original-to": true, "errors-to": true,
	"resent-from": true, "resent-to": true, "resent-cc": true, "resent-sender": true,
	"disposition-notification-to": true, "return-receipt-to": true, "x-envelope-from": true,
	"x-envelope-to": true, "x-original-from": true, "x-original-sender": true, "x-sender": true, "x-rcpt-to": true,
	"x-authenticated-sender": true, "x-authenticated-user": true,
}

// Header is one header as shown in the report.
type Header struct {
	Name  string `json:"name"`
	Value string `json:"value"`
	// Redacted: personal content was hidden or reduced. Removed: a secret-like
	// header whose value is never shown.
	Redacted bool `json:"redacted,omitempty"`
	Removed  bool `json:"removed,omitempty"`
}

func (r *redactor) header(h RawHeader) Header {
	out := Header{Name: h.Name, Value: h.Value}
	if secretHeader.MatchString(h.Name) && !strings.EqualFold(h.Name, "DKIM-Signature") {
		out.Value, out.Removed = "[removed: looks like a credential]", true
		return out
	}
	if !r.on {
		return out
	}
	n := strings.ToLower(h.Name)
	set := func(v string) {
		out.Redacted = v != h.Value
		out.Value = v
	}
	switch {
	case n == "received":
		set(r.received(h.Value))
	case addressHeaders[n]:
		set(r.addressList(h.Value))
	case n == "message-id" || n == "resent-message-id":
		set(r.msgID(h.Value))
	case n == "in-reply-to" || n == "references":
		set("[redacted]")
	case n == "subject" || n == "thread-topic":
		set(fmt.Sprintf("[redacted, %d chars]", utf8.RuneCountInString(h.Value)))
	case n == "list-unsubscribe":
		var schemes []string
		for _, m := range reSchemes.FindAllStringSubmatch(h.Value, -1) {
			schemes = append(schemes, strings.ToLower(m[1]))
		}
		if len(schemes) == 0 {
			set("[present, value hidden]")
		} else {
			set("[present: " + strings.Join(schemes, ", ") + "; values hidden]")
		}
	case n == "dkim-signature" || n == "arc-message-signature" || n == "arc-seal":
		set(r.dkim(h.Value))
	case n == "content-type":
		mt, _, _ := strings.Cut(h.Value, ";")
		set(strings.TrimSpace(mt))
	case keepHeaders[n] || strings.HasPrefix(n, "x-spam-"):
		set(r.text(h.Value))
	default:
		set("[redacted]")
	}
	return out
}
