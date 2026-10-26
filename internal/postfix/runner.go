// Package postfix runs Postfix command-line tools (postqueue, postconf,
// postsuper). Commands are executed directly, never through a shell.
package postfix

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// Runner executes Postfix commands, optionally behind a wrapper such as
// "docker exec -i mailserver" or "ssh mail sudo".
type Runner struct {
	Wrap    []string
	Timeout time.Duration
}

// Run executes name with args and returns stdout.
func (r Runner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	if r.Timeout == 0 {
		r.Timeout = 60 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, r.Timeout)
	defer cancel()
	argv := append(append(append([]string{}, r.Wrap...), name), args...)
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(errb.String())
		if msg == "" {
			msg = err.Error()
		}
		return out.Bytes(), fmt.Errorf("%s: %s", strings.Join(argv, " "), msg)
	}
	return out.Bytes(), nil
}

// QueueJSON returns the output of `postqueue -j`.
func (r Runner) QueueJSON(ctx context.Context) ([]byte, error) {
	return r.Run(ctx, "postqueue", "-j")
}

// secretKey matches postconf parameter names whose values should never be shown.
var secretKey = regexp.MustCompile(`(?i)(password|passwd|secret|token)`)

// Config returns non-default main.cf settings (`postconf -n`) as a map.
// Values of parameters that look like secrets are redacted.
func (r Runner) Config(ctx context.Context) (map[string]string, error) {
	out, err := r.Run(ctx, "postconf", "-n")
	if err != nil {
		return nil, err
	}
	return ParseConfig(string(out)), nil
}

// ParseConfig parses `postconf` output ("name = value" lines).
func ParseConfig(s string) map[string]string {
	m := map[string]string{}
	for _, line := range strings.Split(s, "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		if k == "" {
			continue
		}
		if secretKey.MatchString(k) && !strings.Contains(v, ":") {
			v = "[redacted]"
		}
		m[k] = v
	}
	return m
}

// Postfix queue IDs (src/global/mail_queue.h) come in two shapes:
//
//   - short (default): upper-case hex, 5 hex digits of microseconds followed
//     by the inode number in hex, e.g. 4F2A1C3B9D;
//   - long (enable_long_queue_ids=yes): seconds and microseconds in base 52
//     (digits and letters without vowels), the separator 'z', then the inode
//     in base 51 (the same alphabet without 'z'), e.g. 4bNqJx2rG9z1Hk.
//
// Anything else is rejected before it can reach a command line, including
// the bulk keyword ALL, option-looking strings and shell metacharacters (a
// --wrap "ssh host" prefix hands arguments to a remote shell).
var (
	shortQueueIDRe = regexp.MustCompile(`^[0-9A-F]{6,24}$`)
	longQueueIDRe  = regexp.MustCompile(`^[0-9B-DF-HJ-NP-TV-Zb-df-hj-np-tv-z]{10,16}z[0-9B-DF-HJ-NP-TV-Zb-df-hj-np-tv-y]{1,14}$`)
)

// ValidQueueID reports whether id is a Postfix queue ID in short or long form.
// It never accepts ALL.
func ValidQueueID(id string) bool {
	if len(id) > 32 || strings.EqualFold(id, "ALL") {
		return false
	}
	return shortQueueIDRe.MatchString(id) || longQueueIDRe.MatchString(id)
}

// QueueIDHelp explains the accepted queue ID format in error messages.
const QueueIDHelp = "expected a Postfix queue ID such as 4F2A1C3B9D (short, hex) or 4bNqJx2rG9z1Hk (long); bulk ALL is never accepted"

// QueueMessage returns the envelope records and primary headers of one queued
// message (postcat -e -h -q ID). The body is never requested.
func (r Runner) QueueMessage(ctx context.Context, id string) (string, error) {
	if !ValidQueueID(id) {
		return "", fmt.Errorf("invalid queue ID %q: %s", id, QueueIDHelp)
	}
	out, err := r.Run(ctx, "postcat", "-e", "-h", "-q", id)
	if err != nil {
		if strings.Contains(err.Error(), "No such file or directory") || strings.Contains(err.Error(), "open queue file") {
			return "", fmt.Errorf("%w: %s is not in the queue (already delivered, bounced or deleted?); follow it in the log with: postsleuth trace %s", ErrNotQueued, id, id)
		}
		return "", err
	}
	return string(out), nil
}

// ErrNotQueued means the queue ID does not exist in any queue.
var ErrNotQueued = errors.New("not queued")

func checkIDs(ids []string) error {
	if len(ids) == 0 {
		return fmt.Errorf("no queue IDs given (bulk operations on ALL are not supported)")
	}
	for _, id := range ids {
		if !ValidQueueID(id) {
			return fmt.Errorf("invalid queue ID %q: %s", id, QueueIDHelp)
		}
	}
	return nil
}

// The methods below change the mail queue. Callers must gate them behind an
// explicit opt-in; they are never used by read-only commands.

// Flush asks Postfix to retry delivery: of specific queue IDs (postqueue -i),
// of everything for one destination (postqueue -s), or of the whole queue (postqueue -f).
func (r Runner) Flush(ctx context.Context, ids []string, site string, all bool) ([]string, error) {
	var done []string
	switch {
	case len(ids) > 0:
		if err := checkIDs(ids); err != nil {
			return nil, err
		}
		for _, id := range ids {
			if _, err := r.Run(ctx, "postqueue", "-i", id); err != nil {
				return done, err
			}
			done = append(done, "postqueue -i "+id)
		}
	case site != "":
		if !regexp.MustCompile(`^[A-Za-z0-9.\-\[\]:]+$`).MatchString(site) {
			return nil, fmt.Errorf("invalid site %q", site)
		}
		if _, err := r.Run(ctx, "postqueue", "-s", site); err != nil {
			return nil, err
		}
		done = append(done, "postqueue -s "+site)
	case all:
		if _, err := r.Run(ctx, "postqueue", "-f"); err != nil {
			return nil, err
		}
		done = append(done, "postqueue -f")
	default:
		return nil, fmt.Errorf("give queue IDs, a site, or all")
	}
	return done, nil
}

// Super runs `postsuper -<op> ID` for each ID. op is one of r (requeue),
// d (delete), h (hold), H (release from hold).
func (r Runner) Super(ctx context.Context, op string, ids []string) ([]string, error) {
	switch op {
	case "r", "d", "h", "H":
	default:
		return nil, fmt.Errorf("unsupported postsuper operation %q", op)
	}
	if err := checkIDs(ids); err != nil {
		return nil, err
	}
	var done []string
	for _, id := range ids {
		if _, err := r.Run(ctx, "postsuper", "-"+op, id); err != nil {
			return done, err
		}
		done = append(done, "postsuper -"+op+" "+id)
	}
	return done, nil
}
