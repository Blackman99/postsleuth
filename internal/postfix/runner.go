// Package postfix runs Postfix command-line tools (postqueue, postconf,
// postsuper). Commands are executed directly, never through a shell.
package postfix

import (
	"bytes"
	"context"
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

var queueIDRe = regexp.MustCompile(`^[0-9A-Za-z]{5,32}$`)

// ValidQueueID reports whether id looks like a Postfix queue ID (short or long form).
func ValidQueueID(id string) bool { return queueIDRe.MatchString(id) && !strings.EqualFold(id, "ALL") }

func checkIDs(ids []string) error {
	if len(ids) == 0 {
		return fmt.Errorf("no queue IDs given (bulk operations on ALL are not supported)")
	}
	for _, id := range ids {
		if !ValidQueueID(id) {
			return fmt.Errorf("invalid queue ID %q", id)
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
