package postfix

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/Blackman99/postsleuth/internal/maillog"
)

// LogCandidates are tried in order when no log source is given.
var LogCandidates = []string{"/var/log/mail.log", "/var/log/maillog", "/var/log/mail/mail.log", "/var/log/postfix.log", "/var/log/mail/maillog"}

// LogSource describes where Postfix log lines come from.
type LogSource struct {
	Files []string // explicit files (.gz ok, "-" = stdin)
	Cmd   string   // explicit command, split on spaces, e.g. "journalctl -u postfix -o short-iso"
}

type cmdReader struct {
	io.ReadCloser
	cmd    *exec.Cmd
	cancel context.CancelFunc
}

func (c *cmdReader) Close() error {
	c.ReadCloser.Close()
	c.cancel()
	_ = c.cmd.Wait()
	return nil
}

func startCmd(ctx context.Context, argv []string) (io.ReadCloser, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	out, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		cancel()
		return nil, err
	}
	return &cmdReader{out, cmd, cancel}, nil
}

// OpenLogs returns readers for the configured log source, a description of
// what was opened, or an error when nothing readable was found.
// mailLogFile is Postfix's maillog_file setting (may be empty).
func (r Runner) OpenLogs(ctx context.Context, src LogSource, mailLogFile string, since time.Time) ([]io.ReadCloser, string, error) {
	if src.Cmd != "" {
		argv := strings.Fields(src.Cmd)
		rc, err := startCmd(ctx, argv)
		if err != nil {
			return nil, "", fmt.Errorf("log command: %w", err)
		}
		return []io.ReadCloser{rc}, src.Cmd, nil
	}
	if len(src.Files) > 0 {
		var out []io.ReadCloser
		for _, f := range src.Files {
			rc, err := maillog.OpenFile(f)
			if err != nil {
				for _, o := range out {
					o.Close()
				}
				return nil, "", err
			}
			out = append(out, rc)
		}
		return out, strings.Join(src.Files, ", "), nil
	}
	cands := LogCandidates
	if mailLogFile != "" && !strings.HasPrefix(mailLogFile, "/dev/") {
		cands = append([]string{mailLogFile}, cands...)
	}
	if len(r.Wrap) > 0 {
		for _, f := range cands {
			if _, err := r.Run(ctx, "test", "-r", f); err == nil {
				rc, err := startCmd(ctx, append(append([]string{}, r.Wrap...), "cat", f))
				if err == nil {
					return []io.ReadCloser{rc}, strings.Join(r.Wrap, " ") + " cat " + f, nil
				}
			}
		}
		return nil, "", fmt.Errorf("no readable mail log found via %q (tried %s); pass --log-cmd", strings.Join(r.Wrap, " "), strings.Join(cands, ", "))
	}
	var denied []string
	for _, f := range cands {
		fh, err := os.Open(f)
		if err == nil {
			return []io.ReadCloser{fh}, f, nil
		}
		if os.IsPermission(err) {
			denied = append(denied, f)
		}
	}
	if p, err := exec.LookPath("journalctl"); err == nil {
		argv := []string{p, "--no-pager", "-q", "-o", "short-iso", "SYSLOG_FACILITY=2"}
		if !since.IsZero() {
			argv = append(argv, "--since", since.Format("2006-01-02 15:04:05"))
		}
		rc, err := startCmd(ctx, argv)
		if err == nil {
			return []io.ReadCloser{rc}, "journalctl (mail facility)", nil
		}
	}
	if len(denied) > 0 {
		return nil, "", fmt.Errorf("permission denied reading %s: run as a member of the adm group or with sudo, or pass --log", strings.Join(denied, ", "))
	}
	return nil, "", fmt.Errorf("no mail log found (tried %s and journalctl); pass --log FILE or --log-cmd", strings.Join(cands, ", "))
}

// Params returns expanded values (`postconf -x`) of the given parameters.
func (r Runner) Params(ctx context.Context, names ...string) (map[string]string, error) {
	out, err := r.Run(ctx, "postconf", append([]string{"-x"}, names...)...)
	if err != nil {
		return nil, err
	}
	return ParseConfig(string(out)), nil
}
