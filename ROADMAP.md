# Roadmap

## v0.1 (done)
- `doctor`: queue + qshape + log + DNS findings with next steps, exit code for scripts
- Queue summary/list/filters from `postqueue -j`; qshape matrix by recipient or sender domain
- Mail log: syslog, RFC 3339 and journald timestamps, `maillog_file`, .gz, journald fallback; deferral reasons, bounce causes, smtpd rejects, still-failing domains, trace by queue ID or address (follows bounce notices)
- 17 failure categories with hints (rate_limit, blocklist, ptr, auth, tls, dns, timeout, recipient_unknown, ...)
- DNS: MX, SPF (lookup limit, IP authorisation), DKIM keys (selectors auto-detected from opendkim logs), DMARC, PTR/FCrDNS vs myhostname
- MCP server (stdio) with read-only tools; mutating tools only with `--allow-mutations` + `confirm=true`
- `--wrap` for Postfix in Docker (docker-mailserver, mailcow) or over SSH
- CI: unit tests + integration test against a real Postfix in Docker; GoReleaser binaries

## v0.2
- [x] Per-destination trend: deferral rate over time buckets (is it getting better?)
- Provider-specific playbooks for Gmail (4.7.28 recovery steps), Microsoft (S3150 / SNDS), Yahoo
- `postfix_queue_message` tool: headers of one queued message (`postcat -h`), with redaction
- MCP over streamable HTTP with a bearer token for remote servers
- DNSBL lookup for the sending IP (Spamhaus ZEN, Barracuda) with resolver caveats

## v0.3
- MTA-STS / TLS-RPT / DANE checks for the sending domain
- Multi-instance Postfix (`postmulti`) support
- Homebrew tap and .deb/.rpm packages
