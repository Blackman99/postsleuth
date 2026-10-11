# Goal

**Tell you (or your AI agent), from one read-only command, why a Postfix server is not delivering mail: which destinations are stuck, since when, for what classified reason, and which DNS/authentication record is to blame.**

In scope: reading the Postfix queue (`postqueue -j`), qshape-style age-by-domain analysis, mail-log analysis (deferral reasons, bounce causes, per-domain outcomes, smtpd rejects, message traces), the DNS records receivers check (MX, SPF, DKIM, DMARC, PTR/FCrDNS), delivery-relevant `postconf` settings, an MCP server exposing all of this to agents, and *explicitly opted-in* queue actions (flush, requeue, hold, release, delete by queue ID).

Out of scope: configuring or editing Postfix, sending mail, spam filtering, mailbox/IMAP management, blocklist delisting, hosted email-provider APIs, generic server monitoring, other MTAs (until the core is solid).

Non-negotiable: read-only by default. Anything that changes the queue is off unless the operator starts postsleuth with `--allow-mutations`, and over MCP each change also needs `confirm=true`.
