<p align="center"><img src="assets/logo.svg" width="72" alt="postsleuth logo"></p>

# postsleuth

**Why isn't Postfix delivering?** postsleuth reads the queue (`postqueue -j`), the mail log and DNS, groups every stuck message by *why* it is stuck, and tells you what to do next. It works as a CLI and as an MCP server, so an AI agent can investigate a mail server without being able to touch it.

![postsleuth doctor on a server with a Gmail rate limit, an Outlook blocklist and a dead host, then the Gmail 4.7.28 playbook, one stuck message redacted, the Gmail trend and a trace](site/demo.gif)

<sub>Demo uses generated snapshot data (`testdata/gen.py`) via `--queue-file` / `--log`.</sub>

## Install

```sh
go install github.com/Blackman99/postsleuth/cmd/postsleuth@latest
```

or grab a binary for Linux, macOS or Windows from [Releases](https://github.com/Blackman99/postsleuth/releases/latest).

## Use

```sh
postsleuth doctor                  # queue + qshape + log + SPF/DKIM/DMARC/PTR, with next steps
postsleuth queue --domain .outlook.com
postsleuth shape --by sender       # who filled the deferred queue
postsleuth trend --domain gmail.com  # deferral rate over time — getting better?
postsleuth playbook                # Gmail 4.7.28, Outlook S3150, Yahoo [TSS04]…: the provider's way back
postsleuth message F543B5DFCE      # one queued message: route, DKIM, headers, redacted
postsleuth trace bob@example.org   # one message, start to finish (from the log)
postsleuth dns example.com --ip 203.0.113.7
```

When Gmail, Microsoft or Yahoo is the one refusing you, `playbook` (and the `PLAYBOOK` section of `doctor`) names the provider code, says whether Postfix's retries can succeed, and gives ordered recovery steps written for Postfix with links to the provider's own pages: 18 playbooks, from Gmail's 4.7.28 rate limit and 5.7.26 DMARC failures to Outlook.com's S3150 block list (SNDS, JMRP) and Yahoo's [TSS09]. `postsleuth playbook --reply "…"` looks up a single reply.

When one message is the question, `message QUEUE_ID` reads its envelope and headers with `postcat -e -h -q` (never the body) and shows which queue it sits in and since when, each recipient's status and delay reason, the `Received:` route with TLS, whether its DKIM signature aligns with From:, and header problems that get mail refused, such as bulk mail without RFC 8058 one-click unsubscribe. Output is redacted by default: domains stay, local parts become `[user-1]@example.com`, the subject and display names are hidden, credential headers are removed. `--unredacted` exists on the CLI only.

Postfix in a container or on another box: `--wrap "docker exec -i mailserver"` or run it over `ssh`.

## MCP

```json
{"mcpServers": {"postsleuth": {"command": "postsleuth", "args": ["mcp"]}}}
```

All tools are read-only, and `postfix_queue_message` is always redacted. Requeue, flush, hold and delete exist only when the server is started with `--allow-mutations`, and each call still needs `confirm: true`.

**[Docs](https://blackman99.github.io/postsleuth/docs/)** · [Website](https://blackman99.github.io/postsleuth/) · [Goal](GOAL.md) · [Roadmap](ROADMAP.md) · MIT
