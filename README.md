<p align="center"><img src="assets/logo.svg" width="72" alt="postsleuth logo"></p>

# postsleuth

**Why isn't Postfix delivering?** postsleuth reads the queue (`postqueue -j`), the mail log and DNS, groups every stuck message by *why* it is stuck, and tells you what to do next. It works as a CLI and as an MCP server, so an AI agent can investigate a mail server without being able to touch it.

![postsleuth doctor on a server with a Gmail rate limit, an Outlook blocklist and a dead host](site/demo.gif)

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
postsleuth trace bob@example.org   # one message, start to finish
postsleuth dns example.com --ip 203.0.113.7
```

Postfix in a container or on another box: `--wrap "docker exec -i mailserver"` or run it over `ssh`.

## MCP

```json
{"mcpServers": {"postsleuth": {"command": "postsleuth", "args": ["mcp"]}}}
```

All tools are read-only. Requeue, flush, hold and delete exist only when the server is started with `--allow-mutations`, and each call still needs `confirm: true`.

**[Docs](https://blackman99.github.io/postsleuth/docs/)** · [Website](https://blackman99.github.io/postsleuth/) · [Goal](GOAL.md) · [Roadmap](ROADMAP.md) · MIT
