# Contributing

- Read [GOAL.md](GOAL.md) first; changes outside it will be declined politely.
- `go test -race ./...` must pass; `gofmt` clean.
- New failure texts: add a real (anonymised) example to `internal/reason/reason_test.go`.
- Anything that changes the mail queue must stay behind `--allow-mutations` (and `confirm=true` over MCP).
- The integration test needs Docker: `go build -o postsleuth ./cmd/postsleuth && test/integration.sh ./postsleuth`.
