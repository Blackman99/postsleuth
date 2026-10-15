# Builds the postsleuth MCP server for Glama evaluation and local smoke tests.
# Glama only needs the process to start and answer MCP introspection on stdio.
FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /postsleuth ./cmd/postsleuth

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY --from=build /postsleuth /usr/local/bin/postsleuth
ENTRYPOINT ["postsleuth", "mcp"]
