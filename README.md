# drill (reverse tunnel)

A minimal reverse-tunnel in Go, using:

- [chi](https://github.com/go-chi/chi) for HTTP routing
- [cobra](https://github.com/spf13/cobra) for the CLI
- [gorilla/websocket](https://github.com/gorilla/websocket) for the control/data channel

This is **NOT** production-ready (no TLS termination, auth is stubbed, no multiplexing over multiple streams), but it's a clean starting point you can extend toward ngrok-like functionality.

## Quick start

Terminal 1 — run the public/control server:
```bash
go run . server --public :8080 --domain-base localhost
```

Terminal 2 — start an agent that exposes a local service (e.g. a dev server on :3000):
```bash
go run . agent --server http://localhost:8080 --id alice --to http://127.0.0.1:3000
```

Now hit the tunneled endpoint in a browser or via curl:

- Path-based (works without DNS):  
  `http://localhost:8080/t/alice/`

- Subdomain-based (uses the reserved `.localhost` TLD):  
  `http://alice.localhost:8080/`

## What’s here

- Control/WebSocket endpoint: `/_control?id=<id>&auth=<token>`
- Public HTTP entrypoints: host-based (`{id}.<domain-base>`) and path-based (`/t/{id}/...`)
- Simple JSON envelope protocol for requests/responses
- Agent forwards to a local target (`--to`) and mirrors method, path, query, headers, and body
- Basic timeouts and safe header copying

## Layout

```
revtun/
  cmd/
    agent.go
    root.go
    server.go
  internal/
    agent/agent.go
    server/manager.go
    server/server.go
  pkg/
    proto/proto.go
    util/logger.go
  main.go
```

## Notes & next steps

- **Security**: add real auth, mTLS or signed tokens, rate limiting.
- **TLS**: terminate HTTPS (e.g., behind Caddy/Nginx/Cloudflare) or embed autocert.
- **Multiplexing**: implement streams per request (e.g., yamux), concurrent control/data channels.
- **Persistence**: keep tunnel metadata in a store and add reservations, vanity domains, and auth.
- **Raw TCP**: add a TCP mode in addition to HTTP proxying.
- **Observability**: metrics, structured logs, tracing.
- **Compression**: consider gzip for large payloads.


## HTTPS & auto subdomains on your domain

Enable Let's Encrypt (autocert) and force HTTPS (ports 80/443 must be open and point to this server):

```bash
# On your public host for getexposed.io
sudo setcap 'cap_net_bind_service=+ep' $(which go)  # or run as root to bind :80/:443
go run . server --acme --domain-base getexposed.io --public :443 --acme-email you@example.com
```

Then connect agents with an HTTPS server URL (the agent will use wss):
```bash
./revtun agent --server https://getexposed.io --id alice --to http://127.0.0.1:3000
# Access via: https://alice.getexposed.io/
```

**Note:** Let's Encrypt issues a separate certificate for each `{id}.getexposed.io`. This is fine for small numbers of subdomains but subject to rate limits. For many dynamic subdomains, consider a wildcard certificate via DNS-01 (use a reverse proxy like Caddy/Traefik) or fall back to path routing `/t/{id}/...` on the apex.


## Auth (agents) and Metrics

Enable a shared token for agent control connections:

```bash
# server
revtun server --acme --public :443 --domain-base getexposed.io --auth --auth-token $TOKEN

# agent
revtun agent --server https://getexposed.io --auth $TOKEN --id alice --to http://127.0.0.1:3000
```

Prometheus endpoint is exposed at `/metrics`:
```bash
curl -s https://getexposed.io/metrics | head
```

### Reverse proxy (optional)
If you prefer to terminate TLS and/or use wildcard certs via DNS-01, use the Caddyfile or Traefik example in `deploy/`. Point your proxy upstream to the revtun server's HTTP port and disable `--acme` on revtun.
