# drill (reverse-tunnel scaffold)

- HTTP tunneling via chi + WebSocket control
- TLS (autocert), forced HTTPS, subdomain routing `{id}.domain`
- Auth (shared token) for agents
- Prometheus `/metrics`
- **TCP & UDP** binds with per-id routing
- Viper configs for server/agent

## Config examples

`configs/server.yaml`:
```yaml
server:
  public: ":443"
  domain_base: "getexposed.io"
  acme: { enable: true, email: "you@example.com", cache: "/var/lib/drill-acme" }
  auth: { enable: true, token: "change-me" }

  tcp_binds:
    - { addr: ":9000", id: "autoglue" }
  udp_binds:
    - { addr: ":8125", id: "autoglue" }
```

`configs/agent.yaml`:
```yaml
agent:
  id: "autoglue"
  server: "https://getexposed.io"
  auth: "change-me"
  to: "http://127.0.0.1:8080"
  tcp_targets:
    autoglue: "127.0.0.1:5432"
  udp_targets:
    autoglue: "127.0.0.1:8125"
```

Run:
```bash
drill server --config ./configs/server.yaml
drill agent --config ./configs/agent.yaml
```

## Notes
- TCP: per-port binds map to a single tunnel id; each inbound connection is a stream over the agent WS.
- UDP: scaffold is best-effort and sends one reply per inbound datagram (1s window). For high throughput, extend to keep a persistent UDP socket at the agent.
- Production: add per-tunnel auth, port allocator, retries/backoff, heartbeats.
