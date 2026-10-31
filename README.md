# Nordray Tunnel

Self-hosted HTTP tunnels deployed entirely into **your own Bunny account**. Unmodified upstream [frp](https://github.com/fatedier/frp) runs as the relay (frps) in Bunny Magic Containers and as the agent (frpc) next to your private services. Visitors reach your services through Bunny CDN with Shield. No Nordray-operated relay, account, telemetry or billing intermediary is involved.

Proof of concept. See [docs/feasibility.md](docs/feasibility.md) for what was measured live.

## Quickstart

Prerequisites: a Bunny account and API key, frpc v0.71.1 in `PATH` (from the [frp release](https://github.com/fatedier/frp/releases/tag/v0.71.1), verify its checksum), and a relay image that Magic Containers can pull.

```sh
go install github.com/activout/nordray-tunnel/cmd/nordray-tunnel@latest

# Prints the resources and costs, asks for confirmation, then provisions.
# The API key is asked for once (hidden) and kept in the OS credential store.
nordray-tunnel setup --region DK --image ghcr.io/activout/nordray-tunnel-relay:sha-<commit>

# Publish a local service. With the domain in Bunny DNS the record is created;
# otherwise the exact CNAME to create is printed.
nordray-tunnel add web --hostname app.example.se --local http://127.0.0.1:8080

# Run the agent (no Bunny API key needed).
nordray-tunnel run

nordray-tunnel status --remote
```

To run the agent on another machine, export its configuration and copy it over a private channel:

```sh
nordray-tunnel agent-config -o agent        # on the operator's machine
nordray-tunnel run --config agent/frpc.toml # on the agent machine
```

`--name` selects an installation (default `default`), so several relays can be managed side by side.

## Architecture

```
visitor ──HTTPS──> app pull zone (Shield, no cache) ──> relay :8080 (frps vhost, routes by Host)
                                                              │ tunnel
agent (frpc) ──wss :443──> tunnel pull zone (WebSockets) ──> relay :7000     (transport wss, default)
agent (frpc) ──frp TLS──> Anycast IPv4 :7000 ─────────────> relay :7000     (transport anycast)
   └── http://127.0.0.1:<port> your service
```

- **Transports** are exclusive: `wss` (default, no fixed cost) or `anycast` (`setup --transport anycast`, one paid IPv4 shared by every agent and service). Switch by running setup again with the other transport.
- **Visitor traffic always goes through the CDN and Shield.** The relay's HTTP port is never published on Anycast, and container ports are not reachable directly.
- frps routes requests by `Host` and answers 404 for hostnames no agent has registered, including the pull zone's default `*.b-cdn.net` and `*.bunny.run` hostnames.

## Trust boundaries

- **Agents** authenticate with one installation token. Every holder of the token is a trusted operator: the token does not limit which hostnames an agent may register. This is not tenant isolation.
- **TLS to the relay is always verified.** frpc skips certificate verification when no CA file is configured (frp v0.71.1, for wss and TLS alike), so the generated configuration always includes `ca.pem`. For `wss` that is the NSS (Mozilla) root set shipped in this binary. For `anycast` it is an installation CA whose private key is discarded after issuing the relay certificate.
- **Visitors** reach services through Shield (WAF in blocking mode, DDoS protection, no learning mode). Their `Authorization` and other headers reach your service unchanged. `X-Forwarded-For` is set by Bunny. `X-Forwarded-Proto` reads `http`, because Bunny reaches the relay over HTTP.
- **Origin authentication** is not implemented: services are treated as public websites. Measured so far, the relay is reachable only through its own pull zones (see the feasibility report). Whether other Magic Containers apps can reach it internally has **not been verified yet**. Do not publish anything you would not put on the public internet.
- Shield does not inspect traffic inside the tunnel, only visitor requests.

## Secrets

| Secret | Where it lives |
| --- | --- |
| Bunny API key | OS credential store (`nordray-tunnel` / `bunny-api-key`); `--api-key-env NAME` for automation. Never sent to the relay or agent. |
| Tunnel token, relay TLS key, frpc admin password | OS credential store, per installation |
| Tunnel token (agent copy) | `frpc.toml`, mode 0600, because upstream frpc reads it from the file |
| Relay environment | Magic Containers environment variables. **Not a secret store**: visible in the dashboard and echoed by the API. |

`state.json` (in the user config directory, `nordray-tunnel/<name>/`) holds only resource IDs, addresses and public certificates.

## Relay environment

| Variable | Purpose |
| --- | --- |
| `NORDRAY_TUNNEL_TOKEN` | Agent authentication secret, at least 32 characters (the relay refuses to start otherwise) |
| `NORDRAY_LOG_LEVEL` | frps log level, default `info` |
| `NORDRAY_TLS_CERT`, `NORDRAY_TLS_KEY` | PEM certificate and key for direct (Anycast) agents |
| `NORDRAY_TLS_FORCE` | `true` rejects agents without frp TLS; only valid with the anycast transport |

## Costs to check

Recheck [Bunny's pricing](https://bunny.net/docs/magic-containers/pricing) before deploying. Checked on 31 October 2026:

- **Container:** $0.02 per CPU-hour, $0.005 per GB-hour of RAM in 64 MB blocks (frps idles in one block).
- **wss:** CDN WebSockets at $0.235 per million connection-minutes (one connection per agent, about $0.01 a month). Every visitor byte crosses the CDN twice: visitor ↔ app zone and relay ↔ agent.
- **anycast:** $2 per IPv4 per month while attached. Tunnel traffic is Magic Containers egress ($0.01/GB in Europe and North America) instead of a second CDN leg.
- **Shield:** free plan.

## Limitations

- Local targets must be plain HTTP. HTTPS local targets are not supported yet.
- One replica in one region. A relay restart or pod recreation interrupts service for about 30 seconds, and agents reconnect on their own.
- No origin authentication gateway (see Trust boundaries).
- Visitor-side WebSockets are not configured.

## Teardown

```sh
nordray-tunnel destroy
```

This deletes the DNS records, the Magic Containers app (with its endpoints and any Anycast IP) and both pull zones, by ID. Bunny keeps pull zones when an app is deleted, so `destroy` deletes them explicitly. The Shield zone cannot be deleted through the API: it stays on the free plan, pointing at the deleted zone. Manually: delete the app in Magic Containers, then the `mc-*` pull zones listed by `nordray-tunnel status`, then the DNS records.

## Development

```sh
go test ./...   # e2e tests need frp v0.71.1 binaries in .bin/ (see .github/workflows/test.yml)
```

Licensed under the Apache License 2.0. See [NOTICE](NOTICE) for frp's notice.
