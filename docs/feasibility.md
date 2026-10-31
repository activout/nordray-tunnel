# Feasibility report: frp over WSS through Bunny

Live experiment, 31 October 2026. The operator authorised the billable resources, including one Anycast IPv4 for the Anycast test, and they were torn down afterwards (see [Teardown](#teardown)). Every result below was observed; nothing is extrapolated from documentation unless marked.

## Versions and assumptions

| Item | Value |
| --- | --- |
| frp | v0.71.1, unmodified upstream binaries and image |
| Upstream image | `fatedier/frps:v0.71.1@sha256:48720c81f048e842f7f0b8053753c1a8514053d59d2dee8a953f67995de73a18` |
| Relay image | `ghcr.io/activout/nordray-tunnels-relay:sha-b0f1eda8f4b2f522527ab44642c91ba99bde743b` (`sha256:8e439d63…f75651`) |
| Magic Containers API | `https://api.bunny.net/mc`, spec `https://api-mc.opsbunny.net/docs/public/swagger.json` |
| Core API | spec `https://core-api-public-docs.b-cdn.net/docs/v3/public.json` |
| Shield API | spec `https://api.bunny.net/shield/docs/v1/swagger.json` |
| Region | `DK`, shared runtime, autoscaling min 1 / max 1 |
| Client | frpc on macOS arm64, residential connection in Sweden |

## Topology tested

```
visitor ──HTTPS──> app pull zone (Shield, no cache, Host forwarded) ──HTTP──> container :8080 (frps vhost)
                                                                                    │
frpc ──WSS :443──> tunnel pull zone (WebSockets on) ──HTTP/WS──> container :7000 (frps bindPort)
  └── 127.0.0.1:18081 fixture app
```

## Results

| Check | Result |
| --- | --- |
| MC app creation through the API with two CDN endpoints | Works. Each CDN endpoint creates its **own pull zone** (origin type 5) with hostnames `mc-<id>.b-cdn.net` and `mc-<id>.bunny.run`. |
| WebSockets on MC-created pull zones | **On by default** on both zones (limit 500). It was switched off on the app zone. |
| Host forwarding on MC-created pull zones | `AddHostHeader` is **off by default**. Without it frps cannot route by Host, so it must be enabled on the app zone. |
| frpc `wss` login through the tunnel zone on port 443 | Works, using the returned `publicHost` and `transport.tls.trustedCaFile = /etc/ssl/cert.pem`. |
| TLS verification | Verified against the system CA bundle. A wrong `serverName` fails (`x509: certificate is valid for *.b-cdn.net`). See the warning below about the missing CA file. |
| Wrong tunnel token through Bunny | Rejected: `token in login doesn't match token from configuration`. |
| HTTP Upgrade through the CDN | Works: frps accepted the WS upgrade on `/~!frp`. A plain `GET /` on the tunnel zone returns 502, because frps only serves WS there. |
| Binary frames | Exercised implicitly: the yamux streams carry binary data, and both transfers below were byte-exact. |
| Actual tunnel connections | **1** established TCP/WSS connection per frpc (tcpMux multiplexes control and all work streams). Connection-minutes ≈ 1 per agent per minute. |
| Heartbeat | With tcpMux, frp's application heartbeat is disabled (`heartbeatInterval = -1`) and the yamux keepalive runs every 30 s (`transport.tcpMuxKeepaliveInterval`, both sides). |
| GET with app `Authorization` | 200. `Authorization: Bearer app-own-token` reached the app unchanged. |
| Spoofed forwarding headers | Client-supplied `X-Forwarded-For: 6.6.6.6` and `X-Real-IP: 6.6.6.6` were replaced by Bunny with the real client IP. |
| `X-Forwarded-Proto` seen by the app | `http`, even though the visitor used HTTPS, because Bunny→container is HTTP. Apps that build absolute URLs need to know this. **Limitation.** |
| 32 MiB download | Byte-exact, 2.5 s. |
| 16 MiB upload (POST) | SHA-256 matched end to end, 1.4 s. |
| Unknown hosts | `mc-*.b-cdn.net` and `mc-*.bunny.run` on the app zone return frps's 404 page. The app is reachable only via its registered `customDomains`. |
| Direct origin access | The container ports 7000/8080 are not reachable on the node IP. Port 80 on the node answers with an unrelated nginx 404. |
| Shield | Free plan Shield zone created through the API. It starts in **learning mode for 7 days**, so it does not block. Setting `learningMode: false`, `wafExecutionMode: 1` (Block) and `dDoSShieldSensitivity: 2` (Medium) by `PATCH /shield/shield-zone` takes effect within 20 s. Results: normal GET 200, XSS 403, SQL injection 403, path traversal 400. Shield is on the app zone only; the tunnel zone has none, so no challenge can reach the agent. Challenge levels (4/5) were avoided because they break non-browser clients. |
| Long-lived tunnel | The first frpc kept one WSS connection (same run ID, same local socket) from 20:19 to at least 20:56 local time with no reconnect. Requests after gaps succeeded in 0.14–0.15 s. |
| Unsolicited traffic | Requests from third parties reached `tunnel-test.nordray.net` within about 15 minutes of certificate issuance (20:38, 20:41, 20:51), probably from scanners following Certificate Transparency logs. Every public hostname must be treated as discoverable at once. This traffic also prevented a 15-minute quiet period on that hostname. |
| Idle ≥ 15 min | **Passed.** A second frpc (its own WSS connection, proxy on the zone default hostname that is not in CT logs) carried zero requests from 19:56:20Z to 20:12:20Z: no reconnect, same local socket throughout, and the next request returned 200 in 0.14 s. The yamux keepalive every 30 s keeps the WebSocket active at the CDN, so application idleness does not reach any CDN idle timeout. |
| `POST /mc/apps/{id}/restart` | **No observable effect**: same pod ID, no frpc reconnect, 300 consecutive 200 responses over 6.5 minutes. |
| Pod recreate (`POST /mc/apps/{id}/pods/{podId}/recreate`) | Old pod removed at once, **no overlap** with 1/1. 503 from the CDN for 25 s, frpc noticed the dead connection after about 20 s (keepalive) and got "bad status" until the new frps was ready, then 404 for 1–2 s until the proxies were registered. **Total outage ≈ 28 s**, recovered without intervention. |
| Rolling update (container PATCH) | New pod started before the old one stopped (two pods seen), so the update has overlap. Completed in about 55 s. |

## Anycast transport (direct frp TLS)

Tested on the same app after switching it to the relay image with `NORDRAY_TLS_FORCE=true` and an installation CA, then adding one Anycast endpoint (container 7000 → exposed 7000). The operator authorised the IP for the test.

| Check | Result |
| --- | --- |
| Endpoint creation | `POST /mc/apps/{id}/containers/{cid}/endpoints` with `anycast.type = iPv4`. Read back as `publicHost: "109.224.231.203:7000"`. |
| frpc `tcp` + `transport.tls.*` with installation CA and `serverName = relay.nordray.internal` | Login success. One TCP connection per agent. |
| Round trip, 32 MiB download, 16 MiB upload | 200, byte-exact (2.0 s), SHA-256 matched. |
| Untrusted CA (system bundle) | Rejected (`session shutdown`). |
| Wrong server name | Rejected (`x509: certificate is valid for relay.nordray.internal`). |
| Plaintext agent (`tls.enable = false`) | Rejected (`EOF`) because of `tls.force`. |
| TLS on but **no `trustedCaFile`** | **Logged in**: frpc skipped verification, the same hazard as with WSS. |
| WSS agents after the switch | Rejected (`EOF`), as expected under `tls.force`. Modes are therefore exclusive: `wss` or `anycast`. |
| vhost on the Anycast IP | Ports 80, 443 and 8080 do not answer. Port 7000 answers only TLS. Visitors can only arrive through the CDN with Shield. |
| Cost | One IP serves every agent and service on the relay. $2/month while attached, prorated. The tunnel leg is billed as MC egress instead of a second CDN leg, with no WebSocket minutes. |

## Secrets in API responses

`PATCH /mc/apps/{id}/containers/{cid}` and `GET /mc/apps/{id}` return environment variables **in clear text**, including the tunnel token and the TLS private key. Magic Containers env vars are not a secret store. Tooling must never log these responses.

## Warning: frpc skips certificate verification for wss without a CA file

In frp v0.71.1, `transport.protocol = "wss"` with **no** `transport.tls.trustedCaFile` sets `InsecureSkipVerify = true` (`pkg/transport/tls.go`, `NewClientTLSConfig`). frpc then connects to any server and presents the tunnel token to it. Generated configurations must always set `trustedCaFile`, either to the OS bundle or to a pinned bundle. The local test `TestNoCAFileSkipsVerification` pins this upstream behaviour.

With `wss`, frp's `transport.tls.*` settings configure the outer WebSocket TLS. There is no separate inner frp TLS layer, so `transport.tls.enable` is redundant. Bunny terminates TLS at the edge, and Bunny→container is plain HTTP/WS. frps therefore needs no certificate and must **not** set `transport.tls.force`.

## Costs observed (prices rechecked 31 October 2026)

| Leg | Billed as |
| --- | --- |
| Container | MC CPU ($0.02/CPU-hour) and RAM ($0.005/GB-hour in 64 MB blocks). frps idles at well under one block. |
| Tunnel connection | CDN WebSockets, $0.235 per million connection-minutes. One agent ≈ 43,200 min/month ≈ $0.01. |
| Visitor ↔ app zone | CDN bandwidth |
| Tunnel zone ↔ frpc | CDN bandwidth again, because every visitor byte crosses the CDN twice |
| Container egress via CDN | Not MC egress, since MC excludes CDN traffic |
| Shield | Free plan $0. Advanced plans are billed per zone. |

Avoiding Anycast saves $2/IP/month but doubles CDN bandwidth for every byte. Which is cheaper depends on traffic volume.

## Teardown

Resources were deleted by ID, never by name:

| Resource | ID | Result |
| --- | --- | --- |
| DNS record `tunnel-test.nordray.net` | 32366640 | Deleted |
| MC app (with its endpoints, including the Anycast IP) | HaktXS6JwjEBMW5 | Deleted. The API answered "not found" at once, but **the relay kept answering on the Anycast IP for about 4 minutes**. Deletion is asynchronous. |
| Tunnel pull zone | 6904427 | **Not deleted with the app.** Deleted explicitly. |
| App pull zone | 6904428 | **Not deleted with the app.** Deleted explicitly. |
| Shield zone (free plan) | 210995 | **The API has no delete operation (405).** Remains, pointing at the deleted pull zone, at no cost. |

`destroy` must therefore delete the pull zones explicitly, report the Shield zone, and wait until the Anycast IP stops answering before it reports done.
