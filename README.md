# DNStrike

DNStrike is a web-based DNS security and resilience testing platform for systems you own or are explicitly authorized to test. This foundation release provides safe target management, live DNS discovery, a scenario capability registry, SQLite persistence, WebSocket infrastructure, and a responsive React interface.

## Safety model

- Only literal RFC1918, loopback, link-local, and IPv6 ULA/local addresses are accepted.
- Public target testing is not available in this release.
- Target policy is enforced when saving and immediately before network activity.
- Discovery sends one bounded `example.com A` probe per enabled protocol with a three-second timeout.
- The HTTP server listens on `127.0.0.1:8080` by default.

## Architecture

```text
React UI → Gin REST API → Target service → SQLite
                    ├── DNS discovery engine → miekg/dns
                    ├── Scenario registry
                    └── WebSocket hub
```

Business rules live outside HTTP handlers. Shared JSON contracts are defined in `pkg/models`; matching TypeScript contracts are in `web/src/types.ts`. The SQLite migration includes the planned target, test, result, metric, finding, report, profile, and settings tables.

## Docker

```bash
docker compose up --build
```

The compose port is deliberately bound to localhost. SQLite data and future reports use `./data` and `./reports` volumes.

Compose runs the container with host UID/GID `1000:1000` by default so the bind-mounted directories remain writable. On a host using different IDs, start it with:

```bash
DNSTRIKE_UID=$(id -u) DNSTRIKE_GID=$(id -g) docker compose up --build
```

If an older container reports SQLite error 14 (`unable to open database file`), rebuild it after this UID/GID change:

```bash
docker compose down
docker compose up --build
```

## API

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/health` | Service health |
| `GET` | `/api/targets` | List targets |
| `POST` | `/api/targets` | Create and validate a target |
| `GET` | `/api/targets/:id` | Fetch a target |
| `DELETE` | `/api/targets/:id` | Delete a target |
| `POST` | `/api/targets/:id/check` | Run UDP/TCP discovery |
| `GET` | `/api/scenarios` | List scenario capabilities |
| `POST` | `/api/tests` | Create a pending test record |
| `GET` | `/api/tests` | List and filter test history |
| `GET` | `/api/tests/:id` | Fetch test configuration and lifecycle state |
| `GET` | `/ws/tests/:id` | Test event WebSocket |

Discovery reports UDP/TCP reachability and latency, recursion and authoritative flags, EDNS and DNSSEC signals, response size, TCP fallback, and RA/RD/AA/TC flags. Unavailable protocols return a readable classification, not a raw Go network error.

## Repository layout

```text
cmd/server                 application entry point
internal/api               HTTP transport and error contract
internal/dnsengine         DNS protocol operations
internal/scenarios         plugin-like capability registry
internal/security          target policy
internal/storage/sqlite    persistence and migrations
internal/target            target business rules
internal/websocket         real-time transport foundation
internal/webui             embedded production assets
pkg/models                 shared backend contracts
web                        React + TypeScript application
```

This repository implements the requested starting vertical slice. Stress scenarios are not exposed as runnable operations until their worker pools, hard limits, cancellation, health probes, persistence, and reports can ship together.
