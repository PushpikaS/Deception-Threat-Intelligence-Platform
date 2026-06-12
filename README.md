# Deception-Based Threat Intelligence Platform

A **security deception and threat intelligence platform**. It pretends to be a real company website (login pages, admin panels, APIs) to attract and study attackers, then turns every probe into structured intelligence you can view on a private analyst dashboard.

**Three layers:** deception (Go honeypots) → intelligence (Python engine) → visibility (React dashboard + FastAPI).

---

## In Other Words

Imagine you set up a fake office building that looks exactly like your real one. Burglars who try the fake doors are watched by cameras. Every attempt — what door they tried, what tools they used, where they came from — is logged and scored automatically.

HoneyPot+ does that on the internet:

1. **Attackers** hit `http://localhost:8080` — they see login pages, admin dashboards, and APIs that look real.
2. **Every request** is recorded in a database. Nothing they do affects your real systems.
3. **A background engine** reads those logs, labels attacks (SQL injection, brute force, scanner, etc.), maps them to MITRE ATT&CK, and scores risk.
4. **You** open `http://localhost:9090` on a **separate, private port** and see maps, timelines, profiles, and exports.

The honeypot surface and the analyst dashboard are **physically separated** at the network edge (different nginx gateways and ports). An attacker probing `/login` cannot discover the dashboard.

---

## Quick Start

```bash
cp .env.example .env

docker compose up --build -d
```

| Surface | HTTP (use this) | Who uses it |
|---------|-----------------|-------------|
| **Honeypot** (public deception) | `http://localhost:8080/login` | Attackers, scanners, red team |
| **Dashboard** (private intel) | `http://localhost:9090` | Security analysts |

HTTP communication. Go and Python services speak plain HTTP inside Docker.

**Dashboard auth** uses server-side sessions (`hp_session` cookie). Set `STRICT_PRODUCTION=true` and change all default passwords before a real deployment — enforced at startup by **both** Python services (`shared/production_check.py`) and Go honeypots (`services/shared/runtime/production.go`).

**Simulate attacks:**

```bash
./scripts/simulate-attacks.sh        # Linux/macOS
.\scripts\simulate-attacks.ps1       # Windows
```

Events appear on the dashboard within ~2 seconds (engine polls every 2s).

**Verify the stack** (all three should pass):

```powershell
.\scripts\simulate-attacks.ps1        # generate classified events
.\scripts\test-all-endpoints.ps1      # 104 dashboard + honeypot endpoint checks
.\scripts\verify-production.ps1       # auth, honeytokens, microservice health
.\scripts\test-smoke.ps1              # quick subset smoke test
```

**Red team / attacker entry paths:** see [ATTACKER_ENTRY_GUIDE.md](ATTACKER_ENTRY_GUIDE.md).

---

## Tech Stack

| Layer | Technology | Version | Role |
|-------|------------|---------|------|
| **Deception** | Go | 1.22 | Honeypot microservices (`honeypot-auth`, `honeypot-web`, `honeypot-api`) |
| **Event bus** | Redis Streams | 7 | `honeypot:events` stream on `redis-events` |
| **Ingest** | Python + asyncpg | 3.12 | `threat-ingest` — stream consumer → `postgres-events` |
| **Engine** | Python + asyncpg | 3.12 | `threat-engine` — classification, geo, MITRE, risk scoring |
| **API** | FastAPI + uvicorn | 3.12 | `threat-api` — REST for dashboard |
| **UI** | React + Vite | 20 / 5 | Analyst dashboard (`frontend`) |
| **Events DB** | PostgreSQL | 16 | `postgres-events` — immutable event log |
| **Intel DB** | PostgreSQL | 16 | `postgres-intel` — profiles, classifications, chains |
| **Defense state** | Redis | 7 | `redis-defense` — honeypot sessions, WAF, lockouts |
| **Platform state** | Redis | 7 | `redis-platform` — dashboard sessions + API cache |
| **Gateways** | nginx | 1.27 | HTTP routing, rate limits |
| **Orchestration** | Docker Compose | — | 14 services, health checks, named volumes |

**Shared libraries (not separate deployables):** `services/shared/` (Go), `shared/` (Python MITRE, taxonomy, production checks, trap registry).

**Design principles:** database-per-service, dedicated Redis per bounded context, async I/O throughout Python, connection pooling, Redis response caching (30s), transactional engine batches, idempotent classification inserts.

---

## System at a Glance

```
                    INTERNET / ATTACKERS
                            │
                            ▼
              ┌─────────────────────────┐
              │    nginx-honeypot       │  :8080 HTTP
              │  login · admin · /api/v1  │
              └───────────┬─────────────┘
                          │
         ┌────────────────┼────────────────┐
         ▼                ▼                ▼
   honeypot-auth    honeypot-web     honeypot-api
   (login/MFA)      (admin/traps)    (fake REST)
         │                │                │
         └────────────────┼────────────────┘
                          │  XADD stream
                          ▼
                 ┌─────────────────┐
                 │  redis-events   │
                 └────────┬────────┘
                          │
                          ▼
                 ┌─────────────────┐
                 │  threat-ingest  │  stream → postgres-events
                 └────────┬────────┘
                          │
                          ▼
                 ┌─────────────────┐
                 │ postgres-events   │
                 └────────┬────────┘
                          │  polls every 2s
                          ▼
                 ┌─────────────────┐
                 │  threat-engine  │  classify · geo · risk · chains
                 └────────┬────────┘
                          │
                          ▼
                 ┌─────────────────┐
                 │ postgres-intel  │
                 └────────┬────────┘
                          │
              ┌───────────┴───────────┐
              ▼                       ▼
        ┌──────────────┐       ┌─────────────┐
        │redis-platform│       │ threat-api  │
        │ sessions+cache│      │  (FastAPI)  │
        └──────────────┘       └──────┬──────┘
                                      │
              ANALYSTS ONLY           ▼
              ┌─────────────────────────┐
              │    nginx-dashboard      │  :9090 HTTP
              │   React UI + /api/*     │
              └─────────────────────────┘
```

| Service | Language | Role | Exposed to internet? |
|---------|----------|------|----------------------|
| `nginx-honeypot` | nginx | Deception gateway, rate limits | Yes (8080) |
| `nginx-dashboard` | nginx | Dashboard gateway | No (keep private) |
| `honeypot-auth` | Go | Fake login, MFA, OAuth, LDAP (HTML in `templates/`) | Via honeypot nginx only |
| `honeypot-web` | Go | Fake admin UI, scanner traps, honeyfiles | Via honeypot nginx only |
| `honeypot-api` | Go | Fake REST API, honeytoken detection | Via honeypot nginx only |
| `threat-ingest` | Python | Redis stream → postgres-events | Never |
| `threat-engine` | Python | Classify events → postgres-intel | Never |
| `threat-api` | Python/FastAPI | REST API for dashboard | Via dashboard nginx only |
| `frontend` | React | Analyst UI (refresh + live WebSocket) | Via dashboard nginx only |
| `postgres-events` | PostgreSQL 16 | Raw honeypot events only | Internal only |
| `postgres-intel` | PostgreSQL 16 | Profiles, classifications, chains | Internal only |
| `redis-events` | Redis 7 | Event bus stream | Internal only |
| `redis-defense` | Redis 7 | Honeypot sessions + guard state | Internal only |
| `redis-platform` | Redis 7 | Dashboard sessions + API cache | Internal only |

---

## How an Attack Flows (Step by Step)

1. **Attacker** requests `http://localhost:8080/.env`
2. **nginx-honeypot** applies rate limits, forwards to `honeypot-web`
3. **honeypot-web** serves a realistic fake `.env` file (honeytoken bait) and logs an event:
   - IP, method, endpoint, user-agent, payload (trap name, WAF hits, etc.)
4. **threat-ingest** writes the row to `postgres-events`
5. **threat-engine** (within ~2s) reads new events, classifies them into `postgres-intel`:
   - **Event-local:** `env_leak` on this specific request
   - **Session-context:** `port_scanner` if the same IP hit many endpoints
6. Engine updates `attacker_profiles` (risk score, geo, MITRE tags) and `attack_chains` if multiple services were hit
7. **threat-api** serves enriched data to the dashboard
8. **You** see the event in Event Stream, the IP on the threat map, and MITRE techniques on the profile

---

## Microservices Architecture

Each bounded context has **its own data store** — no shared Postgres or Redis between services.

```
honeypot-*  → redis-events (stream)     → threat-ingest → postgres-events
                                              ↓
                                        threat-engine → postgres-intel
                                              ↑
threat-api / dashboard ← redis-platform (sessions + cache)
honeypot-* sessions    ← redis-defense (isolated)
```

### Deception layer (Go)

**Event bus:** Honeypot services publish to **redis-events** (`honeypot:events` stream). Sessions and WAF state use **redis-defense** only. They never touch PostgreSQL or the analyst stack.

Three independent Go binaries share packages under `services/shared/`:

| Package | Purpose |
|---------|---------|
| `shared/events` | Structured event logger → redis-events stream |
| `shared/defense` | Sessions, lockouts, WAF patterns, honeytoken registry |

**honeypot-auth** (`:8082`) — Fake enterprise auth:
- HTML login/register/MFA/SSO pages (`templates/` via `go:embed`) — generic corp copy, no password-rule hints on the form
- JSON APIs: `/auth/login`, `/auth/mfa/verify`, OAuth, LDAP bind simulation
- Redis-backed session and brute-force lockouts
- Analyst test path (server-side only, not shown in UI): `admin@acmecorp.com` / `password123` / MFA `482910`

**honeypot-web** (`:8080`) — Fake internal apps:
- `/admin` console: dashboard, users, settings, logs, billing, API keys, security, integrations
- Scanner traps: `/.env`, `/.git/HEAD`, `/actuator/*`, `/swagger.json`, Jenkins/Jira decoys
- `/status` recon page, `/downloads/exports/*` storage artifacts, error pages

**honeypot-api** (`:8081`) — Fake REST API:
- `/api/v1/users`, `/api/v1/search`, `/api/v1/webhooks`, etc.
- Detects SQLi, XSS, path traversal, RCE patterns in query params
- Honeytoken triggers when fake AWS keys appear in webhook payloads

### Intelligence layer (Python)

**threat-engine** — Long-running worker (no HTTP):
- Polls `events` table in batches (default 100 events / 2s)
- **Transactional batches** with idempotent classification inserts
- GeoIP enrichment: **MaxMind GeoLite2** (offline, optional) or **IP-API** HTTP fallback — no API keys required
- Single risk-scoring path in `classifier.py` (velocity, decay, ASN rollup)
- Publishes live updates on Redis `tip:live` for dashboard WebSocket
- Writes: `threat_classifications`, `attacker_profiles`, `attack_chains`, `asn_intel`

**threat-ingest** — Stream consumer (no HTTP):
- Reads `honeypot:events` from **redis-events**
- Writes rows to **postgres-events** via consumer group `threat-ingest`
- Poll interval default 1s; decoupled from classification

**threat-api** — FastAPI REST (`:8000`):
- Dual DB pools: `events_pool` + `intel_pool`
- Server-side sessions on **redis-platform** (`hp_session` cookie)
- HTTP Basic Auth fallback for scripts (`curl -u`)
- Redis response caching (30s TTL); CORS restricted to dashboard origin

### Visibility layer (React)

**frontend** — Single-page dashboard:
- Polls core API endpoints every 10 seconds; **WebSocket** (`/api/ws/live`) triggers silent refresh on new events
- **Top attacking countries**, **ASN rollup**, global threat map (English labels, colorful Carto + Esri overlay)
- Global search, heatmap, MITRE guide, profile modal with STIX/blocklist exports
- Event-local vs session-context threat labels shown separately per event

### Gateways (nginx)

**nginx-honeypot** — Public deception entry:
- HTTP on 80 → host `8080`
- Rate limits: auth 8/s, API 18/s, global 30/s
- Blocks `/api/` paths that aren't `/api/v1/` (prevents dashboard API leakage)

**nginx-dashboard** — Private analyst entry:
- HTTP on 80 → host `9090`
- Proxies `/` → React, `/api/*` → threat-api (strip prefix)

---

## Data Model

Schemas are split across two PostgreSQL instances (no cross-DB foreign keys):

**postgres-events** (`db/events/init.sql`):

| Table | What it stores |
|-------|----------------|
| `events` | Raw honeypot requests (immutable log) |

**postgres-intel** (`db/intel/init.sql`):

| Table | What it stores |
|-------|----------------|
| `threat_classifications` | Per-event labels (SQLi, env_leak, etc.) + MITRE in JSON details |
| `attacker_profiles` | One row per IP: risk score, geo, behavior tags, session context in `metadata` |
| `attack_chains` | Multi-service attack sequences per IP |
| `asn_intel` | ASN rollup from GeoIP + honeypot risk (IPs, events, avg risk) |
| `engine_state` | Engine cursor (`last_processed_event_id`) |

**Classification scopes:**

| Scope | Stored where | Examples | Shown on event row? |
|-------|--------------|----------|---------------------|
| **Event-local** | `threat_classifications` | `sqli_attempt`, `env_leak`, `scanner_tool` | Yes |
| **Session-context** | `attacker_profiles.metadata.context_classifications` | `port_scanner`, `credential_stuffing`, `cross_service_probe` | On profile; secondary on event UI |

This split prevents a SQLi event from also displaying `port_scanner` on the same row — session context appears on the attacker profile instead.

---

## Threat Classifications & MITRE

Canonical MITRE map: **`shared/mitre.py`** (copied into Python containers as `shared_mitre.py`). The dashboard loads it via `GET /api/mitre/map` — no duplicate maps in the frontend.

| Classification | What it means |
|----------------|---------------|
| `sqli_attempt` | SQL injection in parameters |
| `xss_attempt` | Cross-site scripting patterns |
| `path_traversal` | Directory traversal (`../`) |
| `rce_attempt` | Remote code execution probes |
| `env_leak` / `config_leak` | Sensitive file traps triggered (`.env`, `config.json`) |
| `git_exposure` / `backup_leak` | Source/backup file probes |
| `honeytoken_trigger` | Fake credential used in a request |
| `brute_force` | Repeated login / lockout |
| `credential_stuffing` | Many unique emails from one IP |
| `scanner_tool` | Known scanner user-agents (sqlmap, nikto, etc.) |
| `port_scanner` | High endpoint diversity from one IP |
| `cross_service_probe` | Hits across multiple honeypot services |
| `reconnaissance` | Generic probe fallback |
| `benign_session` | Legitimate analyst login flow (no MITRE) |

**Risk scoring** combines weighted classifications + request velocity + time decay, blended with previous score (0–100).

---

## Dashboard Guide

Open `http://localhost:9090` after starting the stack. Sign in with dashboard credentials (default local: `analyst` / `changeme_local_only`).

| Section | What you see |
|---------|--------------|
| **System Health** | postgres-events, postgres-intel, redis-platform, engine lag |
| **Stats Cards** | Total events, profiles, high-risk count |
| **Trend Stats** | 7d / 30d volume and high-risk deltas |
| **Top Attacking Countries** | Bar chart + ranked table (24h / 48h / 7d) |
| **ASN Rollup** | Top ASNs by avg risk (from GeoIP, no external feeds) |
| **Global Search** | Search IPs, endpoints, classifications |
| **MITRE Guide** | Technique reference from live map |
| **Attack Timeline** | Hourly event volume |
| **Threat Map** | Verified geo pins, accuracy rings, origin sidebar, risk filters |
| **Attacker Profiles** | Sortable table with risk, geo, tags, blocklist export |
| **Event Stream** | Live feed with per-event threat + MITRE cells |
| **Attack Chains** | Cross-service sequences |

Click any IP to open the **Profile Detail Modal** with full event history and context classifications.

---

## API Reference

All endpoints are prefixed `/api/` on the dashboard port (nginx strips prefix before forwarding to threat-api). Protected routes require an `hp_session` cookie (login via `POST /api/auth/login`) or HTTP Basic Auth.

| Endpoint | Auth | Description |
|----------|------|-------------|
| `GET /api/health` | No | postgres-events + postgres-intel + redis-platform health |
| `GET /api/health/platform` | Yes | Engine lag, profile counts |
| `GET /api/auth/config` | No | Auth mode metadata |
| `POST /api/auth/login` | No | Create session |
| `POST /api/auth/logout` | Yes | Invalidate session |
| `GET /api/auth/session` | Cookie | Session status |
| `GET /api/auth/me` | Yes | Current analyst identity |
| `GET /api/stats/overview` | Yes | Aggregate stats (cached) |
| `GET /api/stats/trends` | Yes | Time-series trends |
| `GET /api/stats/countries?hours=24&limit=8` | Yes | Top attacking countries by event volume |
| `GET /api/stats/asn?limit=10` | Yes | ASN rollup (avg risk, malicious hits) |
| `WS /api/ws/live` | No* | Live engine events (dashboard auto-connects) |
| `GET /api/events?limit=50` | Yes | Recent events with classifications |
| `GET /api/profiles/search` | Yes | Filter/sort profiles (`?q=&min_risk=&sort=risk`) |
| `GET /api/profiles/{ip}` | Yes | Profile detail + events + classifications |
| `GET /api/profiles/{ip}/timeline` | Yes | Per-IP hourly timeline |
| `GET /api/search?q=` | Yes | Global search |
| `GET /api/chains` | Yes | Attack chains |
| `GET /api/timeline?hours=24` | Yes | Hourly timeline |
| `GET /api/heatmap?hours=24` | Yes | Classification heatmap |
| `GET /api/map` | Yes | Geo map pins |
| `GET /api/mitre/map` | Yes | MITRE ATT&CK mapping |
| `GET /api/taxonomy` | Yes | Classification taxonomy |
| `GET /api/export/events.csv` | Yes | CSV export |
| `GET /api/export/profiles.csv` | Yes | CSV export |
| `GET /api/export/blocklist.txt?min_risk=20` | Yes | Firewall blocklist (comment header + threshold) |
| `GET /api/export/blocklist/{ip}` | Yes | Single-IP blocklist file |
| `GET /api/export/stix/{ip}` | Yes | STIX 2.1 bundle for IP |

\* WebSocket accepts connections without cookie; used only from authenticated dashboard origin.

---

## Configuration

Copy `.env.example` → `.env`. Key variables:

```env
# Gateway ports
HONEYPOT_PORT=8080
DASHBOARD_PORT=9090

# Dashboard CORS (must match your dashboard URL)
CORS_ORIGINS=http://localhost:9090

# Engine tuning
POLL_INTERVAL=2
BATCH_SIZE=100
CACHE_TTL=30

# Dashboard auth (on by default)
REQUIRE_DASHBOARD_AUTH=true
DASHBOARD_AUTH_USER=analyst
DASHBOARD_AUTH_PASS=changeme_local_only

# GeoIP (optional offline MaxMind; IP-API fallback works without keys)
GEOIP_HTTP_FALLBACK=true
GEOIP_CACHE_TTL=86400
```

**GeoIP:** Place `GeoLite2-City.mmdb` and `GeoLite2-ASN.mmdb` in `data/geoip/` (bind-mounted into the engine). Without them, **IP-API** provides live geolocation for public IPs. Private/Docker IPs are labeled but excluded from the map. For realistic country pins in local dev, send traffic with `X-Forwarded-For: <public-ip>` (see `scripts/simulate-attacks.ps1`).

```powershell
$env:MAXMIND_LICENSE_KEY='your_key'; .\scripts\download-geoip.ps1
docker compose restart threat-engine
```

---

## Development

### Rebuild one service

```bash
docker compose up --build -d honeypot-api
docker compose up --build -d threat-engine
docker compose up --build -d frontend
```

### Local frontend (hot reload)

```bash
cd frontend && npm install && npm run dev
```

Set `CORS_ORIGINS=http://localhost:3000,http://localhost:9090` in `.env` when the API runs in Docker.

### View logs

```bash
docker compose logs -f threat-engine
docker compose logs -f threat-api
docker compose logs -f nginx-honeypot nginx-dashboard
```

### Reset database (deletes all data)

```bash
docker compose down -v
docker compose up --build -d
```

---

## Troubleshooting

| Issue | Fix |
|-------|-----|
| Honeypot won't load | Verify connectivity to localhost:8080. Check docker logs: `docker compose logs nginx-honeypot` |
| Browser certificate warning | Not applicable with HTTP-only setup |
| nginx exits on startup | Check docker logs: `docker compose logs nginx-honeypot` or `docker compose logs nginx-dashboard` |
| Dashboard shows no data | Run `.\scripts\simulate-attacks.ps1`; wait ~2s |
| Search results won't clear | Hard-refresh (`Ctrl+Shift+R`) after updating frontend |
| Login fails in PowerShell | Use browser UI — PS mangles JSON bodies |
| 429 Too Many Requests | Nginx rate limits — wait between simulation runs |
| Map empty / wrong country | Use public IPs via `X-Forwarded-For`; wait ~2s for engine geo enrich |
| Geo pins missing | Only verified MaxMind/IP-API coords shown; private IPs excluded |
| DB schema mismatch | `docker compose down -v` resets volumes |

### Health checks

```bash
curl http://localhost:8080/health
curl http://localhost:9090/api/health
curl http://localhost:9090/api/health/platform
```

---

## Project Structure

```
├── docker-compose.yml       # 14 microservices + 5 data volumes
├── .env.example             # Configuration template
├── db/
│   ├── events/init.sql      # postgres-events schema
│   └── intel/init.sql       # postgres-intel schema
├── data/geoip/              # MaxMind .mmdb files (optional)
├── shared/
│   ├── mitre.py             # Canonical MITRE ATT&CK map
│   ├── taxonomy.py          # Classification taxonomy
│   ├── traps.py             # Trap rule loader
│   ├── trap_registry.json   # Trap definitions (synced with Go defense)
│   └── production_check.py  # STRICT_PRODUCTION validation
├── nginx/
│   ├── honeypot.conf        # Deception gateway
│   ├── honeypot-locations.conf
│   ├── dashboard.conf       # Dashboard gateway
│   └── dashboard-locations.conf
├── scripts/
│   ├── simulate-attacks.ps1 / .sh       # Generate attack patterns
│   ├── test-smoke.ps1                  # Quick smoke test
│   ├── test-all-endpoints.ps1          # Full endpoint verification
│   ├── verify-production.ps1           # Production readiness checks
│   └── download-geoip.sh               # MaxMind GeoIP data (optional)
├── services/
│   ├── shared/
│   │   ├── events/          # Redis stream event logger (Go)
│   │   ├── defense/         # Sessions, WAF, honeytokens (Go)
│   │   └── runtime/         # Production checks, Redis init (Go)
│   ├── honeypot-web/        # Admin UI + traps
│   ├── honeypot-api/        # Fake REST API
│   └── honeypot-auth/       # Fake auth flows
├── threat-ingest/           # Redis stream → postgres-events
├── threat-engine/           # Classification worker (events → intel)
│   ├── classifier.py        # Single risk + classification path
│   ├── enrichment.py        # MaxMind + IP-API geo
│   └── asn_intel.py         # ASN rollup writer
├── threat-api/              # FastAPI REST + WebSocket for dashboard
├── frontend/
│   └── src/lib/mapLayers.js # Map tile config (English labels)
└── ATTACKER_ENTRY_GUIDE.md  # Red team / deception surface map
```

---

