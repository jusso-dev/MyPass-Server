# MyPass Server

[![CI](https://github.com/jusso-dev/MyPass-Server/actions/workflows/ci.yml/badge.svg)](https://github.com/jusso-dev/MyPass-Server/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

> **The backend for [MyPass](https://github.com/jusso-dev/MyPass) — a way for parents and carers of autistic children to tell their child's story once, share it with the people who need to know, and take it back whenever they want.**

This is the relay server. **It can't read your child's card.** It holds ciphertext, wrapped keys, and ownership hashes — nothing else.

## The story

Families of autistic children explain the same things over and over: how their child communicates, what overwhelms them, what calms them, what's safe to eat, who to call in a crisis. New teacher, new term — same email. New respite carer — same conversation. New paramedic at the door — and there is no time to explain anything.

[MyPass](https://github.com/jusso-dev/MyPass) lets a family write the card once and share it on their terms:

- **Share with someone known** by device ID — for partners, grandparents, long-term carers.
- **Share with someone new** by generating a QR code with a built-in expiry — five minutes for an appointment, a week for a respite stay, a month for a school term.
- **Revoke instantly** when a relationship ends, then rotate the card key so cached ciphertext on revoked devices becomes unreadable.

This server makes that work without ever seeing the card itself.

## Why "zero-knowledge"

The server is **assumed compromisable**. The threat model is built so a fully-compromised server still cannot read user data.

- The card is **encrypted on the family's device** with a random AES-256-GCM key.
- The server only stores the ciphertext, the wrapped keys (one per subscriber, wrapped with their ECDH-P256 public key), and an HMAC hash of the owner's secret.
- The owner's raw secret never leaves the iOS Keychain.
- Share-link decryption keys live in the **URL fragment** (`#key`) — fragments are never sent to the server by browsers or HTTP clients, so the server never sees the key even when redeeming a link.
- There are no accounts. No emails. No passwords. No usernames. Identity is a P-256 device keypair held in the Secure Enclave.

A breach of the server gets the attacker a pile of opaque blobs.

## Architecture

```
+------------+         +-----------------+         +--------------+
|  iOS app   | ──API──>│  MyPass Server  │ ──SQL──>│ PostgreSQL   │
|  (encrypt  │         │  (blob relay,   │         │ (ciphertext  │
|   + decrypt│<──push──│   ECDH keywrap, │         │   only)      │
|   on device│         │   share links)  │         │              │
+------------+         +-----------------+         +--------------+
```

The server's job is narrow:

1. **Devices register** with a P-256 public key. Server issues a nanoid; that's the device identity.
2. **Owners create cards** by uploading ciphertext + an HMAC-hashed ownership secret.
3. **Owners share** by creating a subscription with an ECDH-wrapped copy of the card key, scoped to one subscriber's public key.
4. **Owners generate share links** — random URL-safe tokens with a `max_uses` and `expires_at`. The decryption key never touches the server.
5. **Subscribers fetch** the card by device ID (or by redeeming a link). The server returns ciphertext; the device unwraps the key locally.
6. **Owners revoke** by deleting subscriptions and rotating the card key in a single atomic transaction.

## Tech stack

| Layer | Technology |
|-------|-----------|
| Language | Rust 2021 |
| Web framework | Axum 0.8 |
| Async runtime | Tokio (multi-threaded) |
| Database | PostgreSQL 16+ via SQLx (compile-time-checked queries) |
| Crypto | `hmac` + `sha2` for ownership; `jsonwebtoken` for FCM service-account JWTs |
| HTTP middleware | tower-http (CORS, tracing, gzip, timeouts, security headers) |
| Rate limiting | tower_governor 0.8 (per-peer-IP token bucket) |
| Push notifications | Firebase Cloud Messaging v1 (optional, env-gated) |
| Observability | tracing + tracing-subscriber (structured JSON logs) |

## Security hardening

| Control | Implementation |
|---------|---------------|
| Owner authentication | `X-Owner-Secret` HMAC-SHA256, constant-time comparison |
| Encryption-at-server | Never — server only sees ciphertext (AES-256-GCM) |
| Key validation | `HMAC_KEY` length ≥256 bits enforced at startup; hex-format checked |
| Input validation | Blob ≤64 KiB, strings ≤500 chars, Base64 verified, parameterized SQL |
| Request body limit | 256 KiB cap (`DefaultBodyLimit`) |
| Request timeout | 15s hard cap (`TimeoutLayer`) — bounds resource usage |
| Rate limiting | 10 req/sec sustained, burst 30, per peer IP (`tower_governor`) |
| CORS | Deny-all by default; explicit single-origin allowlist via `CORS_ORIGIN` |
| Security headers | HSTS, X-Frame-Options DENY, X-Content-Type-Options nosniff, Referrer-Policy no-referrer, Permissions-Policy locked-down, COOP/CORP same-origin |
| TLS | Expected at reverse proxy (Nginx/Caddy/Cloudflare); HSTS emitted unconditionally |
| Container | Multi-stage Docker build, non-root runtime user, minimal `debian:bookworm-slim` base |
| Supply chain | `cargo-audit` runs in CI on every push |
| Test isolation | Integration tests use a real Postgres instance (no mocks) |

See [SECURITY.md](SECURITY.md) for the full threat model and reporting policy.

## Getting started

### Prerequisites

- Rust toolchain (stable)
- PostgreSQL 16+
- Optional: Docker + Docker Compose

### Local development

```bash
cp .env.example .env

# Generate a strong HMAC key
openssl rand -hex 32   # paste into HMAC_KEY in .env

cargo run
```

### Docker Compose

```bash
echo "POSTGRES_PASSWORD=$(openssl rand -hex 16)" >> .env
echo "HMAC_KEY=$(openssl rand -hex 32)" >> .env

docker compose up
```

Server listens on `:3000`. Database is only reachable from inside the Compose network.

## Configuration

| Variable | Required | Default | Notes |
|----------|----------|---------|-------|
| `DATABASE_URL` | yes | — | PostgreSQL connection string |
| `HMAC_KEY` | yes | — | ≥64 hex chars (256 bits). `openssl rand -hex 32` |
| `PORT` | no | `3000` | HTTP listen port |
| `RUST_LOG` | no | `mypass_server=info,tower_http=info` | tracing filter |
| `CORS_ORIGIN` | no | unset = no CORS | Single allowed origin. Never set to `*` in production |
| `FCM_PROJECT_ID` | no | — | Firebase project ID (push only) |
| `FCM_CLIENT_EMAIL` | no | — | Service account email |
| `FCM_PRIVATE_KEY` | no | — | Service account private key, PEM (use `\n` for newlines) |

If any FCM variable is missing, push notifications become no-ops (warning logged) — the rest of the API works normally.

## API reference

All endpoints accept and return JSON. Authentication is via request headers, not bearer tokens.

### Health

| Method | Path | Auth |
|--------|------|------|
| GET | `/health` | none |

### Devices

| Method | Path | Auth |
|--------|------|------|
| POST | `/v1/devices` | none (idempotent by public key) |
| PUT | `/v1/devices/{device_id}/push` | none |
| GET | `/v1/devices/{device_id}/public-key` | none |

### Cards

| Method | Path | Auth |
|--------|------|------|
| POST | `/v1/cards` | `X-Owner-Secret` |
| GET | `/v1/cards?owner_device_id=…` | none (device_id is unguessable nanoid) |
| GET | `/v1/cards/{card_id}` | `X-Owner-Secret` or `X-Device-Id` with active subscription |
| PUT | `/v1/cards/{card_id}` | `X-Owner-Secret` |
| DELETE | `/v1/cards/{card_id}` | `X-Owner-Secret` |
| POST | `/v1/cards/{card_id}/rotate-key` | `X-Owner-Secret` |
| PUT | `/v1/cards/{card_id}/owner-secret` | `X-Owner-Secret` (rotates the secret itself) |

### Subscriptions

| Method | Path | Auth |
|--------|------|------|
| POST | `/v1/cards/{card_id}/subscriptions` | `X-Owner-Secret` |
| GET | `/v1/cards/{card_id}/subscriptions` | `X-Owner-Secret` |
| GET | `/v1/subscriptions/received` | `X-Device-Id` |
| DELETE | `/v1/subscriptions/{subscription_id}` | `X-Owner-Secret` |

### Share links

| Method | Path | Auth |
|--------|------|------|
| POST | `/v1/cards/{card_id}/links` | `X-Owner-Secret` |
| GET | `/v1/cards/{card_id}/links` | `X-Owner-Secret` |
| GET | `/v1/links/{token}/card` | none (rate-limited) |
| DELETE | `/v1/cards/{card_id}/links/{token}` | `X-Owner-Secret` |

### Authentication headers

| Header | Purpose |
|--------|---------|
| `X-Owner-Secret` | Raw 32-byte owner secret. Server HMAC-hashes and constant-time compares against stored hash. |
| `X-Device-Id` | Device nanoid. Used for subscriber reads, received-list filtering. |

## Database schema

Four tables, no PII:

- **`devices`** — nanoid id, P-256 public key, optional push token
- **`cards`** — encrypted blob (Base64 AES-GCM ciphertext + IV + auth tag), HMAC-hashed owner secret, version counter
- **`card_subscriptions`** — ECDH-wrapped card key per subscriber, role, optional expiry, fetch tracking
- **`share_links`** — random URL-safe token, role, `max_uses`, `expires_at`

A background task runs every 5 minutes to purge expired share links and subscriptions. Cascading FKs handle delete-time cleanup.

## Testing

Integration tests run against a real PostgreSQL — no mocks. CI spins up Postgres as a service container; locally:

```bash
export TEST_DATABASE_URL=postgres://mypass:mypass@localhost:5432/mypass_test
cargo test
```

Coverage: health probe, full owner happy-path (register → create → fetch → update → version bump), subscription flow with ECDH wrap, share-link lifecycle (creation, multi-use redemption, expiry, revocation), owner-auth failure modes.

## Project structure

```
src/
  main.rs                Server entry point, background cleanup, graceful shutdown
  lib.rs                 Router builder, middleware stack, AppState
  config.rs              Env-based config + HMAC_KEY validation
  db.rs                  Connection pool + migration runner
  error.rs               AppError enum → HTTP status mapping
  cache.rs               ETag helpers for HTTP 304 caching
  middleware/
    owner_auth.rs        HMAC-SHA256 owner secret hashing + constant-time verify
    security_headers.rs  Static security-header values applied by the router
  models/                Request/response types per resource
  routes/                Route handlers (health, devices, cards, subscriptions, links)
  services/
    push.rs              FCM v1 client with OAuth2 JWT exchange + token cache
migrations/              SQLx migrations (idempotent, applied at startup)
tests/
  integration_test.rs    End-to-end API tests against real Postgres
```

## License

MIT — see [LICENSE](LICENSE).
