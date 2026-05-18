# Security Policy

## Threat model

MyPass Server is a zero-knowledge encrypted blob relay. The server is **assumed compromisable** — the security model is built so that even a fully compromised server cannot read user card contents.

### In scope

- Owner authentication via HMAC-SHA256
- Server-side input validation (request size, blob size, Base64 verification, parameterized SQL)
- Transport-layer expectations (TLS at reverse proxy, HSTS)
- Rate limiting on token redemption and registration endpoints
- Defence-in-depth response headers
- Container hardening (non-root, minimal base image)
- CI supply-chain checks (`cargo audit`)

### Out of scope (by design)

- Confidentiality of card data — guaranteed by client-side AES-256-GCM, not server controls
- Subscriber key custody — handled by the iOS Keychain (Secure Enclave)
- TLS termination — expected at a reverse proxy (Nginx, Caddy, Cloudflare). The server speaks plain HTTP and trusts its peer
- DDoS at network layer — expected to be handled upstream

## Cryptography

| Primitive | Use |
|-----------|-----|
| AES-256-GCM | Card content encryption (client-side only — server never sees the key) |
| P-256 ECDH | Key wrapping for sharing with subscribers |
| HMAC-SHA256 | Owner secret verification at the server |
| Random URL-safe tokens (32 bytes) | Share link tokens, generated with `rand::thread_rng` |

The server's only cryptographic responsibility is verifying owner secrets and signing FCM service-account JWTs. The HMAC key must be at least 256 bits, hex-encoded, and is validated at startup.

## Operational controls

| Control | Notes |
|---------|-------|
| Request body limit | 256 KiB (`DefaultBodyLimit`). Cards ≤ 64 KiB; the rest is JSON overhead. |
| Per-request timeout | 15 s (`TimeoutLayer`). Exceeded requests return `504`. |
| Rate limiting | 10 req/sec sustained, burst 30, per peer IP (`tower_governor` 0.8). Behind a reverse proxy this rate-limits the proxy IP; production deploys should swap to `SmartIpKeyExtractor` so X-Forwarded-For is honoured. |
| CORS | Deny-all by default. Set `CORS_ORIGIN` to a single explicit origin to enable. Never `*`. |
| Security headers | HSTS (max-age=1y, includeSubDomains), X-Frame-Options DENY, X-Content-Type-Options nosniff, Referrer-Policy no-referrer, Permissions-Policy locked-down, COOP/CORP same-origin |
| HMAC key validation | Length ≥ 64 hex chars, hex-only character set, validated at startup |
| Logging | Structured JSON via tracing. Card content, tokens, HMAC key, push tokens, and FCM credentials are never logged. |
| Container | Non-root runtime user `mypass`, `debian:bookworm-slim` base, multi-stage build, only `ca-certificates` + `curl` (for healthcheck) in the runtime layer. |
| Background cleanup | Expired share links and subscriptions are purged every 5 minutes; subscribers are pushed an expiry notice before removal. |

## CI security checks

Every push triggers:

- `cargo fmt --check`
- `cargo clippy --all-targets -- -D warnings`
- `cargo test` against a real Postgres service container
- `cargo audit` for known-vulnerable dependencies

A new dependency lands only when all four pass.

## Reporting a vulnerability

Open a private security advisory on the GitHub repo:
<https://github.com/jusso-dev/MyPass-Server/security/advisories/new>

Please include:

- A description of the issue and its impact
- Reproduction steps or PoC
- Any suggested mitigation

I'll acknowledge within 7 days and aim to ship a fix within 30 days of confirmation.

Please **do not** open a public issue for security-relevant findings.

## Known limitations

- **Reverse proxy required for TLS.** The server speaks HTTP; deploy behind Nginx/Caddy/Cloudflare or equivalent.
- **Rate limiter uses peer IP.** Behind a proxy, all clients share the proxy's IP. Swap to `SmartIpKeyExtractor` (reads `X-Forwarded-For`) for a real production rollout.
- **No request signing on FCM credentials.** A server compromise could enable push spam to known device tokens. Push payloads carry no card content, only IDs.
- **No idempotency keys.** A retried `POST /v1/cards/.../subscriptions` could create duplicates. Subscribers are deduplicated at the unique-index level (`UNIQUE(card_id, device_id)`); other endpoints are not affected.
