# Security model

PhishGraph analyses hostile content by design, so the service itself is built to be hard to abuse.

## Authentication and abuse control
- Every API route (except `/health`, `/ready`, `/metrics`) requires `X-API-Key`. Keys come from `API_KEYS` (compared in constant time) or the `users` table (stored as SHA-256 hashes).
- Per-key token-bucket rate limiting (`RATE_LIMIT_PER_MINUTE`); request bodies are size-limited by schema (e.g. URL ≤ 4,000 chars, raw email ≤ 2 MB, `.eml` ≤ 10 MB).
- The WebSocket stream requires the same key.
- CORS is limited to configured origins plus Chrome extension origins.

## SSRF protection (URL investigation and enrichment)
- Refused before any network activity: `localhost`, `*.local`, `*.internal`, `*.corp`, `*.lan`, `metadata.google.internal`, loopback, RFC 1918, link-local (incl. `169.254.169.254`), CGNAT, multicast, reserved and documentation ranges, IPv6 loopback/ULA/link-local/IPv4-mapped, and obfuscated IP literals (`0x7f000001`, `2130706433`).
- Hostnames are resolved first; if any answer is non-public the host is not contacted.
- The only outbound contact with a suspicious host is a TLS handshake to read its certificate. No HTTP request is made to the host itself; page content is never fetched by the API process.
- `ALLOW_PRIVATE_TARGETS=true` exists only for isolated test labs.

## Data sent to third parties
- Only public indicators (URL, domain, IP, file hash) are sent to threat-intel providers; message bodies and headers never leave the deployment.
- URLs whose query string carries personal data (`email=`, `token=`, `session=`, an e-mail address …) are reduced to their hostname before lookup.
- Private or internal indicators are never sent (`skipped_private`).
- External lookups are off until `ENABLE_EXTERNAL_TI=true` and a provider key is set. urlscan submits new scans only with `URLSCAN_SUBMIT=true`, using `URLSCAN_VISIBILITY` (default `private`).

## Response actions
- Default mode is simulated: decisions change PhishGraph's own database state only.
- Live mailbox actions require `RESPONSE_LIVE_ACTIONS=true` plus a configured connector, and only copy/flag or label messages. Nothing is ever deleted.

## Attachments
- Attachments are hashed and typed from their filename and MIME type. They are never executed, opened or rendered.

## Auditing
- `audit_logs` records analyst feedback, IOC additions, investigation submissions and refusals, and every response action with its mode.

## Secrets
- All secrets come from the environment (`.env` is git-ignored; `.env.example` documents every variable). The container runs as a non-root user.

## Reporting
Please report vulnerabilities privately to the repository owner rather than opening a public issue.
