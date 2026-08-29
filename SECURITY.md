# Security policy

## Supported deployment

The supported public topology places Caddy on a VPS and this service on a NAS
behind a dedicated WireGuard peer and an exact nginx allowlist. Publishing the
application port directly, attaching it to the Immich/LAN Docker network, or
placing an Immich API key in the service is outside the security model.

Secure defaults are part of the contract. The service fails closed when the
incoming mount marker, finite budgets, session secret, trusted public origin,
or state directory is missing.

## Residual risks

An authorized visitor can submit malformed media and consume the bounded quota,
bandwidth, CPU, memory, and inode allowance. Extension and signature validation
reduce accidental or obvious misuse; they are not malware analysis. Do not
automatically expose, execute, unpack, preview, or import received files.
Server-side deduplication occurs only after a complete upload, so repeated
identical files can still consume ingress bandwidth and CPU. Immutable
per-invitation attempt and ingress budgets bound that cumulative work.
Duplicate receipts are invitation-scoped, temporary, and capped to prevent
database growth from becoming an unbounded resource vector.

The VPS necessarily handles encrypted public connections and can inject bytes
toward the upload endpoint if compromised. The NAS-side invitation checks,
quotas, disk reserve, network isolation, and absence of public reads bound that
impact. The VPS must never receive the state DB, session secret, incoming mount,
or an Immich credential.

## Reporting

Do not open a public issue containing an invitation URL, password, cookie,
filesystem path, private address, API key, or log excerpt with credentials.
Use GitHub's private vulnerability reporting for the repository.
