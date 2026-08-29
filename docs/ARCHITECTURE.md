# Architecture

## Trust zones

```text
Untrusted browser
       |
       | HTTPS: invitation and bounded upload routes only
       v
Public VPS
  Caddy -> upload guard
       |
       | dedicated WireGuard peer; no durable upload volume
       v
NAS ingress zone
  upload filter -> isolated Docker network -> Immich Drop
                                             |       |
                                      state database |
                                                     v
                                    dedicated staging filesystem

Local operator / NAS job -- explicit review and import --> Immich
```

The public request path ends at the staging service. Immich is not an upstream
of that path. The staging container has no Immich credential, Docker socket,
host network, or route to the Immich Docker network.

The VPS and NAS filters implement the same route allowlist. This is deliberate
defence in depth: a proxy configuration error on either side must not expose an
administration, filesystem, debug, or download route.

## Data flow

1. An operator creates a finite invitation locally. The CLI emits its URL and a
   generated password once.
2. The visitor opens the opaque URL and unlocks it over HTTPS. Authentication
   creates a short-lived, scoped, `Secure`, `HttpOnly` session.
3. Creating an upload reserves one file slot and its declared byte count in a
   transaction before the first chunk is accepted.
4. A fixed-size resumable stream is appended at the exact server-reported
   offset to a server-generated `.part` path.
5. The completed object is checked against both the policy extension and media
   signature, synced, and renamed atomically into `completed/`.
6. A separate trusted local process may review and import accepted files into
   Immich. This action is never triggered by an Internet request.

## Failure behaviour

- Missing or invalid staging marker: service startup fails.
- Insufficient configured reserve or global budget: upload creation fails
  before bytes are accepted.
- Expired or closed invitation: new work is denied and partial work is swept.
- Wrong offset, oversized chunk, quota race, or type mismatch: request is
  rejected without exposing a filesystem path.
- A slow client exceeds the absolute per-chunk deadline and releases its
  bounded application concurrency slot.
- VPS-to-NAS tunnel or NAS filter unavailable: public upload routes fail
  closed.

## Deployment ownership

This repository owns the upload application and image. The companion
`immich-share` repository owns Caddy, WireGuard, NAS filtering, lifecycle,
security checks, and deployment documentation. Keeping those responsibilities
separate prevents application updates from silently changing the network trust
boundary.
