# Agent instructions for Immich Drop

Read `README.md` and `SECURITY.md` before changing code or deployment files.
Treat the browser, VPS, NAS upload service, staging dataset, controller, and
Immich as separate trust zones.

## Non-negotiable boundaries

- The public service must never contain an Immich credential or connect to an
  Immich, database, Redis, Docker, or LAN network.
- Never add a public file listing, preview, stored-file `GET`, `Range`, or
  download route. Public `HEAD` is limited to the authenticated upload offset.
- Invitations always require an opaque token, password, finite expiry, finite
  bytes, finite file count, and finite per-file size.
- Browser-supplied paths, MIME types, client IP headers, and filenames are
  untrusted. Disk paths use server-generated identifiers under one configured
  marker-backed root.
- Quota reservation, exact-offset writes, completion, cancellation, closure,
  and expiry must remain race-safe. Partial uploads count against quotas.
- Content deduplication is server-verified only after completion and is scoped
  to one invitation. Never add a client-hash lookup oracle, cross-invitation
  deduplication, hard links, unbounded duplicate receipts, or a path that
  bypasses the invitation's monotonic attempt/ingress work budgets.
- Never log tokens, passwords, cookies, filenames, paths, query strings, or raw
  request targets. Test upstream-error logging as well as normal requests.
- No CDN, analytics, external font, remote script, service worker, or telemetry
  dependency is allowed in the public UI.
- Do not weaken missing-mount, low-disk, origin, CSRF, cookie, or type checks to
  make a test or local setup easier. Use an explicit isolated test fixture.

## Workflow

1. Run read-only discovery and preserve unrelated changes.
2. Use `apply_patch` for edits.
3. Add regression tests before relaxing or extending any route.
4. Run unit, race, resume, traversal, quota, expiry, type-spoof, crash cleanup,
   public no-read, secret, dependency, and image checks proportionate to change.
5. Keep deployment closed until the companion `immich-share doctor` verifies
   the live WireGuard/filter boundary and sanitized logs.
6. Never ask an operator to paste an invitation password, session secret,
   WireGuard key, SSH key, or Immich API key into chat.
