# Operations

## Initialisation

Use a dedicated staging filesystem or dataset with its own quota. Create the
marker using the CLI, keep application state outside that filesystem, and make
both locations writable only by the container UID. Do not mount an Immich
library path into this service.

Generate the session secret locally into a mode `0600` file. Never put it in a
Compose file, repository, shell history, or support transcript.

## Invitation lifecycle

Create invitations locally with the narrowest suitable profile. The secure
defaults are finite even when the operator omits optional limits. Generated
passwords are preferable to custom passwords because they are not exposed via
process arguments or shell history.

`UPLOAD_WORK_MULTIPLIER` is a secure global default captured into each new
invitation. Its default value `3` permits bounded retries while preventing
repeated duplicates from creating unlimited cumulative work. Raising it also
raises the maximum ingress and request work available to one valid visitor;
the application refuses values above `10`.

Share the invitation URL and password through separate channels when practical.
Closing an invitation immediately prevents new sessions and new upload
requests. A chunk already being written may finish atomically; every waiting or
subsequent chunk is refused. The embedded single-process sweeper expires
abandoned partials at the configured bounded interval. Run the CLI sweeper only
for an explicit operator check; do not install a second recurring sweep job.

## Staging and import

Completed files remain non-public in the invitation's staging directory. An
operator or separate NAS-side job must review and import them. Any Immich API
key used by that job belongs only to the trusted import process and must never
be added to the upload container, VPS, public proxy, or application database.

Do not import partial files. Preserve the generated object identifier as the
filesystem name and treat the original visitor filename as untrusted display
metadata.

The manifest lists only the first canonical copy of identical content within
an invitation. Temporary duplicate receipts contain no media and consume no
byte or file quota; they are bounded per invitation and removed by the embedded
sweeper. Do not treat a duplicate receipt as an importable object.

## Monitoring

Monitor health, staging quota, free-space reserve, inode consumption, failed
authentication, rejected upload creation, abandoned partials, and HTTP error
rates. Unexpected growth in duplicate receipts should also be investigated.
Metrics and logs must use coarse invitation/job identifiers rather than
public tokens or filenames.

## Backup and recovery

Back up the small state database according to local policy. Staged media may be
excluded if contributors can retry and the invitation is still valid. Restore
the state database and staging filesystem consistently; reconciliation must run
before reopening the public route.

## Updates

Build from a reviewed commit, pin the resulting image digest in the deployment
repository, run route/quota/resume/security tests, scan dependencies and the
final image, and deploy with the public lifecycle kept off. Re-enable it only
after WireGuard, both filters, mount-marker, low-disk, and external no-read
checks pass.

The deduplication upgrade is additive: startup adds work-budget columns and a
duplicate-receipt table but does not rewrite or delete historical completed
files. Existing duplicate files therefore remain explicit staging objects;
only later completions are deduplicated. Take a consistent state DB and staging
snapshot before every upgrade as usual. A rollback to `v0.1.1` ignores the
additive schema safely, although uploads represented only by a new-version
duplicate receipt cannot be resumed until the new version is restored.
