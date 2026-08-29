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

Share the invitation URL and password through separate channels when practical.
Closing an invitation immediately prevents new sessions and new upload
requests. A chunk already being written may finish atomically; every waiting or
subsequent chunk is refused. Run the sweeper regularly from one place only to
expire invitations and abandoned partials.

## Staging and import

Completed files remain non-public in the invitation's staging directory. An
operator or separate NAS-side job must review and import them. Any Immich API
key used by that job belongs only to the trusted import process and must never
be added to the upload container, VPS, public proxy, or application database.

Do not import partial files. Preserve the generated object identifier as the
filesystem name and treat the original visitor filename as untrusted display
metadata.

## Monitoring

Monitor health, staging quota, free-space reserve, inode consumption, failed
authentication, rejected upload creation, abandoned partials, and HTTP error
rates. Metrics and logs must use coarse invitation/job identifiers rather than
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
