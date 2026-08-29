#!/bin/sh
# Runtime regression for the final non-root, read-only image. Test credentials
# are ephemeral and never printed.
set -eu

image=${IMMICH_DROP_TEST_IMAGE:-immich-drop:local}
python_bin=${PYTHON:-python3}
suffix=$$
incoming_volume=immich-drop-e2e-incoming-$suffix
state_volume=immich-drop-e2e-state-$suffix
container_name=immich-drop-e2e-$suffix
port=${IMMICH_DROP_TEST_PORT:-18081}
origin=http://127.0.0.1:$port

cleanup() {
    docker rm -f "$container_name" >/dev/null 2>&1 || true
    docker volume rm "$incoming_volume" "$state_volume" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

docker volume create "$incoming_volume" >/dev/null
docker volume create "$state_volume" >/dev/null
docker run --rm --user 0 \
    -v "$incoming_volume:/incoming" -v "$state_volume:/data" \
    "$image" sh -c 'chown 65532:65532 /incoming /data && chmod 0700 /incoming /data'

set -- \
    -e INCOMING_ROOT=/incoming \
    -e STATE_DB=/data/state.db \
    -e PUBLIC_BASE_URL="$origin" \
    -e SESSION_SECRET=container-e2e-session-secret-only-000000000000 \
    -e COOKIE_SECURE=false \
    -e GLOBAL_BUDGET_BYTES=33554432 \
    -e DISK_RESERVE_BYTES=1 \
    -e DEFAULT_MAX_FILE_BYTES=16777216 \
    -e DEFAULT_MAX_FILES=4 \
    -e DEFAULT_QUOTA_BYTES=25165824

docker run --rm "$@" \
    -v "$incoming_volume:/incoming" -v "$state_volume:/data" \
    "$image" python -m app.cli init --yes >/dev/null

docker run -d --name "$container_name" --read-only --cap-drop ALL \
    --security-opt no-new-privileges:true \
    --tmpfs /tmp:rw,noexec,nosuid,nodev,size=16m \
    -p "127.0.0.1:$port:8080" "$@" \
    -v "$incoming_volume:/incoming" -v "$state_volume:/data" \
    "$image" >/dev/null

ready=false
attempt=0
while [ "$attempt" -lt 40 ]; do
    if curl -fsS "$origin/healthz" >/dev/null 2>&1; then
        ready=true
        break
    fi
    attempt=$((attempt + 1))
    sleep 0.25
done
[ "$ready" = true ] || {
    printf 'Container did not become healthy\n' >&2
    exit 1
}

DROP_E2E_CONTAINER=$container_name DROP_E2E_ORIGIN=$origin \
    "$python_bin" - <<'PY'
import base64
import hashlib
import json
import os
import subprocess

import httpx

name = os.environ["DROP_E2E_CONTAINER"]
origin = os.environ["DROP_E2E_ORIGIN"]

opened = json.loads(subprocess.run(
    ["docker", "exec", name, "python", "-m", "app.cli", "open",
     "--label", "Container E2E", "--ttl", "1h", "--profile", "photos", "--json"],
    check=True, capture_output=True, text=True,
).stdout)
token = opened["link"].rsplit("/", 1)[1]
password = opened["generatedPassword"]

with httpx.Client(base_url=origin, follow_redirects=False) as client:
    page = client.get(f"/drop/i/{token}")
    assert page.status_code == 200
    csrf = client.cookies["drop-csrf"]
    headers = {"Origin": origin, "X-Drop-CSRF": csrf}
    unlocked = client.post(
        f"/drop/api/invites/{token}/unlock",
        json={"password": password}, headers=headers,
    )
    assert unlocked.status_code == 204
    policy = client.get(f"/drop/api/invites/{token}/policy")
    assert policy.status_code == 200
    assert policy.json()["chunkBytes"] == 8 * 1024 * 1024

    rejected = client.post(
        f"/drop/api/invites/{token}/uploads",
        json={"name": "malware.exe", "size": 20}, headers=headers,
    )
    assert rejected.status_code == 415

    data = b"\xff\xd8\xff" + b"a" * (8 * 1024 * 1024 + 254)
    created = client.post(
        f"/drop/api/invites/{token}/uploads",
        json={"name": "event.jpg", "size": len(data)}, headers=headers,
    )
    assert created.status_code == 201
    upload_url = created.json()["uploadUrl"]
    offset = 0
    for chunk in (data[:8 * 1024 * 1024], data[8 * 1024 * 1024:]):
        chunk_headers = {
            **headers,
            "Content-Type": "application/offset+octet-stream",
            "Upload-Offset": str(offset),
            "Upload-Checksum": "sha256 " + base64.b64encode(
                hashlib.sha256(chunk).digest()
            ).decode(),
        }
        response = client.patch(upload_url, content=chunk, headers=chunk_headers)
        assert response.status_code == 204
        offset = int(response.headers["Upload-Offset"])
        head = client.head(upload_url)
        assert int(head.headers["Upload-Offset"]) == offset
    assert head.headers["Upload-State"] == "complete"
    assert client.get(upload_url).status_code == 405

closed = json.loads(subprocess.run(
    ["docker", "exec", name, "python", "-m", "app.cli", "close", opened["id"], "--json"],
    check=True, capture_output=True, text=True,
).stdout)
assert closed["closed"] is True

inspection = json.loads(subprocess.run(
    ["docker", "exec", name, "python", "-c",
     "import json,pathlib; f=list(pathlib.Path('/incoming').glob('*/completed/*.jpg')); "
     "m=list(pathlib.Path('/incoming').glob('*/manifest.json')); "
     "print(json.dumps({'files':len(f),'manifests':len(m),'bytes':f[0].stat().st_size}))"],
    check=True, capture_output=True, text=True,
).stdout)
assert inspection == {"files": 1, "manifests": 1, "bytes": 8 * 1024 * 1024 + 257}

logs_result = subprocess.run(["docker", "logs", name], capture_output=True, text=True)
logs = logs_result.stdout + logs_result.stderr
assert token not in logs and password not in logs
print(json.dumps({
    "chunks": 2,
    "containerE2E": "passed",
    "credentialLeakInLogs": False,
    "uploadedBytes": inspection["bytes"],
}, sort_keys=True))
PY
