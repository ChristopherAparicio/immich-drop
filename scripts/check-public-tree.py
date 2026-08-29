#!/usr/bin/env python3
"""Fail CI if public source accidentally gains infrastructure or secret material."""
from __future__ import annotations

import re
import subprocess
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent.parent
TRACKED = subprocess.run(
    ["git", "ls-files", "-co", "--exclude-standard"],
    cwd=ROOT,
    check=True,
    capture_output=True,
    text=True,
).stdout.splitlines()

forbidden_paths = re.compile(r"(^|/)(\.env|id_(rsa|ed25519)|.*\.key|wg.*\.conf)$", re.I)
secret_patterns = {
    "private key": re.compile(r"-----BEGIN (?:OPENSSH |RSA |EC )?PRIVATE KEY-----"),
    "Immich API key variable": re.compile(r"IMMICH_API_KEY\s*=\s*\S+"),
    "WireGuard private key assignment": re.compile(r"PrivateKey\s*=\s*[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]="),
}
url_pattern = re.compile(r"https?://[^\s<>'\"`]+", re.I)
allowed_hosts = {"github.com", "localhost", "127.0.0.1", "drop.test", "evil.test"}

failures: list[str] = []
for relative in TRACKED:
    if forbidden_paths.search(relative):
        failures.append(f"forbidden tracked path: {relative}")
        continue
    path = ROOT / relative
    if not path.is_file() or path.stat().st_size > 2_000_000:
        continue
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        continue
    for label, pattern in secret_patterns.items():
        if pattern.search(text):
            failures.append(f"{label}: {relative}")
    for match in url_pattern.finditer(text):
        host = (urlparse(match.group(0).rstrip(".,);]")).hostname or "").lower()
        if host not in allowed_hosts and not host.endswith(".example.com"):
            failures.append(f"non-example public hostname {host}: {relative}")

if failures:
    raise SystemExit("Public-tree check failed:\n" + "\n".join(sorted(set(failures))))
print(f"Public-tree check passed ({len(TRACKED)} files checked)")
