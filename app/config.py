"""Strict, environment-only configuration for the staging service."""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

MARKER_NAME = ".immich-drop-root"
MARKER_VALUE = "immich-drop-incoming-v1\n"
MAX_PASSWORD_BYTES = 256

def _positive_int(name: str, default: int) -> int:
    try:
        value = int(os.getenv(name, str(default)))
    except ValueError as exc:
        raise RuntimeError(f"{name} must be an integer") from exc
    if value <= 0:
        raise RuntimeError(f"{name} must be greater than zero")
    return value

@dataclass(frozen=True)
class Settings:
    incoming_root: Path
    state_db: Path
    public_base_url: str
    session_secret: str
    global_budget_bytes: int = 100 * 1024**3
    disk_reserve_bytes: int = 10 * 1024**3
    default_max_file_bytes: int = 512 * 1024**2
    default_max_files: int = 500
    default_quota_bytes: int = 1024**3
    chunk_bytes: int = 8 * 1024**2
    incomplete_ttl_seconds: int = 24 * 3600
    session_max_age_seconds: int = 12 * 3600
    max_client_concurrency: int = 2
    max_active_uploads: int = 3
    max_active_unlocks: int = 2
    max_invite_ttl_seconds: int = 7 * 24 * 3600
    log_level: str = "INFO"
    cookie_secure: bool = True

    @property
    def public_origin(self) -> str:
        parsed = urlparse(self.public_base_url)
        return f"{parsed.scheme}://{parsed.netloc}"

    def validate(self, *, require_marker: bool = True) -> None:
        parsed = urlparse(self.public_base_url)
        schemes = {"https"} if self.cookie_secure else {"http", "https"}
        if parsed.scheme not in schemes or not parsed.netloc:
            raise RuntimeError("PUBLIC_BASE_URL must be an absolute HTTPS URL")
        if len(self.session_secret.encode()) < 32:
            raise RuntimeError("SESSION_SECRET must contain at least 32 bytes")
        if self.chunk_bytes != 8 * 1024**2:
            raise RuntimeError("UPLOAD_CHUNK_BYTES must be exactly 8388608")
        root = self.incoming_root
        if not root.is_absolute() or root.is_symlink() or not root.is_dir():
            raise RuntimeError("INCOMING_ROOT must be an existing absolute non-symlink directory")
        if require_marker:
            marker = root / MARKER_NAME
            try:
                if marker.is_symlink() or marker.read_text(encoding="utf-8") != MARKER_VALUE:
                    raise RuntimeError("INCOMING_ROOT marker is invalid")
            except OSError as exc:
                raise RuntimeError("INCOMING_ROOT marker is missing or unreadable") from exc
        try:
            resolved_root = root.resolve(strict=True)
            resolved_db_parent = self.state_db.parent.resolve(strict=True)
        except OSError as exc:
            raise RuntimeError("STATE_DB parent and INCOMING_ROOT must already exist") from exc
        if resolved_db_parent == resolved_root or resolved_root in resolved_db_parent.parents:
            raise RuntimeError("STATE_DB must be outside INCOMING_ROOT")
        values = (self.global_budget_bytes, self.disk_reserve_bytes, self.default_max_file_bytes,
                  self.default_max_files, self.default_quota_bytes, self.incomplete_ttl_seconds,
                  self.max_client_concurrency,self.max_active_uploads,self.max_active_unlocks,self.max_invite_ttl_seconds)
        if any(value <= 0 for value in values):
            raise RuntimeError("All resource limits must be greater than zero")
        if self.default_max_file_bytes > self.default_quota_bytes:
            raise RuntimeError("DEFAULT_MAX_FILE_BYTES cannot exceed DEFAULT_QUOTA_BYTES")
        if self.default_quota_bytes > self.global_budget_bytes:
            raise RuntimeError("DEFAULT_QUOTA_BYTES cannot exceed GLOBAL_BUDGET_BYTES")

def load_settings() -> Settings:
    secret_file = os.getenv("SESSION_SECRET_FILE", "").strip()
    if secret_file:
        path = Path(secret_file)
        try:
            if not path.is_absolute() or path.is_symlink() or not path.is_file():
                raise RuntimeError("SESSION_SECRET_FILE must be an absolute regular non-symlink file")
            if path.stat().st_mode & 0o077:
                raise RuntimeError("SESSION_SECRET_FILE permissions must be 0600 or stricter")
            secret = path.read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise RuntimeError("SESSION_SECRET_FILE is unreadable") from exc
    else:
        secret = os.getenv("SESSION_SECRET", "")
    return Settings(
        incoming_root=Path(os.getenv("INCOMING_ROOT", "/incoming")),
        state_db=Path(os.getenv("STATE_DB", "/data/state.db")),
        public_base_url=os.getenv("PUBLIC_BASE_URL", ""),
        session_secret=secret,
        global_budget_bytes=_positive_int("GLOBAL_BUDGET_BYTES", 100 * 1024**3),
        disk_reserve_bytes=_positive_int("DISK_RESERVE_BYTES", 10 * 1024**3),
        default_max_file_bytes=_positive_int("DEFAULT_MAX_FILE_BYTES", 512 * 1024**2),
        default_max_files=_positive_int("DEFAULT_MAX_FILES", 500),
        default_quota_bytes=_positive_int("DEFAULT_QUOTA_BYTES", 1024**3),
        chunk_bytes=_positive_int("UPLOAD_CHUNK_BYTES", 8 * 1024**2),
        incomplete_ttl_seconds=_positive_int("INCOMPLETE_TTL_SECONDS", 24 * 3600),
        session_max_age_seconds=_positive_int("SESSION_MAX_AGE_SECONDS", 12 * 3600),
        max_client_concurrency=_positive_int("MAX_CLIENT_CONCURRENCY", 2),
        max_active_uploads=_positive_int("MAX_ACTIVE_UPLOADS", 3),
        max_active_unlocks=_positive_int("MAX_ACTIVE_UNLOCKS", 2),
        max_invite_ttl_seconds=_positive_int("MAX_INVITE_TTL_SECONDS", 7 * 24 * 3600),
        log_level=os.getenv("LOG_LEVEL", "INFO").upper(),
        cookie_secure=os.getenv("COOKIE_SECURE", "true").lower() not in {"0", "false", "no"},
    )
