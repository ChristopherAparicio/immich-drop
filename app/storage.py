"""SQLite accounting and filesystem staging primitives."""
from __future__ import annotations

import hashlib
import errno
import json
import os
import re
import shutil
import sqlite3
import time
import uuid
import fcntl
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from argon2 import PasswordHasher
from argon2.exceptions import VerificationError

from app.config import MARKER_NAME, Settings

PROFILES = {"photos", "videos", "both", "live"}
EXTENSIONS = {
    ".jpg": "photo", ".jpeg": "photo", ".png": "photo", ".webp": "photo",
    ".heic": "photo", ".heif": "photo", ".avif": "photo",
    ".mp4": "video", ".mov": "video", ".m4v": "video",
}
PROFILE_EXTENSIONS = {
    "photos": [".jpg", ".jpeg", ".png", ".webp", ".heic", ".heif", ".avif"],
    "videos": [".mp4", ".mov", ".m4v"],
    "both": list(EXTENSIONS),
    "live": [".jpg", ".jpeg", ".heic", ".heif", ".mov"],
}
PHOTO_BRANDS = {b"avif", b"avis", b"heic", b"heix", b"hevc", b"hevx", b"mif1", b"msf1"}
VIDEO_BRANDS = {b"isom", b"iso2", b"mp41", b"mp42", b"avc1", b"qt  ", b"M4V ", b"3gp4", b"3gp5"}

class StorageError(Exception):
    status, code = 400, "invalid_request"
    def __init__(self, message: str = "Request cannot be completed") -> None:
        super().__init__(message)

class NotFound(StorageError): status, code = 404, "not_found"
class Unauthorized(StorageError): status, code = 401, "unlock_required"
class Conflict(StorageError): status, code = 409, "offset_conflict"
class QuotaExceeded(StorageError): status, code = 413, "quota_exceeded"
class UnsupportedType(StorageError): status, code = 415, "unsupported_type"
class Expired(StorageError): status, code = 410, "invite_expired"
class InsufficientStorage(StorageError): status, code = 507, "insufficient_storage"

@dataclass(frozen=True)
class InviteSpec:
    name: str
    target_folder: str
    profile: str
    expires_at: int
    max_file_bytes: int
    max_files: int
    quota_bytes: int

def token_digest(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()

def safe_label(value: str, fallback: str = "Incoming") -> str:
    value = re.sub(r"[\x00-\x1f\x7f/\\]+", "_", value).strip(" .")
    return value[:120] or fallback

def extension_category(filename: str) -> tuple[str, str]:
    ext = Path(filename).suffix.lower()
    if ext not in EXTENSIONS:
        raise UnsupportedType("File extension is not allowed")
    return ext, EXTENSIONS[ext]

def sniff_category(path: Path) -> str:
    with path.open("rb") as handle:
        head = handle.read(64)
    if head.startswith(b"\xff\xd8\xff") or head.startswith(b"\x89PNG\r\n\x1a\n"):
        return "photo"
    if len(head) >= 12 and head[:4] == b"RIFF" and head[8:12] == b"WEBP":
        return "photo"
    if len(head) >= 12 and head[4:8] == b"ftyp":
        brands = {head[8:12]}
        brands.update(head[pos:pos + 4] for pos in range(16, len(head) - 3, 4))
        if brands & PHOTO_BRANDS and not brands & VIDEO_BRANDS:
            return "photo"
        if brands & VIDEO_BRANDS:
            return "video"
    raise UnsupportedType("File content is not an allowed media type")

def profile_accepts(profile: str, category: str, ext: str) -> bool:
    return ext in PROFILE_EXTENSIONS.get(profile, []) and EXTENSIONS[ext] == category

class Store:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.passwords = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2)

    @contextmanager
    def connect(self, immediate: bool = False) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.settings.state_db, timeout=15, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=15000")
        try:
            conn.execute("BEGIN IMMEDIATE" if immediate else "BEGIN")
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()
            for suffix in ("","-wal","-shm"):
                path=Path(f"{self.settings.state_db}{suffix}")
                if path.is_file() and not path.is_symlink(): os.chmod(path,0o600)

    def initialize(self) -> None:
        self.settings.state_db.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with sqlite3.connect(self.settings.state_db) as conn:
            conn.executescript("""
                PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;
                CREATE TABLE IF NOT EXISTS invites (
                    id TEXT PRIMARY KEY, token_hash TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL,
                    name TEXT NOT NULL, target_folder TEXT NOT NULL, profile TEXT NOT NULL,
                    expires_at INTEGER NOT NULL, closed_at INTEGER, max_file_bytes INTEGER NOT NULL,
                    max_files INTEGER NOT NULL, quota_bytes INTEGER NOT NULL, created_at INTEGER NOT NULL);
                CREATE TABLE IF NOT EXISTS uploads (
                    id TEXT PRIMARY KEY, invite_id TEXT NOT NULL REFERENCES invites(id),
                    original_name TEXT NOT NULL, extension TEXT NOT NULL, category TEXT NOT NULL,
                    declared_size INTEGER NOT NULL, offset INTEGER NOT NULL DEFAULT 0,
                    status TEXT NOT NULL, reserved_bytes INTEGER NOT NULL, sha256 TEXT,
                    created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, completed_at INTEGER);
                CREATE INDEX IF NOT EXISTS uploads_invite_status ON uploads(invite_id,status);
            """)
        os.chmod(self.settings.state_db, 0o600)

    def create_invite(self, token: str, password: str, spec: InviteSpec) -> str:
        now=int(time.time())
        if (spec.profile not in PROFILES or spec.expires_at <= now or
                spec.expires_at > now+self.settings.max_invite_ttl_seconds or not password):
            raise StorageError("Invalid invitation")
        if not (0 < spec.max_file_bytes <= spec.quota_bytes <= self.settings.global_budget_bytes) or spec.max_files <= 0:
            raise StorageError("Invalid invitation limits")
        invite_id = str(uuid.uuid4())
        with self.connect(True) as conn:
            conn.execute("""INSERT INTO invites
                (id,token_hash,password_hash,name,target_folder,profile,expires_at,max_file_bytes,max_files,quota_bytes,created_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (invite_id, token_digest(token), self.passwords.hash(password), safe_label(spec.name),
                 safe_label(spec.target_folder), spec.profile, spec.expires_at, spec.max_file_bytes,
                 spec.max_files, spec.quota_bytes, now))
        return invite_id

    def find_invite(self, token: str) -> sqlite3.Row:
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM invites WHERE token_hash=?", (token_digest(token),)).fetchone()
        if row is None: raise NotFound()
        return row

    @staticmethod
    def ensure_open(row: sqlite3.Row) -> None:
        if row["closed_at"] is not None: raise NotFound()
        if row["expires_at"] <= int(time.time()): raise Expired()

    def verify_password(self, invite: sqlite3.Row, password: str) -> bool:
        try: return self.passwords.verify(invite["password_hash"], password)
        except (VerificationError, TypeError): return False

    def paths(self, invite_id: str, upload_id: str, extension: str) -> tuple[Path, Path]:
        base = self.settings.incoming_root / invite_id
        partial = base / "partial" / f"{upload_id}.part"
        completed = base / "completed" / f"{upload_id}{extension}"
        root = self.settings.incoming_root.resolve()
        if any(root not in path.parent.resolve(strict=False).parents for path in (partial, completed)):
            raise RuntimeError("unsafe storage path")
        return partial, completed

    def write_manifest(self, invite_id: str) -> None:
        """Atomically publish NAS-local import metadata; never exposed over HTTP."""
        base = self.settings.incoming_root / invite_id
        base.mkdir(mode=0o700, parents=True, exist_ok=True)
        lock_path = base / ".manifest.lock"
        lock_fd = os.open(lock_path, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            with self.connect() as conn:
                invite = conn.execute("SELECT * FROM invites WHERE id=?", (invite_id,)).fetchone()
                items = conn.execute("SELECT * FROM uploads WHERE invite_id=? AND status='complete' ORDER BY completed_at,id", (invite_id,)).fetchall()
            if invite is None: return
            payload = {"version":1,"inviteId":invite_id,"label":invite["name"],
                "targetFolder":invite["target_folder"],"profile":invite["profile"],"files":[
                    {"uploadId":row["id"],"path":f"completed/{row['id']}{row['extension']}",
                     "originalName":row["original_name"],"size":row["declared_size"],
                     "sha256":row["sha256"],"completedAt":row["completed_at"]} for row in items]}
            temporary = base / f".manifest-{uuid.uuid4()}.tmp"
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            try:
                encoded = (json.dumps(payload,ensure_ascii=False,separators=(",",":"),sort_keys=True)+"\n").encode()
                view = memoryview(encoded)
                while view: view = view[os.write(fd,view):]
                os.fsync(fd)
            finally: os.close(fd)
            os.replace(temporary,base/"manifest.json")
            dir_fd=os.open(base,os.O_RDONLY)
            try: os.fsync(dir_fd)
            finally: os.close(dir_fd)
        finally:
            fcntl.flock(lock_fd,fcntl.LOCK_UN); os.close(lock_fd)

    def reserve_upload(self, invite: sqlite3.Row, filename: str, size: int) -> sqlite3.Row:
        self.ensure_open(invite)
        if type(size) is not int or size <= 0 or size > invite["max_file_bytes"]:
            raise QuotaExceeded("File exceeds invitation limit")
        ext, category = extension_category(filename)
        if not profile_accepts(invite["profile"], category, ext):
            raise UnsupportedType("File is not allowed by this invitation")
        upload_id, now = str(uuid.uuid4()), int(time.time())
        with self.connect(True) as conn:
            current = conn.execute("SELECT * FROM invites WHERE id=?", (invite["id"],)).fetchone()
            assert current is not None
            self.ensure_open(current)
            stats = conn.execute("SELECT COUNT(*) n,COALESCE(SUM(reserved_bytes),0) b FROM uploads WHERE invite_id=? AND status IN ('uploading','complete')", (invite["id"],)).fetchone()
            total = conn.execute("SELECT COALESCE(SUM(reserved_bytes),0) b FROM uploads WHERE status IN ('uploading','complete')").fetchone()["b"]
            pending = conn.execute("SELECT COALESCE(SUM(declared_size-offset),0) b FROM uploads WHERE status='uploading'").fetchone()["b"]
            if stats["n"] + 1 > current["max_files"] or stats["b"] + size > current["quota_bytes"]:
                raise QuotaExceeded("Invitation quota reached")
            if total + size > self.settings.global_budget_bytes:
                raise QuotaExceeded("Global staging budget reached")
            # `free` already accounts for bytes written so far. Subtract every
            # still-reserved byte as well, otherwise several empty `.part`
            # files can collectively promise more than the disk reserve.
            if shutil.disk_usage(self.settings.incoming_root).free - pending - size < self.settings.disk_reserve_bytes:
                raise QuotaExceeded("Disk reserve would be breached")
            conn.execute("""INSERT INTO uploads
                (id,invite_id,original_name,extension,category,declared_size,offset,status,reserved_bytes,created_at,updated_at)
                VALUES (?,?,?,?,?,?,0,'uploading',?,?,?)""",
                (upload_id, invite["id"], safe_label(filename, f"upload{ext}"), ext, category, size, size, now, now))
            row = conn.execute("SELECT * FROM uploads WHERE id=?", (upload_id,)).fetchone()
        partial, completed = self.paths(invite["id"], upload_id, ext)
        try:
            partial.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            completed.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            fd = os.open(partial, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600); os.close(fd)
        except Exception:
            with self.connect(True) as conn: conn.execute("DELETE FROM uploads WHERE id=?", (upload_id,))
            raise
        assert row is not None
        return row

    def get_upload(self, upload_id: str) -> sqlite3.Row:
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM uploads WHERE id=? AND status!='deleted'", (upload_id,)).fetchone()
        if row is None: raise NotFound()
        return row

    def append(self, upload: sqlite3.Row, expected_offset: int, data: bytes, checksum: bytes | None = None) -> sqlite3.Row:
        with self.upload_lock(upload):
            fresh=self.get_upload(upload["id"])
            with self.connect() as conn:
                invite=conn.execute("SELECT * FROM invites WHERE id=?",(fresh["invite_id"],)).fetchone()
            if invite is None: raise NotFound()
            # A close concurrent with an already-writing chunk may finish that chunk;
            # every waiter and every later chunk revalidates here before any write.
            self.ensure_open(invite)
            try:
                return self._append_locked(fresh,expected_offset,data,checksum)
            except OSError as exc:
                if exc.errno not in {errno.ENOSPC,errno.EDQUOT}: raise
                partial,_=self.paths(fresh["invite_id"],fresh["id"],fresh["extension"])
                actual=expected_offset
                if partial.exists():
                    try:
                        with partial.open("r+b",buffering=0) as handle:
                            handle.truncate(expected_offset); os.fsync(handle.fileno())
                        actual=expected_offset
                    except OSError:
                        actual=min(partial.stat().st_size,fresh["declared_size"])
                with self.connect(True) as conn:
                    conn.execute("UPDATE uploads SET offset=?,updated_at=? WHERE id=? AND status='uploading'",(actual,int(time.time()),fresh["id"]))
                raise InsufficientStorage("Staging storage is temporarily full") from exc

    @contextmanager
    def upload_lock(self, upload: sqlite3.Row):
        lock_dir=self.settings.incoming_root/upload["invite_id"]/".locks"
        lock_dir.mkdir(mode=0o700,parents=True,exist_ok=True)
        lock_fd=os.open(lock_dir/f"{upload['id']}.lock",os.O_WRONLY|os.O_CREAT|os.O_NOFOLLOW,0o600)
        try:
            fcntl.flock(lock_fd,fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(lock_fd,fcntl.LOCK_UN); os.close(lock_fd)

    def _lock_path(self, upload: sqlite3.Row) -> Path:
        return self.settings.incoming_root/upload["invite_id"]/".locks"/f"{upload['id']}.lock"

    def _delete_terminal_row(self, upload: sqlite3.Row, *allowed_statuses: str) -> bool:
        placeholders=",".join("?" for _ in allowed_statuses)
        with self.connect(True) as conn:
            result=conn.execute(f"DELETE FROM uploads WHERE id=? AND status IN ({placeholders})",
                (upload["id"],*allowed_statuses))
        if result.rowcount: self._lock_path(upload).unlink(missing_ok=True)
        return result.rowcount==1

    def _append_locked(self, upload: sqlite3.Row, expected_offset: int, data: bytes, checksum: bytes | None = None) -> sqlite3.Row:
        if upload["status"] == "complete":
            if expected_offset == upload["declared_size"] and not data: return upload
            raise Conflict()
        if expected_offset != upload["offset"]: raise Conflict()
        if not data or len(data) > self.settings.chunk_bytes: raise StorageError("Chunk must contain 1 byte to 8 MiB")
        if expected_offset + len(data) > upload["declared_size"]: raise Conflict("Chunk exceeds declared size")
        required=min(self.settings.chunk_bytes,upload["declared_size"]-expected_offset)
        if len(data)!=required: raise StorageError("Chunk must be exactly 8 MiB except for the final chunk")
        if checksum is not None and hashlib.sha256(data).digest() != checksum:
            raise Conflict("Chunk checksum mismatch")
        partial, completed = self.paths(upload["invite_id"], upload["id"], upload["extension"])
        fd = os.open(partial, os.O_WRONLY | os.O_NOFOLLOW)
        try:
            if os.lseek(fd, 0, os.SEEK_END) != expected_offset: raise Conflict()
            view = memoryview(data)
            while view: view = view[os.write(fd, view):]
            os.fsync(fd)
        finally: os.close(fd)
        new_offset, now = expected_offset + len(data), int(time.time())
        if new_offset == upload["declared_size"]:
            try:
                detected = sniff_category(partial)
                if detected != upload["category"]: raise UnsupportedType("Extension and content disagree")
                digest = hashlib.sha256()
                with partial.open("rb") as handle:
                    for block in iter(lambda: handle.read(1024 * 1024), b""): digest.update(block)
                os.replace(partial, completed)
                dir_fd = os.open(completed.parent, os.O_RDONLY)
                try: os.fsync(dir_fd)
                finally: os.close(dir_fd)
                with self.connect(True) as conn:
                    conn.execute("UPDATE uploads SET offset=?,status='complete',sha256=?,updated_at=?,completed_at=? WHERE id=? AND status='uploading'", (new_offset,digest.hexdigest(),now,now,upload["id"]))
                self.write_manifest(upload["invite_id"])
            except UnsupportedType:
                partial.unlink(missing_ok=True)
                self._delete_terminal_row(upload,"uploading")
                raise
        else:
            with self.connect(True) as conn:
                result = conn.execute("UPDATE uploads SET offset=?,updated_at=? WHERE id=? AND status='uploading' AND offset=?", (new_offset,now,upload["id"],expected_offset))
                if result.rowcount != 1: raise Conflict()
        return self.get_upload(upload["id"])

    def delete_upload(self, upload: sqlite3.Row) -> None:
        with self.upload_lock(upload):
            fresh=self.get_upload(upload["id"])
            if fresh["status"] == "complete": raise Conflict("Completed files cannot be deleted publicly")
            self.paths(fresh["invite_id"],fresh["id"],fresh["extension"])[0].unlink(missing_ok=True)
            self._delete_terminal_row(fresh,"uploading","rejected","deleted")

    def close_invite(self, invite_id: str) -> bool:
        with self.connect(True) as conn:
            result = conn.execute("UPDATE invites SET closed_at=? WHERE id=? AND closed_at IS NULL", (int(time.time()),invite_id))
        changed=result.rowcount == 1
        if changed: self.sweep()
        return changed

    def resolve_invite_id(self, value: str) -> str:
        with self.connect() as conn:
            rows=conn.execute("SELECT id FROM invites WHERE id LIKE ? ORDER BY id",(f"{value}%",)).fetchall()
        if len(rows)!=1: raise StorageError("Invitation ID or prefix is missing or ambiguous")
        return rows[0]["id"]

    def list_invites(self) -> list[sqlite3.Row]:
        with self.connect() as conn:
            return conn.execute("""SELECT i.id,i.name,i.target_folder,i.profile,i.expires_at,i.closed_at,i.max_file_bytes,i.max_files,i.quota_bytes,
              COUNT(u.id) files,COALESCE(SUM(u.reserved_bytes),0) bytes FROM invites i
              LEFT JOIN uploads u ON u.invite_id=i.id AND u.status!='deleted' GROUP BY i.id ORDER BY i.created_at DESC""").fetchall()

    def sweep(self, now: int | None = None) -> int:
        now = now or int(time.time()); cutoff = now - self.settings.incomplete_ttl_seconds
        with self.connect() as conn:
            rows=conn.execute("""SELECT u.* FROM uploads u JOIN invites i ON i.id=u.invite_id
                WHERE u.status='uploading' AND (u.updated_at<? OR i.expires_at<=? OR i.closed_at IS NOT NULL)""",(cutoff,now)).fetchall()
        swept=0
        for row in rows:
            with self.upload_lock(row):
                fresh=self.get_upload(row["id"])
                if fresh["status"]!="uploading": continue
                self.paths(fresh["invite_id"],fresh["id"],fresh["extension"])[0].unlink(missing_ok=True)
                swept += int(self._delete_terminal_row(fresh,"uploading"))
        return swept

    def reconcile(self) -> dict[str,int]:
        fixed = removed = 0; manifest_invites:set[str]=set()
        with self.connect() as conn: rows = conn.execute("SELECT * FROM uploads WHERE status IN ('uploading','complete')").fetchall()
        known: set[str] = set()
        for row in rows:
            partial, completed = self.paths(row["invite_id"],row["id"],row["extension"])
            known.update({os.path.abspath(partial),os.path.abspath(completed)})
            with self.upload_lock(row):
                fresh=self.get_upload(row["id"])
                if fresh["status"]=="uploading" and completed.exists() and not partial.exists():
                    candidate=completed
                elif fresh["status"]=="uploading" and partial.exists() and partial.stat().st_size==fresh["declared_size"]:
                    candidate=partial
                else: candidate=None
                if candidate is not None:
                    try:
                        if candidate.stat().st_size!=fresh["declared_size"] or sniff_category(candidate)!=fresh["category"]: raise UnsupportedType()
                        digest=hashlib.sha256()
                        with candidate.open("rb") as handle:
                            for block in iter(lambda:handle.read(1024*1024),b""): digest.update(block)
                        if candidate==partial: os.replace(partial,completed)
                        with self.connect(True) as conn:
                            conn.execute("UPDATE uploads SET offset=declared_size,status='complete',sha256=?,updated_at=?,completed_at=COALESCE(completed_at,?) WHERE id=?",(digest.hexdigest(),int(time.time()),int(time.time()),fresh["id"]))
                    except UnsupportedType:
                        candidate.unlink(missing_ok=True)
                        self._delete_terminal_row(fresh,"uploading")
                        fixed+=1
                    else:
                        self.write_manifest(fresh["invite_id"]); fixed+=1
                elif fresh["status"]=="uploading" and partial.exists():
                    actual=partial.stat().st_size
                    if actual<=fresh["declared_size"] and actual!=fresh["offset"]:
                        with self.connect(True) as conn: conn.execute("UPDATE uploads SET offset=? WHERE id=?",(actual,fresh["id"]))
                        fixed+=1
                elif fresh["status"]=="complete" and not completed.exists():
                    raise RuntimeError("completed staging file is missing")
                elif fresh["status"]=="uploading" and not partial.exists():
                    self._delete_terminal_row(fresh,"uploading")
                    fixed+=1
                elif fresh["status"]=="complete" and completed.exists(): manifest_invites.add(fresh["invite_id"])
        with self.connect() as conn:
            terminal=conn.execute("SELECT * FROM uploads WHERE status IN ('deleted','rejected')").fetchall()
        for row in terminal: self._delete_terminal_row(row,"deleted","rejected"); fixed+=1
        removed+=self._remove_orphans_without_following_symlinks(known)
        for invite_id in manifest_invites: self.write_manifest(invite_id)
        return {"fixed":fixed,"removed":removed}

    def _remove_orphans_without_following_symlinks(self, known: set[str]) -> int:
        """Clean only immediate staging structure entries, never traversing a symlink."""
        removed=0; directory_flags=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW
        root_fd=os.open(self.settings.incoming_root,directory_flags)
        try:
            with os.scandir(root_fd) as invites:
                for invite in invites:
                    if invite.name==MARKER_NAME: continue
                    if invite.is_symlink(): os.unlink(invite.name,dir_fd=root_fd); removed+=1; continue
                    if not invite.is_dir(follow_symlinks=False): continue
                    try: invite_fd=os.open(invite.name,directory_flags,dir_fd=root_fd)
                    except OSError: continue
                    try:
                        with os.scandir(invite_fd) as children:
                            for child in children:
                                if child.is_symlink(): os.unlink(child.name,dir_fd=invite_fd); removed+=1; continue
                                if child.is_file(follow_symlinks=False):
                                    if child.name.startswith(".manifest-") and child.name.endswith(".tmp"):
                                        os.unlink(child.name,dir_fd=invite_fd); removed+=1
                                    continue
                                if not child.is_dir(follow_symlinks=False) or child.name not in {"partial","completed",".locks"}: continue
                                try: child_fd=os.open(child.name,directory_flags,dir_fd=invite_fd)
                                except OSError: continue
                                try:
                                    with os.scandir(child_fd) as entries:
                                        for entry in entries:
                                            if entry.is_symlink(): os.unlink(entry.name,dir_fd=child_fd); removed+=1; continue
                                            if child.name==".locks" or not entry.is_file(follow_symlinks=False): continue
                                            lexical=os.path.abspath(self.settings.incoming_root/invite.name/child.name/entry.name)
                                            if lexical not in known: os.unlink(entry.name,dir_fd=child_fd); removed+=1
                                finally: os.close(child_fd)
                    finally: os.close(invite_fd)
        finally: os.close(root_fd)
        return removed

    def purge(self, invite_id: str) -> bool:
        try: uuid.UUID(invite_id)
        except ValueError: return False
        with self.connect() as conn: invite=conn.execute("SELECT closed_at FROM invites WHERE id=?",(invite_id,)).fetchone()
        if invite is None: return False
        if invite["closed_at"] is None: raise StorageError("Close the invitation before purging it")
        target = self.settings.incoming_root / invite_id
        if target.parent.resolve() != self.settings.incoming_root.resolve(): raise RuntimeError("unsafe purge target")
        if target.exists(): shutil.rmtree(target)
        with self.connect(True) as conn:
            conn.execute("DELETE FROM uploads WHERE invite_id=?",(invite_id,)); conn.execute("DELETE FROM invites WHERE id=?",(invite_id,))
        return True
