#!/usr/bin/env python3
"""Local-only operator CLI. It never accepts passwords as command arguments."""
from __future__ import annotations

import argparse
import getpass
import json
import os
import secrets
import string
import stat
import time
from pathlib import Path

from app.config import MAX_PASSWORD_BYTES, MARKER_NAME, MARKER_VALUE, load_settings
from app.storage import InviteSpec, StorageError, Store

def duration(value: str) -> int:
    units = {"m":60,"h":3600,"d":86400,"w":604800}
    try: amount, unit = int(value[:-1]), value[-1].lower()
    except (ValueError, IndexError) as exc: raise argparse.ArgumentTypeError("use 30m, 12h, 7d, or 2w") from exc
    if amount <= 0 or unit not in units: raise argparse.ArgumentTypeError("duration must be positive and end in m/h/d/w")
    return amount * units[unit]

def byte_size(value: str) -> int:
    units = {"b":1,"kib":1024,"mib":1024**2,"gib":1024**3,"tib":1024**4}
    raw = value.strip().lower()
    for suffix in sorted(units,key=len,reverse=True):
        if raw.endswith(suffix):
            try: number = float(raw[:-len(suffix)])
            except ValueError: break
            if number > 0: return int(number * units[suffix])
    raise argparse.ArgumentTypeError("use a positive size such as 500MiB or 2GiB")

def generated_password(length: int = 22) -> str:
    alphabet = string.ascii_letters + string.digits + "-._~"
    return "".join(secrets.choice(alphabet) for _ in range(length))

def profile(value: str) -> str:
    aliases={"photos":"photos","videos":"videos","both":"both","live":"live",
             "photos+videos":"both","photos+live":"live"}
    try: return aliases[value.lower()]
    except KeyError as exc: raise argparse.ArgumentTypeError("choose photos, videos, photos+videos, or photos+live") from exc

def read_password(args: argparse.Namespace) -> tuple[str,bool]:
    if args.password_file:
        path = Path(args.password_file)
        try: fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
        except OSError as exc: raise SystemExit("password file cannot be opened safely") from exc
        try:
            info=os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid(): raise SystemExit("password file must be a regular file owned by this user")
            if info.st_mode & 0o077: raise SystemExit("password file permissions must be 0600 or stricter")
            raw=os.read(fd,MAX_PASSWORD_BYTES+3)
        finally: os.close(fd)
        try: value=raw.decode("utf-8").rstrip("\r\n")
        except UnicodeDecodeError as exc: raise SystemExit("password file must be UTF-8") from exc
        if not value: raise SystemExit("password file is empty")
        if len(value.encode("utf-8")) > MAX_PASSWORD_BYTES: raise SystemExit("password is too long")
        return value, False
    if args.prompt_password:
        first = getpass.getpass("Invitation password: "); second = getpass.getpass("Confirm password: ")
        if not first or first != second: raise SystemExit("passwords are empty or do not match")
        if len(first.encode("utf-8")) > MAX_PASSWORD_BYTES: raise SystemExit("password is too long")
        return first, False
    return generated_password(), True

def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="dropctl", description="Manage local staging invitations",allow_abbrev=False)
    root.add_argument("--json",action="store_true",help="emit stable machine-readable JSON")
    sub = root.add_subparsers(dest="command",required=True)
    init = sub.add_parser("init"); init.add_argument("--yes",action="store_true")
    create = sub.add_parser("open", aliases=["create"],allow_abbrev=False)
    create.add_argument("--label","--name",dest="name",required=True); create.add_argument("--folder")
    create.add_argument("--profile",type=profile,default="photos")
    create.add_argument("--ttl",type=duration,default=24*3600)
    create.add_argument("--max-file",type=byte_size); create.add_argument("--max-files",type=int)
    create.add_argument("--quota",type=byte_size); create.add_argument("--password-file")
    create.add_argument("--prompt-password",action="store_true")
    create.add_argument("--json",action="store_true",default=argparse.SUPPRESS)
    listing=sub.add_parser("list"); listing.add_argument("--json",action="store_true",default=argparse.SUPPRESS)
    close = sub.add_parser("close"); close.add_argument("invite_id"); close.add_argument("--json",action="store_true",default=argparse.SUPPRESS)
    sweep=sub.add_parser("sweep"); sweep.add_argument("--json",action="store_true",default=argparse.SUPPRESS)
    purge = sub.add_parser("purge"); purge.add_argument("invite_id"); purge.add_argument("--yes",action="store_true")
    return root

def main(argv: list[str] | None = None) -> int:
    # Operator-facing failures are one clean line on stderr and exit status 1,
    # never a traceback (which would print the state or staging paths).
    try: return _run(argv)
    except StorageError as exc: raise SystemExit(f"dropctl: {exc}") from exc

def _run(argv: list[str] | None) -> int:
    args = parser().parse_args(argv); cfg = load_settings()
    if args.command == "init":
        if not args.yes: raise SystemExit("init requires --yes after verifying INCOMING_ROOT is the mounted staging volume")
        if not cfg.incoming_root.is_absolute() or cfg.incoming_root.is_symlink() or not cfg.incoming_root.is_dir():
            raise SystemExit("INCOMING_ROOT must already be an absolute mounted directory")
        cfg.state_db.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
        marker = cfg.incoming_root / MARKER_NAME
        if marker.exists():
            if marker.is_symlink() or marker.read_text(encoding="utf-8") != MARKER_VALUE: raise SystemExit("existing marker is invalid")
        else:
            fd = os.open(marker,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
            try: os.write(fd,MARKER_VALUE.encode()); os.fsync(fd)
            finally: os.close(fd)
        cfg.validate(); Store(cfg).initialize(); print("Staging root and database initialized"); return 0
    cfg.validate(); store = Store(cfg); store.initialize()
    if args.command in {"open","create"}:
        if args.password_file and args.prompt_password: raise SystemExit("choose either --password-file or --prompt-password")
        password, show = read_password(args); token = secrets.token_urlsafe(32)
        max_file = args.max_file or cfg.default_max_file_bytes; max_files = args.max_files or cfg.default_max_files
        quota = args.quota or cfg.default_quota_bytes
        if args.ttl>cfg.max_invite_ttl_seconds: raise SystemExit("TTL exceeds MAX_INVITE_TTL_SECONDS")
        spec = InviteSpec(args.name,args.folder or args.name,args.profile,int(time.time())+args.ttl,max_file,max_files,quota)
        invite_id = store.create_invite(token,password,spec)
        link=f"{cfg.public_base_url.rstrip('/')}/drop/i/{token}"
        if args.json: print(json.dumps({"id":invite_id,"link":link,"generatedPassword":password if show else None},separators=(",",":"),sort_keys=True))
        else:
            print(f"Invitation ID: {invite_id}"); print(f"Link: {link}")
            if show: print(f"Password (shown once): {password}")
    elif args.command == "list":
        now = int(time.time()); rows=store.list_invites()
        if args.json:
            print(json.dumps([{"id":row["id"],"label":row["name"],"targetFolder":row["target_folder"],
                "profile":row["profile"],"expiresAt":row["expires_at"],
                "active":row["closed_at"] is None and row["expires_at"]>now,
                "fileCount":row["files"],"maxFiles":row["max_files"],"reservedBytes":row["bytes"],
                "quotaBytes":row["quota_bytes"],"maxFileBytes":row["max_file_bytes"]} for row in rows],
                separators=(",",":"),sort_keys=True))
            return 0
        for row in rows:
            state = "closed" if row["closed_at"] else ("expired" if row["expires_at"] <= now else "open")
            print(f"{row['id']}\t{state}\t{row['profile']}\t{row['files']}/{row['max_files']} files\t{row['bytes']}/{row['quota_bytes']} bytes\t{row['name']} -> {row['target_folder']}")
    elif args.command == "close":
        try: invite_id=store.resolve_invite_id(args.invite_id)
        except Exception as exc: raise SystemExit(str(exc)) from exc
        if not store.close_invite(invite_id): raise SystemExit("invitation not found or already closed")
        if args.json: print(json.dumps({"id":invite_id,"closed":True},separators=(",",":"),sort_keys=True))
        else: print("Invitation closed")
    elif args.command == "sweep":
        reconciled = store.reconcile(); swept = store.sweep()
        if args.json: print(json.dumps({"reconciled":reconciled,"swept":swept},separators=(",",":"),sort_keys=True))
        else: print(f"Reconciled: {reconciled['fixed']} fixed, {reconciled['removed']} stray files removed, "
                    f"{reconciled['orphaned']} completed files moved to orphaned/; swept: {swept}")
    elif args.command == "purge":
        if not args.yes:
            answer = input(f"Permanently delete invitation {args.invite_id} and all staged files? [y/N] ")
            if answer.strip().lower() != "y": return 1
        if not store.purge(args.invite_id): raise SystemExit("invitation not found")
        print("Invitation and staged files purged")
    return 0

if __name__ == "__main__": raise SystemExit(main())
