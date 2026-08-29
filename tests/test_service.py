from __future__ import annotations

import base64
import errno
import hashlib
import json
import os
import shutil
import sqlite3
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
import app.storage as storage_module
from fastapi.testclient import TestClient

from app.app import CSRF_COOKIE, create_app
from app.config import MARKER_NAME, MARKER_VALUE, Settings, load_settings
from app.storage import InsufficientStorage, InviteSpec, QuotaExceeded, StorageError, Store
from dropctl import main as cli_main, parser, read_password

ORIGIN = "https://drop.test"

@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    incoming = tmp_path / "incoming"; incoming.mkdir(mode=0o700)
    marker=incoming / MARKER_NAME; marker.write_text(MARKER_VALUE); marker.chmod(0o600)
    data = tmp_path / "data"; data.mkdir(mode=0o700)
    return Settings(incoming,data/"state.db",ORIGIN,"s"*48,global_budget_bytes=10_000_000,
                    disk_reserve_bytes=1,default_max_file_bytes=2_000_000,
                    default_max_files=10,default_quota_bytes=5_000_000,
                    incomplete_ttl_seconds=60,cookie_secure=True)

@pytest.fixture
def invitation(settings: Settings):
    store = Store(settings); store.initialize(); token="public-token-for-test"
    invite_id = store.create_invite(token,"correct horse battery staple",
        InviteSpec("Family drop","Family incoming","both",int(time.time())+3600,9_000_000,10,9_500_000))
    return store,token,invite_id

@pytest.fixture
def client(settings: Settings, invitation):
    with TestClient(create_app(settings),base_url=ORIGIN) as test_client: yield test_client

def csrf(client: TestClient) -> str:
    value = client.cookies.get(CSRF_COOKIE)
    assert value; return value

def unlock(client: TestClient, token: str, password="correct horse battery staple"):
    first = client.get(f"/drop/api/invites/{token}/policy")
    assert first.status_code == 401 and first.json()["error"] == "unlock_required"
    response = client.post(f"/drop/api/invites/{token}/unlock",json={"password":password},
        headers={"Origin":ORIGIN,"X-Drop-CSRF":csrf(client)})
    return response

def create_upload(client: TestClient, token: str, name: str, data: bytes) -> dict:
    response = client.post(f"/drop/api/invites/{token}/uploads",
        json={"name":name,"size":len(data),"lastModified":123},
        headers={"Origin":ORIGIN,"X-Drop-CSRF":csrf(client)})
    assert response.status_code == 201, response.text
    return response.json()

def patch(client: TestClient, url: str, offset: int, data: bytes, checksum=True):
    headers={"Origin":ORIGIN,"X-Drop-CSRF":csrf(client),"Upload-Offset":str(offset),
             "Content-Type":"application/offset+octet-stream"}
    if checksum:
        headers["Upload-Checksum"]="sha256 "+base64.b64encode(hashlib.sha256(data).digest()).decode()
    return client.patch(url,content=data,headers=headers)

def test_marker_and_secret_are_fail_closed(tmp_path: Path):
    incoming=tmp_path/"incoming"; incoming.mkdir(mode=0o700)
    data=tmp_path/"data"; data.mkdir(mode=0o700)
    cfg=Settings(incoming,data/"state.db",ORIGIN,"short",disk_reserve_bytes=1)
    with pytest.raises(RuntimeError): cfg.validate()
    cfg=Settings(incoming,data/"state.db",ORIGIN,"x"*40,disk_reserve_bytes=1)
    with pytest.raises(RuntimeError,match="marker"): cfg.validate()
    marker=incoming/MARKER_NAME; marker.write_text(MARKER_VALUE); marker.chmod(0o600)
    cfg.validate()

def test_password_csrf_origin_and_policy(client: TestClient, invitation):
    _,token,_=invitation
    assert client.get(f"/drop/api/invites/{token}/policy").status_code==401
    assert client.post(f"/drop/api/invites/{token}/unlock",json={"password":"x"},
        headers={"Origin":"https://evil.test","X-Drop-CSRF":csrf(client)}).status_code==400
    assert client.post(f"/drop/api/invites/{token}/unlock",json={"password":"wrong"},
        headers={"Origin":ORIGIN,"X-Drop-CSRF":csrf(client)}).status_code==401
    assert unlock(client,token).status_code==204
    policy=client.get(f"/drop/api/invites/{token}/policy")
    assert policy.status_code==200
    assert policy.json()["chunkBytes"]==8*1024**2
    assert "targetFolder" not in policy.json() and "remaining" not in policy.json()
    session=client.cookies.get("drop-session")
    assert session and "correct" not in session

def test_successful_unlocks_are_rate_limited_too(client: TestClient,invitation):
    _,token,_=invitation; client.get(f"/drop/api/invites/{token}/policy")
    headers={"Origin":ORIGIN,"X-Drop-CSRF":csrf(client)}
    for _ in range(5):
        assert client.post(f"/drop/api/invites/{token}/unlock",json={"password":"correct horse battery staple"},headers=headers).status_code==204
    response=client.post(f"/drop/api/invites/{token}/unlock",json={"password":"correct horse battery staple"},headers=headers)
    assert response.status_code==429 and response.headers["retry-after"]=="300"

def test_small_json_routes_reject_oversize_and_chunked_bodies(client: TestClient, invitation):
    _,token,_=invitation
    client.get(f"/drop/api/invites/{token}/policy")
    headers={"Origin":ORIGIN,"X-Drop-CSRF":csrf(client),"Content-Type":"application/json"}
    oversized=client.post(f"/drop/api/invites/{token}/unlock",content=b'{' + b' ' * 5000 + b'}',headers=headers)
    assert oversized.status_code==413
    chunked=client.post(f"/drop/api/invites/{token}/unlock",content=b'{"password":"x"}',
        headers={**headers,"Transfer-Encoding":"chunked"})
    assert chunked.status_code==400

def test_patch_rejects_transfer_encoding(client: TestClient,invitation):
    _,token,_=invitation; assert unlock(client,token).status_code==204
    data=b"\xff\xd8\xffokay"; created=create_upload(client,token,"x.jpg",data)
    response=client.patch(created["uploadUrl"],content=data,headers={"Origin":ORIGIN,
        "X-Drop-CSRF":csrf(client),"Upload-Offset":"0","Content-Type":"application/offset+octet-stream",
        "Transfer-Encoding":"chunked"})
    assert response.status_code==400 and response.json()["error"]=="ambiguous_body_framing"

def test_resumable_upload_exact_offsets_checksum_and_manifest(client: TestClient, invitation, settings: Settings):
    _,token,invite_id=invitation; assert unlock(client,token).status_code==204
    data=b"\xff\xd8\xff"+os.urandom(8*1024**2+97); created=create_upload(client,token,"../holiday.jpg",data)
    assert created["chunkBytes"]==8*1024**2 and created["uploadUrl"].startswith("/drop/api/uploads/")
    first=data[:8*1024**2]; r=patch(client,created["uploadUrl"],0,first)
    assert r.status_code==204 and r.headers["upload-offset"]==str(8*1024**2)
    head=client.head(created["uploadUrl"]); assert head.headers["upload-state"]=="receiving"
    duplicate=patch(client,created["uploadUrl"],0,first); assert duplicate.status_code==409
    wrong=patch(client,created["uploadUrl"],8*1024**2,data[8*1024**2:],checksum=False)
    assert wrong.status_code==204 and wrong.headers["upload-state"]=="complete"
    assert client.head(created["uploadUrl"]).headers["upload-state"]=="complete"
    assert patch(client,created["uploadUrl"],0,b"x").status_code==409
    manifest=json.loads((settings.incoming_root/invite_id/"manifest.json").read_text())
    assert manifest["targetFolder"]=="Family incoming" and manifest["files"][0]["size"]==len(data)
    assert ".." not in manifest["files"][0]["originalName"]
    assert not any(path.name.startswith("holiday") for path in (settings.incoming_root/invite_id/"completed").iterdir())

def test_spoofed_type_is_rejected_and_reservation_released(client: TestClient, invitation,settings: Settings):
    store,token,_=invitation; assert unlock(client,token).status_code==204
    fake=b"not a jpeg at all"; created=create_upload(client,token,"photo.jpg",fake)
    response=patch(client,created["uploadUrl"],0,fake)
    assert response.status_code==415
    with store.connect() as conn:
        assert conn.execute("SELECT COUNT(*) FROM uploads WHERE id=?",(created["uploadId"],)).fetchone()[0]==0
    assert not list(settings.incoming_root.glob("*/.locks/*.lock"))

def test_profile_rejects_video_extension_before_writing(settings: Settings):
    store=Store(settings); store.initialize(); token="photos-only"
    store.create_invite(token,"password",InviteSpec("Photos","Photos","photos",int(time.time())+60,1000,3,2000))
    invite=store.find_invite(token)
    with pytest.raises(Exception) as exc: store.reserve_upload(invite,"movie.mp4",100)
    assert getattr(exc.value,"status",None)==415
    assert list(settings.incoming_root.glob("*/*/*.part"))==[]

def test_atomic_quota_reservation_race(settings: Settings):
    store=Store(settings); store.initialize(); token="race"
    store.create_invite(token,"password",InviteSpec("Race","Race","photos",int(time.time())+60,800,5,1000))
    barrier=threading.Barrier(2)
    def attempt(index):
        barrier.wait()
        try: store.reserve_upload(store.find_invite(token),f"{index}.jpg",600); return "ok"
        except QuotaExceeded: return "quota"
    with ThreadPoolExecutor(max_workers=2) as pool: results=list(pool.map(attempt,range(2)))
    assert sorted(results)==["ok","quota"]
    with store.connect() as conn:
        assert conn.execute("SELECT SUM(reserved_bytes) FROM uploads").fetchone()[0]==600

def test_expiry_blocks_existing_session(client: TestClient, invitation):
    store,token,invite_id=invitation; assert unlock(client,token).status_code==204
    with store.connect(True) as conn: conn.execute("UPDATE invites SET expires_at=? WHERE id=?",(int(time.time())-1,invite_id))
    response=client.post(f"/drop/api/invites/{token}/uploads",json={"name":"x.jpg","size":10},
        headers={"Origin":ORIGIN,"X-Drop-CSRF":csrf(client)})
    assert response.status_code==410

def test_reconcile_sweep_and_orphan_cleanup(settings: Settings):
    store=Store(settings); store.initialize(); token="cleanup"
    store.create_invite(token,"password",InviteSpec("Cleanup","Cleanup","photos",int(time.time())+60,1000,5,3000))
    upload=store.reserve_upload(store.find_invite(token),"x.jpg",100)
    partial,_=store.paths(upload["invite_id"],upload["id"],upload["extension"]); partial.write_bytes(b"123")
    orphan=partial.parent/"orphan.part"; orphan.write_bytes(b"x")
    result=store.reconcile(); assert result=={"fixed":1,"removed":1}
    assert store.get_upload(upload["id"])["offset"]==3 and not orphan.exists()
    with store.connect(True) as conn: conn.execute("UPDATE uploads SET updated_at=0 WHERE id=?",(upload["id"],))
    assert store.sweep(now=1000)==1 and not partial.exists()
    with store.connect() as conn:
        assert conn.execute("SELECT COUNT(*) FROM uploads WHERE id=?",(upload["id"],)).fetchone()[0]==0

def test_concurrent_duplicate_patch_is_serialized(settings: Settings):
    store=Store(settings); store.initialize(); token="patch-race"
    store.create_invite(token,"password",InviteSpec("Race","Race","photos",int(time.time())+60,1000,2,1500))
    upload=store.reserve_upload(store.find_invite(token),"x.jpg",103)
    data=b"\xff\xd8\xff"+b"a"*100; barrier=threading.Barrier(2)
    def attempt(_):
        barrier.wait()
        try: store.append(upload,0,data); return "ok"
        except Exception as exc: return getattr(exc,"code",type(exc).__name__)
    with ThreadPoolExecutor(max_workers=2) as pool: results=list(pool.map(attempt,range(2)))
    assert sorted(results)==["offset_conflict","ok"]
    assert store.get_upload(upload["id"])["status"]=="complete"

def test_non_final_chunks_must_be_exactly_8_mib(settings: Settings):
    store=Store(settings); store.initialize(); token="exact-chunk"
    store.create_invite(token,"password",InviteSpec("Exact","Exact","photos",int(time.time())+60,9_000_000,2,9_500_000))
    upload=store.reserve_upload(store.find_invite(token),"x.jpg",8*1024**2+1)
    with pytest.raises(StorageError,match="exactly 8 MiB"): store.append(upload,0,b"\xff\xd8\xffsmall")
    assert store.get_upload(upload["id"])["offset"]==0

def test_pending_chunk_revalidates_invite_after_close(settings: Settings):
    store=Store(settings); store.initialize(); token="close-race"
    invite_id=store.create_invite(token,"password",InviteSpec("Close","Close","photos",int(time.time())+60,1000,2,1500))
    upload=store.reserve_upload(store.find_invite(token),"x.jpg",7)
    with store.upload_lock(upload):
        with store.connect(True) as conn: conn.execute("UPDATE invites SET closed_at=? WHERE id=?",(int(time.time()),invite_id))
    with pytest.raises(Exception) as exc: store.append(upload,0,b"\xff\xd8\xffokay")
    assert getattr(exc.value,"status",None)==404
    assert store.get_upload(upload["id"])["offset"]==0

def test_reconcile_recovers_crash_after_atomic_rename(settings: Settings):
    store=Store(settings); store.initialize(); token="crash"
    invite_id=store.create_invite(token,"password",InviteSpec("Crash","Crash","photos",int(time.time())+60,1000,2,1500))
    upload=store.reserve_upload(store.find_invite(token),"x.jpg",7)
    partial,completed=store.paths(invite_id,upload["id"],upload["extension"])
    partial.write_bytes(b"\xff\xd8\xffokay"); os.replace(partial,completed)
    assert store.reconcile()["fixed"]==1
    row=store.get_upload(upload["id"]); assert row["status"]=="complete" and row["sha256"]
    assert completed.exists() and json.loads((settings.incoming_root/invite_id/"manifest.json").read_text())["files"]

def test_reconcile_regenerates_missing_or_stale_manifest(settings: Settings):
    store=Store(settings); store.initialize(); token="manifest-repair"
    invite_id=store.create_invite(token,"password",InviteSpec("Manifest","Manifest","photos",int(time.time())+60,1000,2,1500))
    data=b"\xff\xd8\xffvalid"; upload=store.reserve_upload(store.find_invite(token),"x.jpg",len(data)); store.append(upload,0,data)
    manifest=settings.incoming_root/invite_id/"manifest.json"; manifest.write_text('{"stale":true}')
    store.reconcile(); repaired=json.loads(manifest.read_text())
    assert repaired["version"]==1 and repaired["files"][0]["uploadId"]==upload["id"]

def test_reconcile_io_error_preserves_completed_candidate(settings: Settings,monkeypatch):
    store=Store(settings); store.initialize(); token="io-preserve"
    invite_id=store.create_invite(token,"password",InviteSpec("IO","IO","photos",int(time.time())+60,1000,2,1500))
    upload=store.reserve_upload(store.find_invite(token),"x.jpg",7)
    partial,completed=store.paths(invite_id,upload["id"],upload["extension"])
    partial.write_bytes(b"\xff\xd8\xffokay"); os.replace(partial,completed)
    def io_failure(_path): raise OSError(errno.EIO,"read failure")
    monkeypatch.setattr(storage_module,"sniff_category",io_failure)
    with pytest.raises(OSError): store.reconcile()
    assert completed.read_bytes()==b"\xff\xd8\xffokay"
    row=store.get_upload(upload["id"])
    assert row["status"]=="uploading" and row["reserved_bytes"]==7

def test_cancel_and_reject_cycles_remain_bounded(settings: Settings):
    store=Store(settings); store.initialize(); token="bounded-cycles"
    invite_id=store.create_invite(token,"password",InviteSpec("Bounded","Bounded","photos",int(time.time())+60,1000,1,1500))
    for index in range(20):
        upload=store.reserve_upload(store.find_invite(token),f"cancel-{index}.jpg",10)
        store.delete_upload(upload)
    for index in range(20):
        upload=store.reserve_upload(store.find_invite(token),f"reject-{index}.jpg",4)
        with pytest.raises(Exception) as exc: store.append(upload,0,b"nope")
        assert getattr(exc.value,"status",None)==415
    with store.connect() as conn: assert conn.execute("SELECT COUNT(*) FROM uploads").fetchone()[0]==0
    assert not list((settings.incoming_root/invite_id/".locks").glob("*.lock"))

def test_reconcile_never_traverses_directory_symlinks(settings: Settings,tmp_path: Path):
    external=tmp_path/"external"; nested=external/"partial"; nested.mkdir(parents=True)
    victim=nested/"keep.jpg"; victim.write_bytes(b"important")
    rogue=settings.incoming_root/"rogue-invite"; rogue.symlink_to(external,target_is_directory=True)
    store=Store(settings); store.initialize(); result=store.reconcile()
    assert result["removed"]==1 and victim.read_bytes()==b"important" and not rogue.exists()

def test_enospc_becomes_507_without_releasing_reservation(settings: Settings, monkeypatch):
    store=Store(settings); store.initialize(); token="storage-full"
    store.create_invite(token,"password",InviteSpec("Full","Full","photos",int(time.time())+60,1000,2,1500))
    upload=store.reserve_upload(store.find_invite(token),"x.jpg",10)
    def full(*_args,**_kwargs): raise OSError(errno.ENOSPC,"full")
    monkeypatch.setattr(store,"_append_locked",full)
    with pytest.raises(InsufficientStorage) as exc: store.append(upload,0,b"123")
    assert exc.value.status==507
    row=store.get_upload(upload["id"]); assert row["status"]=="uploading" and row["reserved_bytes"]==10

def test_purge_requires_closed_invitation(settings: Settings,monkeypatch):
    store=Store(settings); store.initialize(); token="purge-closed"
    invite_id=store.create_invite(token,"password",InviteSpec("Purge","Purge","photos",int(time.time())+60,1000,2,1500))
    with pytest.raises(StorageError,match="Close"): store.purge(invite_id)
    assert store.close_invite(invite_id)
    target=settings.incoming_root/invite_id; target.mkdir(exist_ok=True)
    def fail(_target): raise OSError(errno.EIO,"filesystem failure")
    monkeypatch.setattr(shutil,"rmtree",fail)
    with pytest.raises(OSError): store.purge(invite_id)
    with store.connect() as conn: assert conn.execute("SELECT COUNT(*) FROM invites WHERE id=?",(invite_id,)).fetchone()[0]==1

def test_tokens_and_passwords_are_not_logged(client: TestClient, invitation, caplog):
    _,token,_=invitation
    caplog.set_level("DEBUG")
    client.get(f"/drop/api/invites/{token}/policy")
    unlock(client,token,"wrong-secret-password")
    text="\n".join(record.getMessage() for record in caplog.records if record.name=="immich_drop")
    assert "status=401" in text
    assert token not in text and "wrong-secret-password" not in text

def test_validation_errors_never_echo_password_or_filename(client: TestClient, invitation):
    _,token,_=invitation
    client.get(f"/drop/i/{token}")
    secret="private-password-" + "x"*250
    response=client.post(f"/drop/api/invites/{token}/unlock",json={"password":secret},
        headers={"Origin":ORIGIN,"X-Drop-CSRF":csrf(client)})
    assert response.status_code==422 and response.json()["error"]=="invalid_request"
    assert secret not in response.text

def test_secret_file_and_state_permissions_fail_closed(settings: Settings,monkeypatch,tmp_path: Path):
    secret=tmp_path/"session-secret"; secret.write_text("s"*48); secret.chmod(0o644)
    monkeypatch.setenv("SESSION_SECRET_FILE",str(secret))
    with pytest.raises(RuntimeError,match="private regular file"): load_settings()
    insecure=tmp_path/"insecure-state"; insecure.mkdir(mode=0o755)
    candidate=Settings(**{**settings.__dict__,"state_db":insecure/"state.db"})
    with pytest.raises(RuntimeError,match="STATE_DB parent"): candidate.validate()

def test_unexpected_errors_do_not_log_internal_paths(settings: Settings, caplog, monkeypatch):
    token="unexpected-error-token-1234"; store=Store(settings); store.initialize()
    store.create_invite(token,"password",InviteSpec("Failure","Failure","photos",int(time.time())+60,1000,2,1500))
    secret_path="/incoming/private/invite-token/photo.jpg"
    with TestClient(create_app(settings),base_url=ORIGIN,raise_server_exceptions=False) as c:
        assert unlock(c,token,"password").status_code==204
        upload=create_upload(c,token,"photo.jpg",b"\xff\xd8\xff"+b"x"*50)
        def fail(*_args,**_kwargs): raise OSError(secret_path)
        monkeypatch.setattr(c.app.state.store,"append",fail)
        caplog.clear(); response=patch(c,upload["uploadUrl"],0,b"\xff\xd8\xff"+b"x"*50)
    assert response.status_code==500 and response.json()["error"]=="internal_error"
    assert secret_path not in "\n".join(record.getMessage() for record in caplog.records)

def test_no_public_listing_read_admin_or_docs(client: TestClient, invitation):
    _,token,_=invitation
    for path in ("/docs","/openapi.json","/drop/api/invites","/drop/api/uploads","/api/albums"):
        assert client.get(path).status_code==404
    assert client.get(f"/drop/i/{token}").status_code==200

def test_global_active_patch_limit_returns_429(settings: Settings):
    limited=Settings(**{**settings.__dict__,"max_active_uploads":1})
    store=Store(limited); store.initialize(); token="active-limit-token-1234"
    store.create_invite(token,"password",InviteSpec("Limit","Limit","photos",int(time.time())+60,1000,3,2000))
    with TestClient(create_app(limited),base_url=ORIGIN) as c:
        assert unlock(c,token,"password").status_code==204
        data=b"\xff\xd8\xff"+b"x"*50
        one=create_upload(c,token,"one.jpg",data); two=create_upload(c,token,"two.jpg",data)
        entered=threading.Event(); release=threading.Event(); original=c.app.state.store.append
        def blocking(*args,**kwargs):
            entered.set(); assert release.wait(5); return original(*args,**kwargs)
        c.app.state.store.append=blocking
        with ThreadPoolExecutor(max_workers=2) as pool:
            first=pool.submit(patch,c,one["uploadUrl"],0,data)
            assert entered.wait(5)
            second=patch(c,two["uploadUrl"],0,data)
            release.set(); done=first.result(timeout=5)
        assert done.status_code==204
        assert second.status_code==429 and second.headers["retry-after"]=="2"

def test_global_argon_limiter_returns_429(settings: Settings):
    limited=Settings(**{**settings.__dict__,"max_active_unlocks":1}); store=Store(limited); store.initialize()
    token="argon-limit-token-1234"; store.create_invite(token,"password",InviteSpec("Argon","Argon","photos",int(time.time())+60,1000,2,1500))
    with TestClient(create_app(limited),base_url=ORIGIN) as c:
        c.get(f"/drop/api/invites/{token}/policy"); headers={"Origin":ORIGIN,"X-Drop-CSRF":csrf(c)}
        entered=threading.Event(); release=threading.Event(); original=c.app.state.store.verify_password
        def blocking(*args,**kwargs): entered.set(); assert release.wait(5); return original(*args,**kwargs)
        c.app.state.store.verify_password=blocking
        with ThreadPoolExecutor(max_workers=2) as pool:
            first=pool.submit(c.post,f"/drop/api/invites/{token}/unlock",json={"password":"password"},headers=headers)
            assert entered.wait(5)
            second=c.post(f"/drop/api/invites/{token}/unlock",json={"password":"password"},headers=headers)
            release.set(); done=first.result(timeout=5)
        assert done.status_code==204 and second.status_code==429 and second.headers["retry-after"]=="2"

def test_sweep_releases_expired_incomplete_upload(settings: Settings):
    store=Store(settings); store.initialize(); token="expire-sweep"
    invite_id=store.create_invite(token,"password",InviteSpec("Expiry","Expiry","photos",int(time.time())+30,1000,2,1500))
    upload=store.reserve_upload(store.find_invite(token),"x.jpg",100)
    with store.connect(True) as conn: conn.execute("UPDATE invites SET expires_at=? WHERE id=?",(1,invite_id))
    assert store.sweep()==1
    with store.connect() as conn: assert conn.execute("SELECT COUNT(*) FROM uploads WHERE id=?",(upload["id"],)).fetchone()[0]==0

def test_cli_has_no_password_argument_and_secure_defaults():
    parsed=parser().parse_args(["open","--label","Event","--profile","photos+videos","--ttl","1h"])
    assert parsed.profile=="both" and parsed.folder is None
    with pytest.raises(SystemExit): parser().parse_args(["open","--name","Event","--password","secret"])

def test_session_cookie_is_scoped_to_drop(client: TestClient, invitation):
    _,token,_=invitation
    response=client.get(f"/drop/i/{token}")
    session_cookie=next(value for value in response.headers.get_list("set-cookie") if value.startswith("drop-session=")).lower()
    assert all(attribute in session_cookie for attribute in ("path=/drop","secure","httponly","samesite=strict"))

def test_custom_password_limit_is_consistent(tmp_path: Path):
    password_file=tmp_path/"password"; password_file.write_text("x"*257,encoding="utf-8"); password_file.chmod(0o600)
    args=parser().parse_args(["open","--name","Event","--password-file",str(password_file)])
    with pytest.raises(SystemExit,match="too long"): read_password(args)

def test_cli_json_is_stable_and_does_not_list_tokens(settings: Settings,monkeypatch,capsys):
    env={"INCOMING_ROOT":str(settings.incoming_root),"STATE_DB":str(settings.state_db),
         "PUBLIC_BASE_URL":ORIGIN,"SESSION_SECRET":"s"*48,"COOKIE_SECURE":"true",
         "GLOBAL_BUDGET_BYTES":"10000000","DISK_RESERVE_BYTES":"1",
         "DEFAULT_MAX_FILE_BYTES":"1000","DEFAULT_MAX_FILES":"2","DEFAULT_QUOTA_BYTES":"1500"}
    for name,value in env.items(): monkeypatch.setenv(name,value)
    assert cli_main(["open","--label","JSON event","--ttl","1h","--json"])==0
    opened=json.loads(capsys.readouterr().out); assert set(opened)=={"generatedPassword","id","link"} and opened["generatedPassword"]
    assert cli_main(["list","--json"])==0
    listed=json.loads(capsys.readouterr().out); assert listed[0]["active"] is True
    assert "token" not in json.dumps(listed).lower() and "link" not in listed[0]
