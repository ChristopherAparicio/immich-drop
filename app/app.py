"""Fail-closed public API for password-gated, resumable NAS staging."""
from __future__ import annotations

import base64
import binascii
import hmac
import logging
import re
import secrets
import time
import uuid
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from pathlib import Path

from anyio import CapacityLimiter, WouldBlock, create_task_group, fail_after, sleep, to_thread
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse, Response
from pydantic import BaseModel, ConfigDict, Field
from starlette.middleware.sessions import SessionMiddleware
from starlette.concurrency import run_in_threadpool

from app.config import MAX_PASSWORD_BYTES, Settings, load_settings
from app.storage import (PROFILE_EXTENSIONS, Conflict, NotFound, StorageError, Store,
                         Unauthorized, token_digest)

logger = logging.getLogger("immich_drop")
CSRF_COOKIE = "drop-csrf"
CSRF_HEADER = "X-Drop-CSRF"

class UnlockBody(BaseModel):
    password: str = Field(min_length=1, max_length=MAX_PASSWORD_BYTES)

class UploadBody(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    name: str = Field(min_length=1, max_length=255)
    size: int = Field(gt=0)
    last_modified: int | None = Field(default=None, alias="lastModified")

def _error(status: int, code: str, message: str | None = None, headers: dict[str,str] | None = None) -> JSONResponse:
    return JSONResponse({"error": code, "message": message or "Request cannot be completed"}, status_code=status, headers=headers)

def _public_state(database_state: str) -> str:
    return "receiving" if database_state == "uploading" else database_state

def _validate_token(token: str) -> None:
    if not re.fullmatch(r"[A-Za-z0-9_-]{20,128}",token): raise NotFound()

def _validate_upload_id(upload_id: str) -> None:
    try:
        if str(uuid.UUID(upload_id))!=upload_id.lower(): raise ValueError
    except ValueError as exc: raise NotFound() from exc

def create_app(settings: Settings | None = None) -> FastAPI:
    configured = settings

    @asynccontextmanager
    async def lifespan(application: FastAPI):
        current = configured or load_settings()
        current.validate()
        logging.basicConfig(level=current.log_level, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
        store = Store(current); store.initialize(); store.reconcile(); store.sweep()
        application.state.settings = current; application.state.store = store
        async def maintenance() -> None:
            while True:
                await sleep(current.sweep_interval_seconds)
                try:
                    removed = await to_thread.run_sync(store.sweep)
                    if removed: logger.info("maintenance action=sweep removed=%s",removed)
                except Exception:
                    logger.error("maintenance action=sweep status=failed")
        async with create_task_group() as tasks:
            tasks.start_soon(maintenance)
            yield
            tasks.cancel_scope.cancel()

    application = FastAPI(title="Immich Drop Staging", docs_url=None, redoc_url=None,
                          openapi_url=None, lifespan=lifespan)
    # The only signed authentication state is an opaque invite UUID and expiry.
    secret = settings.session_secret if settings else "x" * 32
    max_age = settings.session_max_age_seconds if settings else 12 * 3600
    secure = settings.cookie_secure if settings else True
    application.add_middleware(SessionMiddleware, secret_key=secret, session_cookie="drop-session",
                               max_age=max_age, path="/drop", same_site="strict", https_only=secure)
    attempts: dict[str, deque[float]] = defaultdict(deque)
    patch_limiter=CapacityLimiter(settings.max_active_uploads if settings else 3)
    unlock_limiter=CapacityLimiter(settings.max_active_unlocks if settings else 2)

    def get_store(request: Request) -> Store: return request.app.state.store
    def get_settings(request: Request) -> Settings: return request.app.state.settings

    def csrf_token(request: Request) -> str:
        token = request.session.get("csrf")
        if not isinstance(token, str) or len(token) < 32:
            token = secrets.token_urlsafe(32); request.session["csrf"] = token
        return token

    def set_csrf(response: Response, request: Request) -> None:
        cfg = get_settings(request)
        response.set_cookie(CSRF_COOKIE, csrf_token(request), secure=cfg.cookie_secure,
                            httponly=False, samesite="strict", path="/drop", max_age=cfg.session_max_age_seconds)

    def require_mutation(request: Request) -> None:
        cfg = get_settings(request)
        if request.headers.get("origin") != cfg.public_origin:
            raise StorageError("Invalid request origin")
        expected = request.session.get("csrf")
        cookie = request.cookies.get(CSRF_COOKIE)
        header = request.headers.get(CSRF_HEADER)
        if not all(isinstance(value, str) for value in (expected, cookie, header)):
            raise StorageError("CSRF validation failed")
        if not hmac.compare_digest(expected, cookie) or not hmac.compare_digest(expected, header):
            raise StorageError("CSRF validation failed")

    def invite_for_session(request: Request, token: str):
        _validate_token(token)
        store = get_store(request); invite = store.find_invite(token); store.ensure_open(invite)
        auth = request.session.get("invite")
        if not isinstance(auth, dict) or auth.get("id") != invite["id"] or auth.get("until", 0) < int(time.time()):
            raise Unauthorized()
        return invite

    def upload_for_session(request: Request, upload_id: str):
        _validate_upload_id(upload_id)
        upload = get_store(request).get_upload(upload_id)
        auth = request.session.get("invite")
        if not isinstance(auth, dict) or auth.get("id") != upload["invite_id"] or auth.get("until", 0) < int(time.time()):
            raise NotFound()
        with get_store(request).connect() as conn:
            invite = conn.execute("SELECT * FROM invites WHERE id=?", (upload["invite_id"],)).fetchone()
        if invite is None: raise NotFound()
        get_store(request).ensure_open(invite)
        return upload

    @application.exception_handler(StorageError)
    async def storage_error(_request: Request, exc: StorageError):
        return _error(exc.status, exc.code, str(exc))

    @application.exception_handler(RequestValidationError)
    async def invalid_body(_request: Request, _exc: RequestValidationError):
        # FastAPI's default validation payload repeats rejected input. That can
        # include a password or visitor filename, so expose only a stable code.
        return _error(422, "invalid_request")

    @application.exception_handler(Exception)
    async def unexpected_error(_request: Request, _exc: Exception):
        # Paths and invite credentials can be present in exception strings. Keep
        # the public response and the runtime log deliberately generic.
        logger.error("request failed status=500")
        return _error(500, "internal_error")

    @application.middleware("http")
    async def harden(request: Request, call_next):
        path_parts=request.url.path.strip("/").split("/")
        json_mutation=(request.method=="POST" and len(path_parts)==5 and
            path_parts[:3]==["drop","api","invites"] and path_parts[4] in {"unlock","uploads"})
        content_length=request.headers.get("content-length")
        transfer_encoding=request.headers.get("transfer-encoding")
        response=None
        if json_mutation:
            if transfer_encoding: response=_error(400,"ambiguous_body_framing")
            elif content_length is None: response=_error(411,"length_required")
            else:
                try: length=int(content_length)
                except ValueError: response=_error(400,"invalid_length")
                else:
                    if length<0: response=_error(400,"invalid_length")
                    elif length>4096: response=_error(413,"body_too_large")
                    elif request.headers.get("content-type","").split(";",1)[0].lower()!="application/json":
                        response=_error(415,"unsupported_media_type")
        elif request.method in {"GET","HEAD","DELETE"}:
            if transfer_encoding or (content_length is not None and content_length not in {"0",""}):
                response=_error(400,"request_body_not_allowed")
        if response is None: response = await call_next(request)
        logger.info("request method=%s status=%s",request.method,response.status_code)
        response.headers.update({
            "Cache-Control": "no-store", "Pragma": "no-cache", "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer", "X-Frame-Options": "DENY",
            "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
            "Content-Security-Policy": "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
        })
        return response

    @application.get("/healthz")
    async def health() -> dict[str,str]: return {"status": "ok"}

    @application.get("/drop/i/{token}")
    async def invite_page(request: Request, token: str):
        _validate_token(token)
        target = Path(__file__).resolve().parent.parent / "frontend" / "invite.html"
        response = FileResponse(target)
        set_csrf(response, request)
        return response

    @application.get("/drop/assets/{asset:path}")
    async def static_asset(asset: str):
        if asset not in {"app.js","drop.css","favicon.png"}: raise NotFound()
        root = Path(__file__).resolve().parent.parent / "frontend"
        target = (root / asset).resolve()
        if root.resolve() not in target.parents or not target.is_file(): raise NotFound()
        return FileResponse(target)

    @application.get("/drop/api/invites/{token}/policy")
    async def policy(request: Request, token: str):
        _validate_token(token)
        store = get_store(request); invite = store.find_invite(token); store.ensure_open(invite)
        auth = request.session.get("invite")
        if not isinstance(auth, dict) or auth.get("id") != invite["id"] or auth.get("until", 0) < int(time.time()):
            response = _error(Unauthorized.status, Unauthorized.code)
            set_csrf(response, request)
            return response
        cfg = get_settings(request)
        response = JSONResponse({
            "label": invite["name"], "expiresAt": invite["expires_at"], "profile": invite["profile"],
            "allowedExtensions": PROFILE_EXTENSIONS[invite["profile"]], "maxFileBytes": invite["max_file_bytes"],
            "maxFiles": invite["max_files"], "quotaBytes": invite["quota_bytes"], "chunkBytes": cfg.chunk_bytes,
            "maxClientConcurrency": cfg.max_client_concurrency,
        })
        set_csrf(response, request)
        return response

    @application.post("/drop/api/invites/{token}/unlock")
    async def unlock(request: Request, token: str, body: UnlockBody):
        require_mutation(request)
        _validate_token(token)
        store = get_store(request); invite = store.find_invite(token); store.ensure_open(invite)
        key = token_digest(token); now = time.monotonic(); bucket = attempts[key]
        while bucket and bucket[0] < now - 300: bucket.popleft()
        if len(bucket) >= 5: return _error(429, "too_many_attempts", headers={"Retry-After":"300"})
        try: unlock_limiter.acquire_nowait()
        except WouldBlock: return _error(429,"server_busy",headers={"Retry-After":"2"})
        bucket.append(now)
        try: verified=await run_in_threadpool(store.verify_password,invite,body.password)
        finally: unlock_limiter.release()
        if not verified: return _error(401, "invalid_password")
        until = min(invite["expires_at"], int(time.time()) + get_settings(request).session_max_age_seconds)
        request.session["invite"] = {"id": invite["id"], "until": until}
        return Response(status_code=204)

    @application.post("/drop/api/invites/{token}/uploads", status_code=201)
    async def create_upload(request: Request, token: str, body: UploadBody):
        require_mutation(request); invite = invite_for_session(request, token)
        upload = get_store(request).reserve_upload(invite, body.name, body.size)
        url = f"/drop/api/uploads/{upload['id']}"
        return JSONResponse({"uploadId":upload["id"],"uploadUrl":url,"offset":0,
                             "chunkBytes":get_settings(request).chunk_bytes}, status_code=201,
                            headers={"Location":url})

    @application.head("/drop/api/uploads/{upload_id}")
    async def head_upload(request: Request, upload_id: str):
        upload = upload_for_session(request, upload_id)
        return Response(status_code=204, headers={"Upload-Offset":str(upload["offset"]),
            "Upload-Length":str(upload["declared_size"]),"Upload-State":_public_state(upload["status"])})

    @application.patch("/drop/api/uploads/{upload_id}")
    async def patch_upload(request: Request, upload_id: str):
        require_mutation(request); upload = upload_for_session(request, upload_id)
        raw_length=request.headers.get("content-length"); charged_bytes=0
        try:
            parsed_for_charge=int(raw_length) if raw_length is not None else 0
            if parsed_for_charge>0: charged_bytes=min(parsed_for_charge,get_settings(request).chunk_bytes)
        except ValueError:
            pass
        get_store(request).reserve_ingress(upload,charged_bytes)
        if request.headers.get("content-type", "").split(";",1)[0].strip().lower() != "application/offset+octet-stream":
            return _error(415,"unsupported_media_type")
        if request.headers.get("transfer-encoding"): return _error(400,"ambiguous_body_framing")
        try: expected = int(request.headers["upload-offset"])
        except (KeyError, ValueError): return _error(400,"invalid_offset")
        content_length = request.headers.get("content-length")
        if content_length is None: return _error(411,"length_required")
        try: declared_chunk = int(content_length)
        except ValueError: return _error(400,"invalid_length")
        if not 0 < declared_chunk <= get_settings(request).chunk_bytes: return _error(413,"chunk_too_large")
        if upload["status"] in {"complete","duplicate"}:
            return _error(409,"offset_conflict",headers={"Upload-Offset":str(upload["offset"]),
                "Upload-Length":str(upload["declared_size"]),"Upload-State":_public_state(upload["status"])})
        try: patch_limiter.acquire_nowait()
        except WouldBlock: return _error(429,"server_busy",headers={"Retry-After":"2"})
        try:
            data = bytearray()
            try:
                with fail_after(get_settings(request).chunk_read_timeout_seconds):
                    async for block in request.stream():
                        data.extend(block)
                        if len(data) > get_settings(request).chunk_bytes: return _error(413,"chunk_too_large")
            except TimeoutError:
                return _error(408,"chunk_timeout")
            if len(data) != declared_chunk: return _error(400,"length_mismatch")
            checksum = None
            raw_checksum = request.headers.get("upload-checksum")
            if raw_checksum:
                parts = raw_checksum.split(" ",1)
                if len(parts) != 2 or parts[0].lower() != "sha256": return _error(400,"invalid_checksum")
                try: checksum = base64.b64decode(parts[1], validate=True)
                except binascii.Error: return _error(400,"invalid_checksum")
                if len(checksum) != 32: return _error(400,"invalid_checksum")
            try:
                result = await run_in_threadpool(get_store(request).append,upload,expected,bytes(data),checksum)
            except Conflict as exc:
                current=get_store(request).get_upload(upload_id)
                return _error(409,exc.code,str(exc),headers={"Upload-Offset":str(current["offset"]),
                    "Upload-Length":str(current["declared_size"]),"Upload-State":_public_state(current["status"])})
            return Response(status_code=204, headers={"Upload-Offset":str(result["offset"]),
                "Upload-Length":str(result["declared_size"]),"Upload-State":_public_state(result["status"])})
        finally: patch_limiter.release()

    @application.delete("/drop/api/uploads/{upload_id}")
    async def delete_upload(request: Request, upload_id: str):
        require_mutation(request); upload = upload_for_session(request, upload_id)
        get_store(request).delete_upload(upload); return Response(status_code=204)

    return application

app = create_app(load_settings())
