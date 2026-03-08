"""Transfer relay — zero-context-cost file push/pull for sandboxed agents."""

from __future__ import annotations

import hmac
import json
import logging
import tempfile
import time
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

from starlette.requests import Request
from starlette.responses import Response, JSONResponse, FileResponse
from starlette.background import BackgroundTask

from maestro.config import MaestroConfig

logger = logging.getLogger("maestro")
audit_logger = logging.getLogger("maestro-audit")


def _audit(event: str, **kwargs: Any) -> None:
    entry = {"ts": time.time(), "event": event, **kwargs}
    audit_logger.info(json.dumps(entry))


# ---------------------------------------------------------------------------
# Late-bound references (set by configure_relay)
# ---------------------------------------------------------------------------

_CONFIG: MaestroConfig | None = None
_RESOLVE_HOST: Callable[[str], Any] | None = None
_SCP_RUN: Callable[..., Awaitable[str]] | None = None

_TRANSFER_ALLOWED_DIRS: list[Path] = []
_SYSTEM_DIRS = frozenset({
    "/etc", "/proc", "/sys", "/dev", "/boot", "/sbin", "/bin", "/usr", "/lib", "/var",
})


def configure_relay(
    *,
    config: MaestroConfig,
    resolve_host: Callable[[str], Any],
    scp_run: Callable[..., Awaitable[str]],
) -> None:
    global _CONFIG, _RESOLVE_HOST, _SCP_RUN, _TRANSFER_ALLOWED_DIRS
    _CONFIG = config
    _RESOLVE_HOST = resolve_host
    _SCP_RUN = scp_run
    _TRANSFER_ALLOWED_DIRS = [
        Path(d.strip()).expanduser().resolve()
        for d in config.transfer_allowed_dirs_raw.split(",") if d.strip()
    ]


def _cfg() -> MaestroConfig:
    if _CONFIG is None:
        raise RuntimeError("relay not configured")
    return _CONFIG


# ---------------------------------------------------------------------------
# Path validation
# ---------------------------------------------------------------------------

def _validate_transfer_path(remote_path: str, is_local: bool) -> str | None:
    """Validate a transfer path. Returns an error message if invalid, None if OK."""
    if not remote_path or not remote_path.strip():
        return "remote_path is empty"

    path_parts = Path(remote_path).parts
    if ".." in path_parts:
        return "path contains '..' components"

    if is_local:
        resolved = Path(remote_path).expanduser().resolve()
        if not any(
            resolved == allowed or resolved.is_relative_to(allowed)
            for allowed in _TRANSFER_ALLOWED_DIRS
        ):
            return "path is outside allowed directories"
        for sys_dir in _SYSTEM_DIRS:
            sys_path = Path(sys_dir).resolve()
            if resolved == sys_path or resolved.is_relative_to(sys_path):
                if not any(
                    allowed == sys_path or allowed.is_relative_to(sys_path)
                    for allowed in _TRANSFER_ALLOWED_DIRS
                ):
                    return "path resolves to a protected system directory"
    else:
        expanded = remote_path.replace("~", "/home/_placeholder_")
        resolved_str = str(Path(expanded).resolve())
        for sys_dir in _SYSTEM_DIRS:
            if resolved_str == sys_dir or resolved_str.startswith(sys_dir + "/"):
                if not any(
                    str(allowed).startswith(sys_dir)
                    for allowed in _TRANSFER_ALLOWED_DIRS
                ):
                    return "path targets a protected system directory"

    return None


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

def _transfer_auth_ok(request: Request) -> bool:
    """Validate Bearer token for transfer endpoints (constant-time)."""
    cfg = _cfg()
    if not cfg.transfer_token:
        return False
    auth = request.headers.get("authorization", "")
    if not auth.lower().startswith("bearer "):
        return False
    return hmac.compare_digest(auth[7:], cfg.transfer_token)


def _auth_error() -> JSONResponse:
    return JSONResponse(
        {"error": "unauthorized", "detail": "valid Bearer token required"},
        status_code=401,
        headers={"WWW-Authenticate": "Bearer"},
    )


# ---------------------------------------------------------------------------
# Push / Pull handlers
# ---------------------------------------------------------------------------

async def transfer_push(request: Request) -> Response:
    """Receive a file upload and write it to the target host."""
    assert _RESOLVE_HOST and _SCP_RUN
    cfg = _cfg()

    if not _transfer_auth_ok(request):
        return _auth_error()

    host = request.query_params.get("host")
    remote_path = request.query_params.get("remote_path")
    if not host or not remote_path:
        return JSONResponse(
            {"error": "bad_request", "detail": "host and remote_path query params required"},
            status_code=400,
        )

    try:
        config = _RESOLVE_HOST(host)
    except Exception as e:
        return JSONResponse({"error": "bad_request", "detail": str(e)}, status_code=400)

    path_err = _validate_transfer_path(remote_path, config.is_local)
    if path_err:
        _audit("transfer_push_rejected", host=host, path=remote_path, reason=path_err)
        return JSONResponse(
            {"error": "forbidden", "detail": f"path rejected: {path_err}"},
            status_code=403,
        )

    form = await request.form()
    uploaded = form.get("file")
    if uploaded is None:
        return JSONResponse(
            {"error": "bad_request", "detail": "multipart 'file' field required"},
            status_code=400,
        )

    content_bytes = await uploaded.read()
    if len(content_bytes) > cfg.max_transfer_size:
        return JSONResponse(
            {"error": "too_large", "detail": f"file exceeds {cfg.max_transfer_size // (1024*1024)}MB limit"},
            status_code=413,
        )

    if config.is_local:
        try:
            p = Path(remote_path)
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(content_bytes)
            _audit("transfer_push_ok", host=host, path=remote_path, bytes=len(content_bytes))
            logger.info(f"transfer/push: {len(content_bytes)} bytes -> {host}:{remote_path}")
            return JSONResponse({
                "status": "ok", "host": host,
                "path": remote_path, "bytes": len(content_bytes),
            })
        except Exception as e:
            return JSONResponse({"error": "write_failed", "detail": str(e)}, status_code=500)
    else:
        with tempfile.NamedTemporaryFile(delete=False, suffix=Path(remote_path).suffix) as tmp:
            tmp.write(content_bytes)
            tmp_path = tmp.name
        try:
            result = await _SCP_RUN(host, tmp_path, remote_path, upload=True)
            if result.startswith("[OK]"):
                _audit("transfer_push_ok", host=host, path=remote_path, bytes=len(content_bytes))
                logger.info(f"transfer/push: {len(content_bytes)} bytes -> {host}:{remote_path} (scp)")
                return JSONResponse({
                    "status": "ok", "host": host,
                    "path": remote_path, "bytes": len(content_bytes),
                })
            else:
                return JSONResponse({"error": "scp_failed", "detail": result}, status_code=502)
        finally:
            Path(tmp_path).unlink(missing_ok=True)


async def transfer_pull(request: Request) -> Response:
    """Stream a file from the target host back to the caller."""
    assert _RESOLVE_HOST and _SCP_RUN
    cfg = _cfg()

    if not _transfer_auth_ok(request):
        return _auth_error()

    host = request.query_params.get("host")
    remote_path = request.query_params.get("remote_path")
    if not host or not remote_path:
        return JSONResponse(
            {"error": "bad_request", "detail": "host and remote_path query params required"},
            status_code=400,
        )

    try:
        config = _RESOLVE_HOST(host)
    except Exception as e:
        return JSONResponse({"error": "bad_request", "detail": str(e)}, status_code=400)

    path_err = _validate_transfer_path(remote_path, config.is_local)
    if path_err:
        _audit("transfer_pull_rejected", host=host, path=remote_path, reason=path_err)
        return JSONResponse(
            {"error": "forbidden", "detail": f"path rejected: {path_err}"},
            status_code=403,
        )

    if config.is_local:
        p = Path(remote_path)
        if not p.is_file():
            return JSONResponse(
                {"error": "not_found", "detail": f"{remote_path} not found"},
                status_code=404,
            )
        if p.stat().st_size > cfg.max_transfer_size:
            return JSONResponse(
                {"error": "too_large", "detail": f"file exceeds {cfg.max_transfer_size // (1024*1024)}MB limit"},
                status_code=413,
            )
        _audit("transfer_pull_ok", host=host, path=remote_path)
        logger.info(f"transfer/pull: {host}:{remote_path} -> caller")
        return FileResponse(remote_path, filename=p.name, media_type="application/octet-stream")
    else:
        with tempfile.NamedTemporaryFile(delete=False, suffix=Path(remote_path).suffix) as tmp:
            tmp_path = tmp.name
        try:
            result = await _SCP_RUN(host, remote_path, tmp_path, upload=False)
            if not result.startswith("[OK]"):
                Path(tmp_path).unlink(missing_ok=True)
                return JSONResponse({"error": "scp_failed", "detail": result}, status_code=502)
            if Path(tmp_path).stat().st_size > cfg.max_transfer_size:
                Path(tmp_path).unlink(missing_ok=True)
                return JSONResponse(
                    {"error": "too_large", "detail": f"file exceeds {cfg.max_transfer_size // (1024*1024)}MB limit"},
                    status_code=413,
                )
            _audit("transfer_pull_ok", host=host, path=remote_path)
            logger.info(f"transfer/pull: {host}:{remote_path} -> caller (scp)")
            return FileResponse(
                tmp_path, filename=Path(remote_path).name,
                media_type="application/octet-stream",
                background=BackgroundTask(lambda: Path(tmp_path).unlink(missing_ok=True)),
            )
        except Exception as e:
            Path(tmp_path).unlink(missing_ok=True)
            return JSONResponse({"error": "pull_failed", "detail": str(e)}, status_code=500)
