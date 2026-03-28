#!/usr/bin/env python3
"""
Maestro MCP — multi-host machine fleet + AI agent orchestra.

Slim entry point: module imports, FastMCP wiring, and uvicorn startup.
Fleet tools live in maestro.tools.fleet, orchestra tools in maestro.tools.orchestra,
relay in maestro.relay, hosts in maestro.hosts.
"""

import asyncio
import argparse
import logging
import os
import sys
from pathlib import Path

from pydantic import AnyHttpUrl
from mcp.server.fastmcp import FastMCP
from mcp.server.auth.settings import AuthSettings, ClientRegistrationOptions, RevocationOptions
from mcp.server.transport_security import TransportSecuritySettings
from starlette.requests import Request
from starlette.responses import Response

from maestro.client import set_client_context
from maestro.config import MaestroConfig
from maestro.hosts import (
    HOSTS,
    HostStatus,
    _HOST_LOCKS,
    _format_result,
    _resolve_host,
    _update_host_status,
    _wrap_command,
    init_hosts,
)
from maestro.local import _local_run, configure_local
from maestro.mux import configure_mux
from maestro.relay import configure_relay, task_result, transfer_push, transfer_pull
from maestro.tools.fleet import register_fleet_tools
from maestro.tools.orchestra import (
    TASK_REGISTRY,
    TaskLedger,
    _REGISTRY_LOCK,
    cancel_eviction_loop,
    configure_orchestra,
    register_orchestra_tools,
    start_eviction_loop,
)
from maestro.transport import (
    _async_run,
    _ensure_connection,
    _is_transient_failure,
    _scp_run,
    _ssh_run,
    _teardown_connection,
    configure_transport,
    teardown_all_hosts,
    warmup_all_hosts,
)
from maestro_oauth import MaestroOAuthProvider
from maestro.oauth_state import OAuthStateStore

logger = logging.getLogger("maestro")

# Configure root logging early — before any module-level instantiation emits
# log messages. Without this, loggers created before basicConfig (e.g.
# OAuthStateStore.load() called during _oauth_provider __init__) have no
# handler and their output is silently discarded.
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)

# ---------------------------------------------------------------------------
# Bootstrap
# ---------------------------------------------------------------------------

CONFIG = MaestroConfig.from_env()
init_hosts()

# Detect transport from sys.argv before module-level FastMCP construction
_TRANSPORT = "streamable-http"
if "--transport" in sys.argv:
    _idx = sys.argv.index("--transport")
    if _idx + 1 < len(sys.argv):
        _TRANSPORT = sys.argv[_idx + 1]

if _TRANSPORT == "stdio":
    from maestro.client import set_stdio_mode
    from maestro.hosts import _local_host_name as _get_local_name
    set_stdio_mode(local_host_name=_get_local_name())

_oauth_state_store = OAuthStateStore(CONFIG.oauth_state_path)
_oauth_provider = MaestroOAuthProvider(
    issuer_url=CONFIG.issuer_url,
    host_names=list(HOSTS.keys()),
    state_store=_oauth_state_store,
    trusted_client_ids=CONFIG.trusted_client_ids,
)

# Wire up modules
configure_transport(
    config=CONFIG, hosts=HOSTS, locks=_HOST_LOCKS,
    update_host_status=_update_host_status,
    resolve_host=_resolve_host, host_status=HostStatus,
    format_result=_format_result,
)
configure_local(config=CONFIG, format_result=_format_result)
configure_mux(
    host_output_retention_days=CONFIG.host_output_retention_days
)  # ADR-0007: Hub-local tmux, no legacy kwargs
_task_ledger = TaskLedger(CONFIG.task_ledger_path, CONFIG.issuer_url)

configure_orchestra(
    config=CONFIG, resolve_host=_resolve_host, wrap_command=_wrap_command,
    format_result=_format_result, update_host_status=_update_host_status,
    host_status=HostStatus, ensure_connection=_ensure_connection,
    teardown_connection=_teardown_connection, async_run=_async_run,
    is_transient_failure=_is_transient_failure,
    task_store=None,
    task_ledger=_task_ledger,
)

async def _task_lookup(task_id: str) -> dict | None:
    """Look up a task in the registry for the HTTP result endpoint."""
    from datetime import datetime, timezone
    import json as _json

    async with _REGISTRY_LOCK:
        ts = TASK_REGISTRY.get(task_id)

    if ts is None:
        return None

    if ts.status == "running":
        elapsed = (datetime.now(timezone.utc) - ts.started_at).total_seconds()
        return {
            "task_id": task_id,
            "agent": ts.agent,
            "host": ts.host,
            "status": "running",
            "elapsed_seconds": round(elapsed, 1),
        }

    if ts.status == "orphaned":
        result: dict = {
            "task_id": task_id,
            "agent": ts.agent,
            "host": ts.host,
            "status": "orphaned",
        }
        if ts.output_file:
            result["output_file"] = str(ts.output_file)
        return result

    # Task is complete — parse the stored result JSON and return it
    try:
        result = _json.loads(ts.result_json) if ts.result_json else {}
    except (_json.JSONDecodeError, TypeError):
        result = {"raw": ts.result_json}

    result["task_id"] = task_id
    result["status"] = ts.status
    result["_verify_host"] = ts.host
    result["_verify_task_id"] = task_id
    result["_verify_agent"] = ts.agent
    return result


configure_relay(config=CONFIG, resolve_host=_resolve_host, scp_run=_scp_run, task_lookup=_task_lookup)

# ---------------------------------------------------------------------------
# MCP Server
# ---------------------------------------------------------------------------

def _build_instructions(transport: str = "http") -> str:
    if transport == "stdio":
        from maestro.hosts import _local_host_name
        local_name = _local_host_name()
        local_desc = HOSTS[local_name].description if local_name and local_name in HOSTS else ""
        remote_hosts = [f"  {name}: {cfg.description}" for name, cfg in HOSTS.items() if not cfg.is_local]
        remote_block = "\n".join(remote_hosts) if remote_hosts else "  (none configured)"

        return (
            f"You are running locally on {local_name}"
            + (f" ({local_desc})" if local_desc else "")
            + ".\n\n"
            "CRITICAL: Do NOT use Maestro exec/script/read/write to target " + (local_name or "this host") + ".\n"
            "You have native tools (Bash, filesystem) that are faster and more capable.\n"
            "Maestro will REJECT local-targeting commands from local agents.\n\n"
            "Use Maestro ONLY for:\n"
            "  - Remote fleet hosts (listed below)\n"
            "  - Agent dispatch (codex, gemini, claude) to any host including local\n"
            "  - Fleet status, transfer, add_host, reconnect_host, list_ssh_hosts, agent_status\n"
            "  - Orchestra tools: prepare_relay, poll, read_output, tasks\n\n"
            "Remote fleet hosts:\n" + remote_block
        )

    dispatch_rule = "All dispatch tools return a task_id. Use poll(task_id) for results."
    host_list = ", ".join(HOSTS.keys())
    instructions = f"Hosts: {host_list}. {dispatch_rule}"
    if len(instructions) <= 300:
        return instructions
    max_hosts_len = max(0, 300 - len("Hosts: . ") - len(dispatch_rule))
    trimmed_hosts = host_list[:max_hosts_len]
    if len(host_list) > max_hosts_len and max_hosts_len > 3:
        trimmed_hosts = trimmed_hosts[:-3].rstrip(", ") + "..."
    return f"Hosts: {trimmed_hosts}. {dispatch_rule}"[:300]


mcp = FastMCP(
    "maestro",
    auth_server_provider=_oauth_provider,
    auth=AuthSettings(
        issuer_url=AnyHttpUrl(CONFIG.issuer_url),
        resource_server_url=AnyHttpUrl(f"{CONFIG.issuer_url}/mcp"),
        client_registration_options=ClientRegistrationOptions(
            enabled=True, valid_scopes=["maestro"], default_scopes=["maestro"],
        ),
        revocation_options=RevocationOptions(enabled=True),
        required_scopes=["maestro"],
    ),
    transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
    instructions=_build_instructions(_TRANSPORT),
)

# Register routes and tools
@mcp.custom_route("/approve", methods=["GET", "POST"])
async def _approve_route(request: Request) -> Response:
    # /approve is the normal OAuth consent flow — must be accessible from
    # LAN clients (Claude Desktop, etc.). PIN security relies on rate limiting
    # and HMAC comparison in the handler itself, not transport restrictions.
    # Only /admin/rotate-pin is locked to HTTPS/localhost.
    return await _oauth_provider.handle_approve(request)

@mcp.custom_route("/admin/rotate-pin", methods=["GET", "POST"])
async def _rotate_pin_route(request: Request) -> Response:
    # Security: PIN rotation must only occur over secure channels.
    # Allow if: (1) request came through Cloudflare tunnel (CF-Ray header = TLS),
    # or (2) request is from localhost (loopback, no network exposure).
    # Reject LAN/direct HTTP requests where the PIN would travel in plaintext.
    cf_ray = request.headers.get("cf-ray")
    client_host = request.client.host if request.client else ""
    is_localhost = client_host in ("127.0.0.1", "::1", "localhost")
    if not cf_ray and not is_localhost:
        return Response(
            content="PIN rotation is only available over HTTPS (via Cloudflare tunnel) "
                    "or from localhost. Direct LAN access is blocked to prevent "
                    "plaintext PIN exposure.",
            status_code=403,
            media_type="text/plain",
        )
    return await _oauth_provider.handle_rotate_pin(request)

@mcp.custom_route("/transfer/push", methods=["POST"])
async def _transfer_push(request: Request) -> Response:
    return await transfer_push(request)

@mcp.custom_route("/transfer/pull", methods=["GET"])
async def _transfer_pull(request: Request) -> Response:
    return await transfer_pull(request)

@mcp.custom_route("/tasks/{task_id}/result", methods=["GET"])
async def _task_result(request: Request) -> Response:
    return await task_result(request)

register_fleet_tools(mcp, CONFIG)
register_orchestra_tools(mcp, CONFIG)

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Maestro MCP server")
    parser.add_argument("--transport", choices=["stdio", "streamable-http"], default="streamable-http")
    parser.add_argument("--port", type=int, default=8222)
    parser.add_argument("--host", default="127.0.0.1")
    args = parser.parse_args()

    _audit_log_path = Path.home() / ".maestro" / "audit.log"
    _audit_logger = logging.getLogger("maestro-audit")
    try:
        _audit_log_path.parent.mkdir(parents=True, exist_ok=True)
        _audit_handler = logging.FileHandler(_audit_log_path)
    except OSError as exc:
        logger.warning("maestro: audit logging disabled: %s", exc)
    else:
        _audit_handler.setFormatter(logging.Formatter("%(message)s"))
        _audit_logger.addHandler(_audit_handler)
        _audit_logger.setLevel(logging.INFO)
        _audit_logger.propagate = False

    if args.transport == "streamable-http":
        import uvicorn
        from oauth_rewrite import OAuthURLRewriteMiddleware, _parse_lan_origins
        from urllib.parse import urlparse as _urlparse
        from starlette.types import ASGIApp as _ASGIApp, Receive as _Recv, Scope as _Scp, Send as _Snd

        app = mcp.streamable_http_app()

        # OAuth URL rewrite middleware
        _parsed_issuer = _urlparse(CONFIG.issuer_url)
        _allowed_origins: dict[str, str] = {
            _parsed_issuer.netloc: CONFIG.issuer_url,
            "localhost:8222": "http://localhost:8222",
            "127.0.0.1:8222": "http://127.0.0.1:8222",
        }
        _allowed_origins.update(_parse_lan_origins(os.environ.get("MAESTRO_LAN_ORIGINS", "")))
        app = OAuthURLRewriteMiddleware(app, CONFIG.issuer_url, allowed_origins=_allowed_origins)

        # Logging + client context middleware
        class _MaestroMiddleware:
            def __init__(self, inner: _ASGIApp):
                self.inner = inner

            async def __call__(self, scope: _Scp, receive: _Recv, send: _Snd) -> None:
                if scope["type"] != "http":
                    await self.inner(scope, receive, send)
                    return
                hdrs = dict(scope.get("headers", []))
                path = scope.get("path", "?")
                method = scope.get("method", "?")
                auth = hdrs.get(b"authorization", b"").decode(errors="replace")
                ua = hdrs.get(b"user-agent", b"").decode(errors="replace")
                logger.info("recv: %s %s auth=%s ua=%s", method, path,
                            auth[:40] + "..." if len(auth) > 40 else (auth or "none"), ua[:60])
                request = Request(scope, receive, send)
                set_client_context(request)
                await self.inner(scope, receive, send)

        app = _MaestroMiddleware(app)
        logger.info(f"maestro: starting HTTP server on {args.host}:{args.port}")

        config = uvicorn.Config(app, host=args.host, port=args.port, log_level="info",
                                proxy_headers=True, forwarded_allow_ips="*")
        server = uvicorn.Server(config)

        async def _serve_with_maestro_lifecycle() -> None:
            logger.info("maestro: warming up connections...")
            results = await warmup_all_hosts()
            connected = sum(1 for v in results.values() if v)
            logger.info(f"maestro: {connected}/{len(results)} hosts connected")
            start_eviction_loop()
            try:
                await server.serve()
            finally:
                cancel_eviction_loop()
                try:
                    logger.info("maestro: shutting down, closing connections...")
                    await teardown_all_hosts()
                except Exception:
                    logger.exception("maestro: error during teardown")

        asyncio.run(_serve_with_maestro_lifecycle())
    else:
        mcp.run(transport="stdio")
