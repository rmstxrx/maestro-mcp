#!/usr/bin/env python3
"""
Maestro MCP — multi-host machine fleet + AI agent orchestra.

Slim entry point: module imports, FastMCP wiring, and uvicorn startup.
All tool logic lives in maestro.tools.fleet, orchestra in maestro.tools.orchestra,
relay in maestro.relay, hosts in maestro.hosts.
"""

import asyncio
import argparse
import logging
import os
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
from maestro.local import configure_local
from maestro.relay import configure_relay, transfer_push, transfer_pull
from maestro.tools.fleet import register_tools
from maestro.tools.orchestra import (
    cancel_eviction_loop,
    configure_orchestra,
    start_eviction_loop,
)
from maestro.transport import (
    _async_run,
    _ensure_connection,
    _is_transient_failure,
    _scp_run,
    _teardown_connection,
    configure_transport,
    teardown_all_hosts,
    warmup_all_hosts,
)
from maestro_oauth import MaestroOAuthProvider

logger = logging.getLogger("maestro")

# ---------------------------------------------------------------------------
# Bootstrap
# ---------------------------------------------------------------------------

CONFIG = MaestroConfig.from_env()
init_hosts()

_oauth_provider = MaestroOAuthProvider(
    issuer_url=CONFIG.issuer_url,
    host_names=list(HOSTS.keys()),
)

# Wire up modules
configure_transport(
    config=CONFIG, hosts=HOSTS, locks=_HOST_LOCKS,
    update_host_status=_update_host_status,
    resolve_host=_resolve_host, host_status=HostStatus,
    format_result=_format_result,
)
configure_local(config=CONFIG, format_result=_format_result)
configure_orchestra(
    config=CONFIG, resolve_host=_resolve_host, wrap_command=_wrap_command,
    format_result=_format_result, update_host_status=_update_host_status,
    host_status=HostStatus, ensure_connection=_ensure_connection,
    teardown_connection=_teardown_connection, async_run=_async_run,
    is_transient_failure=_is_transient_failure,
)
configure_relay(config=CONFIG, resolve_host=_resolve_host, scp_run=_scp_run)

# ---------------------------------------------------------------------------
# MCP Server
# ---------------------------------------------------------------------------

def _build_instructions() -> str:
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
    instructions=_build_instructions(),
)

# Register routes and tools
@mcp.custom_route("/approve", methods=["GET", "POST"])
async def _approve_route(request: Request) -> Response:
    return await _oauth_provider.handle_approve(request)

@mcp.custom_route("/transfer/push", methods=["POST"])
async def _transfer_push(request: Request) -> Response:
    return await transfer_push(request)

@mcp.custom_route("/transfer/pull", methods=["GET"])
async def _transfer_pull(request: Request) -> Response:
    return await transfer_pull(request)

register_tools(mcp, CONFIG)

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    )

    _audit_log_path = Path.home() / ".maestro" / "audit.log"
    _audit_log_path.parent.mkdir(parents=True, exist_ok=True)
    _audit_handler = logging.FileHandler(_audit_log_path)
    _audit_handler.setFormatter(logging.Formatter("%(message)s"))
    _audit_logger = logging.getLogger("maestro-audit")
    _audit_logger.addHandler(_audit_handler)
    _audit_logger.setLevel(logging.INFO)
    _audit_logger.propagate = False

    parser = argparse.ArgumentParser(description="Maestro MCP server")
    parser.add_argument("--transport", choices=["stdio", "streamable-http"], default="streamable-http")
    parser.add_argument("--port", type=int, default=8222)
    parser.add_argument("--host", default="127.0.0.1")
    args = parser.parse_args()

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
