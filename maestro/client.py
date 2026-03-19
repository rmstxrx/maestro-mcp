"""Client classification and per-client execution profiles."""

from __future__ import annotations

from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import Any

from starlette.requests import Request


# ---------------------------------------------------------------------------
# Per-client profiles — controls block_timeout and poll cooldown
# ---------------------------------------------------------------------------

CLIENT_PROFILES: dict[str, dict[str, Any]] = {
    "remote": {
        # Remote clients (Cloudflare tunnel / unknown) — constrained
        "block_timeout_agent": 0,     # always dispatch immediately
        "block_timeout_exec": 5,      # short inline window
        "poll_cooldown": 10,          # min seconds between polls
    },
    "local": {
        # Claude Code running on Apollyon — generous
        "block_timeout_agent": 30,    # try to complete inline
        "block_timeout_exec": 60,     # long inline for exec/script
        "poll_cooldown": 2,           # fast polls OK
    },
    "lan": {
        # LAN clients — middle ground
        "block_timeout_agent": 10,
        "block_timeout_exec": 20,
        "poll_cooldown": 5,
    },
}

STDIO_PROFILE: dict[str, Any] = {
    "block_timeout_agent": 30,
    "block_timeout_exec": 60,
    "poll_cooldown": 2,
}


@dataclass
class ClientContext:
    classification: str
    profile: dict[str, Any]
    client_id: str | None = None
    client_type: str = ""
    local_host: str | None = None

    def __post_init__(self) -> None:
        if not self.client_type:
            self.client_type = self.classification


# ---------------------------------------------------------------------------
# stdio mode detection
# ---------------------------------------------------------------------------

_STDIO_MODE: bool = False
_STDIO_LOCAL_HOST: str | None = None


def set_stdio_mode(local_host_name: str | None = None) -> None:
    """Flag this process as running in MCP stdio transport mode."""
    global _STDIO_MODE, _STDIO_LOCAL_HOST
    _STDIO_MODE = True
    _STDIO_LOCAL_HOST = local_host_name


_client_ctx: ContextVar[ClientContext] = ContextVar("_client_ctx")

# Default context for non-HTTP usage (when not in stdio mode)
_DEFAULT_CTX = ClientContext(
    classification="local",
    profile=CLIENT_PROFILES["local"],
)


def _classify_client(request: Request) -> str:
    """Classify a client from the HTTP request."""
    # Cloudflare Tunnel → remote
    if request.headers.get("cf-ray"):
        return "remote"

    # Check client IP
    client = request.client
    if client:
        host = client.host
        if host in ("127.0.0.1", "::1", "localhost"):
            return "local"
        if host.startswith("10.42.69."):
            return "lan"

    # Default: treat unknown as remote (safe)
    return "remote"


def set_client_context(request: Request) -> None:
    """Create ClientContext from request and set it in the contextvar."""
    classification = _classify_client(request)
    ctx = ClientContext(
        classification=classification,
        profile=CLIENT_PROFILES[classification],
    )
    _client_ctx.set(ctx)


def get_client_context() -> ClientContext:
    """Get the current client context, falling back to local defaults."""
    if _STDIO_MODE:
        return ClientContext(
            classification="stdio",
            profile=STDIO_PROFILE,
            client_type="stdio",
            local_host=_STDIO_LOCAL_HOST,
        )
    return _client_ctx.get(_DEFAULT_CTX)
