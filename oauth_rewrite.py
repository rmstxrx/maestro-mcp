"""
oauth_rewrite.py — ASGI middleware that rewrites OAuth metadata URLs
based on the incoming request's Host header.

Problem:
  Maestro's OAuth metadata is static (MAESTRO_ISSUER_URL), but clients
  connect via different paths:
    - https://maestro.yourdomain.dev  (Cloudflare tunnel — public)
    - http://198.51.100.167:8222      (LAN — fleet machines)
    - http://localhost:8222            (loopback — hub itself)

  The MCP OAuth spec (RFC 9728) requires the `resource` in the protected
  resource metadata to match the URL the client is connecting to. If a
  LAN client hits http://198.51.100.167:8222/mcp but gets metadata saying
  the resource is https://maestro.yourdomain.dev/mcp, the client rejects it.

Solution:
  This middleware intercepts ALL responses for non-canonical hosts and:
    1. /.well-known/* responses → rewrites URLs in the JSON body
    2. 3xx responses → rewrites Location headers (authorize → approve redirects)
    3. 401 responses → rewrites resource_metadata in WWW-Authenticate header
    4. HTML responses → rewrites canonical URLs in the body (approve page forms)

  It uses an allowlist of Host → base URL mappings to determine the
  effective URL. Only allowed origins get URL rewriting; unknown hosts
  are passed through without rewrite (they get the canonical URL — safe
  default). This prevents Host header injection attacks.
"""

import json
import logging
import os

from starlette.types import ASGIApp, Receive, Scope, Send

logger = logging.getLogger("maestro-oauth-rewrite")

# Well-known paths that contain OAuth metadata with URLs to rewrite
_METADATA_PATHS = frozenset({
    "/.well-known/oauth-authorization-server",
    "/.well-known/oauth-protected-resource/mcp",
})


def _parse_lan_origins(env_val: str) -> dict[str, str]:
    """Parse MAESTRO_LAN_ORIGINS env var into host→base_url mapping.

    Format: comma-separated 'host:port=scheme' pairs.
    Example: '198.51.100.167:8222=http,192.168.1.100:8222=http'
    """
    result: dict[str, str] = {}
    for entry in env_val.split(","):
        entry = entry.strip()
        if not entry:
            continue
        if "=" not in entry:
            logger.warning("invalid LAN origin entry (missing '='): %s", entry)
            continue
        host_port, scheme = entry.rsplit("=", 1)
        host_port = host_port.strip()
        scheme = scheme.strip()
        if host_port and scheme in ("http", "https"):
            result[host_port] = f"{scheme}://{host_port}"
        else:
            logger.warning("invalid LAN origin entry: %s", entry)
    return result


class OAuthURLRewriteMiddleware:
    """Rewrites OAuth/consent URLs based on an allowlist of Host → URL mappings.

    Intercepts all responses for non-canonical hosts and rewrites:
      - JSON body in well-known metadata paths
      - Location headers on 3xx redirects
      - WWW-Authenticate headers on 401 responses
      - HTML body content (form actions, links in consent pages)

    Only hosts present in the allowed_origins dict get URL rewriting.
    Unknown hosts are passed through without rewrite (safe default).

    Args:
        inner: The wrapped ASGI application.
        canonical_url: The static issuer URL (e.g. "https://maestro.yourdomain.dev").
            Responses containing this URL will have it replaced when the
            client connects via an allowed non-canonical host.
        allowed_origins: Mapping of Host header value → effective base URL.
            The canonical host should be included (it gets pass-through).
    """

    def __init__(self, inner: ASGIApp, canonical_url: str,
                 allowed_origins: dict[str, str] | None = None):
        self.inner = inner
        self.canonical = canonical_url.rstrip("/")
        self.allowed_origins: dict[str, str] = dict(allowed_origins or {})

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.inner(scope, receive, send)
            return

        # Derive the effective base URL from the Host header.
        headers = dict(scope.get("headers", []))
        host = headers.get(b"host", b"").decode("ascii", errors="replace")

        # Look up the host in the allowlist
        effective_url = self.allowed_origins.get(host)

        if effective_url is None:
            # Unknown host — pass through without rewrite (safe default).
            if host:
                logger.warning("unknown Host header '%s' — no rewrite", host)
            await self.inner(scope, receive, send)
            return

        # If the effective URL matches canonical, no rewrite needed.
        if effective_url.rstrip("/") == self.canonical:
            await self.inner(scope, receive, send)
            return

        effective = effective_url.rstrip("/")
        canonical_bytes = self.canonical.encode()
        effective_bytes = effective.encode()
        path = scope.get("path", "")

        # Buffer ALL responses for non-canonical hosts so we can rewrite
        # Location headers, body content, and WWW-Authenticate headers.
        status_code = 0
        response_headers: list[tuple[bytes, bytes]] = []
        body_chunks: list[bytes] = []

        async def rewrite_send(message: dict) -> None:
            nonlocal status_code, response_headers, body_chunks

            if message["type"] == "http.response.start":
                status_code = message.get("status", 0)
                response_headers = list(message.get("headers", []))
                return  # Buffer — wait for body

            if message["type"] == "http.response.body":
                body = message.get("body", b"")
                more_body = message.get("more_body", False)
                body_chunks.append(body)

                if more_body:
                    return  # Keep buffering

                # --- Full response collected — apply rewrites ---
                full_body = b"".join(body_chunks)

                # Body rewrite: metadata JSON + HTML content (approve pages)
                if canonical_bytes in full_body:
                    full_body = full_body.replace(canonical_bytes, effective_bytes)

                # Header rewrites
                new_headers = []
                for k, v in response_headers:
                    kl = k.lower()
                    # 3xx: rewrite Location header
                    if kl == b"location" and 300 <= status_code < 400:
                        v = v.replace(canonical_bytes, effective_bytes)
                    # 401: rewrite WWW-Authenticate
                    elif kl == b"www-authenticate" and status_code == 401:
                        v = v.replace(canonical_bytes, effective_bytes)
                    # Fix content-length after body rewrite
                    elif kl == b"content-length":
                        v = str(len(full_body)).encode()
                    new_headers.append((k, v))

                logger.debug(
                    "rewrite: %s %s → %s (status=%d, body_len=%d)",
                    scope.get("method"), path, effective, status_code, len(full_body),
                )

                await send({
                    "type": "http.response.start",
                    "status": status_code,
                    "headers": new_headers,
                })
                await send({
                    "type": "http.response.body",
                    "body": full_body,
                })
                return

            # Pass through other message types
            await send(message)

        await self.inner(scope, receive, rewrite_send)
