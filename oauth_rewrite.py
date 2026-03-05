"""
oauth_rewrite.py — ASGI middleware that rewrites OAuth metadata URLs
based on the incoming request's Host header.

Problem:
  Maestro's OAuth metadata is static (MAESTRO_ISSUER_URL), but clients
  connect via different paths:
    - https://maestro.rmstxrx.dev  (Cloudflare tunnel — public)
    - http://10.42.69.167:8222     (LAN — fleet machines)
    - http://localhost:8222         (loopback — Apollyon itself)

  The MCP OAuth spec (RFC 9728) requires the `resource` in the protected
  resource metadata to match the URL the client is connecting to. If a
  LAN client hits http://10.42.69.167:8222/mcp but gets metadata saying
  the resource is https://maestro.rmstxrx.dev/mcp, the client rejects it.

Solution:
  This middleware intercepts:
    1. /.well-known/* responses → rewrites URLs in the JSON body
    2. 401 responses → rewrites resource_metadata in WWW-Authenticate header

  It derives the "effective base URL" from the Host header and replaces
  the canonical issuer URL with it. Public requests pass through unchanged.
"""

import json
import logging

from starlette.types import ASGIApp, Receive, Scope, Send

logger = logging.getLogger("maestro-oauth-rewrite")

# Well-known paths that contain OAuth metadata with URLs to rewrite
_METADATA_PATHS = frozenset({
    "/.well-known/oauth-authorization-server",
    "/.well-known/oauth-protected-resource/mcp",
})


class OAuthURLRewriteMiddleware:
    """Rewrites OAuth metadata URLs based on the incoming Host header.

    Args:
        inner: The wrapped ASGI application.
        canonical_url: The static issuer URL (e.g. "https://maestro.rmstxrx.dev").
            Responses containing this URL will have it replaced when the
            client connects via a different host.
    """

    def __init__(self, inner: ASGIApp, canonical_url: str):
        self.inner = inner
        self.canonical = canonical_url.rstrip("/")

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.inner(scope, receive, send)
            return

        # Derive the effective base URL from the Host header.
        headers = dict(scope.get("headers", []))
        host = headers.get(b"host", b"").decode("ascii", errors="replace")
        path = scope.get("path", "")

        # Determine scheme: if host matches public domain, it's behind
        # Cloudflare TLS termination → https. Otherwise it's plain http.
        if "maestro.rmstxrx.dev" in host:
            # Public access — no rewrite needed
            await self.inner(scope, receive, send)
            return

        effective = f"http://{host}"

        # Only intercept metadata paths and potentially auth-bearing paths
        needs_body_rewrite = path in _METADATA_PATHS
        needs_header_rewrite = True  # any path can return 401

        if not needs_body_rewrite and not needs_header_rewrite:
            await self.inner(scope, receive, send)
            return

        # Buffer the response to rewrite URLs
        response_started = False
        status_code = 0
        response_headers: list[tuple[bytes, bytes]] = []
        body_chunks: list[bytes] = []

        async def rewrite_send(message: dict) -> None:
            nonlocal response_started, status_code, response_headers, body_chunks

            if message["type"] == "http.response.start":
                status_code = message.get("status", 0)
                response_headers = list(message.get("headers", []))
                response_started = True
                # Don't forward yet — wait for body to decide on rewrites
                return

            if message["type"] == "http.response.body":
                body = message.get("body", b"")
                more_body = message.get("more_body", False)
                body_chunks.append(body)

                if more_body:
                    return  # Keep buffering

                # Full response collected — apply rewrites
                full_body = b"".join(body_chunks)

                if needs_body_rewrite and path in _METADATA_PATHS:
                    full_body = full_body.replace(
                        self.canonical.encode(),
                        effective.encode(),
                    )

                if status_code == 401:
                    # Rewrite www-authenticate header
                    new_headers = []
                    for k, v in response_headers:
                        if k.lower() == b"www-authenticate":
                            v = v.replace(
                                self.canonical.encode(),
                                effective.encode(),
                            )
                        new_headers.append((k, v))
                    response_headers = new_headers

                # Fix content-length after body rewrite
                new_headers = []
                for k, v in response_headers:
                    if k.lower() == b"content-length":
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
