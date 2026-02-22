"""
fleet_oauth.py — Minimal OAuth 2.0 Authorization Code + PKCE for fleet-ssh.

Single-user OAuth server designed for MCP connector authentication.
The "authorize" page shows a simple approve/deny form since Rômulo is
the only user. The access token issued is the same bearer token stored
in ~/.fleet-ssh/bearer_token.

Implements:
  /.well-known/oauth-authorization-server  — RFC 8414 metadata
  /oauth/register                          — RFC 7591 dynamic client registration
  /oauth/authorize                         — Authorization endpoint (GET → form, POST → redirect)
  /oauth/token                             — Token endpoint (code → access_token)

All state (clients, auth codes) is in-memory and ephemeral.
"""

import hashlib
import hmac
import json
import logging
import secrets
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Any

from starlette.types import ASGIApp, Receive, Scope, Send

logger = logging.getLogger("fleet-oauth")

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class OAuthClient:
    client_id: str
    client_secret: str | None = None
    redirect_uris: list[str] = field(default_factory=list)
    client_name: str = ""
    created_at: float = 0.0


@dataclass
class AuthCode:
    code: str
    client_id: str
    redirect_uri: str
    code_challenge: str
    code_challenge_method: str
    created_at: float
    ttl: int = 300  # 5 minutes


# ---------------------------------------------------------------------------
# ASGI helpers
# ---------------------------------------------------------------------------

async def _read_body(receive: Receive) -> bytes:
    body = b""
    while True:
        message = await receive()
        body += message.get("body", b"")
        if not message.get("more_body", False):
            break
    return body


async def _send_json(send: Send, status: int, data: dict, extra_headers: list | None = None) -> None:
    body = json.dumps(data).encode()
    headers = [
        [b"content-type", b"application/json"],
        [b"content-length", str(len(body)).encode()],
        [b"cache-control", b"no-store"],
    ]
    if extra_headers:
        headers.extend(extra_headers)
    await send({"type": "http.response.start", "status": status, "headers": headers})
    await send({"type": "http.response.body", "body": body})


async def _send_html(send: Send, status: int, html: str) -> None:
    body = html.encode()
    await send({
        "type": "http.response.start",
        "status": status,
        "headers": [
            [b"content-type", b"text/html; charset=utf-8"],
            [b"content-length", str(len(body)).encode()],
        ],
    })
    await send({"type": "http.response.body", "body": body})


async def _send_redirect(send: Send, location: str) -> None:
    await send({
        "type": "http.response.start",
        "status": 302,
        "headers": [
            [b"location", location.encode()],
            [b"content-length", b"0"],
        ],
    })
    await send({"type": "http.response.body", "body": b""})


def _parse_qs(query: str) -> dict[str, str]:
    """Parse query string, returning first value for each key."""
    parsed = urllib.parse.parse_qs(query, keep_blank_values=True)
    return {k: v[0] for k, v in parsed.items()}


def _parse_form(body: bytes) -> dict[str, str]:
    """Parse application/x-www-form-urlencoded body."""
    return _parse_qs(body.decode("utf-8", errors="replace"))


# ---------------------------------------------------------------------------
# PKCE verification
# ---------------------------------------------------------------------------

def _verify_pkce(verifier: str, challenge: str, method: str) -> bool:
    if method == "S256":
        computed = hashlib.sha256(verifier.encode("ascii")).digest()
        # base64url encode without padding
        import base64
        expected = base64.urlsafe_b64encode(computed).rstrip(b"=").decode("ascii")
        return hmac.compare_digest(expected, challenge)
    elif method == "plain":
        return hmac.compare_digest(verifier, challenge)
    return False


# ---------------------------------------------------------------------------
# Authorization page HTML
# ---------------------------------------------------------------------------

def _authorize_page(client_name: str, client_id: str, redirect_uri: str,
                    state: str, code_challenge: str, code_challenge_method: str) -> str:
    return f"""<!DOCTYPE html>
<html>
<head>
    <title>fleet-ssh — Authorize</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: #0a0a1a;
            color: #e0e0e0;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            margin: 0;
        }}
        .card {{
            background: #1a1a2e;
            border: 1px solid #2a2a4a;
            border-radius: 12px;
            padding: 2rem;
            max-width: 400px;
            width: 90%;
            box-shadow: 0 4px 24px rgba(0, 0, 0, 0.5);
        }}
        h1 {{
            font-size: 1.3rem;
            margin: 0 0 0.5rem 0;
            color: #00d4ff;
        }}
        .client {{
            color: #ff6b9d;
            font-weight: 600;
        }}
        .perms {{
            background: #12122a;
            border: 1px solid #2a2a4a;
            border-radius: 8px;
            padding: 1rem;
            margin: 1rem 0;
            font-size: 0.9rem;
        }}
        .perms li {{
            margin: 0.3rem 0;
        }}
        .buttons {{
            display: flex;
            gap: 1rem;
            margin-top: 1.5rem;
        }}
        button {{
            flex: 1;
            padding: 0.75rem;
            border: none;
            border-radius: 8px;
            font-size: 1rem;
            cursor: pointer;
            font-weight: 600;
        }}
        .approve {{
            background: #00d4ff;
            color: #0a0a1a;
        }}
        .approve:hover {{
            background: #00b8e6;
        }}
        .deny {{
            background: #2a2a4a;
            color: #e0e0e0;
        }}
        .deny:hover {{
            background: #3a3a5a;
        }}
    </style>
</head>
<body>
    <div class="card">
        <h1>⚡ fleet-ssh</h1>
        <p><span class="client">{client_name or client_id}</span> wants access to your fleet.</p>
        <div class="perms">
            <strong>This will allow:</strong>
            <ul>
                <li>Execute commands on apollyon, eden, judas</li>
                <li>Read and write files on all hosts</li>
                <li>Transfer files between machines</li>
            </ul>
        </div>
        <form method="POST" action="/oauth/authorize">
            <input type="hidden" name="client_id" value="{client_id}">
            <input type="hidden" name="redirect_uri" value="{redirect_uri}">
            <input type="hidden" name="state" value="{state}">
            <input type="hidden" name="code_challenge" value="{code_challenge}">
            <input type="hidden" name="code_challenge_method" value="{code_challenge_method}">
            <div class="buttons">
                <button type="submit" name="action" value="deny" class="deny">Deny</button>
                <button type="submit" name="action" value="approve" class="approve">Approve</button>
            </div>
        </form>
    </div>
</body>
</html>"""


# ---------------------------------------------------------------------------
# FleetOAuthMiddleware
# ---------------------------------------------------------------------------

class FleetOAuthMiddleware:
    """ASGI middleware implementing OAuth 2.0 for fleet-ssh.

    Intercepts OAuth-related paths before they reach the MCP app.
    All other paths require a valid Bearer token.
    """

    # Paths that don't require authentication
    OPEN_PATHS = {
        "/.well-known/oauth-authorization-server",
        "/oauth/authorize",
        "/oauth/token",
        "/oauth/register",
    }

    def __init__(self, app: ASGIApp, bearer_token: str | None, issuer_url: str):
        self.app = app
        self.bearer_token = bearer_token
        self.issuer_url = issuer_url.rstrip("/")
        self.clients: dict[str, OAuthClient] = {}
        self.auth_codes: dict[str, AuthCode] = {}

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        method = scope.get("method", "GET")

        # --- OAuth endpoints (no auth required) ---

        if path == "/.well-known/oauth-authorization-server":
            await self._handle_metadata(send)
            return

        if path == "/oauth/register" and method == "POST":
            body = await _read_body(receive)
            await self._handle_register(send, body)
            return

        if path == "/oauth/authorize":
            if method == "GET":
                qs = _parse_qs(scope.get("query_string", b"").decode())
                await self._handle_authorize_get(send, qs)
            elif method == "POST":
                body = await _read_body(receive)
                await self._handle_authorize_post(send, body)
            else:
                await _send_json(send, 405, {"error": "method_not_allowed"})
            return

        if path == "/oauth/token" and method == "POST":
            body = await _read_body(receive)
            await self._handle_token(send, body)
            return

        # --- All other paths: require Bearer token ---

        if self.bearer_token:
            headers = dict(scope.get("headers", []))
            auth = headers.get(b"authorization", b"").decode()
            if not hmac.compare_digest(auth, f"Bearer {self.bearer_token}"):
                await _send_json(send, 401, {"error": "unauthorized"}, [
                    [b"www-authenticate", b"Bearer"],
                ])
                return

        await self.app(scope, receive, send)

    # --- Endpoint handlers ---

    async def _handle_metadata(self, send: Send) -> None:
        """RFC 8414 — OAuth Authorization Server Metadata."""
        await _send_json(send, 200, {
            "issuer": self.issuer_url,
            "authorization_endpoint": f"{self.issuer_url}/oauth/authorize",
            "token_endpoint": f"{self.issuer_url}/oauth/token",
            "registration_endpoint": f"{self.issuer_url}/oauth/register",
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code"],
            "token_endpoint_auth_methods_supported": ["none", "client_secret_post"],
            "code_challenge_methods_supported": ["S256", "plain"],
            "scopes_supported": ["fleet"],
        })

    async def _handle_register(self, send: Send, body: bytes) -> None:
        """RFC 7591 — Dynamic Client Registration."""
        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            await _send_json(send, 400, {"error": "invalid_request"})
            return

        client_id = f"fleet-{secrets.token_hex(8)}"
        client_secret = secrets.token_urlsafe(32)
        redirect_uris = data.get("redirect_uris", [])
        client_name = data.get("client_name", "")

        client = OAuthClient(
            client_id=client_id,
            client_secret=client_secret,
            redirect_uris=redirect_uris,
            client_name=client_name,
            created_at=time.time(),
        )
        self.clients[client_id] = client
        logger.info(f"OAuth: registered client '{client_name}' ({client_id})")

        await _send_json(send, 201, {
            "client_id": client_id,
            "client_secret": client_secret,
            "client_name": client_name,
            "redirect_uris": redirect_uris,
            "grant_types": ["authorization_code"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "client_secret_post",
        })

    async def _handle_authorize_get(self, send: Send, params: dict) -> None:
        """Show the approve/deny page."""
        client_id = params.get("client_id", "")
        redirect_uri = params.get("redirect_uri", "")
        state = params.get("state", "")
        code_challenge = params.get("code_challenge", "")
        code_challenge_method = params.get("code_challenge_method", "S256")

        if not client_id or not redirect_uri:
            await _send_json(send, 400, {"error": "invalid_request",
                                          "error_description": "Missing client_id or redirect_uri"})
            return

        client = self.clients.get(client_id)
        client_name = client.client_name if client else client_id

        html = _authorize_page(
            client_name=client_name,
            client_id=client_id,
            redirect_uri=redirect_uri,
            state=state,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
        )
        await _send_html(send, 200, html)

    async def _handle_authorize_post(self, send: Send, body: bytes) -> None:
        """Process the approve/deny form submission."""
        form = _parse_form(body)
        action = form.get("action", "deny")
        client_id = form.get("client_id", "")
        redirect_uri = form.get("redirect_uri", "")
        state = form.get("state", "")
        code_challenge = form.get("code_challenge", "")
        code_challenge_method = form.get("code_challenge_method", "S256")

        if action == "deny":
            sep = "&" if "?" in redirect_uri else "?"
            location = f"{redirect_uri}{sep}error=access_denied&state={urllib.parse.quote(state)}"
            await _send_redirect(send, location)
            return

        # Generate authorization code
        code = secrets.token_urlsafe(32)
        self.auth_codes[code] = AuthCode(
            code=code,
            client_id=client_id,
            redirect_uri=redirect_uri,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            created_at=time.time(),
        )
        logger.info(f"OAuth: issued auth code for client {client_id}")

        # Purge expired codes while we're here
        now = time.time()
        expired = [c for c, ac in self.auth_codes.items() if now - ac.created_at > ac.ttl]
        for c in expired:
            del self.auth_codes[c]

        sep = "&" if "?" in redirect_uri else "?"
        location = f"{redirect_uri}{sep}code={urllib.parse.quote(code)}&state={urllib.parse.quote(state)}"
        await _send_redirect(send, location)

    async def _handle_token(self, send: Send, body: bytes) -> None:
        """Exchange authorization code for access token."""
        form = _parse_form(body)
        grant_type = form.get("grant_type", "")
        code = form.get("code", "")
        client_id = form.get("client_id", "")
        code_verifier = form.get("code_verifier", "")

        if grant_type != "authorization_code":
            await _send_json(send, 400, {"error": "unsupported_grant_type"})
            return

        auth_code = self.auth_codes.pop(code, None)
        if not auth_code:
            await _send_json(send, 400, {"error": "invalid_grant",
                                          "error_description": "Unknown or expired code"})
            return

        # Check expiration
        if time.time() - auth_code.created_at > auth_code.ttl:
            await _send_json(send, 400, {"error": "invalid_grant",
                                          "error_description": "Code expired"})
            return

        # Check client_id matches
        if auth_code.client_id != client_id:
            await _send_json(send, 400, {"error": "invalid_grant",
                                          "error_description": "client_id mismatch"})
            return

        # Verify PKCE
        if auth_code.code_challenge:
            if not code_verifier:
                await _send_json(send, 400, {"error": "invalid_request",
                                              "error_description": "Missing code_verifier"})
                return
            if not _verify_pkce(code_verifier, auth_code.code_challenge,
                               auth_code.code_challenge_method):
                await _send_json(send, 400, {"error": "invalid_grant",
                                              "error_description": "PKCE verification failed"})
                return

        # Issue token (the same bearer token we use for direct auth)
        logger.info(f"OAuth: token issued for client {client_id}")
        await _send_json(send, 200, {
            "access_token": self.bearer_token,
            "token_type": "Bearer",
            "scope": "fleet",
        })
