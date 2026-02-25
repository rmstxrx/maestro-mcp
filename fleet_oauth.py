"""
fleet_oauth.py — OAuth 2.0 Authorization Code + PKCE for Agent Orchestrator MCP.

Single-user OAuth server designed for MCP connector authentication.
The "authorize" page shows a simple approve/deny form since Rômulo is
the only user. Access tokens are per-client JWTs (HS256) signed with
the bearer secret from ~/.fleet-ssh/bearer_token, expiring after 8 hours.

Implements:
  /.well-known/oauth-authorization-server  — RFC 8414 metadata
  /oauth/register                          — RFC 7591 dynamic client registration (gated)
  /oauth/authorize                         — Authorization endpoint (GET → form, POST → redirect)
  /oauth/token                             — Token endpoint (code → per-client JWT)

Security features:
  - Registration gated by FLEET_REGISTRATION_SECRET env var
  - Per-client JWTs with expiry (no shared static token)
  - S256-only PKCE (plain method rejected)
  - CSRF protection on authorize form
  - In-memory sliding window rate limiter on auth endpoints
  - Structured audit logging (JSON-lines to fleet-audit logger)
  - Fail-closed when no signing key is configured

All state (clients, auth codes, CSRF tokens) is in-memory and ephemeral.
"""

import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import time
import urllib.parse
from collections import deque
from dataclasses import dataclass, field
from typing import Any

import jwt

from starlette.types import ASGIApp, Receive, Scope, Send

logger = logging.getLogger("fleet-oauth")
audit_logger = logging.getLogger("fleet-audit")

# ---------------------------------------------------------------------------
# Security configuration
# ---------------------------------------------------------------------------

JWT_ALGORITHM = "HS256"
JWT_EXPIRY_SECONDS = 8 * 3600  # 8 hours
MAX_REGISTERED_CLIENTS = 20
RATE_LIMIT_WINDOW = 60  # seconds
RATE_LIMIT_MAX_REQUESTS = 10  # per window per IP per endpoint
REGISTRATION_SECRET = os.environ.get("FLEET_REGISTRATION_SECRET")
AUTHORIZE_PIN_HASH = os.environ.get("FLEET_AUTHORIZE_PIN_HASH")  # SHA-256 of the PIN


# ---------------------------------------------------------------------------
# Audit logging
# ---------------------------------------------------------------------------

def _audit(event: str, **kwargs: Any) -> None:
    """Emit a structured JSON audit log entry."""
    entry = {"ts": time.time(), "event": event, **kwargs}
    audit_logger.info(json.dumps(entry))


# ---------------------------------------------------------------------------
# Rate limiter
# ---------------------------------------------------------------------------

class _RateLimiter:
    """In-memory sliding window rate limiter."""

    def __init__(self, max_requests: int = RATE_LIMIT_MAX_REQUESTS,
                 window: int = RATE_LIMIT_WINDOW):
        self.max_requests = max_requests
        self.window = window
        self._buckets: dict[str, deque[float]] = {}

    def is_allowed(self, key: str) -> bool:
        now = time.time()
        cutoff = now - self.window
        bucket = self._buckets.get(key)
        if bucket is None:
            bucket = deque()
            self._buckets[key] = bucket
        while bucket and bucket[0] < cutoff:
            bucket.popleft()
        if len(bucket) >= self.max_requests:
            return False
        bucket.append(now)
        return True

    def cleanup(self) -> None:
        """Remove empty buckets."""
        empty = [k for k, v in self._buckets.items() if not v]
        for k in empty:
            del self._buckets[k]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_client_ip(scope: Scope) -> str:
    """Extract real client IP, preferring CF-Connecting-IP."""
    headers = dict(scope.get("headers", []))
    cf_ip = headers.get(b"cf-connecting-ip")
    if cf_ip:
        return cf_ip.decode("ascii", errors="replace").strip()
    client = scope.get("client")
    if client:
        return client[0]
    return "unknown"

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
    if method != "S256":
        return False  # Only S256 is allowed
    computed = hashlib.sha256(verifier.encode("ascii")).digest()
    expected = base64.urlsafe_b64encode(computed).rstrip(b"=").decode("ascii")
    return hmac.compare_digest(expected, challenge)


def _verify_authorize_pin(pin: str) -> bool:
    """Verify the authorize PIN against stored hash."""
    if not AUTHORIZE_PIN_HASH:
        return True  # No PIN configured = no gate (backward compat)
    pin_hash = hashlib.sha256(pin.encode()).hexdigest()
    return hmac.compare_digest(pin_hash, AUTHORIZE_PIN_HASH)


# ---------------------------------------------------------------------------
# Authorization page HTML
# ---------------------------------------------------------------------------

def _authorize_page(client_name: str, client_id: str, redirect_uri: str,
                    state: str, code_challenge: str, code_challenge_method: str,
                    csrf_token: str = "") -> str:
    return f"""<!DOCTYPE html>
<html>
<head>
    <title>Agent Orchestrator — Authorize</title>
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
        .pin-field {{
            margin: 1rem 0 0.5rem 0;
        }}
        .pin-field label {{
            font-size: 0.9rem;
            color: #aaa;
        }}
    </style>
</head>
<body>
    <div class="card">
        <h1>⚡ Agent Orchestrator</h1>
        <p><span class="client">{client_name or client_id}</span> wants access to the orchestrator.</p>
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
            <input type="hidden" name="csrf_token" value="{csrf_token}">
            <div class="pin-field">
                <label for="pin">Authorization PIN:</label>
                <input type="password" id="pin" name="pin" placeholder="Enter PIN"
                       autocomplete="off" required
                       style="width:100%; padding:0.6rem; border:1px solid #2a2a4a;
                              border-radius:6px; background:#12122a; color:#e0e0e0;
                              font-family:monospace; font-size:1rem; margin-top:0.4rem;">
            </div>
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

def _error_page(title: str, message: str) -> str:
    """Render a styled error page."""
    return f"""<!DOCTYPE html>
<html>
<head>
    <title>Agent Orchestrator — {title}</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: #0a0a1a; color: #e0e0e0;
            display: flex; justify-content: center; align-items: center;
            min-height: 100vh; margin: 0;
        }}
        .card {{
            background: #1a1a2e; border: 1px solid #ff4444;
            border-radius: 12px; padding: 2rem; max-width: 400px;
            width: 90%; box-shadow: 0 4px 24px rgba(0, 0, 0, 0.5);
            text-align: center;
        }}
        h1 {{ font-size: 1.3rem; color: #ff4444; margin: 0 0 1rem 0; }}
        a {{ color: #00d4ff; }}
    </style>
</head>
<body>
    <div class="card">
        <h1>\u26a0\ufe0f {title}</h1>
        <p>{message}</p>
        <p style="margin-top:1.5rem"><a href="javascript:window.close()">Close this tab</a></p>
    </div>
</body>
</html>"""


def _success_page(redirect_url: str) -> str:
    """Render a success interstitial that redirects after a brief pause."""
    import html as html_mod
    escaped_url = html_mod.escape(redirect_url, quote=True)
    return f"""<!DOCTYPE html>
<html>
<head>
    <title>Agent Orchestrator — Authorized</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: #0a0a1a; color: #e0e0e0;
            display: flex; justify-content: center; align-items: center;
            min-height: 100vh; margin: 0;
        }}
        .card {{
            background: #1a1a2e; border: 1px solid #00d4ff;
            border-radius: 12px; padding: 2rem; max-width: 400px;
            width: 90%; box-shadow: 0 4px 24px rgba(0, 0, 0, 0.5);
            text-align: center;
        }}
        h1 {{ font-size: 1.3rem; color: #00d4ff; margin: 0 0 1rem 0; }}
        .spinner {{
            display: inline-block; width: 20px; height: 20px;
            border: 2px solid #2a2a4a; border-top: 2px solid #00d4ff;
            border-radius: 50%; animation: spin 0.8s linear infinite;
            vertical-align: middle; margin-right: 0.5rem;
        }}
        @keyframes spin {{ to {{ transform: rotate(360deg); }} }}
        a {{ color: #00d4ff; }}
    </style>
</head>
<body>
    <div class="card">
        <h1>\u2705 Authorized</h1>
        <p>Agent Orchestrator access granted.</p>
        <p style="margin-top:1rem; color:#888;">
            <span class="spinner"></span>Completing handshake...
        </p>
        <p style="margin-top:1.5rem; font-size:0.85rem; color:#666;">
            If nothing happens, <a href="{escaped_url}">click here</a>
            or close this tab.
        </p>
    </div>
    <script>
        // Give the user a moment to see the success message, then redirect
        setTimeout(function() {{
            window.location.href = "{escaped_url}";
        }}, 1500);
        // Try to close the tab after the redirect has had time to process
        setTimeout(function() {{
            window.close();
        }}, 4000);
    </script>
</body>
</html>"""


class FleetOAuthMiddleware:
    """ASGI middleware implementing OAuth 2.0 for Agent Orchestrator MCP.

    Intercepts OAuth-related paths before they reach the MCP app.
    All other paths require a valid Bearer token.
    """

    # Paths that don't require authentication
    OPEN_PATHS = {
        "/.well-known/oauth-authorization-server",
        "/.well-known/openid-configuration",
        "/.well-known/oauth-protected-resource",
        "/.well-known/oauth-protected-resource/mcp",
        "/oauth/authorize",
        "/oauth/token",
        "/oauth/register",
        "/register",
        "/authorize",
        "/token",
    }

    def __init__(self, app: ASGIApp, bearer_token: str | None, issuer_url: str):
        self.app = app
        self.bearer_token = bearer_token  # Used as JWT signing key
        self.issuer_url = issuer_url.rstrip("/")
        self.clients: dict[str, OAuthClient] = {}
        self.auth_codes: dict[str, AuthCode] = {}
        self.csrf_tokens: dict[str, float] = {}  # token -> created_at
        self._rate_limiter = _RateLimiter()
        self._last_cleanup = time.time()

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        method = scope.get("method", "GET")

        # Periodic cleanup (every 5 minutes)
        now = time.time()
        if now - self._last_cleanup > 300:
            self._rate_limiter.cleanup()
            self._purge_csrf_tokens()
            self._last_cleanup = now

        # Rate limit OAuth endpoints
        if path in ("/oauth/register", "/oauth/token", "/oauth/authorize",
                     "/register", "/token", "/authorize"):
            client_ip = _get_client_ip(scope)
            if not self._rate_limiter.is_allowed(f"{path}:{client_ip}"):
                _audit("rate_limited", ip=client_ip, path=path)
                await _send_json(send, 429, {
                    "error": "too_many_requests",
                    "error_description": "Rate limit exceeded. Try again later.",
                }, [[b"retry-after", b"60"]])
                return

        # --- OAuth endpoints (no auth required) ---

        if path in ("/.well-known/oauth-authorization-server",
                    "/.well-known/openid-configuration"):
            await self._handle_metadata(send)
            return

        if path in ("/.well-known/oauth-protected-resource",
                     "/.well-known/oauth-protected-resource/mcp"):
            await self._handle_protected_resource_metadata(send)
            return

        if path in ("/oauth/register", "/register") and method == "POST":
            body = await _read_body(receive)
            await self._handle_register(send, body, scope)
            return

        if path in ("/oauth/authorize", "/authorize"):
            if method == "GET":
                qs = _parse_qs(scope.get("query_string", b"").decode())
                await self._handle_authorize_get(send, qs)
            elif method == "POST":
                body = await _read_body(receive)
                await self._handle_authorize_post(send, body, scope)
            else:
                await _send_json(send, 405, {"error": "method_not_allowed"})
            return

        if path in ("/oauth/token", "/token") and method == "POST":
            body = await _read_body(receive)
            await self._handle_token(send, body)
            return

        # --- All other paths: require valid JWT ---

        if not self.bearer_token:
            _audit("auth_bypass_blocked", reason="no_signing_key_configured")
            await _send_json(send, 503, {
                "error": "server_misconfigured",
                "error_description": "Authentication not configured.",
            })
            return

        _rm_url = f"{self.issuer_url}/.well-known/oauth-protected-resource"
        _www_auth = f'Bearer resource_metadata="{_rm_url}"'.encode()

        headers = dict(scope.get("headers", []))
        auth = headers.get(b"authorization", b"").decode()
        if not auth.startswith("Bearer "):
            await _send_json(send, 401, {"error": "unauthorized"}, [
                [b"www-authenticate", _www_auth],
            ])
            return

        token = auth[7:]
        try:
            jwt.decode(
                token,
                self.bearer_token,
                algorithms=[JWT_ALGORITHM],
                issuer=self.issuer_url,
                options={"require": ["sub", "exp", "iss", "jti"]},
            )
        except jwt.ExpiredSignatureError:
            _audit("token_rejected", reason="expired")
            await _send_json(send, 401, {
                "error": "unauthorized",
                "error_description": "Token expired.",
            }, [[b"www-authenticate", _www_auth]])
            return
        except jwt.InvalidTokenError as e:
            _audit("token_rejected", reason=str(e))
            await _send_json(send, 401, {"error": "unauthorized"}, [
                [b"www-authenticate", _www_auth],
            ])
            return

        await self.app(scope, receive, send)

    # --- Internal helpers ---

    def _purge_csrf_tokens(self) -> None:
        now = time.time()
        expired = [t for t, ts in self.csrf_tokens.items() if now - ts > 300]
        for t in expired:
            del self.csrf_tokens[t]

    # --- Endpoint handlers ---

    async def _handle_metadata(self, send: Send) -> None:
        """RFC 8414 — OAuth Authorization Server Metadata."""
        await _send_json(send, 200, {
            "issuer": self.issuer_url,
            "authorization_endpoint": f"{self.issuer_url}/authorize",
            "token_endpoint": f"{self.issuer_url}/token",
            "registration_endpoint": f"{self.issuer_url}/register",
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code"],
            "token_endpoint_auth_methods_supported": ["none", "client_secret_post"],
            "code_challenge_methods_supported": ["S256"],
            "scopes_supported": ["fleet"],
        })

    async def _handle_protected_resource_metadata(self, send: Send) -> None:
        """RFC 9728 — OAuth Protected Resource Metadata."""
        await _send_json(send, 200, {
            "resource": f"{self.issuer_url}/mcp",
            "authorization_servers": [self.issuer_url],
            "scopes_supported": ["fleet"],
            "bearer_methods_supported": ["header"],
        })

    async def _handle_register(self, send: Send, body: bytes, scope: Scope) -> None:
        """RFC 7591 — Dynamic Client Registration (gated)."""
        client_ip = _get_client_ip(scope)

        # Gate 1: Require registration secret
        if REGISTRATION_SECRET:
            headers = dict(scope.get("headers", []))
            auth = headers.get(b"authorization", b"").decode()
            if not hmac.compare_digest(auth, f"Bearer {REGISTRATION_SECRET}"):
                _audit("register_rejected", ip=client_ip, reason="bad_secret")
                await _send_json(send, 401, {
                    "error": "unauthorized",
                    "error_description": "Valid registration secret required.",
                })
                return

        # Gate 2: Cap number of clients
        if len(self.clients) >= MAX_REGISTERED_CLIENTS:
            _audit("register_rejected", ip=client_ip, reason="max_clients")
            await _send_json(send, 403, {
                "error": "client_limit_reached",
                "error_description": f"Maximum {MAX_REGISTERED_CLIENTS} clients.",
            })
            return

        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            await _send_json(send, 400, {"error": "invalid_request"})
            return

        # Gate 3: Validate redirect_uris
        redirect_uris = data.get("redirect_uris", [])
        if not isinstance(redirect_uris, list) or not redirect_uris:
            await _send_json(send, 400, {
                "error": "invalid_request",
                "error_description": "At least one redirect_uri is required.",
            })
            return

        for uri in redirect_uris:
            if not isinstance(uri, str):
                await _send_json(send, 400, {
                    "error": "invalid_request",
                    "error_description": "redirect_uris must be strings.",
                })
                return
            parsed = urllib.parse.urlparse(uri)
            if parsed.scheme == "http" and parsed.hostname in ("localhost", "127.0.0.1"):
                continue
            if parsed.scheme == "https":
                continue
            await _send_json(send, 400, {
                "error": "invalid_request",
                "error_description": f"Invalid redirect_uri scheme: {uri}",
            })
            return

        client_id = f"fleet-{secrets.token_hex(8)}"
        client_secret = secrets.token_urlsafe(32)
        client_name = data.get("client_name", "")

        client = OAuthClient(
            client_id=client_id,
            client_secret=client_secret,
            redirect_uris=redirect_uris,
            client_name=client_name,
            created_at=time.time(),
        )
        self.clients[client_id] = client
        _audit("client_registered", client_id=client_id, client_name=client_name, ip=client_ip)

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

        # Require registered client
        client = self.clients.get(client_id)
        if not client:
            await _send_json(send, 400, {
                "error": "unauthorized_client",
                "error_description": "Unknown client_id. Register first.",
            })
            return

        # Validate redirect_uri matches registration
        if redirect_uri not in client.redirect_uris:
            await _send_json(send, 400, {
                "error": "invalid_request",
                "error_description": "redirect_uri does not match registration.",
            })
            return

        # S256 only
        if code_challenge_method != "S256":
            await _send_json(send, 400, {
                "error": "invalid_request",
                "error_description": "Only S256 code_challenge_method is supported.",
            })
            return

        # Generate CSRF token
        csrf_token = secrets.token_urlsafe(32)
        self.csrf_tokens[csrf_token] = time.time()

        html = _authorize_page(
            client_name=client.client_name or client_id,
            client_id=client_id,
            redirect_uri=redirect_uri,
            state=state,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            csrf_token=csrf_token,
        )
        await _send_html(send, 200, html)

    async def _handle_authorize_post(self, send: Send, body: bytes, scope: Scope) -> None:
        """Process the approve/deny form submission."""
        form = _parse_form(body)
        client_ip = _get_client_ip(scope)
        action = form.get("action", "deny")
        client_id = form.get("client_id", "")
        redirect_uri = form.get("redirect_uri", "")
        state = form.get("state", "")
        code_challenge = form.get("code_challenge", "")
        code_challenge_method = form.get("code_challenge_method", "S256")

        # Validate authorize PIN (before anything else)
        pin = form.get("pin", "")
        if action == "approve" and not _verify_authorize_pin(pin):
            _audit("authorize_pin_rejected", ip=client_ip, client_id=client_id)
            await _send_html(send, 403, _error_page(
                "Invalid PIN",
                "The authorization PIN is incorrect. Access denied.",
            ))
            return

        # Validate CSRF token
        csrf_token = form.get("csrf_token", "")
        stored_time = self.csrf_tokens.pop(csrf_token, None)
        if stored_time is None or (time.time() - stored_time > 300):
            _audit("csrf_rejected", ip=client_ip, client_id=client_id)
            await _send_json(send, 403, {"error": "invalid_csrf_token"})
            return

        # Validate client exists
        if client_id not in self.clients:
            _audit("authorize_rejected", reason="unknown_client", client_id=client_id, ip=client_ip)
            sep = "&" if "?" in redirect_uri else "?"
            location = f"{redirect_uri}{sep}error=unauthorized_client&state={urllib.parse.quote(state)}"
            await _send_redirect(send, location)
            return

        if action == "deny":
            _audit("authorize_denied", client_id=client_id, ip=client_ip)
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
        _audit("authorize_approved", client_id=client_id, ip=client_ip)

        # Purge expired codes
        now = time.time()
        expired = [c for c, ac in self.auth_codes.items() if now - ac.created_at > ac.ttl]
        for c in expired:
            del self.auth_codes[c]

        sep = "&" if "?" in redirect_uri else "?"
        location = f"{redirect_uri}{sep}code={urllib.parse.quote(code)}&state={urllib.parse.quote(state)}"
        await _send_redirect(send, location)

    async def _handle_token(self, send: Send, body: bytes) -> None:
        """Exchange authorization code for per-client JWT."""
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

        # Mint per-client JWT
        now = time.time()
        jti = secrets.token_hex(16)
        payload = {
            "sub": client_id,
            "iss": self.issuer_url,
            "iat": int(now),
            "exp": int(now) + JWT_EXPIRY_SECONDS,
            "scope": "fleet",
            "jti": jti,
        }
        access_token = jwt.encode(payload, self.bearer_token, algorithm=JWT_ALGORITHM)
        _audit("token_issued", client_id=client_id, jti=jti, expires_in=JWT_EXPIRY_SECONDS)

        await _send_json(send, 200, {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": JWT_EXPIRY_SECONDS,
            "scope": "fleet",
        })
