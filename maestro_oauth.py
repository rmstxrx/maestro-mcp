"""
maestro_oauth.py — OAuthAuthorizationServerProvider for Maestro MCP.

Implements the FastMCP auth provider protocol. All OAuth routes, metadata,
and bearer-token verification are handled by the SDK's built-in auth system.

Security layers:
  - Dynamic registration rate-limited (10 per minute).
  - Claude.ai (detected by redirect_uri) is auto-approved — the user is
    already authenticated in their Anthropic account.
  - All other MCP clients go through a consent page with PIN gate.
  - Tokens are opaque random strings stored in-memory.
"""

import hashlib
import hmac
import html as html_mod
import json
import logging
import os
import secrets
import time
from typing import Any

from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse, Response

from urllib.parse import parse_qs, urlparse

from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    AuthorizeError,
    RefreshToken,
    construct_redirect_uri,
)
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken

logger = logging.getLogger("maestro-oauth")
audit_logger = logging.getLogger("maestro-audit")

TOKEN_EXPIRY = 8 * 3600  # 8 hours
REFRESH_TOKEN_EXPIRY = 30 * 86400  # 30 days
AUTH_CODE_TTL = 300  # 5 minutes

AUTHORIZE_PIN_HASH = os.environ.get("MAESTRO_AUTHORIZE_PIN_HASH")
CLAUDE_AI_CALLBACK = "https://claude.ai/api/mcp/auth_callback"


def _audit(event: str, **kwargs: Any) -> None:
    entry = {"ts": time.time(), "event": event, **kwargs}
    audit_logger.info(json.dumps(entry))


class MaestroOAuthProvider:
    """OAuth 2.0 provider for Maestro MCP.

    Claude.ai → auto-approve (redirect_uri gated).
    Other clients → consent page + PIN gate.
    Registration rate-limited to 10/min.
    """

    REG_RATE_LIMIT = 10
    REG_RATE_WINDOW = 60  # seconds

    def __init__(self, issuer_url: str, host_names: list[str] | None = None):
        self.issuer_url = issuer_url.rstrip("/")
        self.host_names = host_names or []
        self.clients: dict[str, OAuthClientInformationFull] = {}
        self.auth_codes: dict[str, AuthorizationCode] = {}
        self.access_tokens: dict[str, AccessToken] = {}
        self.refresh_tokens: dict[str, RefreshToken] = {}
        self.pending_approvals: dict[str, dict] = {}
        self._reg_timestamps: list[float] = []

    # --- OAuthAuthorizationServerProvider protocol ---

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        return self.clients.get(client_id)

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        now = time.time()
        self._reg_timestamps = [t for t in self._reg_timestamps
                                if now - t < self.REG_RATE_WINDOW]
        if len(self._reg_timestamps) >= self.REG_RATE_LIMIT:
            _audit("register_rate_limited")
            raise ValueError("Too many registration requests — try again later")
        self._reg_timestamps.append(now)

        self.clients[client_info.client_id] = client_info
        _audit("client_registered", client_id=client_info.client_id,
               client_name=client_info.client_name)
        logger.info("client_registered: %s", client_info.client_id)

    async def authorize(
        self,
        client: OAuthClientInformationFull,
        params: AuthorizationParams,
    ) -> str:
        redirect_str = str(params.redirect_uri).rstrip("/")

        # All clients → consent page + PIN gate.
        approval_id = secrets.token_urlsafe(24)
        self.pending_approvals[approval_id] = {
            "client_id": client.client_id,
            "client_name": client.client_name or client.client_id,
            "params": params,
            "created_at": time.time(),
        }
        _audit("authorize_pending", client_id=client.client_id)
        logger.info("authorize_consent: client=%s → /approve?id=%s",
                     client.client_id, approval_id)
        return f"{self.issuer_url}/approve?id={approval_id}"

    async def load_authorization_code(
        self,
        client: OAuthClientInformationFull,
        authorization_code: str,
    ) -> AuthorizationCode | None:
        return self.auth_codes.pop(authorization_code, None)

    async def exchange_authorization_code(
        self,
        client: OAuthClientInformationFull,
        authorization_code: AuthorizationCode,
    ) -> OAuthToken:
        now = int(time.time())
        access_tok = secrets.token_urlsafe(32)
        refresh_tok = secrets.token_urlsafe(32)

        self.access_tokens[access_tok] = AccessToken(
            token=access_tok,
            client_id=client.client_id,
            scopes=authorization_code.scopes or ["maestro"],
            expires_at=now + TOKEN_EXPIRY,
            resource=authorization_code.resource,
        )
        self.refresh_tokens[refresh_tok] = RefreshToken(
            token=refresh_tok,
            client_id=client.client_id,
            scopes=authorization_code.scopes or ["maestro"],
            expires_at=now + REFRESH_TOKEN_EXPIRY,
        )
        _audit("token_issued", client_id=client.client_id, expires_in=TOKEN_EXPIRY)
        logger.info("token_issued: access=%s... stored=%d",
                     access_tok[:20], len(self.access_tokens))

        return OAuthToken(
            access_token=access_tok,
            token_type="Bearer",
            expires_in=TOKEN_EXPIRY,
            scope=" ".join(authorization_code.scopes or ["maestro"]),
            refresh_token=refresh_tok,
        )

    async def load_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: str,
    ) -> RefreshToken | None:
        return self.refresh_tokens.get(refresh_token)

    async def exchange_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: RefreshToken,
        scopes: list[str],
    ) -> OAuthToken:
        del self.refresh_tokens[refresh_token.token]
        now = int(time.time())
        access_tok = secrets.token_urlsafe(32)
        new_refresh = secrets.token_urlsafe(32)

        self.access_tokens[access_tok] = AccessToken(
            token=access_tok,
            client_id=client.client_id,
            scopes=scopes,
            expires_at=now + TOKEN_EXPIRY,
        )
        self.refresh_tokens[new_refresh] = RefreshToken(
            token=new_refresh,
            client_id=client.client_id,
            scopes=scopes,
            expires_at=now + REFRESH_TOKEN_EXPIRY,
        )
        _audit("token_refreshed", client_id=client.client_id)

        return OAuthToken(
            access_token=access_tok,
            token_type="Bearer",
            expires_in=TOKEN_EXPIRY,
            scope=" ".join(scopes),
            refresh_token=new_refresh,
        )

    async def load_access_token(self, token: str) -> AccessToken | None:
        logger.info("load_access_token: token=%s... stored=%d",
                     token[:20] if token else "None", len(self.access_tokens))
        at = self.access_tokens.get(token)
        if at and at.expires_at and at.expires_at < time.time():
            logger.info("load_access_token: EXPIRED for %s", at.client_id)
            del self.access_tokens[token]
            return None
        if at:
            logger.info("load_access_token: OK client=%s scopes=%s", at.client_id, at.scopes)
        else:
            logger.info("load_access_token: NOT FOUND (known tokens: %s)",
                         [t[:12] + "..." for t in self.access_tokens.keys()])
        return at

    async def revoke_token(self, token: AccessToken | RefreshToken) -> None:
        if isinstance(token, AccessToken):
            self.access_tokens.pop(token.token, None)
        else:
            self.refresh_tokens.pop(token.token, None)

    # --- Internal ---

    def _store_auth_code(
        self,
        client: OAuthClientInformationFull,
        params: AuthorizationParams,
    ) -> str:
        code_str = secrets.token_urlsafe(32)
        self.auth_codes[code_str] = AuthorizationCode(
            code=code_str,
            scopes=params.scopes or [],
            expires_at=time.time() + AUTH_CODE_TTL,
            client_id=client.client_id,
            code_challenge=params.code_challenge,
            redirect_uri=params.redirect_uri,
            redirect_uri_provided_explicitly=params.redirect_uri_provided_explicitly,
            resource=params.resource,
        )
        now = time.time()
        expired = [c for c, ac in self.auth_codes.items() if ac.expires_at < now]
        for c in expired:
            del self.auth_codes[c]
        return code_str

    # --- /approve consent page ---

    async def handle_approve(self, request: Request) -> Response:
        if request.method == "GET":
            return await self._approve_get(request)
        return await self._approve_post(request)

    async def _approve_get(self, request: Request) -> Response:
        approval_id = request.query_params.get("id", "")
        pending = self.pending_approvals.get(approval_id)
        if not pending or time.time() - pending["created_at"] > AUTH_CODE_TTL:
            self.pending_approvals.pop(approval_id, None)
            return HTMLResponse(
                _error_page("Expired", "This authorization request has expired."),
                status_code=400,
            )

        csrf = secrets.token_urlsafe(32)
        pending["csrf"] = csrf

        return HTMLResponse(_approve_page(
            client_name=pending["client_name"],
            approval_id=approval_id,
            csrf_token=csrf,
            host_names=self.host_names,
        ))

    async def _approve_post(self, request: Request) -> Response:
        form = await request.form()
        approval_id = str(form.get("id", ""))
        csrf = str(form.get("csrf_token", ""))
        action = str(form.get("action", "approve"))
        pin = str(form.get("pin", ""))

        pending = self.pending_approvals.pop(approval_id, None)
        if not pending:
            return HTMLResponse(
                _error_page("Invalid", "Unknown or expired request."),
                status_code=400,
            )

        if csrf != pending.get("csrf", ""):
            return HTMLResponse(
                _error_page("CSRF Error", "Invalid CSRF token."),
                status_code=403,
            )

        params: AuthorizationParams = pending["params"]

        if action == "deny":
            _audit("authorize_denied", client_id=pending["client_id"])
            deny_url = construct_redirect_uri(
                str(params.redirect_uri),
                error="access_denied",
                state=params.state,
            )
            return HTMLResponse(_redirect_page(deny_url))

        if AUTHORIZE_PIN_HASH:
            pin_hash = hashlib.sha256(pin.encode()).hexdigest()
            if not hmac.compare_digest(pin_hash, AUTHORIZE_PIN_HASH):
                _audit("authorize_pin_rejected", client_id=pending["client_id"])
                return HTMLResponse(
                    _error_page("Invalid PIN", "The authorization PIN is incorrect."),
                    status_code=403,
                )

        client = self.clients.get(pending["client_id"])
        if not client:
            return HTMLResponse(
                _error_page("Error", "Client no longer exists."),
                status_code=400,
            )

        code = self._store_auth_code(client, params)
        _audit("authorize_approved", client_id=client.client_id)

        redirect_url = construct_redirect_uri(
            str(params.redirect_uri), code=code, state=params.state,
        )
        logger.info("approve_redirect: %s", redirect_url)

        # Use HTML redirect instead of bare 302 — more reliable through
        # Cloudflare Tunnel which can interfere with Location headers.
        return HTMLResponse(_redirect_page(redirect_url))


# ---------------------------------------------------------------------------
# HTML templates
# ---------------------------------------------------------------------------

def _approve_page(client_name: str, approval_id: str, csrf_token: str, host_names: list[str] | None = None) -> str:
    safe_name = html_mod.escape(client_name)
    safe_id = html_mod.escape(approval_id)
    safe_csrf = html_mod.escape(csrf_token)
    hosts_str = html_mod.escape(", ".join(host_names)) if host_names else "configured hosts"
    return f"""<!DOCTYPE html>
<html>
<head>
    <title>Maestro — Authorize</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: #0a0a1a; color: #e0e0e0;
            display: flex; justify-content: center; align-items: center;
            min-height: 100vh; margin: 0; }}
        .card {{ background: #1a1a2e; border: 1px solid #2a2a4a; border-radius: 12px;
            padding: 2rem; max-width: 400px; width: 90%;
            box-shadow: 0 4px 24px rgba(0, 0, 0, 0.5); }}
        h1 {{ font-size: 1.3rem; margin: 0 0 0.5rem 0; color: #00d4ff; }}
        .client {{ color: #ff6b9d; font-weight: 600; }}
        .perms {{ background: #12122a; border: 1px solid #2a2a4a; border-radius: 8px;
            padding: 1rem; margin: 1rem 0; font-size: 0.9rem; }}
        .perms li {{ margin: 0.3rem 0; }}
        .buttons {{ display: flex; gap: 1rem; margin-top: 1.5rem; }}
        button {{ flex: 1; padding: 0.75rem; border: none; border-radius: 8px;
            font-size: 1rem; cursor: pointer; font-weight: 600; }}
        .approve {{ background: #00d4ff; color: #0a0a1a; }}
        .approve:hover {{ background: #00b8e6; }}
        .deny {{ background: #2a2a4a; color: #e0e0e0; }}
        .deny:hover {{ background: #3a3a5a; }}
        .pin-field {{ margin: 1rem 0 0.5rem 0; }}
        .pin-field label {{ font-size: 0.9rem; color: #aaa; }}
    </style>
</head>
<body>
    <div class="card">
        <h1>Maestro</h1>
        <p><span class="client">{safe_name}</span> wants access to Maestro.</p>
        <div class="perms">
            <strong>This will allow:</strong>
            <ul>
                <li>Execute commands on {hosts_str}</li>
                <li>Read and write files on all hosts</li>
                <li>Transfer files between machines</li>
            </ul>
        </div>
        <form method="POST" action="/approve">
            <input type="hidden" name="id" value="{safe_id}">
            <input type="hidden" name="csrf_token" value="{safe_csrf}">
            <div class="pin-field">
                <label for="pin">Authorization PIN:</label>
                <input type="password" id="pin" name="pin" placeholder="Enter PIN"
                    autocomplete="off" required
                    style="width:100%; padding:0.6rem; border:1px solid #2a2a4a;
                    border-radius:6px; background:#12122a; color:#e0e0e0;
                    font-family:monospace; font-size:1rem; margin-top:0.4rem;">
            </div>
            <div class="buttons">
                <button type="submit" name="action" value="approve" class="approve">Approve</button>
                <button type="submit" name="action" value="deny" class="deny">Deny</button>
            </div>
        </form>
    </div>
</body>
</html>"""


def _redirect_page(url: str) -> str:
    # HTML-escaped URL for attributes (href, meta content) where the
    # browser decodes &amp; → &.
    html_url = html_mod.escape(url, quote=True)
    # JSON-encoded URL for <script> context where HTML entities are NOT
    # decoded — use json.dumps to produce a safe JS string literal.
    js_url = json.dumps(url)  # includes surrounding quotes
    return f"""<!DOCTYPE html>
<html>
<head>
    <title>Maestro — Redirecting</title>
    <meta http-equiv="refresh" content="0;url={html_url}">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: #0a0a1a; color: #e0e0e0;
            display: flex; justify-content: center; align-items: center;
            min-height: 100vh; margin: 0; }}
        .card {{ background: #1a1a2e; border: 1px solid #2a2a4a; border-radius: 12px;
            padding: 2rem; max-width: 400px; width: 90%;
            box-shadow: 0 4px 24px rgba(0, 0, 0, 0.5); text-align: center; }}
        h1 {{ font-size: 1.3rem; color: #00d4ff; margin: 0 0 1rem 0; }}
        a {{ color: #00d4ff; }}
    </style>
</head>
<body>
    <div class="card">
        <h1>Approved</h1>
        <p>Redirecting...</p>
        <p style="margin-top:1rem"><a href="{html_url}">Click here if not redirected</a></p>
    </div>
    <script>window.location.replace({js_url});</script>
</body>
</html>"""


def _error_page(title: str, message: str) -> str:
    safe_title = html_mod.escape(title)
    safe_msg = html_mod.escape(message)
    return f"""<!DOCTYPE html>
<html>
<head>
    <title>Maestro — {safe_title}</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: #0a0a1a; color: #e0e0e0;
            display: flex; justify-content: center; align-items: center;
            min-height: 100vh; margin: 0; }}
        .card {{ background: #1a1a2e; border: 1px solid #ff4444; border-radius: 12px;
            padding: 2rem; max-width: 400px; width: 90%;
            box-shadow: 0 4px 24px rgba(0, 0, 0, 0.5); text-align: center; }}
        h1 {{ font-size: 1.3rem; color: #ff4444; margin: 0 0 1rem 0; }}
        a {{ color: #00d4ff; }}
    </style>
</head>
<body>
    <div class="card">
        <h1>{safe_title}</h1>
        <p>{safe_msg}</p>
        <p style="margin-top:1.5rem"><a href="javascript:window.close()">Close this tab</a></p>
    </div>
</body>
</html>"""
