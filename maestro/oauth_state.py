"""
maestro/oauth_state.py — Atomic JSON persistence for OAuth state.

Persists the three dicts that matter across restarts:
  - clients       (registered OAuth clients, no expiry)
  - access_tokens (8h expiry — the ones that break live sessions on restart)
  - refresh_tokens (30d expiry)

Auth codes and pending approvals are intentionally ephemeral and not persisted.

Write strategy: serialize to a .tmp file, then os.replace() → atomic on POSIX
(same filesystem, single syscall). Readers never see a partial write.

Load strategy: deserialize at startup, silently drop any token whose
expires_at is in the past. Corrupted entries are skipped with a warning.
"""

from __future__ import annotations

import json
import logging
import os
import time
from pathlib import Path
from typing import TYPE_CHECKING

from mcp.server.auth.provider import AccessToken, RefreshToken
from mcp.shared.auth import OAuthClientInformationFull

if TYPE_CHECKING:
    from maestro_oauth import MaestroOAuthProvider

logger = logging.getLogger("maestro-oauth")

_STATE_VERSION = 1


class OAuthStateStore:
    """Atomic JSON persistence for MaestroOAuthProvider state.

    Usage::

        store = OAuthStateStore(Path("~/.maestro/oauth_state.json").expanduser())
        provider = MaestroOAuthProvider(issuer_url=..., state_store=store)
        # store.load() is called inside __init__; store.save() is called on mutations.
    """

    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def save(self, provider: "MaestroOAuthProvider") -> None:
        """Atomically serialise current provider state to disk."""
        now = time.time()
        state = {
            "version": _STATE_VERSION,
            "saved_at": now,
            "clients": {
                cid: client.model_dump(mode="json")
                for cid, client in provider.clients.items()
            },
            "access_tokens": {
                tok: {
                    "token": at.token,
                    "client_id": at.client_id,
                    "scopes": list(at.scopes),
                    "expires_at": at.expires_at,
                    "resource": at.resource,
                }
                for tok, at in provider.access_tokens.items()
                if at.expires_at is None or at.expires_at > now  # skip already-expired
            },
            "refresh_tokens": {
                tok: {
                    "token": rt.token,
                    "client_id": rt.client_id,
                    "scopes": list(rt.scopes),
                    "expires_at": rt.expires_at,
                }
                for tok, rt in provider.refresh_tokens.items()
                if rt.expires_at is None or rt.expires_at > now
            },
        }
        tmp = self.path.with_suffix(".tmp")
        try:
            tmp.write_text(json.dumps(state, indent=2))
            os.replace(tmp, self.path)
            logger.debug(
                "oauth_state: saved %d clients, %d access, %d refresh → %s",
                len(state["clients"]),
                len(state["access_tokens"]),
                len(state["refresh_tokens"]),
                self.path,
            )
        except Exception as exc:
            logger.warning("oauth_state: save failed: %s", exc)
            tmp.unlink(missing_ok=True)

    def load(self, provider: "MaestroOAuthProvider") -> None:
        """Deserialise persisted state into provider, dropping expired tokens."""
        if not self.path.exists():
            logger.info("oauth_state: no state file at %s — starting fresh", self.path)
            return

        try:
            raw = self.path.read_text()
            state = json.loads(raw)
        except Exception as exc:
            logger.warning("oauth_state: failed to parse %s: %s — starting fresh", self.path, exc)
            return

        version = state.get("version", 0)
        if version != _STATE_VERSION:
            logger.warning(
                "oauth_state: unsupported version %d (expected %d) — starting fresh",
                version, _STATE_VERSION,
            )
            return

        now = time.time()
        counts = {"clients": 0, "access_tokens": 0, "refresh_tokens": 0,
                  "skipped_expired": 0, "skipped_invalid": 0}

        # --- clients (no expiry) ---
        for cid, data in state.get("clients", {}).items():
            try:
                provider.clients[cid] = OAuthClientInformationFull.model_validate(data)
                counts["clients"] += 1
            except Exception as exc:
                logger.warning("oauth_state: skip client %r: %s", cid, exc)
                counts["skipped_invalid"] += 1

        # --- access tokens ---
        for tok, data in state.get("access_tokens", {}).items():
            exp = data.get("expires_at")
            if exp is not None and exp < now:
                counts["skipped_expired"] += 1
                continue
            try:
                provider.access_tokens[tok] = AccessToken(
                    token=data["token"],
                    client_id=data["client_id"],
                    scopes=data["scopes"],
                    expires_at=data.get("expires_at"),
                    resource=data.get("resource"),
                )
                counts["access_tokens"] += 1
            except Exception as exc:
                logger.warning("oauth_state: skip access_token %r: %s", tok[:16] + "…", exc)
                counts["skipped_invalid"] += 1

        # --- refresh tokens ---
        for tok, data in state.get("refresh_tokens", {}).items():
            exp = data.get("expires_at")
            if exp is not None and exp < now:
                counts["skipped_expired"] += 1
                continue
            try:
                provider.refresh_tokens[tok] = RefreshToken(
                    token=data["token"],
                    client_id=data["client_id"],
                    scopes=data["scopes"],
                    expires_at=data.get("expires_at"),
                )
                counts["refresh_tokens"] += 1
            except Exception as exc:
                logger.warning("oauth_state: skip refresh_token %r: %s", tok[:16] + "…", exc)
                counts["skipped_invalid"] += 1

        logger.info(
            "oauth_state: loaded clients=%d access=%d refresh=%d "
            "(expired_skipped=%d invalid_skipped=%d)",
            counts["clients"], counts["access_tokens"], counts["refresh_tokens"],
            counts["skipped_expired"], counts["skipped_invalid"],
        )
