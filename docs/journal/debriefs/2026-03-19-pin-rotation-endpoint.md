# Debrief: POST /admin/rotate-pin

**Date:** 2026-03-19
**Task:** Add hot-reload PIN rotation endpoint so the OAuth consent PIN can be changed without restarting Maestro.

## Files Changed

- **maestro_oauth.py** — Replaced module-level `AUTHORIZE_PIN_HASH` constant with mutable `_authorize_pin_hash` + `get_pin_hash()`/`set_pin_hash()` accessors; updated both references in `_approve_post`; added `handle_rotate_pin` (GET/POST) and `_render_rotate_pin_page` to `MaestroOAuthProvider`; added `from pathlib import Path` import.
- **server.py** — Registered `@mcp.custom_route("/admin/rotate-pin", methods=["GET", "POST"])` wired to the new handler.

## Decisions

- Reused the existing `_pin_fail_timestamps` rate-limit mechanism from the consent page for rotate-pin attempts (shared counter, same window/limit).
- PIN rotation persists the new hash to `.env` on disk in addition to updating the in-memory value; logs a warning if disk write fails.
- No CSRF token on the rotate form — the current-PIN requirement serves as the authentication gate (this endpoint is admin-only and not linked from the OAuth flow).
