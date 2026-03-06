# Maestro MCP — Security & Feature Audit

**Date:** 2026-03-03  
**Auditor:** Claude (Opus 4.6)  
**Codebase:** `/home/rmstxrx/Development/maestro-mcp/` on Apollyon  
**Last commit:** `2c1fd52` — *fix: remove per-result local host hint to save context tokens*  
**Deployment:** `maestro.rmstxrx.dev` + `fleet.rmstxrx.dev` → Cloudflare Tunnel → `localhost:8222`

---

## Executive Summary

Since the original six-issue security roadmap (Feb 2026), significant hardening has been done: OAuth was rebuilt on FastMCP's built-in auth with RS256 JWT + JWKS, tokens now expire (8h access / 30d refresh), a PIN gate protects non-Claude.ai clients, audit logging is active, and PKCE with S256 is enforced. However, several **critical and moderate issues remain** — most notably an authentication bypass via redirect_uri spoofing, no path sanitization on the transfer relay, and all state living in-process memory with no persistence.

### Severity Summary

| Severity | Count | Status |
|----------|-------|--------|
| **CRITICAL** | 2 | Open |
| **HIGH** | 3 | Open |
| **MEDIUM** | 4 | Open |
| **LOW** | 3 | Open |
| **INFO** | 2 | Noted |

---

## Original Roadmap Status (Feb 2026)

| # | Issue | Status | Notes |
|---|-------|--------|-------|
| 1 | Re-scope WAF rule | **DONE** | Narrowed to Bot Fight Mode + Browser Integrity Check only |
| 2 | Token expiration | **DONE** | 8h access, 30d refresh, proper rotation on refresh |
| 3 | Rate limiting on auth endpoints | **PARTIAL** | Registration: 10/min. PIN attempts: 5/5min. No rate limit on `/token` or `/authorize` |
| 4 | Audit logging | **DONE** | JSON-lines to `~/.maestro/audit.log`, covers register, authorize, token, PIN fail |
| 5 | Granular client management | **PARTIAL** | Per-client tokens exist, but no client revocation UI and no token-per-client listing |
| 6 | Open dynamic registration | **OPEN** | Still fully open to the internet |

---

## Critical Findings

### C-1: Claude.ai Auto-Approve Bypass via Redirect URI Spoofing

**Severity:** CRITICAL  
**Verified:** Yes (reproduced during audit)

Anyone on the internet can register an OAuth client with `redirect_uri = https://claude.ai/api/mcp/auth_callback`. When an authorization flow is initiated for that client, the server sees the Claude.ai callback URL and **auto-approves without PIN**, issuing an auth code.

The auth code is sent to Claude.ai's real callback (which the attacker doesn't control), so this doesn't directly yield a token *today*. But it's a **trust boundary violation** — the auto-approve decision assumes the caller *is* Claude.ai, when in reality the check only looks at the redirect_uri string, which the caller controls.

**Risk scenarios:**
- If Claude.ai ever introduces an open-redirect vulnerability, the auth code could be intercepted
- A man-in-the-middle on the TLS connection to Claude.ai could intercept the code
- The logic conflates "where the code goes" with "who is asking"

**Recommendation:** Auto-approve should be based on a **pre-registered, hardcoded client_id** for Claude.ai, not the redirect_uri. Register a static confidential client for Claude.ai with a known `client_id` and `client_secret`, and only auto-approve that specific client.

```python
# Instead of:
if redirect_str == CLAUDE_AI_CALLBACK:
    # auto-approve

# Do:
TRUSTED_CLIENT_IDS = {"claude-ai-prod": "known-secret-hash"}
if client.client_id in TRUSTED_CLIENT_IDS:
    # auto-approve
```

### C-2: No Path Sanitization on Transfer Relay

**Severity:** CRITICAL  
**Component:** `/transfer/push` and `/transfer/pull`

The `remote_path` parameter from query strings is passed directly to filesystem operations (local) and SCP commands (remote) with **zero validation**. An authenticated caller can:

- Read any file: `GET /transfer/pull?host=apollyon&remote_path=/etc/shadow`
- Write anywhere: `POST /transfer/push?host=apollyon&remote_path=/etc/cron.d/backdoor`
- Traverse paths: `remote_path=../../.ssh/authorized_keys`

The transfer token is a static bearer token shared in the user preferences of every Claude.ai conversation, making it semi-public.

**Recommendation:**
1. Restrict transfer paths to a configured whitelist of base directories (e.g., `~/workspace`, `/tmp/maestro-transfers`)
2. Validate and canonicalize paths, rejecting `..` traversal
3. Consider per-session transfer tokens instead of a static one

---

## High Findings

### H-1: All State In-Memory — Service Restart Loses Everything

**Severity:** HIGH

All OAuth state (registered clients, access tokens, refresh tokens, pending approvals) is stored in Python dictionaries. A service restart, crash, or `systemctl restart maestro` invalidates every active session. The service has been up since 07:51 today with 0 restarts, but this is fragile.

**Impact:** Every Claude.ai session must re-authenticate after any server hiccup. In production, this creates availability issues.

**Recommendation:** Persist token state to SQLite (or a simple JSON file with fsync). Even a basic `shelve` database would survive restarts.

### H-2: Static Transfer Token with No Rotation

**Severity:** HIGH  
**Component:** `MAESTRO_TRANSFER_TOKEN` env var

The transfer relay uses a single static bearer token set via environment variable. This token is embedded in Claude.ai user preferences, meaning it's sent to every Claude conversation. If any conversation is compromised or logged, the token is exposed permanently.

**Recommendation:**
1. Implement time-limited transfer tokens derived from the OAuth access token
2. Or use HMAC-signed, short-lived URLs (pre-signed URL pattern, like S3)
3. At minimum, add a rotation mechanism and log transfer operations to the audit log

### H-3: No Rate Limiting on Token Endpoint

**Severity:** HIGH  
**Component:** `/token`

The `/token` endpoint has no rate limiting. While auth codes are 32-byte random strings (infeasible to brute-force), the absence of rate limiting means a compromised refresh token could be used for rapid token rotation attacks, and there's no protection against token endpoint abuse.

**Recommendation:** Add rate limiting of 20 requests/minute per client_id on `/token`.

---

## Medium Findings

### M-1: Dynamic Registration Still Open

**Severity:** MEDIUM

Anyone who discovers the server URL can call `/register` and create OAuth clients. Rate-limited to 10/min, but an attacker can:
- Create 10 clients/minute (14,400/day)
- Each client accumulates in memory (memory leak / DoS vector)
- Attacker-controlled `client_name` is displayed on consent pages (phishing)

**Recommendation:** Either disable dynamic registration entirely (use pre-registered clients only) or require a registration secret/token.

### M-2: Transfer Operations Not Audit-Logged

**Severity:** MEDIUM

The OAuth flow and token lifecycle are well-audited, but `/transfer/push` and `/transfer/pull` operations are only logged via the standard logger, not the structured audit log. An attacker with the transfer token could exfiltrate files without a clear audit trail.

**Recommendation:** Add `_audit("transfer_push", host=host, path=remote_path, bytes=len(content))` and equivalent for pull.

### M-3: No Client Expiration or Cleanup

**Severity:** MEDIUM

Registered clients persist in-memory indefinitely (until service restart). There's no TTL on client registrations and no way to list or revoke clients. The audit log shows multiple "Claude" clients registering over time, accumulating without bound.

**Recommendation:** Add client TTL (e.g., 7 days), a `/admin/clients` listing endpoint behind PIN auth, and client revocation capability.

### M-4: CORS Not Explicitly Configured

**Severity:** MEDIUM

No CORS headers are set on any endpoint. While Cloudflare Tunnel provides some protection, if the server is ever accessed directly (e.g., from local network), browser-based attacks could interact with the endpoints.

**Recommendation:** Set explicit CORS policy allowing only `https://claude.ai` and `https://maestro.rmstxrx.dev`.

---

## Low Findings

### L-1: Consent Page Displays Attacker-Controlled Client Name

**Severity:** LOW (mitigated by PIN gate)

The `/approve` consent page renders `client_name` from registration. While HTML-escaped properly (no XSS), an attacker could register with `client_name = "Claude — Official Anthropic Client"` to phish PIN entry.

Input validation limits `client_name` to 256 chars, but doesn't restrict character set or content.

### L-2: No TLS Certificate Pinning for SSH Hosts

**Severity:** LOW

SSH ControlMaster connections rely on `~/.ssh/known_hosts` for host verification. If an attacker compromises DNS resolution on the local network, SSH MITM is possible. Standard SSH security, but worth noting for a security-critical control plane.

### L-3: Uvicorn Proxy Headers Trust

**Severity:** LOW  
**Line:** `forwarded_allow_ips="*"`

The uvicorn config trusts `X-Forwarded-For` from any source. Behind Cloudflare Tunnel this is fine (Cloudflare sets these headers), but if the server is ever exposed directly, IP-based logging and rate limiting could be spoofed.

---

## Informational

### I-1: Feature Inventory

The server exposes 17 MCP tools and 3 custom HTTP routes:

**MCP Tools (require OAuth):**
- Fleet management: `maestro_exec`, `maestro_script`, `maestro_read`, `maestro_write`, `maestro_upload`, `maestro_download`, `maestro_status`
- Agent orchestra: `codex_execute`, `gemini_execute`, `gemini_analyze`, `gemini_research`, `claude_execute`
- Async dispatch: `codex_dispatch`, `gemini_dispatch`, `claude_dispatch`, `agent_poll`, `agent_read_output`, `agent_status`
- Background: `maestro_bg`, `maestro_bg_log`

**Custom HTTP routes:**
- `/approve` — OAuth consent page with PIN gate
- `/transfer/push` — File upload to hosts (separate bearer token)
- `/transfer/pull` — File download from hosts (separate bearer token)

**Hosts:** apollyon (local), eden (PowerShell), judas (MacBook), eden-wsl (WSL2 Ubuntu)

### I-2: Dependency Versions

Current `requirements.txt` pins minimum versions but not maximums. Consider pinning exact versions for reproducibility:
- `mcp[cli]>=1.9.0` — should pin to tested version
- `pydantic>=2.0` — wide range
- `uvicorn>=0.30.0`, `starlette>=0.40.0` — should align with mcp SDK's expectations

---

## Recommended Priority Order

1. **C-1** — Fix auto-approve bypass (switch to client_id-based trust) — *1 hour*
2. **C-2** — Add path sanitization to transfer relay — *1 hour*  
3. **H-2** — Audit-log transfer operations + consider token rotation — *30 min*
4. **H-1** — Add SQLite persistence for OAuth state — *2-3 hours*
5. **H-3** — Rate-limit `/token` endpoint — *30 min*
6. **M-1** — Restrict or disable open registration — *30 min*
7. **M-3** — Client TTL and cleanup — *1 hour*
8. **M-4** — CORS policy — *15 min*

Items 1, 2, and 3 can be addressed as a single Claude Code session. Items 4-8 as a second session.
