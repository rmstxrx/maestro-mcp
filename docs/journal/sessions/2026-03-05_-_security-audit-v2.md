# Maestro MCP — Security & Feature Audit (Rev. 2)

**Date:** 2026-03-05  
**Auditor:** Claude (Opus 4.6)  
**Prior audit:** 2026-03-03  
**Codebase:** `/home/rmstxrx/Development/maestro-mcp/` on Apollyon  
**HEAD commit:** `d2ea418` — *feat(orchestra): update agent routing, model defaults, and reasoning effort*  
**Deployment:** `maestro.rmstxrx.dev` → Cloudflare Tunnel → `localhost:8222`  
**fleet.rmstxrx.dev:** DNS no longer resolves (subdomain removed or tunnel reconfigured)

---

## Executive Summary

Two commits landed since the prior audit: an OAuth URL rewrite middleware for LAN/localhost MCP clients (`oauth_rewrite.py`), background command dispatch tools (`maestro_bg`, `maestro_bg_log`), Codex `reasoning_effort` parameter, and updated Gemini model descriptions (ADR-0001).

**Both critical findings from the prior audit (C-1, C-2) remain unresolved and were re-verified.** The new OAuth rewrite middleware introduces a **new high-severity finding (H-NEW-1)** — Host header injection that allows any LAN client to poison OAuth metadata URLs. A config drift between the systemd unit file and the running process introduces another **new medium finding (M-NEW-1)**.

### Severity Summary

| Severity | Count | Prior | New | Resolved |
|----------|-------|-------|-----|----------|
| **CRITICAL** | 2 | 2 | 0 | 0 |
| **HIGH** | 4 | 3 | 1 | 0 |
| **MEDIUM** | 5 | 4 | 1 | 0 |
| **LOW** | 3 | 3 | 0 | 0 |
| **INFO** | 3 | 2 | 1 | 0 |

---

## Critical Findings (Unchanged)

### C-1: Claude.ai Auto-Approve Bypass via Redirect URI Spoofing

**Status:** STILL OPEN — re-verified 2026-03-05  
**File:** `maestro_oauth.py`, line ~117 (`authorize` method)

Anyone can register a client with `redirect_uri = https://claude.ai/api/mcp/auth_callback` via the open `/register` endpoint. That client then gets auto-approved without a PIN because the `authorize()` method checks `redirect_str == CLAUDE_AI_CALLBACK` — trusting where the code *goes* rather than *who is asking*.

**Re-verification:** Successfully registered `client_id=374ad823...` with Claude.ai's callback. The auto-approve logic would fire for this client.

**Fix:** Switch auto-approve trust anchor from `redirect_uri` matching to a hardcoded trusted `client_id`. Pre-register a static Claude.ai confidential client.

### C-2: No Path Sanitization on Transfer Relay

**Status:** STILL OPEN — re-verified 2026-03-05  
**File:** `server.py`, lines ~686-797 (`_transfer_push`, `_transfer_pull`)

The `remote_path` query parameter flows unchecked to filesystem operations (local hosts) and SCP (remote hosts). During re-verification:

- `remote_path=/etc/hostname` → returned `apollyon` (arbitrary file read)
- `remote_path=/home/rmstxrx/../../etc/passwd` → returned all 54 lines (path traversal)

The transfer token is a static bearer, embedded in user preferences, shared with every Claude conversation.

**Fix:** Restrict to a whitelist of allowed base directories, reject `..` components, canonicalize paths.

---

## High Findings

### H-1: All OAuth State In-Memory (Unchanged)

**Status:** STILL OPEN  

All registered clients, access tokens, refresh tokens, and pending approvals live in Python dicts. Service restart wipes everything. The service was last restarted 2026-03-05 16:29 (0 restarts since), meaning all prior sessions were invalidated.

### H-2: Static Transfer Token with No Rotation (Unchanged)

**Status:** STILL OPEN  

`MAESTRO_TRANSFER_TOKEN` is a static env var with no rotation or expiry. Embedded in every Claude conversation's user preferences.

### H-3: No Rate Limiting on `/token` Endpoint (Unchanged)

**Status:** STILL OPEN — re-verified  

Sent 15 rapid-fire requests to `/token`; all returned HTTP 401, none returned 429. No rate limiting in place.

### H-NEW-1: OAuth Metadata Host Header Injection (NEW)

**Severity:** HIGH  
**File:** `oauth_rewrite.py`  
**Introduced in:** commit `74d5e99`

The new `OAuthURLRewriteMiddleware` rewrites OAuth metadata URLs to match the incoming request's `Host` header for LAN/localhost clients. The middleware checks if the Host contains `maestro.rmstxrx.dev` — if not, it treats the Host value as the "effective base URL" and rewrites all OAuth endpoints in the metadata response.

**Verified from Apollyon:**
```
GET /.well-known/oauth-authorization-server  (Host: evil.attacker.com:8222)
→ issuer: http://evil.attacker.com:8222/
→ authorization_endpoint: http://evil.attacker.com:8222/authorize
→ token_endpoint: http://evil.attacker.com:8222/token
→ registration_endpoint: http://evil.attacker.com:8222/register
```

**Attack scenario:** A rogue device on the LAN (or an attacker who can reach port 8222) sends a request with `Host: evil.attacker.com:8222`. An MCP client that trusts this metadata would send its authorization code, tokens, and credentials to the attacker's server.

**Aggravating factors:**
- The running Maestro process binds `0.0.0.0:8222` (see M-NEW-1), making it reachable from the entire LAN
- No firewall is active (`ufw status: inactive`, `iptables policy: ACCEPT`)
- The `.well-known` metadata endpoint requires no authentication

**Fix:** The rewrite middleware should use an **allowlist** of known valid base URLs rather than blindly trusting the Host header:

```python
ALLOWED_ORIGINS = {
    "maestro.rmstxrx.dev": "https://maestro.rmstxrx.dev",
    "10.42.69.167:8222": "http://10.42.69.167:8222",
    "localhost:8222": "http://localhost:8222",
    "127.0.0.1:8222": "http://127.0.0.1:8222",
}

# In __call__:
effective = ALLOWED_ORIGINS.get(host)
if effective is None:
    # Unknown host — pass through without rewrite (uses canonical URL)
    await self.inner(scope, receive, send)
    return
```

---

## Medium Findings

### M-1: Open Dynamic Registration (Unchanged)

**Status:** STILL OPEN  

`/register` accepts any client. The audit log shows steady accumulation of test clients: `AuditRetest` from this audit was registered as `client_id=374ad823...`. No cleanup, no TTL, memory grows unbounded.

### M-2: Transfer Operations Not Audit-Logged (Unchanged)

**Status:** STILL OPEN  

Confirmed: `grep "_audit" server.py` shows zero audit calls in the transfer relay code. Transfer push/pull only use the standard `logger.info()`, which goes to stderr/journal — not the structured `~/.maestro/audit.log`.

### M-3: No Client Expiration or Cleanup (Unchanged)

**Status:** STILL OPEN  

Audit log shows accumulation of "Claude" clients across sessions — each new Claude.ai conversation registers a fresh client. No TTL, no listing endpoint, no revocation UI.

### M-4: CORS Not Explicitly Configured (Unchanged)

**Status:** STILL OPEN

### M-NEW-1: Config Drift — Bind Address Mismatch (NEW)

**Severity:** MEDIUM  
**Component:** `maestro.service` vs running process

The systemd unit file specifies `--host 127.0.0.1` (localhost-only), but the running process was started with `--host 0.0.0.0` (all interfaces):

| Source | Bind address |
|--------|-------------|
| `maestro.service` ExecStart | `--host 127.0.0.1` |
| Running process (`/proc/821435/cmdline`) | `--host 0.0.0.0` |
| `ss -tlnp` | `0.0.0.0:8222` |

This means the server was started manually (not via `systemctl start maestro`), bypassing the service file's intended security posture. The `0.0.0.0` binding exposes port 8222 to the entire LAN with no firewall protection, directly enabling H-NEW-1.

**Fix:** Either restart via `systemctl restart maestro` to enforce `127.0.0.1`, or update the service file to `0.0.0.0` if LAN access is intentional (and implement H-NEW-1's allowlist fix).

---

## Low Findings (All Unchanged)

### L-1: Consent Page Phishing via Attacker-Controlled Client Name
### L-2: No TLS Certificate Pinning for SSH Hosts  
### L-3: Uvicorn `forwarded_allow_ips="*"` Trusts All Proxies

All unchanged from prior audit — see `docs/audit-2026-03-03.md` for details.

---

## Informational

### I-1: Feature Inventory (Updated)

New tools since prior audit:

| Tool | Type | Purpose |
|------|------|---------|
| `maestro_bg` | MCP tool | Fire-and-forget background command dispatch; returns task_id |
| `maestro_bg_log` | MCP tool | Tail output from a running/finished background command |
| Codex `reasoning_effort` | Parameter | Configurable thinking effort (`low`/`medium`/`high`/`xhigh`) on `codex_execute` and `codex_dispatch` |

Total MCP tools: **21** (was 17+2, now 19+2 custom HTTP routes)

### I-2: New ADR System

`docs/adr/0001-agent-routing.md` establishes agent routing heuristics and model defaults. Good architectural hygiene.

### I-NEW-1: `fleet.rmstxrx.dev` DNS Removed

`fleet.rmstxrx.dev` no longer resolves (DNS NXDOMAIN). The Cloudflare tunnel config still lists it as an ingress rule pointing to `localhost:8222`, but it appears the DNS record was removed. This is effectively a dead route — no security impact, but should be cleaned up in the tunnel config.

---

## What Got Better Since Last Audit

1. **Agent orchestra expanded** — `maestro_bg` / `maestro_bg_log` provide proper async background execution, reducing tool-call timeouts for long operations
2. **LAN access path** — `oauth_rewrite.py` correctly identifies the *problem* (RFC 9728 resource matching requires URL alignment), though the implementation needs hardening (H-NEW-1)
3. **ADR documentation** — Formalized agent routing decisions
4. **Model currency** — Updated from deprecated GPT-5.1 family to GPT-5.3-Codex, Gemini 3.1 Pro
5. **`shlex.quote` on all user inputs** — Codex `reasoning_effort`, `model`, `prompt`, `working_dir` all properly shell-escaped; no injection vectors in the new parameters

---

## Recommended Priority Order

| Priority | Finding | Effort | Notes |
|----------|---------|--------|-------|
| 1 | **C-1** Auto-approve bypass | ~1h | Switch to `client_id`-based trust |
| 2 | **C-2** Transfer path traversal | ~1h | Allowlist base dirs, reject `..` |
| 3 | **H-NEW-1** Host header injection | ~30m | Allowlist valid Host values in rewrite middleware |
| 4 | **M-NEW-1** Config drift | ~5m | `systemctl restart maestro` or update service file |
| 5 | **H-2** Transfer audit logging | ~30m | Add `_audit()` calls to push/pull |
| 6 | **H-1** Persist OAuth state | ~2-3h | SQLite or shelve for tokens/clients |
| 7 | **H-3** Rate-limit `/token` | ~30m | 20 req/min per client_id |
| 8 | **M-1** Restrict registration | ~30m | Require registration secret |
| 9 | **M-3** Client TTL/cleanup | ~1h | Expiry + admin listing |

Items 1–4 form a natural first batch — the two criticals, the new high, and the quick config fix. Should be achievable in a single Claude Code session (~2.5h).
