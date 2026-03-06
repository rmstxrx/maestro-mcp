# Session Log — 2026-02-27: File Transfer Relay

## Problem

Sandboxed/containerized agents (e.g. Claude.ai computer-use) need to transfer
files to/from fleet hosts. The existing `maestro_write` tool works but routes
file content through the LLM context window as MCP tool parameters — every byte
costs output tokens and consumes the finite context budget.

```
BEFORE (context-heavy):
  Container → [file content as output tokens] → MCP tool call → Maestro → Host

AFTER (zero context cost):
  Container → curl POST/GET → Cloudflare Tunnel → Maestro HTTP → Host
```

## Solution: HTTP Transfer Relay

Added two `@mcp.custom_route` endpoints to the Maestro server:

- **`POST /transfer/push?host=<host>&remote_path=<path>`** — Multipart file upload
  to any fleet host. Local hosts get direct filesystem writes; remote hosts go
  through SCP.

- **`GET /transfer/pull?host=<host>&remote_path=<path>`** — Streams file content
  from any fleet host back to the caller. Local hosts serve directly via
  `FileResponse`; remote hosts SCP to a temp file first.

### Auth

Bearer token via `MAESTRO_TRANSFER_TOKEN` env var, validated with
`hmac.compare_digest` (constant-time comparison). Deliberately separated from
the OAuth consent PIN to maintain credential isolation between attack surfaces.

### Key design decisions

1. **Reuses existing infrastructure** — `_resolve_host`, `_scp_run`, local file
   I/O helpers. No new dependencies.

2. **Starlette `BackgroundTask`** for temp file cleanup on remote pulls —
   ensures temp files are deleted after the response streams.

3. **100MB size cap** (configurable via `MAESTRO_MAX_TRANSFER_MB` env var).

4. **Token renamed** from `MAESTRO_TOKEN` → `MAESTRO_TRANSFER_TOKEN` for
   clarity of intent. The original value was a pre-generated `secrets.token_urlsafe(48)`,
   unrelated to the PIN hash, but naming should document purpose.

## Files changed

- `server.py` — Added imports (`tempfile`, `JSONResponse`, `FileResponse`,
  `BackgroundTask`), transfer config constants, auth helper, and two custom
  route handlers (~120 lines inserted after `/approve` route).
- `.env` — Renamed `MAESTRO_TOKEN` → `MAESTRO_TRANSFER_TOKEN`.
- `.env.example` — Added `MAESTRO_TRANSFER_TOKEN` with generation instructions.

## Verification

All tests passed from the sandboxed container via `curl`:

| Test                        | Expected | Got  |
|-----------------------------|----------|------|
| No auth token               | 401      | 401  |
| Bad auth token              | 401      | 401  |
| Missing params              | 400      | 400  |
| Push text (local/apollyon)  | 200 + ok | ✓    |
| Pull text (local/apollyon)  | match    | ✓    |
| Pull nonexistent            | 404      | 404  |
| Invalid host                | 400      | 400  |
| Binary 64KB roundtrip (SHA) | match    | ✓    |
| Push via SCP (judas)        | 200 + ok | ✓    |
| Pull via SCP (judas)        | match    | ✓    |

## Usage

```bash
# Push (container → host, zero context cost):
curl -s -H "Authorization: Bearer $MAESTRO_TRANSFER_TOKEN" \
  -F "file=@/home/claude/output.py" \
  "https://maestro.rmstxrx.dev/transfer/push?host=apollyon&remote_path=/home/rmstxrx/workspace/output.py"

# Pull (host → container, zero context cost):
curl -s -H "Authorization: Bearer $MAESTRO_TRANSFER_TOKEN" \
  -o /home/claude/data.json \
  "https://maestro.rmstxrx.dev/transfer/pull?host=apollyon&remote_path=/home/rmstxrx/workspace/data.json"
```
