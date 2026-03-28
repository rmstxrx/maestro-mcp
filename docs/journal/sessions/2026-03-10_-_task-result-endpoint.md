# Task Result HTTP Endpoint — Zero-Token-Cost Polling

**Date:** 2026-03-10
**Commit:** 8abfec8 `feat: add HTTP task result endpoint for zero-token-cost polling`

## Problem

MCP is request-response with no server-push. When a task is auto-promoted
to background (block_timeout exceeded), the agent's only option to retrieve
results is the MCP `poll(task_id)` tool. Each poll round-trip costs ~400 tokens
(tool call schema + response JSON + LLM reasoning). A 3-minute Codex task
triggers 6-18 poll calls at the remote cooldown rate (10s), burning 2,400-7,200
tokens for zero information gain.

The analogy: a busy-wait spinlock. The CPU (LLM) is spinning when it could be
sleeping on a condition variable.

## Insight

`bash_tool` in the Claude.ai container has a crucial property: while a command
blocks (e.g. `sleep` or a curl loop), **zero LLM tokens are consumed**. The
container process waits; the LLM only wakes when the command returns output.

This means if we expose task results via a plain HTTP endpoint (not MCP), the
agent can dispatch a task, then immediately start a bash_tool curl loop that
sleeps between requests. The entire wait costs exactly 2 tool calls: the
dispatch and the bash wait — regardless of whether the task takes 30 seconds
or 10 minutes.

## Solution

`GET /tasks/{task_id}/result` — a new HTTP endpoint alongside the existing
transfer relay.

### Response semantics

| HTTP Status | Meaning | Body |
|---|---|---|
| 200 | Task complete | Full result JSON (same as MCP poll would return) |
| 202 | Task running | `{"task_id", "agent", "host", "status": "running", "elapsed_seconds"}` |
| 401 | Unauthorized | Missing or invalid Bearer token |
| 404 | Not found | Task ID unknown or already evicted |

### Auth

Reuses the daily-HMAC token derivation from the transfer relay. No new auth
mechanism. Agents that already derive transfer tokens can use this endpoint
immediately.

### Architecture

The endpoint lives in `relay.py` (which already owns the non-MCP HTTP surface).
To avoid coupling relay → orchestra, the task lookup is injected as a late-bound
callable via `configure_relay(task_lookup=...)`. The callable is defined in
`server.py` where both `TASK_REGISTRY` and the relay are in scope.

```
relay.py (handler)  ←──calls──  _TASK_LOOKUP(task_id)
                                     │
server.py (wiring)  ──provides──→  _task_lookup()
                                     │
orchestra.py        ←──reads────  TASK_REGISTRY
```

Same dependency inversion pattern used for `_RESOLVE_HOST` and `_SCP_RUN`.

## Agent workflow

```bash
# 1. Dispatch via MCP → get task_id
# 2. Immediately use bash_tool:

TOKEN=$(python3 -c "import hmac,hashlib,time; print(hmac.new(b'SECRET', str(int(time.time())//86400).encode(), hashlib.sha256).hexdigest())")
TASK_ID="<task_id>"

for i in $(seq 1 40); do
  HTTP_CODE=$(curl -s -o /tmp/task_result.json -w '%{http_code}' \
    -H "Authorization: Bearer $TOKEN" \
    "https://maestro.yourdomain.dev/tasks/$TASK_ID/result")
  if [ "$HTTP_CODE" = "200" ]; then
    cat /tmp/task_result.json
    exit 0
  fi
  sleep 15
done
echo "TIMEOUT"
```

Total token cost: 2 tool calls (dispatch + bash_tool), regardless of task duration.

## Test results

- Dispatched `sleep 30 && echo done` → auto-promoted at 5s
- bash_tool curl loop: 202 at 15.7s, 21.6s, 27.6s → 200 at ~32s
- Auth: 401 without token, 404 for unknown task_id ✓
- No MCP changes, all 54 existing tests pass

## What this does NOT change

- The MCP `poll` tool remains for Claude Code (local) and quick status checks
- Auto-promote semantics unchanged
- No new dependencies or auth mechanisms
- Task eviction unchanged (stale tasks still cleaned after `task_eviction_seconds`)

## Impact

| Metric | Before (MCP poll) | After (HTTP endpoint) |
|---|---|---|
| Token cost per 3-min wait | ~2,400-7,200 | ~800 (2 tool calls) |
| LLM idle during wait | Never (always reasoning) | Entire duration |
| Round-trips per task | 6-18 | 2 |
| Quota pressure | Significant | Minimal |
