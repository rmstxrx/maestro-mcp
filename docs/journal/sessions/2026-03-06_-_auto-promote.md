# Auto-Promote Pattern + Long-Poll

**Date:** 2026-03-06
**Commit:** 3864a00 `feat: auto-promote pattern + long-poll on agent_poll`

## Problem

Blocking tool calls (`maestro_exec`, `codex_execute`, etc.) with long timeouts
(up to 300s) would freeze the entire conversation. The caller had to predict
whether a task would be fast or slow and choose between `_execute` (blocking)
and `_dispatch` (async) accordingly — two separate APIs for the same operation.

## Solution: Auto-Promote

Every execution tool now has a `block_timeout` parameter (default 20s). The
server tries to return the result inline. If `block_timeout` elapses, the task
is **promoted** to a background task and the tool returns a `task_id` instead
of blocking further. The subprocess keeps running (up to 600s).

### Core mechanism

`asyncio.shield()` wraps the inner task so that when `asyncio.wait_for()`
raises `TimeoutError` after `block_timeout`, the inner task is NOT cancelled.
We stop waiting; the subprocess continues in the background.

### block_timeout semantics

- `> 0` (default 20): try inline, promote if slow
- `= 0`: dispatch immediately (never block) — replaces `_dispatch` tools
- `< 0`: block forever (legacy behaviour)

### Long-poll on agent_poll

`agent_poll(task_id, wait=N)` holds the connection for up to N seconds using
`asyncio.Event`. The event fires the instant the task completes, waking the
poll immediately. Reduces polling from 5-10 round-trips to 1-2.

Note: MCP is request-response with no server-push, so long-poll is the best we
can do. The real win is in the promotion itself — worst-case conversation freeze
is now 20s instead of 300s.

## Changes

- `BLOCK_TIMEOUT_DEFAULT = 20` added to global constants
- Agent timeouts raised: `CODEX_TIMEOUT`, `GEMINI_TIMEOUT`, `CLAUDE_TIMEOUT` → 600s
- `TaskState._done_event: asyncio.Event` added for long-poll signalling
- New `_auto_promote()` function (~60 lines) — the core pattern
- All execution tools wrapped in `_auto_promote`
- `_dispatch` variants simplified to `_execute(block_timeout=0)` thin wrappers
- `_dispatch_async()` removed (replaced by `_auto_promote`)
- `_build_instructions()` updated to reflect new unified pattern

## Gotcha

`BLOCK_TIMEOUT_DEFAULT` must be defined **before** any function that uses it as
a default parameter value. Python evaluates defaults at definition time, not
call time. Initial deployment crashed because the constant was defined in the
orchestra section (line ~1320) but referenced as a default param in
`maestro_exec` (line ~900).

## Test Results

- Fast command (`echo + date`): returned inline instantly ✓
- Slow command (`sleep 25`): auto-promoted at 20.0s, returned task_id ✓
- Long-poll (`agent_poll(wait=10)`): caught result at ~5s into wait ✓
