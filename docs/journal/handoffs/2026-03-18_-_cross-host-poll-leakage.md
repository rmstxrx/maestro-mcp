# BUG-0001: Cross-Host Task Leakage in poll()

**Reported:** 2026-03-18T19:00Z
**Severity:** High — data integrity / correctness
**Component:** Task registry + poll endpoint

## Summary

`poll(task_id)` returned output from a **different task on a different host** than the one the task_id was issued for. This is a cross-host task leakage bug.

## Reproduction

### Exact sequence of events

1. **`exec(host="win-server-wsl", command="sleep 300 && tail -30 /tmp/nvfp4_awq_test.log")`**
   - Returned: `{"auto_promoted": true, "task_id": "75ac9e4cd0a60439", "agent": "exec", "host": "win-server-wsl", "status": "running", "elapsed_seconds": 5.0}`

2. **`poll(task_id="75ac9e4cd0a60439", wait=360)`**
   - **Expected:** Output from `tail -30 /tmp/nvfp4_awq_test.log` on win-server-wsl
   - **Actual:** Returned output from an **GPU-server** task (GPQA Diamond Benchmark):
     ```
     ============================================
      GPQA Diamond Benchmark — Full Pipeline
      2026-03-18T14:59:16-04:00
     ============================================

     [0/4] Cleaning up existing vLLM processes...
     ERROR: vLLM processes still alive after kill. Aborting.
     ```

### Context

- The GPQA benchmark was queued/running on **GPU-server** around the same time.
- The exec task was dispatched to **win-server-wsl**.
- The task_id `75ac9e4cd0a60439` was returned by the win-server-wsl exec call but poll returned GPU-server output.

## Possible causes

1. **Task ID collision** — If task IDs are generated without incorporating the host, two tasks on different hosts could collide in a shared registry.
2. **Shared task registry without host scoping** — If the task store is a flat dict keyed only by task_id, a newer task on GPU-server could overwrite an win-server-wsl entry with the same ID.
3. **Race condition in auto-promote** — The `auto_promoted: true` flag suggests the exec was promoted to an async task. If promotion writes to a global store without host-namespacing, cross-host pollution is possible.

## Impact

- **Silent data corruption**: The caller has no way to know the output is from the wrong host/task. It looks like a valid result.
- **Debugging nightmare**: In this instance the output was obviously wrong (GPQA output for an Win-server log tail), but if both tasks produced similar-looking text, this would be undetectable.

## Suggested fix

- Task IDs must be globally unique OR the task registry must be keyed by `(host, task_id)`.
- `poll()` should verify the returned result's host matches the originating task's host.
- Consider including `host` in the poll response so callers can cross-check.

## Fix applied — 2026-03-18

### Root cause analysis

**The task registry is clean.** Task `75ac9e4cd0a60439` has the correct
`host: "win-server-wsl"` and correct `result_json` (an SSH timeout error) stored
in the registry. The GPQA output lives in a completely separate task
(`6a422f33d8a2f468`) on gpu-server with a different task_id.

This means the contamination occurred at the **MCP Streamable HTTP transport
layer** — somewhere between Maestro returning the correct `poll()` response
and Claude.ai attributing it to the right tool call, the responses were
misrouted. Evidence: server logs show persistent `GET /mcp → 409 Conflict`
responses, indicating SSE session contention under concurrent requests.

Analogy: two case files are correctly stored in the right drawers at the
courthouse, but the clerk hands the wrong file to the wrong lawyer at the
counter. The archives are correct; the delivery was wrong.

### Changes

**maestro/tools/fleet.py:**
- Added `_inject_poll_verification()` helper — injects `_verify_host`,
  `_verify_task_id`, `_verify_agent` into every completed task result
  returned by `poll()`. Works on both JSON and raw-text results.
- `exec` tool: `_execute` closure now wraps output in
  `{"_host": host, "_agent": "exec", "output": raw}` — both inline
  and auto-promoted paths carry host identity.
- `script` tool: same treatment for both local and remote branches.
- `poll()`: both `return ts.result_json` paths now go through
  `_inject_poll_verification()`. Cooldown response also includes `host`.

**server.py:**
- `_task_lookup()` (HTTP `/tasks/{task_id}/result` endpoint): completed
  task responses now include `_verify_host`, `_verify_task_id`,
  `_verify_agent` fields.

### What this does NOT fix

The MCP transport mixup itself — that's a FastMCP SDK or Claude.ai client
bug. What this fix does is turn **silent data corruption** into
**immediately detectable mismatches**. Any caller can now cross-check
`_verify_host` against their expectation.

### Test results

54/54 tests pass. No behavioral regressions.
