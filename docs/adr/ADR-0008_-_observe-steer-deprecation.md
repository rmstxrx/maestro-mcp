# ADR-0008: Deprecate observe/steer as Monitoring Patterns

**Status:** Accepted
**Date:** 2026-03-28
**Deciders:** (maintainer), Claude

## Context

The Maestro MCP server connects to Claude.ai through a Cloudflare tunnel (cloudflared). The transport layer (SSE over HTTP/2 or QUIC) exhibits an inherent ~5% per-call failure rate due to Cloudflare edge connection management and Claude.ai's MCP client SSE session handling. This is not fixable from the server side — it lives in infrastructure we do not control.

For one-shot tools like `run`, `dispatch`, and `status`, a 5% drop rate is tolerable: a failed call simply retries on the next turn. But for `observe` and `steer`, which are designed for tight monitoring loops (call every few seconds to watch agent progress), the failure rate compounds: P(at least one failure in 20 calls) = 1 - 0.95^20 = 64%. In practice, any autonomous monitoring workflow breaks within minutes.

Investigation on 2026-03-28 traced the drops through three layers:
1. **QUIC UDP buffer starvation** (fixed: sysctl 32 MiB buffers)
2. **MCP SDK SSE 409 Conflict on reconnect** (fixed: Dockerfile patch replaces stale stream)
3. **Cloudflare edge / Claude.ai SSE session cycling** (not fixable: ~5% residual rate persists across both QUIC and HTTP/2)

## Decision

**Retire `observe` and `steer` as monitoring patterns.** The tools remain available for occasional, ad-hoc inspection but must not be used in tight loops or autonomous workflows.

### Recommended patterns

**Service monitoring — before (broken):**
```
service(command, host) -> observe(id) -> observe(id) -> observe(id) ...
```

**Service monitoring — after (resilient):**
```
service(command, host, capture=True) -> run(host, "tail -50 /path/to/output")
```

One-shot `run` calls tolerate the 5% rate (retry on next turn). The service writes to a log file; monitoring reads the file via `run` at whatever cadence is needed.

**Agent progress — before (broken):**
```
dispatch(agent, host, prompt) -> observe(id) -> observe(id) ...
```

**Agent progress — after (resilient):**
```
dispatch(agent, host, prompt) -> tasks(status="running") -> read_output(file)
```

Check `tasks()` for completion, then `read_output()` for the full result. No polling loop needed.

### Tool status after this ADR

| Tool | Status | Use case |
|---|---|---|
| `observe` | Available, not recommended for loops | Ad-hoc single inspection of a running task |
| `steer` | Available, not recommended for automation | One-off interactive redirect |
| `run` + log files | Recommended | Service monitoring via tail/grep |
| `tasks` + `read_output` | Recommended | Agent progress tracking |
| `stop` | Unchanged | Kill any task |

### Interactive dispatch (Whiplash conductor pattern)

The interactive dispatch mode (`mode="interactive"`) that drives agents via `observe`/`steer` is architecturally sound but requires a more reliable transport to be practical. It remains available for experimentation but should not be relied upon for production workflows until the transport layer improves.

## Consequences

- Autonomous monitoring workflows become reliable at the cost of slightly higher latency (read log files vs. live pane)
- `service` tasks should use `capture=True` or write to known log paths
- Agent dispatch workflows shift from "watch the agent work" to "check when it's done"
- The Whiplash conductor pattern is deferred, not abandoned — it needs a transport upgrade (WebSocket, direct SSH, or improved Cloudflare SSE handling) to be viable
