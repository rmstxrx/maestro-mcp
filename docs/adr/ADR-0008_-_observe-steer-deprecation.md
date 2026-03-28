# ADR-0008: Remove observe and steer tools

**Status:** Accepted
**Date:** 2026-03-28
**Deciders:** (maintainer), Claude

## Context

SSE transport through the Cloudflare tunnel has an unrecoverable ~5% per-call failure rate from infrastructure/session churn (not server-fixable).

For one-shot tools such as `run`, `dispatch`, and `status`, a single failed call is tolerable: retries occur on the next turn.
For continuous polling patterns, failure compounds:

`P(at least one failure in 20 calls) = 1 - 0.95^20 = 64%`.

`observe` and `steer` were used for tight loops and amplify this failure mode. Exposing broken tools causes agents to fail in production.

## Decision

- Remove `observe` and `steer` from the MCP tool surface.
- Remove `mode="interactive"` from `dispatch`; only one-shot dispatch is supported.
- Keep service execution support (`service`) and monitoring through standard file-backed patterns.
- Use `run` against log files (for service monitoring) and `tasks()` / `read_output()` (for agent progress) instead of pane polling/steering.

The tool surface drops from 13 to 11.

## Implementation

1. Delete MCP tool wrappers for `observe()` and `steer()` from `maestro/tools/fleet.py`.
2. Remove `mode="interactive"` parameter and branches from `dispatch()`/`_build_agent_cli()` in `maestro/tools/orchestra.py`.
3. Remove tool surface references in operational docs (`CLAUDE.md`, `TOOLS.md`, `STATE.md`).
4. Keep `capture_pane` and `send_keys` in `maestro/mux.py`; no mux function removals.

## Consequences

- Service monitoring shifts from live pane reads to log-file reads via `run`.
- Agent workflows switch to:
  - `dispatch(...) -> tasks(status="running") -> read_output(output_file)`
- Interactive steering loops are no longer available in the MCP surface.

