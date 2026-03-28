# Debrief — remove observe/steer from tool surface

## Task summary
ADR-0008 was implemented as a full removal of `observe`/`steer`, with `dispatch` forced to one-shot mode and monitoring guidance shifted to log-file based workflows.

## Files changed
- `maestro/tools/fleet.py`: removed MCP wrappers for `observe()` and `steer()`, and updated `run`/`service` docs and hints to reference log-based monitoring.
- `maestro/tools/orchestra.py`: removed `mode="interactive"` support from `dispatch` and `_build_agent_cli`, removing interactive steering/observation pathways.
- `docs/adr/ADR-0008_-_observe-steer-deprecation.md`: rewrote ADR title/context/decision as removal-only with transport-reliability rationale and 13→11 tool count.
- `CLAUDE.md`: updated architecture/tool-surface/tool-patterns/lifecycle notes to reflect removed wrappers and one-shot dispatch.
- `TOOLS.md`: removed Observe/Steer monitoring guidance section.
- `STATE.md`: updated `Last Updated` and tool inventory/count note to reflect ADR-0008 (`13 -> 11`) and removed tools.

## Decisions and surprises
- `dispatch(mode="interactive")` is implemented in `maestro/tools/orchestra.py`, not `fleet.py`, so the actual code-path cleanup had to target that file in addition to the user-requested file list.
- `server.py` did not reference `observe`/`steer` directly after inspection, so no `server.py` edits were required.
