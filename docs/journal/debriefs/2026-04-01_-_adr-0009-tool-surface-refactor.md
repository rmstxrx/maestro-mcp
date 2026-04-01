# ADR-0009 Tool Surface Refactor

## Summary

Implemented ADR-0009 across four commits: removed zombie tools, renamed the live surface, merged `service` into `run_task`, routed all command execution through tmux + auto-promote, added staged transfer helpers plus `read_task_output`, and rewrote the operator docs for the 11-tool surface.

## Files Changed

- `maestro/tools/fleet.py`: Replaced the old task/file tool names, merged persistent service behavior into `run_task`, added graceful `stop_task`, and updated file tool docstrings.
- `maestro/tools/orchestra.py`: Renamed orchestration tools, added transfer/output tools, preserved killed-task state in auto-promote, and hid container paths from `current_tasks`.
- `maestro/relay.py`: Added staged pull/push preparation helpers with ephemeral relay tokens and TTL-based staged-file cleanup.
- `maestro/task_result.py`: Moved the `/tasks/{id}/result` handler out of `relay.py`.
- `maestro/mux.py`: Allowed `wait_for_completion()` to run without a ceiling for persistent tasks.
- `server.py`: Updated runtime instructions and imported the extracted `task_result` handler.
- `CLAUDE.md`: Rewrote the tool surface, quick reference, decision trees, and Cellar/Maestro identity guidance.
- `STATE.md`: Updated the development state and tool inventory to the ADR-0009 surface.
- `tests/test_primitives.py`: Renamed tool calls, removed stale assertions, and added coverage for the new task/output/transfer behaviors.

## Decisions And Surprises

- The repo test command had to run under `./.venv/bin/python -m pytest`; the ambient Python environment lacked the async pytest plugin the repo expects.
- A stale config test still referenced `orchestra_output_dir`, which had already been removed earlier in the branch history; the test was dropped instead of reintroducing dead config.
- `stop_task(graceful=True)` needed registry-aware handling so a later auto-promote monitor would not overwrite `killed` with `done` or `failed`.
- Staged relay downloads use TTL cleanup in `/tmp/maestro/staged/` to satisfy the ADR without changing the existing HTTP endpoint routes.
