# AGENT DEBRIEF — Phase 5 legacy cleanup

## Summary
Implemented Phase 5 of ADR-0009 by removing remaining legacy inline-command mux pathways and updating call sites to staged-only task execution.

## Files changed
- `maestro/mux.py`: removed `_remote_preamble`, `_build_wrapper`, and `mux_spawn`; simplified `create_task_window` to staged-only execution with the spec'd signature and removed deprecation compatibility branches/comments.
- `maestro/tools/orchestra.py`: simplified `_orchestra_run_cli` signature by removing `window_name` and `cleanup`, and removed the mux_spawn fallback branch.
- `maestro/tools/fleet.py`: updated `create_task_window` call sites in `exec` and `service` to use staged-only argument list.
- `maestro/tools/orchestra.py`: updated the `dispatch` execution path call to `create_task_window` for the staged-only interface.
- `tests/test_primitives.py`: updated ` _orchestra_run_cli` and `exec` tests to reflect the removed legacy arguments and behavior.
- `tests/test_mux.py`: deleted as requested by the spec.
