# ADR-0009 Phase 5: Legacy cleanup

All inline-command construction paths are now dead code. Remove them.

## 1. maestro/mux.py — Delete legacy functions

Delete these three functions entirely (including docstrings):
- `_remote_preamble(shell: str) -> str` (the powershell/bash preamble builder)
- `_build_wrapper(task_id, ssh_alias, command, ...)` (the inline-command wrapper)
- `mux_spawn(host, command, name, timeout, ...)` (compatibility wrapper)

## 2. maestro/mux.py — Simplify create_task_window

Remove the `command`, `shell`, and `staged` parameters. The function now ONLY does staged execution. Remove the `else` branch that calls `_build_wrapper`. Remove the `if staged:` conditional — the body of the `if staged:` branch becomes the only path.

The simplified signature should be:
```python
async def create_task_window(
    task_id: str,
    ssh_alias: str,
    *,
    tee: bool = True,
    interactive: bool = False,
    cwd: str | None = None,
    sudo: bool = False,
    stream: bool = False,
) -> Path | None:
```

Remove the deprecation comments about "retained for dispatch compatibility" and "Deprecated command-based wrapper".

## 3. maestro/tools/orchestra.py — Clean _orchestra_run_cli

In `_orchestra_run_cli()`:
- Remove the `window_name` parameter
- Remove the `cleanup` parameter  
- Remove the entire `if window_name:` branch (which imports and calls mux_spawn)
- Remove the docstring sentence about window_name being accepted for compatibility

## 4. tests/test_mux.py — Delete the file

The entire file is already skip-marked and references functions that no longer exist (`_build_ephemeral_wrapper`, `_build_spawn_wrapper`, `mux_list_windows`). Delete it.

## After changes

Run `.venv/bin/pytest tests/ -x --tb=short` and report full output.
Do NOT commit or push.
