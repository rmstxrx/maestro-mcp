# Fix dispatch staging mkdir on PowerShell hosts

## Task summary
Adjusted dispatch/service staging directory creation to use shell-aware commands so PowerShell hosts can create `/tmp/maestro/inbox` and `/tmp/maestro/outbox` idempotently.

## Files changed
- `maestro/mux.py`: Added host-shell-aware staging directory creation and made `stage_script` accept a shell parameter so PowerShell uses `New-Item -Force -ErrorAction SilentlyContinue` for inbox creation; passed shell through `create_task_window`.
- `maestro/tools/orchestra.py`: Threaded `host_cfg.shell` into `stage_script(...)` and `create_task_window(...)` for dispatches.
- `maestro/tools/fleet.py`: Threaded `cfg.shell` into `create_task_window(...)` for `exec`, and `stage_script(...)`/`create_task_window(...)` for `service`.

## Decisions and notes
- `hosts.yaml` parsing already exposes a `shell` field via `HostConfig.shell`, so host OS/shell awareness is available; default remains Bash.
- Could not run full test assertions due test environment missing pytest async plugin (`pytest-asyncio`); `python -m pytest tests/ -x -q` fails at collection with `async def functions are not natively supported` on `tests/test_oauth.py::TestRegistrationRateLimit::test_allows_under_limit`.
