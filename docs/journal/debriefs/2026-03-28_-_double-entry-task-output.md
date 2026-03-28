# Debrief — Double-Entry Task Output

## Task Summary
Implemented additive double-entry task output so command/script wrappers keep writing live output to tmux and Cellar output files while also writing/copying a host-local copy at `~/.maestro/task_output/<task_id>.txt`.

## Files Changed
- `maestro/config.py`: Added `host_output_retention_days` (env `MAESTRO_HOST_RETENTION_DAYS`, default `30`) and changed `output_retention_days` default from `90` to `180`.
- `maestro/mux.py`: Added host retention module state, `configure_mux` wiring, `_remote_preamble()`, nested remote tee behavior for single commands, bash temp-file execution + remote tee for scripts, and PowerShell post-run SCP fallback for script outputs.
- `server.py`: Updated `configure_mux()` call site to pass `host_output_retention_days=CONFIG.host_output_retention_days`.

## Decisions / Surprises
- Kept the existing outer tee pipeline and `tmux wait-for` signal untouched to preserve live-pane behavior used by observe/steer/stop.
- For PowerShell multi-line scripts, retained stdin execution and added best-effort post-completion SCP as specified.
- Verified wrapper generation with the exact command requested in the task prompt.
