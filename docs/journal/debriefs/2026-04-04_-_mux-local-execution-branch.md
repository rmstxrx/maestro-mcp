Task summary: Added an `is_local` execution branch in `maestro/mux.py` and threaded it through the fleet and orchestra callers so hub-local hosts no longer try `ssh localhost` when staging or launching tmux tasks.

Files changed:
- `maestro/mux.py`: added `is_local` to the staged-script and task-window helpers, with direct local staging to `/tmp/maestro/inbox/` and a `bash -c` wrapper path instead of SSH.
- `maestro/tools/fleet.py`: passed `cfg.is_local` through `run_task` when staging the script and creating the tmux window.
- `maestro/tools/orchestra.py`: passed `host_cfg.is_local` through `dispatch_agent` when staging the agent launcher script and creating the tmux window.

Decisions or surprises: Kept the change minimal and limited to the bash/local path described in the task; no extra mux refactors or test changes were needed, and the existing suite passed unchanged.
