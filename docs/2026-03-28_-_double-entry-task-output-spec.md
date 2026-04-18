# Double-Entry Task Output — Implementation Spec

## Context

Maestro's task output currently lives only on Cellar (hub) at `/root/.maestro/task_output/`.
Agents dispatched to leaf nodes cannot read their own task results without crossing back to Cellar.
This change adds a **second copy** on the target host at `~/.maestro/task_output/`, creating
"double-entry" output — one copy for the hub (archival), one for the leaf (agent convenience).

## Files to modify

1. `/volume2/docker/maestro/repo/maestro/config.py`
2. `/volume2/docker/maestro/repo/maestro/mux.py`

Read both files fully before making changes.

## CRITICAL INVARIANT — DO NOT BREAK

The tmux pane MUST still show live output. These features depend on it and MUST continue working:
- `observe(task_id)` — reads live pane content via `tmux capture-pane`
- `steer(task_id)` — sends keystrokes to the pane via `tmux send-keys`
- `stop(task_id)` — kills the tmux window

The outer `tee` writes to both stdout (the pane) and the Cellar file. This must remain.
All changes are ADDITIVE — we are adding a remote output copy, not replacing the local one.

## Changes to `config.py`

1. Add field `host_output_retention_days: int` to `MaestroConfig`
2. In `from_env()`, set default: `host_output_retention_days=int(os.environ.get("MAESTRO_HOST_RETENTION_DAYS", "30"))`
3. Change `output_retention_days` default from `90` to `180`

## Changes to `mux.py`

### New module-level state

Add `HOST_OUTPUT_RETENTION_DAYS: int = 30` alongside existing `OUTPUT_DIR`.
Update `configure_mux()` to accept and set `host_output_retention_days: int | None = None`.

### Helper: `_remote_preamble(task_id: str, shell: str) -> str`

Generates the remote-side preamble that:
1. Creates `~/.maestro/task_output/` if missing
2. Prunes output files older than `HOST_OUTPUT_RETENTION_DAYS` days (cleanup-on-use)

For bash:
```bash
mkdir -p ~/.maestro/task_output && find ~/.maestro/task_output -name '*.txt' -mtime +30 -delete 2>/dev/null;
```

For powershell:
```powershell
if (!(Test-Path ~/.maestro/task_output)) { New-Item -ItemType Directory -Path ~/.maestro/task_output -Force | Out-Null };
Get-ChildItem ~/.maestro/task_output -Filter '*.txt' | Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-30) } | Remove-Item -Force 2>$null;
```

Use `HOST_OUTPUT_RETENTION_DAYS` for the `-mtime`/`AddDays` value, not a hardcoded 30.

### Modify `_build_wrapper()` — single commands

Current pattern:
```bash
ssh host '<command>' 2>&1 | tee /cellar/<id>.txt
```

New pattern for bash hosts:
```bash
ssh host 'PREAMBLE <command> 2>&1 | tee ~/.maestro/task_output/<id>.txt' 2>&1 | tee /cellar/<id>.txt
```

New pattern for powershell hosts:
```bash
ssh host 'PREAMBLE <command> 2>&1 | Tee-Object -FilePath ~/.maestro/task_output/<id>.txt' 2>&1 | tee /cellar/<id>.txt
```

The remote `tee`/`Tee-Object` writes to the target host's filesystem. The outer `tee` (on Cellar)
still writes to both stdout (tmux pane) and the Cellar file. Live output is preserved.

IMPORTANT: The `PIPESTATUS` / return code capture must still work. The `${PIPESTATUS[0]}` captures
the exit code of the SSH command (first element in the pipe). With nested tee inside SSH, the SSH
exit code reflects the tee's exit (which is usually 0). Consider using:
```bash
ssh host '... command; echo __RC=$? >&2 | tee ...'
```
or simply accept that the inner tee may mask the real exit code and rely on the outer PIPESTATUS
which captures SSH's exit code. The current behavior already captures PIPESTATUS[0] from the SSH
process, which reflects the remote command's exit code when not using remote tee. With remote tee,
PIPESTATUS[0] from the outer pipe still captures SSH's exit, which now reflects the remote tee's
exit code. This is acceptable — the pattern already tolerates this for the outer tee.

### Modify `_build_script_wrapper()` — multi-line scripts

Current pattern (bash):
```bash
cat << '__MAESTRO_SCRIPT__'
...script body...
__MAESTRO_SCRIPT__
| ssh host 'bash -s' 2>&1 | tee /cellar/<id>.txt
```

The challenge: stdin is consumed by the script body, so we can't add a remote tee around `bash -s`.

**Solution for bash hosts — save-to-temp-then-execute:**

Change the remote command from `bash -s` to:
```bash
cat > /tmp/_maestro_<task_id>.sh && PREAMBLE bash /tmp/_maestro_<task_id>.sh 2>&1 | tee ~/.maestro/task_output/<id>.txt; rm -f /tmp/_maestro_<task_id>.sh
```

The heredoc is piped through SSH. Remote `cat` consumes stdin and saves to a temp file.
Then `bash` executes the temp file with output piped through tee. Temp file is cleaned up after.

The outer `tee` (on Cellar) remains unchanged — it still captures everything to the Cellar file
and stdout (tmux pane).

**Solution for PowerShell hosts — post-completion SCP:**

PowerShell's stdin handling (`$input`, `Set-Content`) is too fragile for save-to-temp in a pipe.
Keep the current script wrapper logic for PowerShell as-is, but ADD a post-completion SCP line
to the wrapper script, AFTER the outer tee and BEFORE the `tmux wait-for`:

```bash
# Post-completion: copy output to target host (best-effort)
ssh <ssh_alias> 'if (!(Test-Path ~/.maestro/task_output)) { New-Item -ItemType Directory -Path ~/.maestro/task_output -Force | Out-Null }'
scp <output_file> <ssh_alias>:~/.maestro/task_output/<task_id>.txt 2>/dev/null || true
```

This adds ~1s latency after PowerShell scripts complete. Acceptable.

### What NOT to change

- `create_task_window()` — no changes needed, it just calls the build functions
- `capture_pane()` — reads tmux pane, unrelated to output files
- `send_keys()` — sends keystrokes, unrelated
- `kill_window()` — kills window, unrelated
- `wait_for_completion()` — waits on tmux signal, unrelated
- `get_output_path()` / `get_rc_path()` — these return Cellar paths, keep them

### Startup initialization

Update `configure_mux()` call site (likely in `server.py` or wherever it's called) to pass
`host_output_retention_days=cfg.host_output_retention_days`.

Find where `configure_mux()` is called by grepping for `configure_mux` in the repo.

## Testing considerations

After making changes, verify by reading the generated wrapper scripts:
1. `cat /root/.maestro/task_output/<any_task_id>.sh` — inspect the wrapper
2. Confirm the nested tee / save-to-temp pattern is correct
3. Run a test command: a simple `echo hello` on any host
4. Verify output exists at BOTH `/root/.maestro/task_output/<id>.txt` (Cellar) and `~/.maestro/task_output/<id>.txt` (target host)
5. Verify `observe` still shows live output during execution

## Summary of changes

- config.py: +1 field, +1 env var, 1 default change (90→180)
- mux.py: +1 module var, +1 helper function, modify 2 existing functions, update configure_mux signature
- No changes to fleet.py, orchestra.py, or any tool handlers
- Observe/steer/stop are UNTOUCHED and MUST continue working
