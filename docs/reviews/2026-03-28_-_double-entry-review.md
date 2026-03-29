# Code Review: Double-Entry Task Output

**Branch:** `feat/double-entry-output` (commit `329377d`)
**Spec:** `docs/double-entry-spec.md`
**Reviewed:** 2026-03-28
**Files reviewed:** `maestro/config.py`, `maestro/mux.py`, `server.py`

---

## 1. Correctness

### Bash single command — PASS

Traced example: `command="ls -la"`, `ssh_alias="judas"`, `cwd="/home/user"`, `tee=True`

Generated wrapper (conceptual):
```bash
ssh 'judas' 'mkdir -p ~/.maestro/task_output && find ~/.maestro/task_output -name '\''*.txt'\'' -mtime +30 -delete 2>/dev/null; cd '\''/home/user'\'' && ls -la 2>&1 | tee ~/.maestro/task_output/<id>.txt' 2>&1 | tee '/root/.maestro/task_output/<id>.txt'
```

The `shlex.quote()` on `remote_cmd` correctly handles the embedded single quotes from the preamble (`'*.txt'`) and cwd (`'/home/user'`). After bash processes the outer quoting, SSH receives the correct command string. The remote bash shell executes:

1. `mkdir -p` + `find -delete` (preamble)
2. `cd && ls -la 2>&1 | tee <remote_file>` (command with remote tee)

Remote tee writes to leaf disk AND passes stdout back through SSH. Outer tee writes to hub disk AND passes to stdout (tmux pane). Correct.

### Bash script — PASS

The save-to-temp pattern (`mux.py:177-183`) works:

```
cat << '__MAESTRO_SCRIPT__' | ssh host 'cat > /tmp/_maestro_<id>.sh && <preamble> bash /tmp/_maestro_<id>.sh 2>&1 | tee <remote_file>; rm -f /tmp/_maestro_<id>.sh'
```

Heredoc stdin is consumed by remote `cat >` to write the temp file. Then `&&` chains preamble + execution. The `; rm -f` cleanup runs regardless of script exit code. The single-quoted heredoc delimiter (`'__MAESTRO_SCRIPT__'`) prevents variable expansion, so script bodies with `$`, single quotes, backticks, etc. pass through safely.

### PowerShell single command — PASS

The `Tee-Object -FilePath ~/.maestro/task_output/<id>.txt` is valid PowerShell. The `~` tilde resolves correctly in PowerShell provider-aware cmdlets including `Tee-Object`, `Test-Path`, and `New-Item`. The `2>&1` redirect before `| Tee-Object` merges stderr into stdout correctly in PowerShell.

### PowerShell script — PASS (with warnings below)

The post-completion SCP fallback (`mux.py:193-201`) is the right call given PowerShell's fragile stdin handling. The SCP destination `host:~/.maestro/task_output/<id>.txt` works because SCP passes the path to the remote sshd which expands `~` server-side.

---

## 2. Invariant Preservation — PASS

All changes are purely additive:

- **Outer tee unchanged:** `mux.py:140` — `{ssh_cmd} 2>&1 | tee {output_file}` still writes to both stdout (tmux pane) and the hub file. The `PIPESTATUS[0]` capture at `mux.py:141` is unchanged.
- **`capture_pane()`** (`mux.py:284`): untouched, reads tmux pane content.
- **`send_keys()`** (`mux.py:293`): untouched, sends keystrokes to pane.
- **`kill_window()`** (`mux.py:302`): untouched, kills tmux window.
- **`wait_for_completion()`** (`mux.py:261`): untouched, waits on tmux signal.
- **`get_output_path()` / `get_rc_path()`**: untouched, return hub paths.

The remote tee is nested *inside* the SSH command, before stdout crosses the SSH boundary. Live pane output is preserved.

---

## 3. Edge Cases

### 3a. Fresh host with no `~/.maestro/task_output/` — PASS

The preamble runs `mkdir -p` before `find -delete` (connected by `&&` in bash, sequential statements in PowerShell). Order is correct. If the directory doesn't exist, `mkdir -p` creates it; `find` then finds nothing to delete. No error.

### 3b. `tee=False` (interactive mode) — NOTE

**NOTE:** When `tee=False`, the remote preamble still executes (`mux.py:122`, `mux.py:133`):

```python
remote_cmd = f"{remote_preamble} {remote_core_cmd}"
```

This creates `~/.maestro/task_output/` and runs retention cleanup on every interactive session, even though no output file is written. Harmless but wasteful. Consider gating the preamble on `tee=True`:

```python
if tee:
    remote_cmd = f"{remote_preamble} {remote_core_cmd} 2>&1 | tee {remote_output_file}"
else:
    remote_cmd = remote_core_cmd
```

### 3c. PowerShell tilde expansion — PASS

`~` resolves correctly in all PowerShell contexts used: `Test-Path`, `New-Item -Path`, `Tee-Object -FilePath`, `Get-ChildItem`. Also works in SCP remote paths (expanded by remote sshd).

### 3d. Script body with single quotes / heredoc markers — PASS (pre-existing limitation)

The heredoc delimiter `'__MAESTRO_SCRIPT__'` is single-quoted, disabling all expansion. Single quotes, `$variables`, backticks in the script body pass through. The only pre-existing risk is a script body containing the literal line `__MAESTRO_SCRIPT__` — this would prematurely end the heredoc. Not introduced by this change.

### 3e. PowerShell `}}` brace escaping — PASS

`mux.py:48`:
```python
f"(Get-Date).AddDays(-{HOST_OUTPUT_RETENTION_DAYS}) }} | "
```

Only this line is an f-string. `{HOST_OUTPUT_RETENTION_DAYS}` interpolates the value; `}}` produces a single literal `}`. The preceding plain string `"Where-Object { $_.LastWriteTime -lt "` contributes the opening `{`. Result:

```powershell
Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-30) } |
```

Syntactically correct PowerShell. The Where-Object scriptblock is properly delimited.

---

## 4. Cleanup-on-Use Retention

### Leaf-side cleanup — PASS

Both shell variants use the `HOST_OUTPUT_RETENTION_DAYS` module variable, not hardcoded values:

- **Bash** (`mux.py:53`): `f"find ... -mtime +{HOST_OUTPUT_RETENTION_DAYS} -delete"`
- **PowerShell** (`mux.py:48`): `f"(Get-Date).AddDays(-{HOST_OUTPUT_RETENTION_DAYS})"`

The flow is correct:
1. `config.py:84` reads `MAESTRO_HOST_RETENTION_DAYS` env var (default `30`)
2. `server.py:110` passes to `configure_mux(host_output_retention_days=...)`
3. `mux.py:35` sets `HOST_OUTPUT_RETENTION_DAYS` module global
4. `_remote_preamble()` uses it in f-strings

### Hub-side retention — NOTE

**NOTE:** `output_retention_days` was changed from 90 to 180 (`config.py:83`) per spec, but this value is not referenced anywhere in the codebase beyond its definition. Hub-side output cleanup is not implemented in this changeset — the 180-day retention is a policy declaration only. If hub-side pruning exists elsewhere (cron, systemd timer), verify it reads this config value.

---

## 5. Additional Findings

### WARNING: PowerShell `$ErrorActionPreference = 'Stop'` + cleanup can abort scripts

`mux.py:165`:
```python
script_lines = ["$ErrorActionPreference = 'Stop'", _remote_preamble(task_id, shell)]
```

The PowerShell script preamble includes `Remove-Item -Force 2>$null`. In PowerShell, `2>$null` redirects the error *stream* but does **not** suppress error *records* from being generated. With `$ErrorActionPreference = 'Stop'`, any non-terminating error from `Remove-Item` (e.g., a locked file, permission denied) is promoted to a terminating error, aborting the entire script before the user's actual work begins.

**Fix:** Replace `2>$null` with `-ErrorAction SilentlyContinue`:

```python
"Remove-Item -Force -ErrorAction SilentlyContinue;"
```

This suppresses errors at the cmdlet level, preventing `$ErrorActionPreference` from catching them.

**Severity:** WARNING. The failure scenario (locked `.txt` file in `~/.maestro/task_output/`) is unlikely but would silently abort the user's script with a confusing cleanup error.

### WARNING: PowerShell single-command preamble has the same `2>$null` issue

`mux.py:49`:
```python
"Remove-Item -Force 2>$null;"
```

When the preamble runs as part of a single command via SSH, PowerShell's default `$ErrorActionPreference` is `Continue`, so `Remove-Item` errors are non-terminating and `2>$null` works. This is less severe than the script case — but if any caller ever sets `$ErrorActionPreference` globally on the remote host (e.g., in a PowerShell profile), the same abort risk applies.

**Fix:** Same as above — use `-ErrorAction SilentlyContinue` consistently.

### NOTE: Redundant mkdir in PowerShell script post-completion

`mux.py:193-197` — The post-completion SSH creates `~/.maestro/task_output/` via `New-Item`. But the preamble injected into the script body (`mux.py:165`) already runs the same mkdir. The second mkdir is redundant.

However, this redundancy is arguably correct defensive design: if the script fails before the preamble executes (e.g., PowerShell parse error), the post-completion mkdir ensures SCP has a target directory. Keep as-is.

### NOTE: Unused `task_id` parameter in `_remote_preamble`

`mux.py:41`:
```python
_ = task_id
```

The `task_id` parameter is accepted but explicitly discarded. If it's reserved for future use, a comment would clarify intent. If not needed, remove the parameter — both callers already have `task_id` available if the signature changes later.

### NOTE: `configure_mux` not passing `output_dir`

`server.py:109-111`:
```python
configure_mux(
    host_output_retention_days=CONFIG.host_output_retention_days
)
```

The `output_dir` parameter is not passed, so `OUTPUT_DIR` defaults to `/root/.maestro/task_output`. This is correct for the Docker deployment (runs as root), and matches pre-existing behavior (previous call was `configure_mux()` with no args). Just noting for visibility.

---

## Summary

| # | Severity | Issue | Location |
|---|----------|-------|----------|
| 1 | **WARNING** | `$ErrorActionPreference = 'Stop'` + `2>$null` can abort PS scripts on cleanup errors | `mux.py:49`, `mux.py:165` |
| 2 | NOTE | `tee=False` still runs remote preamble (wasteful mkdir + find) | `mux.py:122`, `mux.py:133` |
| 3 | NOTE | Hub-side `output_retention_days=180` is declared but unused in code | `config.py:83` |
| 4 | NOTE | Redundant mkdir in PS script post-completion (defensively correct) | `mux.py:193-197` |
| 5 | NOTE | Unused `task_id` param in `_remote_preamble` | `mux.py:41` |

**No blockers.** The core double-entry mechanism is correct — nested tee produces output on both sides, the tmux pane invariant is preserved, quoting is sound across all four paths (bash cmd, bash script, PS cmd, PS script), and retention cleanup uses configured values. The PowerShell `2>$null` vs `-ErrorAction SilentlyContinue` issue (WARNING #1) is the only item worth fixing before merge.
