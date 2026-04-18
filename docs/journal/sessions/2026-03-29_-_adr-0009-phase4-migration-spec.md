# ADR-0009 Phase 4: Migrate dispatch and service to staged-script pattern

Three files to modify: `maestro/mux.py`, `maestro/tools/orchestra.py`, `maestro/tools/fleet.py`

## 1. maestro/mux.py — Add `stage_script` function

Insert this function AFTER `_build_staged_wrapper` (after the closing of that function, before the `# Core primitives` comment block):

```python
async def stage_script(task_id: str, ssh_alias: str, content: str) -> None:
    """Write a script to the remote host's /tmp/maestro/inbox via SSH.

    Used by dispatch and service to pre-stage their commands before
    triggering execution via create_task_window(staged=True).
    """
    inbox_path = f"/tmp/maestro/inbox/{task_id}.sh"
    cmd = f"mkdir -p /tmp/maestro/inbox && cat > {inbox_path} && chmod +x {inbox_path}"
    proc = await asyncio.create_subprocess_exec(
        "ssh", ssh_alias, cmd,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        _, stderr_bytes = await asyncio.wait_for(
            proc.communicate(input=content.encode("utf-8")), timeout=30,
        )
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        raise RuntimeError(f"stage_script timed out on {ssh_alias}")
    if proc.returncode != 0:
        raise RuntimeError(
            f"stage_script failed on {ssh_alias}: "
            f"{stderr_bytes.decode(errors='replace').strip()}"
        )
    logger.debug("mux: staged script %s on %s (%d bytes)", inbox_path, ssh_alias, len(content))
```

## 2. maestro/mux.py — Add `stream` parameter to `_build_staged_wrapper`

Add `stream: bool = False` to the function signature. Then change the line:

OLD:
```python
    remote_parts.append(f"{{ {exec_cmd}; }} > {outbox_out} 2>&1; echo $? > {outbox_rc}")
```

NEW:
```python
    if stream:
        remote_parts.append(exec_cmd)
    else:
        remote_parts.append(f"{{ {exec_cmd}; }} > {outbox_out} 2>&1; echo $? > {outbox_rc}")
```

## 3. maestro/mux.py — Add `stream` parameter to `create_task_window`

Add `stream: bool = False` to the function signature. Pass it through in the staged branch:

OLD:
```python
        wrapper = _build_staged_wrapper(
            task_id,
            ssh_alias,
            tee=tee,
            cwd=cwd,
            sudo=sudo,
        )
```

NEW:
```python
        wrapper = _build_staged_wrapper(
            task_id,
            ssh_alias,
            tee=tee,
            cwd=cwd,
            sudo=sudo,
            stream=stream,
        )
```

## 4. maestro/tools/orchestra.py — Modify `dispatch` to use staged pattern

### 4a. Change the import inside dispatch:

OLD:
```python
        from maestro.mux import create_task_window, wait_for_completion, get_output_path
```

NEW:
```python
        from maestro.mux import create_task_window, wait_for_completion, get_output_path, stage_script
```

### 4b. Change the `_execute` closure:

OLD:
```python
        async def _execute() -> str:
            output_file = await create_task_window(
                task_id,
                host_cfg.alias,
                cli_cmd,
                tee=True,
                interactive=False,
                cwd=working_dir,
                shell=host_cfg.shell.value,
            )
```

NEW:
```python
        async def _execute() -> str:
            script_content = f"#!/bin/bash\n{cli_cmd}\n"
            await stage_script(task_id, host_cfg.alias, script_content)
            output_file = await create_task_window(
                task_id,
                host_cfg.alias,
                tee=True,
                interactive=False,
                cwd=working_dir,
                staged=True,
                stream=True,
            )
```

## 5. maestro/tools/fleet.py — Modify `service` to use staged pattern

### 5a. Add `stage_script` to the module-level mux imports:

OLD:
```python
from maestro.mux import (
    create_task_window,
    get_output_path,
    kill_window,
    wait_for_completion,
    TMUX_SESSION,
)
```

NEW:
```python
from maestro.mux import (
    create_task_window,
    get_output_path,
    kill_window,
    stage_script,
    wait_for_completion,
    TMUX_SESSION,
)
```

### 5b. In the `service` tool body, replace the create_task_window call:

OLD:
```python
        await create_task_window(
            task_id,
            cfg.alias,
            command,
            tee=capture,
            interactive=False,
            cwd=cwd,
            shell=cfg.shell.value,
        )
```

NEW:
```python
        script_content = f"#!/bin/bash\n{command}\n"
        await stage_script(task_id, cfg.alias, script_content)
        await create_task_window(
            task_id,
            cfg.alias,
            tee=capture,
            interactive=False,
            cwd=cwd,
            staged=True,
            stream=True,
        )
```

## After all changes

Run `pytest tests/ -x` from the repo root and report full output.
