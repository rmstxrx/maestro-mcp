"""Host registry — fleet topology, status tracking, and command helpers."""

from __future__ import annotations

import asyncio
import logging
import os
import shlex
import time
import yaml
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class HostStatus(Enum):
    UNKNOWN = "unknown"
    CONNECTED = "connected"
    DISCONNECTED = "disconnected"
    ERROR = "error"


class HostShell(Enum):
    BASH = "bash"
    POWERSHELL = "powershell"


class RemoteCLI(Enum):
    CODEX = "codex"
    GEMINI = "gemini"
    CLAUDE = "claude"


@dataclass
class HostConfig:
    alias: str
    display_name: str
    description: str
    shell: HostShell = HostShell.BASH
    remote_cli: RemoteCLI = RemoteCLI.CODEX
    is_local: bool = False
    status: HostStatus = HostStatus.UNKNOWN
    last_check: float = 0.0
    last_error: str = ""
    allowed_dirs: list[str] = field(default_factory=list)


def _parse_ssh_config(alias: str) -> dict[str, Any]:
    """Parse ~/.ssh/config for a given Host alias.

    Returns {hostname, port, user, key_path}.  Read-only discovery —
    we do NOT use these values for connections (ControlMaster handles that).
    Limitations: no Match, Include, or complex directives.
    """
    ssh_config_path = Path.home() / ".ssh" / "config"
    if not ssh_config_path.exists():
        return {}

    result: dict[str, Any] = {}
    in_block = False

    with open(ssh_config_path) as f:
        for line in f:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            if stripped.lower().startswith("host "):
                aliases = stripped.split()[1:]
                in_block = alias in aliases
                continue

            if in_block:
                parts = stripped.split(None, 1)
                if len(parts) != 2:
                    continue
                key, value = parts[0].lower(), parts[1]
                if key == "hostname":
                    result["hostname"] = value
                elif key == "port":
                    result["port"] = int(value)
                elif key == "user":
                    result["user"] = value
                elif key == "identityfile":
                    result["key_path"] = value

    return result


def _list_ssh_config_hosts() -> list[dict[str, Any]]:
    """Enumerate all Host blocks in ~/.ssh/config.

    Returns list of {aliases, hostname, port, user, key_path}.
    Skips ``Host *`` entries.
    """
    ssh_config_path = Path.home() / ".ssh" / "config"
    if not ssh_config_path.exists():
        return []

    hosts: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None

    with open(ssh_config_path) as f:
        for line in f:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            if stripped.lower().startswith("host "):
                if current is not None:
                    hosts.append(current)
                aliases = stripped.split()[1:]
                if aliases == ["*"]:
                    current = None
                    continue
                current = {"aliases": aliases}
                continue

            if current is not None:
                parts = stripped.split(None, 1)
                if len(parts) != 2:
                    continue
                key, value = parts[0].lower(), parts[1]
                if key == "hostname":
                    current["hostname"] = value
                elif key == "port":
                    current["port"] = int(value)
                elif key == "user":
                    current["user"] = value
                elif key == "identityfile":
                    current["key_path"] = value

    if current is not None:
        hosts.append(current)

    return hosts


def _find_hosts_config() -> Path | None:
    """Search for hosts.yaml via environment variables.

    Priority:
      1. MAESTRO_HOSTS_PATH (explicit path)
      2. MAESTRO_PROJECT_DIR/.maestro/hosts.yaml (project-level)
      3. None (caller falls back to repo default)
    """
    if path := os.environ.get("MAESTRO_HOSTS_PATH"):
        p = Path(path)
        if p.exists():
            return p
    if proj_dir := os.environ.get("MAESTRO_PROJECT_DIR"):
        p = Path(proj_dir) / ".maestro" / "hosts.yaml"
        if p.exists():
            return p
    return None


def _load_hosts(config_path: Path | None = None) -> dict[str, HostConfig]:
    """Load host registry from hosts.yaml."""
    if config_path is None:
        config_path = _find_hosts_config()
    if config_path is None:
        config_path = Path(__file__).resolve().parent.parent / "hosts.yaml"
    if not config_path.exists():
        example = config_path.parent / "hosts.example.yaml"
        msg = f"Host config not found: {config_path}"
        if example.exists():
            msg += f"\n  Copy the example:  cp {example} {config_path}"
        raise SystemExit(msg)

    with open(config_path) as f:
        raw = yaml.safe_load(f)

    if not isinstance(raw, dict) or "hosts" not in raw:
        raise SystemExit(f"Invalid hosts.yaml: expected top-level 'hosts' key in {config_path}")

    hosts: dict[str, HostConfig] = {}
    for name, cfg in raw["hosts"].items():
        if not isinstance(cfg, dict) or "alias" not in cfg:
            raise SystemExit(f"Invalid host '{name}' in {config_path}: 'alias' is required")
        shell_str = cfg.get("shell", "bash").lower()
        try:
            shell = HostShell(shell_str)
        except ValueError:
            raise SystemExit(
                f"Invalid shell '{shell_str}' for host '{name}'. "
                f"Valid options: {', '.join(s.value for s in HostShell)}"
            )
        cli_str = cfg.get("remote_cli", "codex").lower()
        try:
            remote_cli = RemoteCLI(cli_str)
        except ValueError:
            raise SystemExit(
                f"Invalid remote_cli '{cli_str}' for host '{name}'. "
                f"Valid options: {', '.join(c.value for c in RemoteCLI)}"
            )
        hosts[name] = HostConfig(
            alias=cfg["alias"],
            display_name=cfg.get("display_name", name),
            description=cfg.get("description", ""),
            shell=shell,
            remote_cli=remote_cli,
            is_local=cfg.get("is_local", False),
            allowed_dirs=cfg.get("allowed_dirs", []),
        )

    if not hosts:
        raise SystemExit(f"No hosts defined in {config_path}")

    return hosts


# ---------------------------------------------------------------------------
# Module-level state (populated by init_hosts)
# ---------------------------------------------------------------------------

HOSTS: dict[str, HostConfig] = {}
_HOST_LOCKS: dict[str, asyncio.Lock] = {}


def init_hosts(config_path: Path | None = None) -> dict[str, HostConfig]:
    """Load hosts and initialise locks. Called once at import time from server.py."""
    loaded = _load_hosts(config_path)
    HOSTS.clear()
    HOSTS.update(loaded)
    _HOST_LOCKS.clear()
    _HOST_LOCKS.update({name: asyncio.Lock() for name in HOSTS})
    return HOSTS


async def _update_host_status(
    name: str,
    status: HostStatus,
    last_error: str = "",
) -> None:
    config = HOSTS[name]
    async with _HOST_LOCKS[name]:
        config.status = status
        config.last_check = time.time()
        if last_error:
            config.last_error = last_error


def _local_host_name() -> str | None:
    for name, config in HOSTS.items():
        if config.is_local:
            return name
    return None


def _resolve_host(host: str) -> HostConfig:
    if host not in HOSTS:
        available = ", ".join(sorted(HOSTS.keys()))
        raise ValueError(f"Unknown host '{host}'. Available hosts: {available}")
    return HOSTS[host]


# ---------------------------------------------------------------------------
# Command helpers
# ---------------------------------------------------------------------------

def _format_result(stdout: str, stderr: str, returncode: int) -> str:
    parts = []
    if stdout:
        parts.append(stdout)
    if stderr:
        parts.append(f"[stderr]\n{stderr}")
    if returncode != 0:
        parts.append(f"[exit code: {returncode}]")
    return "\n".join(parts) or "[no output]"


def _ps_quote(value: str) -> str:
    """Quote a value for PowerShell using double quotes with backtick escaping."""
    escaped = value.replace('`', '``').replace('"', '`"').replace('$', '`$')
    return f'"{escaped}"'


def _wrap_command(config: HostConfig, command: str, cwd: str | None, sudo: bool) -> str:
    if config.shell == HostShell.POWERSHELL:
        parts = []
        if cwd:
            parts.append(f"Set-Location -LiteralPath {_ps_quote(cwd)};")
        parts.append(command)
        full = " ".join(parts)
        return f"sudo {full}" if sudo else full
    else:
        parts = []
        if cwd:
            parts.append(f"cd {shlex.quote(cwd)} &&")
        if sudo:
            parts.append("sudo")
        parts.append(command)
        return " ".join(parts)
