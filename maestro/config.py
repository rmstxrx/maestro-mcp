from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class MaestroConfig:
    issuer_url: str
    ssh_timeout: int
    block_timeout_default: int
    max_retries: int
    retry_backoff_base: float
    transfer_token: str
    max_transfer_size: int
    transfer_allowed_dirs_raw: str
    bg_output_dir: Path
    bg_default_timeout: int
    orchestra_output_dir: Path
    codex_timeout: int
    gemini_timeout: int
    claude_timeout: int
    opencode_timeout: int
    max_inline_output: int
    default_repo: str
    task_eviction_seconds: int
    task_output_retention_seconds: int
    oauth_state_path: Path

    @classmethod
    def from_env(cls) -> "MaestroConfig":
        return cls(
            issuer_url=os.environ.get("MAESTRO_ISSUER_URL", "https://localhost:8222"),
            ssh_timeout=int(os.environ.get("SSH_TIMEOUT", "300")),
            block_timeout_default=20,
            max_retries=3,
            retry_backoff_base=1.0,
            transfer_token=os.environ.get("MAESTRO_TRANSFER_TOKEN", ""),
            max_transfer_size=int(os.environ.get("MAESTRO_MAX_TRANSFER_MB", "100"))
            * 1024
            * 1024,
            transfer_allowed_dirs_raw=os.environ.get(
                "MAESTRO_TRANSFER_ALLOWED_DIRS", "~/"
            ),
            bg_output_dir=Path.home() / ".maestro" / "bg-outputs",
            bg_default_timeout=300,
            orchestra_output_dir=Path.home() / ".agent-orchestra" / "outputs",
            codex_timeout=600,
            gemini_timeout=600,
            claude_timeout=600,
            opencode_timeout=600,
            max_inline_output=1500,
            default_repo=os.environ.get(
                "MAESTRO_DEFAULT_REPO", str(Path.home() / "workspace")
            ),
            task_eviction_seconds=3600,
            task_output_retention_seconds=86400,
            oauth_state_path=Path(
                os.environ.get(
                    "MAESTRO_OAUTH_STATE_PATH",
                    str(Path.home() / ".maestro" / "oauth_state.json"),
                )
            ),
        )
