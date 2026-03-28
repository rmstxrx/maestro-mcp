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
    orchestra_output_dir: Path
    codex_timeout: int
    gemini_timeout: int
    claude_timeout: int
    max_inline_output: int
    default_repo: str
    task_eviction_seconds: int
    task_output_retention_seconds: int
    oauth_state_path: Path
    task_ledger_path: Path
    trusted_client_ids: frozenset[str]
    # ADR-0007: system-policy timeouts and runtime estimates
    run_ceiling: int
    dispatch_ceiling: int
    default_expected_runtime_run: int
    default_expected_runtime_dispatch: int
    output_retention_days: int
    host_output_retention_days: int
    max_tasks_per_host: int
    service_overtime_advisory: int

    @classmethod
    def from_env(cls) -> "MaestroConfig":
        return cls(
            issuer_url=os.environ.get("MAESTRO_ISSUER_URL", "https://localhost:8222"),
            ssh_timeout=int(os.environ.get("SSH_TIMEOUT", "300")),
            block_timeout_default=20,
            max_retries=3,
            retry_backoff_base=1.0,
            transfer_token=os.environ.get("MAESTRO_TRANSFER_TOKEN", ""),
            max_transfer_size=int(os.environ.get("MAESTRO_MAX_TRANSFER_MB", "100")) * 1024 * 1024,
            transfer_allowed_dirs_raw=os.environ.get("MAESTRO_TRANSFER_ALLOWED_DIRS", "~/"),
            orchestra_output_dir=Path(
                os.environ.get(
                    "MAESTRO_ORCHESTRA_OUTPUT_DIR",
                    str(Path.home() / ".maestro" / "outputs"),
                )
            ),
            codex_timeout=int(os.environ.get("MAESTRO_CODEX_TIMEOUT", "1800")),
            gemini_timeout=int(os.environ.get("MAESTRO_GEMINI_TIMEOUT", "900")),
            claude_timeout=int(os.environ.get("MAESTRO_CLAUDE_TIMEOUT", "1200")),
            max_inline_output=1500,
            default_repo=os.environ.get("MAESTRO_DEFAULT_REPO", str(Path.home() / "workspace")),
            task_eviction_seconds=3600,
            task_output_retention_seconds=86400,
            oauth_state_path=Path(
                os.environ.get("MAESTRO_OAUTH_STATE_PATH",
                               str(Path.home() / ".maestro" / "oauth_state.json"))
            ),
            task_ledger_path=Path(
                os.environ.get(
                    "MAESTRO_TASK_LEDGER_PATH",
                    str(Path.home() / ".maestro" / "task_ledger.json"),
                )
            ),
            trusted_client_ids=frozenset(
                c.strip()
                for c in os.environ.get("MAESTRO_TRUSTED_CLIENT_IDS", "").split(",")
                if c.strip()
            ),
            # ADR-0007: system-policy timeouts (not exposed to callers)
            run_ceiling=300,
            dispatch_ceiling=int(os.environ.get("MAESTRO_DISPATCH_CEILING", "21600")),
            default_expected_runtime_run=15,
            default_expected_runtime_dispatch=1800,
            output_retention_days=180,
            host_output_retention_days=int(
                os.environ.get("MAESTRO_HOST_RETENTION_DAYS", "30")
            ),
            max_tasks_per_host=int(os.environ.get("MAESTRO_MAX_TASKS_PER_HOST", "10")),
            service_overtime_advisory=86400,
        )
