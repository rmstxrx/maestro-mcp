# Debrief: Unify Output Paths to task_output/

## Task summary
Unified orchestra output path handling so dispatch/ledger/cleanup now use the tmux canonical `task_output/` location, and removed the unused ghost `outputs/` config path.

## Files changed
- `maestro/config.py`: Removed `orchestra_output_dir` and `task_output_retention_seconds` from `MaestroConfig` and deleted their env/default wiring.
- `maestro/tools/orchestra.py`: Removed `_orchestra_output_dir()` and `_orchestra_output_path()`, switched dispatch auto-promote ledger output paths to `get_output_path(task_id)`, updated eviction cleanup to iterate the canonical `task_output/` directory, and routed dispatch result building through `_orchestra_build_result()` to write enriched output to the canonical file.

## Decisions and surprises
- Used `cfg.output_retention_days` for task-output file pruning during periodic eviction after removing the old seconds-based output-retention field.
- `service` already recorded `output_file` via `get_output_path(task_id)` and required no code change.
- Verified zero remaining references in `maestro/` to `_orchestra_output_path`, `_orchestra_output_dir`, `orchestra_output_dir`, `MAESTRO_ORCHESTRA_OUTPUT_DIR`, and literal `/outputs/`.
