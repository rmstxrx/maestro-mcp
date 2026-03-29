# Phase 4 Staged-Script Migration

## Task Summary

Implemented the ADR-0009 phase 4 staged-script changes exactly as specified in `docs/journal/sessions/phase4-spec.md`, limited to the requested modules and followed by the requested pytest run.

## Files Changed

- `maestro/mux.py`: Added `stage_script`, added `stream` to the staged wrapper and `create_task_window`, and passed the flag through the staged path.
- `maestro/tools/orchestra.py`: Updated `dispatch` to pre-stage the CLI command as a script and then launch it with `create_task_window(staged=True, stream=True)`.
- `maestro/tools/fleet.py`: Updated `service` to pre-stage the service command as a script and then launch it with `create_task_window(staged=True, stream=True)`.
- `docs/journal/debriefs/2026-03-29_-_phase4-staged-script-migration.md`: Recorded the required dispatched-agent debrief for this task.

## Decisions Or Surprises

- No additional refactors or cleanup were applied; the diff was kept to the spec's verbatim old/new changes plus this required debrief.
- The requested test command passed cleanly: `60 passed, 7 skipped`.
