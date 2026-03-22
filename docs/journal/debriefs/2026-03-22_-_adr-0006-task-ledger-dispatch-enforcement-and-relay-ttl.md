# ADR-0006 Debrief

## Task Summary

Implemented ADR-0006 phases 1 through 5 on `feat/adr-0006-task-ledger`: relay TTL was extended to one hour, persistent task ledger storage was added and wired into dispatch completion, the new `tasks` tool was added, `poll` was rewritten as ledger-backed metadata only, and `exec`/`script` now block raw agent CLI dispatches.

## Files Changed

- `maestro/config.py`: Added `task_ledger_path` to `MaestroConfig` with `MAESTRO_TASK_LEDGER_PATH` environment support.
- `maestro/tools/orchestra.py`: Added `TaskLedgerEntry` and `TaskLedger`, wired ledger recording/completion into `_auto_promote`, and exposed the configured ledger for tool lookups.
- `maestro/tools/fleet.py`: Bumped relay TTL, added `tasks`, rewrote `poll`, and added the dispatch bypass guard in `exec` and `script`.
- `server.py`: Instantiated the task ledger at startup and passed it into `configure_orchestra()`.
- `STATE.md`: Updated the branch status summary to reflect ADR-0006 phases 1 through 5 and the new 59-test baseline.
- `tests/test_primitives.py`: Added focused coverage for `tasks`, metadata-only `poll`, and the new dispatch guard behavior.

## Surprises / Decisions

- The implementation plan only mentioned ledger updates in the background monitor path, but quick inline completions would have been stranded as `running`, so the ledger is updated for both inline and promoted executions.
- Ledger load marks persisted `running` entries as `orphaned`, matching task registry restart behavior so historical status does not stay stale across restarts.
- I kept return-code extraction conservative for generic `exec`/`script` results: explicit `return_code` values and formatted non-zero exit markers are captured, otherwise the ledger leaves `return_code` as `null`.
