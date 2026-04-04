## Task Summary

Implemented two independent fixes: `read_file` now auto-stages a relay download when its inline preview is truncated, and relay SCP failures now return categorized `422` JSON errors instead of `502`.

## Files Changed

- `maestro/tools/fleet.py`: Added `transfer_pull_impl` usage so truncated `read_file` responses can include a relay `curl` command, full byte count, and an updated hint/docstring.
- `maestro/relay.py`: Added `_categorize_scp_error()` and changed relay SCP failure responses in both transfer directions from `502` to categorized `422` JSON errors.
- `docs/journal/debriefs/2026-04-04_-_read-file-relay-and-422-errors.md`: Recorded this debrief for the dispatched-task journal.

## Decisions Or Surprises

- Kept the `read_file` fallback best-effort with `except Exception` exactly as requested, so truncated inline content still returns even if relay staging fails.
- Included the debrief in the same local commit despite the sample `git add` only naming the two code files, to satisfy the fleet conduct rule requiring a debrief for dispatched work.
- Verification succeeded with `.venv/bin/pytest tests/ -x --tb=short` (`62 passed`).
