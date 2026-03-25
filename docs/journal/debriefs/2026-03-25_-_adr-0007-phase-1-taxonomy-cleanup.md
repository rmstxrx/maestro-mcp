# ADR-0007 Phase 1 Taxonomy Cleanup

## Summary

Split MCP tool registration along the fleet/orchestra boundary, updated the orchestra output directory default to `~/.maestro/outputs`, refreshed `CLAUDE.md` taxonomy/architecture text, and verified the test suite.

## Files Changed

- `maestro/tools/fleet.py` — Renamed `register_tools()` to `register_fleet_tools()` and kept only fleet-facing registrations plus agent availability helpers already outside the requested move set.
- `maestro/tools/orchestra.py` — Added `register_orchestra_tools()` and moved the agent dispatch, task observation, and relay-token registrations onto the orchestra side.
- `server.py` — Wired both registration functions and updated the stdio instruction text to reflect the fleet/orchestra split.
- `maestro/config.py` — Changed the default `MAESTRO_ORCHESTRA_OUTPUT_DIR` path from `~/.agent-orchestra/outputs` to `~/.maestro/outputs`.
- `CLAUDE.md` — Added the requested taxonomy glossary, updated the architecture bullets, and corrected the documented output-dir default.
- `tests/test_primitives.py` — Registered both tool groups in tests and repointed ledger monkeypatches to the moved orchestra tool module.

## Decisions And Surprises

- Kept `gemini_sessions` in `fleet.py` because the requested move list covered dispatch, observation, and relay tools specifically; the tool name and behavior remain unchanged.
- The first `pytest tests/` run used an external virtualenv without `pytest-asyncio`, so I created a repo-local `.venv` and installed `.[dev]` before rerunning the suite successfully.
- Verification result: `./.venv/bin/pytest tests/` passed with 59/59 tests green.
