# STATE.md — maestro-mcp

**Last Updated:** 2026-03-22

---

## Current Focus

Core feature work is now complete through ADR-0006 on the feature branch. The current branch implements:
- **ADR-0006 Phase 1:** `prepare_relay()` TTL extended from 5 minutes to 1 hour.
- **ADR-0006 Phase 2:** Persistent task ledger storage with dispatch/completion tracking and client attribution.
- **ADR-0006 Phase 3:** New `tasks` tool for querying recent ledger entries.
- **ADR-0006 Phase 4:** `poll()` rewritten as ledger-backed metadata only, with result retrieval pushed to HTTP or `read_output`.
- **ADR-0006 Phase 5:** Dispatch guard blocking raw Codex/Gemini/Claude CLI usage through `exec` and `script`.

## Active Branches

| Branch | Location | Status |
|--------|----------|--------|
| `main` | local + remote | Active development branch |
| `feat/adr-0006-task-ledger` | local | ADR-0006 implementation branch |
| `feat/adr-0004-0005-pin-rotation` | remote only | Feature branch — appears merged to main, candidate for deletion |

## Blockers

- **TODO item 6:** Three F3 naming iteration commits (699f2b3 .. e117083) should be squashed before any public push. Status unknown — may already be in remote history.

## What's Next

1. **Land ADR-0006 branch** — review and merge `feat/adr-0006-task-ledger` into `main`.
2. **Remaining TODO items** (from `docs/TODO.md`):
   - Item 4: Set `MAESTRO_DEFAULT_REPO` in `.env` to a real path.
   - Item 6: Squash F3 naming commits if not already done.
   - Items 1–3, 5: Completed per commit history.
3. **ADR status docs** — ADR-0005 and ADR-0006 documentation status fields still need follow-up when doc updates are in scope.
4. **Delete stale remote branch** `feat/adr-0004-0005-pin-rotation` if fully merged.
5. **Tests** — 59/59 passing on the ADR-0006 branch after the final Phase 5 commit.
