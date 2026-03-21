# STATE.md — maestro-mcp

**Last Updated:** 2026-03-21

---

## Current Focus

Core feature work is complete through ADR-0005. The last development sprint (2026-03-19) delivered:
- **ADR-0004:** Fork cherry-pick — fleet discovery tools (`reconnect_host`, `list_ssh_hosts`, `add_host`), SSH config parsing, poll() hardening for BUG-0001.
- **ADR-0005:** Host-aware agent routing — stdio client classification, local self-reference guard on fleet I/O tools.
- **PIN rotation:** `/admin/rotate-pin` endpoint with secure-channel guards.
- **Security:** `/approve` POST restricted to HTTPS/localhost; `/admin/rotate-pin` locked down on all methods.

Working tree has uncommitted housekeeping: docs renamed to fleet naming convention, old `journal/` files deleted (moved to `docs/journal/sessions/`), and an edit in `maestro/tools/orchestra.py`.

## Active Branches

| Branch | Location | Status |
|--------|----------|--------|
| `main` | local + remote | Active development branch |
| `feat/adr-0004-0005-pin-rotation` | remote only | Feature branch — appears merged to main, candidate for deletion |

## Blockers

- **Uncommitted working tree:** Renamed docs, deleted stale journal files, modified `CLAUDE.md` and `maestro/tools/orchestra.py` sitting unstaged. Needs a cleanup commit.
- **TODO item 6:** Three F3 naming iteration commits (699f2b3 .. e117083) should be squashed before any public push. Status unknown — may already be in remote history.

## What's Next

1. **Commit working tree cleanup** — stage the doc renames, journal moves, and orchestra.py changes.
2. **Remaining TODO items** (from `docs/TODO.md`):
   - Item 4: Set `MAESTRO_DEFAULT_REPO` in `.env` to a real path.
   - Item 6: Squash F3 naming commits if not already done.
   - Items 1–3, 5: Completed per commit history.
3. **ADR-0005 status field** — ADR doc still says "Proposed" but implementation is merged. Update status to "Accepted" or "Implemented."
4. **Delete stale remote branch** `feat/adr-0004-0005-pin-rotation` if fully merged.
5. **Tests** — 54/54 passing as of last session. No new test gaps identified.
