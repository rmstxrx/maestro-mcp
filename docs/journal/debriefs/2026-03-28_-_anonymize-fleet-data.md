# Debrief: Anonymize fleet-specific data in public repo

**Date:** 2026-03-28
**Task:** Scrub real fleet infrastructure data from tracked files in the public GitHub repo.

## Summary

Audited all tracked files for real fleet hostnames, private IPs, usernames, SSH aliases, and domain names. Applied consistent replacements across ~30 files (docs, config templates, shell scripts, Python comments/docstrings, tests).

## Replacement Map

| Real | Anonymized |
|------|-----------|
| Apollyon | GPU-server |
| Eden | Win-server |
| Eden-WSL | Win-server-WSL |
| Judas | Mac-laptop |
| Cellar | Hub |
| rmstxrx (username) | youruser |
| romul (username) | youruser |
| 10.42.69.x | 192.0.2.x (RFC 5737) |
| maestro.rmstxrx.dev | maestro.yourdomain.dev |
| fleet.rmstxrx.dev | fleet.yourdomain.dev |
| cellar_ed25519 | hub_ed25519 |

## Files Changed

- **TOOLS.md** — Replaced hostnames in example JSON output.
- **docs/TODO.md** — Replaced username in path example.
- **docs/adr/ADR-0007_-_taxonomy-mux-state.SUPERSEDED.md** — Replaced all hostnames throughout.
- **docs/journal/** (10 files) — Replaced hostnames, IPs, domains, usernames across all session/handoff/debrief docs.
- **docs/research/** (1 file) — Replaced fleet hostnames in cleanup prompt.
- **pyproject.toml** — Replaced GitHub username in repo URL.
- **entrypoint.sh** — Replaced SSH key filename (cellar_ed25519 -> hub_ed25519).
- **scripts/fleet-du-snapshot.sh** — Replaced hostnames in case patterns and WSL paths.
- **maestro/mux.py** — Replaced "Cellar" in docstrings only.
- **maestro/tools/fleet.py** — Replaced "Cellar" in comments/docstrings only.
- **maestro/client.py** — Replaced "Apollyon" in comment only. Code logic (10.42.69. subnet check) intentionally kept.
- **server.py** — Replaced "Cellar" in comment.
- **tests/test_primitives.py** — Replaced "eden" hostname in test data.
- **README.md** — Replaced GitHub username in clone URL.

## Decisions

- **maestro/client.py:93** (`10.42.69.` subnet check) left unchanged — this is functional code logic, not a doc/example.
- **Many files were already anonymized** — CLAUDE.md, .env.example, hosts.example.yaml, README.md (most of it), GEMINI.md, and several ADR/journal files had been cleaned in a prior pass.
- Used RFC 5737 documentation IPs (192.0.2.x) per task instructions.
- `.gitignore` entries (apollyon-maestro-state-archive.tar.gz, docs/eden-wsl/) left untouched per task constraints.
