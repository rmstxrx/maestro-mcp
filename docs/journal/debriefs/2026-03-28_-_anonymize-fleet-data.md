# Debrief: Anonymize fleet-specific data in public repo

**Date:** 2026-03-28
**Task:** Scrub real fleet infrastructure data from tracked files in the public GitHub repo.

## Summary

Audited all tracked files for real fleet hostnames, private IPs, usernames, SSH aliases, and domain names. Applied consistent replacements across ~30 files (docs, config templates, shell scripts, Python comments/docstrings, tests).

## Replacement Map

Real fleet hostnames, private IPs, usernames, SSH key names, and domain names were replaced with generic placeholders (e.g. GPU-server, Hub, 198.51.100.x, maestro.yourdomain.dev). See the anonymized files for the canonical placeholder names.

## Files Changed

- **TOOLS.md** — Replaced hostnames in example JSON output.
- **docs/TODO.md** — Replaced username in path example.
- **docs/adr/ADR-0007_-_taxonomy-mux-state.SUPERSEDED.md** — Replaced all hostnames throughout.
- **docs/journal/** (10 files) — Replaced hostnames, IPs, domains, usernames across all session/handoff/debrief docs.
- **docs/research/** (1 file) — Replaced fleet hostnames in cleanup prompt.
- **pyproject.toml** — Replaced GitHub username in repo URL.
- **entrypoint.sh** — Replaced SSH key filename with generic placeholder.
- **scripts/fleet-du-snapshot.sh** — Replaced hostnames in case patterns and WSL paths.
- **maestro/mux.py** — Replaced real hostname in docstrings only.
- **maestro/tools/fleet.py** — Replaced real hostname in comments/docstrings only.
- **maestro/client.py** — Replaced real hostname in comment only. Code logic (LAN subnet check) intentionally kept.
- **server.py** — Replaced real hostname in comment.
- **tests/test_primitives.py** — Replaced real hostname in test data.
- **README.md** — Replaced GitHub username in clone URL.

## Decisions

- **maestro/client.py:93** (LAN subnet check) left unchanged — this is functional code logic, not a doc/example.
- **Many files were already anonymized** — CLAUDE.md, .env.example, hosts.example.yaml, README.md (most of it), GEMINI.md, and several ADR/journal files had been cleaned in a prior pass.
- Used RFC 5737 documentation IPs (198.51.100.x) per task instructions.
- `.gitignore` entries left untouched per task constraints.
