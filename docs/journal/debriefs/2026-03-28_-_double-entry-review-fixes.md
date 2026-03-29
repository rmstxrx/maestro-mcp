# Debrief: 2026-03-28 — Double-entry review fixes

Task: Apply the five findings from `docs/reviews/2026-03-28_-_double-entry-review.md` in `maestro/mux.py`.

Files changed:
- `maestro/mux.py`: Updated PowerShell remote preamble cleanup to use `-ErrorAction SilentlyContinue`, removed `task_id` parameter from `_remote_preamble`, gated preamble insertion on `tee=True` in both wrapper branches, and updated callers accordingly.

Decisions and surprises:
- Kept the PowerShell post-completion SCP fallback `mkdir` as-is because the review marks it as defensively correct and explicitly requested not changing it.
- No other files were modified to keep scope minimal.
