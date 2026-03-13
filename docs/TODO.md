# Maestro TODO

Identified during the Mar 12–13 2026 audit session. These are follow-ups to ADR-0003 (fully implemented) and the tool surface review.

## Tool ergonomics

1. **Make `working_dir` required on dispatch tools.** Remove the default from `codex`, `claude`, `gemini`. Agents that don't specify where to work should fail explicitly, not silently land in a nonexistent `~/workspace`. This prevents the scope creep pattern where agents create files in unexpected locations.

2. **Broaden `claude` `allowed_tools` default.** Current default is `"Edit,Write,Bash(git:*),Read"` — too restrictive for any real task. Change to a standard dev set: `"Edit,Write,Bash(git:*),Bash(python:*),Bash(python3:*),Bash(pip:*),Bash(cat:*),Bash(grep:*),Bash(head:*),Bash(tail:*),Bash(ls:*),Bash(find:*),Bash(mkdir:*),Bash(cp:*),Bash(sed:*),Bash(wc:*),Bash(echo:*),Bash(diff:*),Bash(timeout:*),Read"`. Callers can still override downward.

3. **Cross-reference HTTP alternatives in tool descriptions.** `poll` should mention `/tasks/{task_id}/result` as a zero-context HTTP alternative (use with `prepare_relay` key). `transfer` should mention `prepare_relay` + `curl push/pull` as the preferred path for large files. `read` should note that large files are better accessed via `exec` + `grep/head/sed`.

4. **Set `MAESTRO_DEFAULT_REPO` in `.env`.** Even after making `working_dir` required, the config fallback should point somewhere real — `/home/rmstxrx/Development` not `~/workspace`.

## Discovery

5. **Claude.ai MCP connector filters tools by intent classification.** A tool originally named `get_transfer_token` with a description mentioning "bearer token" was silently dropped from tool discovery. Renaming to `prepare_relay` with neutral description resolved it. Document this in README for anyone publishing MCP servers — avoid tool names or descriptions that suggest credential generation.

## Squash before push

6. **Squash the three F3 naming iteration commits** (699f2b3 → af68463 → e117083) into one clean commit before pushing to GitHub.
