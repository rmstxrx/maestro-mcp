# STATE.md — maestro-mcp

**Last Updated:** 2026-03-23

---

## Current Focus

**Cellar migration complete.** Maestro now runs as a Docker container on the Cellar (TrueNAS SCALE), the fleet's always-on infrastructure hub. Apollyon is a pure compute leaf. The migration was config-only — zero source code changes.

### Deployment (Cellar)

| Component | Location |
|---|---|
| Repo (git clone) | `/volume2/docker/maestro/repo/` |
| Config (.env, hosts.yaml, ssh/, cloudflared/) | `/volume2/docker/maestro/config/` |
| Persistent state (oauth, ledger, registry) | `/volume2/docker/maestro/state/` |
| Containers | `maestro` (python:3.12-slim) + `maestro-cloudflared` (Alpine + cloudflared) |
| Update workflow | `cd repo && git pull && docker compose up -d --build` |

### Fleet Topology (post-migration)

| Host | Role | Status |
|---|---|---|
| Cellar | Hub (`is_local: true`), orchestration only | Docker, always-on |
| Apollyon | Compute leaf, agent dispatch target | DGX Spark, GPU workloads |
| Eden | Compute leaf, agent dispatch target | RTX 5090, PowerShell |
| Judas | Compute leaf, agent dispatch target | MacBook Pro M3 Max |
| Eden-WSL | Compute leaf (proxy through Eden) | WSL2 Ubuntu on Eden |

## Active Branches

| Branch | Location | Status |
|--------|----------|--------|
| `main` | local + remote | Active development branch |
| `feat/adr-0006-task-ledger` | local | ADR-0006 implementation — candidate for merge |

## Blockers

- None. Migration landed cleanly.

## What's Next

1. **Land ADR-0006 branch** — review and merge `feat/adr-0006-task-ledger` into `main`.
2. **Commit Dockerfile + docker-compose.yml + entrypoints** to the repo (currently only on Cellar, not in git).
3. **Remaining TODO items** (from `docs/TODO.md`):
   - Item 4: Set `MAESTRO_DEFAULT_REPO` in `.env` to a real path.
   - Item 6: Squash F3 naming commits if not already done.
4. **Delete stale remote branch** `feat/adr-0004-0005-pin-rotation` if fully merged.
5. **Tests** — 59/59 passing on the ADR-0006 branch. Re-verify after merge.

## Lessons Learned (Migration)

- TrueNAS SCALE ZFS ACLs override POSIX `chmod`. Docker bind mounts inherit the volume's permissions. Solution: entrypoint scripts that copy files with correct perms at startup.
- The `cloudflare/cloudflared:latest` image is distroless (no shell). Use Alpine multi-stage builds.
- `network_mode: "service:maestro"` ties cloudflared to maestro's network namespace. **Never restart maestro alone** — always `docker compose restart` or cloudflared's namespace goes stale.
