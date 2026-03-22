# Fleet Cleanup Handoff — 2026-03-13

## Session Summary

Four phases completed across Apollyon and Eden. **~711GB reclaimed** total.

| Phase | Scope | Reclaimed |
|-------|-------|-----------|
| 1 | Zero-risk wins + SOAR consolidation | ~82MB (+ 21GB moved into soar-challenge/) |
| 2 | HF caches, Docker, pip cache, Downloads | ~382GB |
| 3 | Apollyon ~/models/ (GGUF purge + archived models + DeepSeek-OCR) | ~329GB |
| 4 | Eden relator.IA/training/models/ + Downloads installers | ~158GB |

## Current Fleet State

### Apollyon (DGX Spark)

**~/models/ (122GB)** — clean, only active models:
- Qwen3.5-35B-A3B (67GB), Qwen3.5-9B (19GB), Qwen3.5-4B (8.8GB), Qwen3.5-2B (4.3GB) — HF format
- MiniCPM-SALA (18GB) + GPTQ-W4A16 (6GB) — SOAR

**~/Development/** — clean:
- relator.IA/ — untouched (active project)
- maestro-mcp/ — untouched (active project), journal updated
- soar-challenge/ — consolidated: now contains scripts/, sglang-venv/, gptq_env/, gptqmodel_offload/ moved from ~/
- llama.cpp/ — moved from ~/ to ~/Development/
- Stale repos (qutlass, Quartet, sglang-sala) — not yet evaluated

**Docker:** 6 images, 63GB. Running: none (DeepSeek-OCR stopped and removed).
**HF cache:** 1.8GB (e5-base, Docling, MiniLM, stubs).
**Ollama:** 8 models still registered (nemotron:70b 42GB, llama3.3:70b 42GB, qwen3.5:27b 17GB, etc.) — not yet audited.

### Eden (Win11)

**HF cache:** ~4GB (embeddings + stubs only).
**Docker:** 1 image (vllm-openai:latest, 30.2GB). Container `relatoria-vlm-9b` was running `ingest_mega.py --run-tag golden_mega` during session — VLM inference completed, post-processing was still active at session end.
**relator.IA/training/models/:** emptied (147GB purged, will retrain from scratch).
**Downloads:** ~60 work documents remain — need renaming + relocation (see below).
**Stale repos kept:** super-sapiens-crawler (2.1GB), sglang (30MB), SOAR-Toolkit (70MB), soar-challenge (4.9GB) — all preserved for when SOAR resumes.
**soar-challenge on Eden:** has untracked files not on Apollyon's copy: `eval/debug_memory.sh`, `eval/run_gptq_v2_eval.sh`, `scripts/gptq_quantize_sala_v2.py`, `scripts/run_gptq_v2.sh`, `gptqmodel_offload/` (4.67GB), a GPTQ log file. These should be synced to Apollyon's canonical copy.

### Eden-WSL

**Not yet cleaned.** From recon:
- relator.IA clone (11GB) — agent scope creep, not canonical. Check for uncommitted changes then delete.
- ~/.cache/ (50GB) — HF + pip from agent-triggered installs.
- Docker shares with Eden host — old image already removed.

### Judas (MBP M3 Max)

**Not yet surveyed.** Phase 6 in the original plan.

## Remaining Work

### Phase 4 (continued) — Eden Downloads naming + relocation

**~60 files** in `C:\Users\romul\Downloads` need:

1. **Rename** to ASCII-safe convention: `YYYY-MM-DD_descricao-breve_contexto.ext` (no accents, no spaces). SEI docs keep their NUP. Templates get no date prefix.

2. **Check D: drive** (iCloud Drive) for existing Documents hierarchy before deciding destinations. The user has a structure there already — conform to it rather than inventing a new one.

3. **Relocate** renamed files to proper homes.

Files that need user identification before moving:
- `PARECER.pdf`, `PARECER (1).pdf`, `PARECER (2).pdf` — which pareceres are these?
- `MODELO.pdf`, `MODELO (1).pdf`, `MODELO (2).pdf` — which models?
- `document.pdf`, `c17915b1-9fb2-498c-b975-0d0f4552deca.pdf` — unknown content
- `base escrota.pdf` + `base escrota_extracted.json` — what base/dataset?
- `output.txt`, `extraction_output.txt` — from what run?

Agent ephemera (scripts that were likely one-off explorations):
- `extract_financial_data.py`, `serialize_tables.py`, `inspect_docling_structure.py`, `atualiza_vivery.ipynb` — delete or archive?

### Phase 5 — WSL quarantine

- `git status` on Eden-WSL relator.IA clone
- Delete clone if clean
- Purge ~/.cache/ (50GB)

### Phase 6 — Judas audit

- Run reconnaissance (same `du` survey as Apollyon/Eden)
- Apply same decision framework

### Phase 7 — Conventions

Draft and deploy:
- **Model storage policy:** models live in `~/models/` (Apollyon) or project-specific dirs, never in HF cache for production use. GGUF format is not used — HF only.
- **Agent hygiene rules** for CLAUDE.md / AGENTS.md across all projects:
  - No downloads to ~/.cache or ~/ — use project model directories
  - No venvs, repos, or scripts in user home
  - All logs in project logs/ dir
  - All outputs in project output/ dir
  - No Windows backslash paths from Unix context
- **Downloads policy:** transient staging only. Rename on arrival, file within 24h, purge weekly.
- **Weekly `du` snapshot script** logging top-level dir sizes (proposed but not yet implemented).

### Apollyon — deferred items

- **Stale repos in ~/Development/:** qutlass (Nov 2025), Quartet (Nov 2025), sglang-sala (Feb 2026) — not yet evaluated.
- **Ollama models:** 8 models registered (~150GB+ estimated). Audit which are actively used vs. stale.
- **~/.agent-orchestra/outputs/:** trimmed to last 10, but consider a retention policy.

## Key Decisions Made This Session

1. **GGUF is dead.** All GGUF models fleet-wide deleted. HF format only going forward.
2. **DeepSeek-OCR discarded** from relator.IA plans. Container stopped, all copies deleted.
3. **Qwen3-era training artifacts purged.** Will retrain from scratch — old outputs not worth preserving.
4. **SOAR repos preserved** across all machines — competition will resume.
5. **llama.cpp:** one copy per machine (Apollyon: ~/Development/llama.cpp, Eden: C:\Users\romul\Development\llama.cpp). Kept for GGUF converter utility.
6. **SOAR venvs moved** (not deleted) into soar-challenge/ — cheaper than rebuilding.

## Journal Location

`apollyon:~/Development/maestro-mcp/docs/journal/fleet-cleanup-2026-03.md`

Complete deletion log with timestamps, per-item sizes, and actions taken.
