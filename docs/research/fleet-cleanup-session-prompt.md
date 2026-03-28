# Fleet Cleanup Session

## Goal
Audit and clean bloat across all machines (GPU-server, Win-server, Win-server-WSL, Macbook). Agents have been downloading models, creating venvs, cloning repos, and leaving documents/outputs in scattered locations. Reclaim disk and establish conventions so it doesn't drift again.

## Reconnaissance (already done — Mar 12, 2026)

### GPU-server (GPU workstation, 987GB used / 3.6TB)

**Model bloat:**
- **HF cache: 134GB** at ~/.cache/huggingface/hub/
  - `unsloth/Nemotron-3-Nano-30B-A3B` — 59GB (SOAR experiment, not actively used)
  - `openai/gpt-oss-20b` — 39GB (one-off exploration)
  - `nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B-NVFP4` — 19GB
  - `deepseek-ai/DeepSeek-OCR` — 6.3GB (KEEP — active VLM pipeline)
  - `intfloat/multilingual-e5-base` — 1.1GB (KEEP — relator.IA embeddings)
  - Docling models — ~0.5GB (KEEP if Docling still used, otherwise cut)
  - `sentence-transformers/all-MiniLM-L6-v2` — 88MB (KEEP or verify if superseded by e5-base)
- **~/models/ — 451GB** of downloaded models in home dir, outside any project:
  - OCR benchmark models: DeepSeek-OCR, GLM-OCR, GOT-OCR-2.0-hf
  - MiniCPM-SALA + GPTQ quantized copy (SOAR)
  - nemotron-nano-30b (old experiment)
  - qwen3-235b-a22b, qwen3-next-80b-a3b-instruct (Qwen3 archived family)
  - Full Qwen3.5 suite: 122b, 35b, 27b, 9b, 4b, 2b — GGUF and HF variants
  - This is the biggest single cleanup target. Most were one-off downloads by agents.

**Agent-created environments littering home dir:**
- `~/gptq_env/` — 6.9GB (GPTQ quantization venv, SOAR experiment)
- `~/gptqmodel_offload/` — 4.7GB (GPTQ offload artifacts)
- `~/sglang-venv/` — 9.3GB (SGLang virtual env, stale)
- `~/llama.cpp/` — 596MB (llama.cpp clone in home dir, NOT in Development/)
- `~/nvidia-workbench/` — 368KB (probably empty scaffold)
- `~/tiktoken_encodings/` — 5MB (orphaned tokenizer cache)

**Stray logs and scripts in home dir:**
- `~/download_qwen3next.log`, `~/qwen3-235b-server.log` — model download/serving logs
- `~/gptq_log_*.log` (3 files) — GPTQ quantization run logs
- `~/build_cuda_ext.log`, `~/build_cuda_ext.sh` — CUDA build artifacts
- `~/setup_sglang.sh` — one-off setup script
- `~/scripts/sglang-*.sh`, `~/scripts/gptq_quantize_sala.py` — scattered scripts
- `~/models/download_benchmark_models.py` — download script left in model dir

**Docker:** 101.8GB images, 73GB reclaimable (71%). Only 3 of 11 images active.

**Stale repos in ~/Development/:**
- `qutlass` — last commit Nov 6, 2025
- `Quartet` — last commit Nov 19, 2025
- `sglang-sala` — last commit Feb 11, 2026 (SOAR-related — check if needed)

**Other:**
- pip cache: 4.7GB at ~/.cache/pip/
- ~/.agent-orchestra/outputs/: 117 files, 14MB
- /tmp/: ruff_test, test_intake, sapiens_agu_test, zip_test — agent test artifacts
- Downloads: 463MB (VS Code .deb, Chrome .deb, Acer utils)

### Win-server (Win11, 1275GB used on C:\)

**HF cache: ~196GB** at C:\Users\youruser\.cache\huggingface\hub\
- `unsloth/Nemotron-3-Nano-30B-A3B` — 59GB
- `unsloth/qwen3-30b-a3b` — 57GB (Qwen3 — ARCHIVED)
- `unsloth/Qwen3-32B-unsloth-bnb-4bit` — 37GB (Qwen3 — ARCHIVED)
- `unsloth/Qwen3-30B-A3B-bnb-4bit` — 16GB (Qwen3 — ARCHIVED)
- `unsloth/Qwen3-14B-unsloth-bnb-4bit` — 10GB (Qwen3 — ARCHIVED)
- `unsloth/qwen3-14b-bnb-4bit` — 9GB (Qwen3 — ARCHIVED)
- `unsloth/Qwen3-8B-unsloth-bnb-4bit` — 7GB (Qwen3 — ARCHIVED)
- Small models (embeddings, sentence-transformers) — KEEP

**relator.IA repo: 282GB** on C:\Users\youruser\Development\relator.IA
- training/models/ — 167GB of model weights inside the repo
- resources/ — 87GB (intake PDFs, benchmark data)
- output/ — 13.4GB (LanceDB, ingestion output)
- intake/ — 10.3GB
- .venv-gpu/ — 4.4GB

**Mangled-path log files in user home** (agents used escaped backslashes):
- `E?Developmentrelator.IAtraininglogsdpo_v6_win-server.log` (0 bytes)
- `E?Developmentrelator.IAtraininglogspip_liger.log` (0 bytes)
- `E??Development?relator.IA?training?logs?server.log` (0 bytes)
- `ingest_all_win-server.log`, `ingest_all_win-server_err.log`, `ingest_all_err.log`, `ingest_all_out.log` — all 0 bytes, in user home instead of project dir

**Other stray files in user home:**
- AMD Ryzen Master logs (~18MB total)
- `.wsl-ssh-boot.log`, `openssh_install.log`, `openssh_remove.log`
- `start-sshd.ps1` — one-off SSH setup script
- `syncthing_stderr.txt`, `syncthing_stdout.txt`

**Stale repos in C:\Users\youruser\Development:**
- `super-sapiens-crawler` — 2.1GB, last write Jan 29 (dead project?)
- `llama.cpp` — 520MB, last write Mar 1 (duplicate — also on GPU-server)
- `sglang` — 30MB, last write Feb 14 (stale SOAR experiment)
- `SOAR-Toolkit` — 70MB, last write Mar 2 (competition specific)
- `soar-challenge` — 4.9GB, last write Mar 4

**Docker:** 57GB images, 31GB reclaimable. Old vLLM image.
**Downloads:** 10.8GB

### Win-server-WSL (101GB total in WSL home)
- **relator.IA clone: 11GB** at ~/Development/relator.IA — agent scope creep, not canonical
- **Cache: 50GB** at ~/.cache/ — HF + pip from agent-triggered installs
- **Old Docker image**: vllm/vllm-openai 10 months old — 26.5GB. Recent one (30.2GB) is presumably active.

### Macbook — not yet surveyed. Include in session.

## Decision framework

1. **Actively used by a running service or current project phase?** → KEEP
2. **From an archived model family (Qwen3) or completed experiment?** → DELETE
3. **Duplicate that exists on another machine?** → DELETE the non-canonical copy
4. **Cache that can be re-downloaded if needed?** → DELETE
5. **Agent scope creep (repos/venvs in WSL, wrong drives, home dir litter)?** → DELETE
6. **Zero-byte log or mangled-path file?** → DELETE immediately
7. **Script or env created for a one-off task?** → DELETE unless documented in a project

## Execution plan

### Phase 1: Zero-risk wins (zero-byte files, mangled paths, empty scaffolds)
- GPU-server: delete stray logs in ~/
- Win-server: delete all zero-byte mangled-path logs in C:\Users\youruser\
- Win-server: delete empty ingest_all_*.log files
- GPU-server: delete ~/nvidia-workbench/, ~/tiktoken_encodings/

### Phase 2: Caches and reclaimable Docker
- `huggingface-cli delete-cache` on GPU-server — evict Nemotron, gpt-oss, Nemotron-NVFP4 (117GB)
- `huggingface-cli delete-cache` on Win-server — evict all Qwen3-family models (~136GB)
- `docker system prune` on GPU-server — reclaim ~73GB (confirm DeepSeek-OCR container stays)
- `docker image prune` on Win-server — remove old vLLM image
- `pip cache purge` on GPU-server
- Clean /tmp on GPU-server

### Phase 3: Agent-created environments and scattered models (GPU-server)
- ~/models/ (451GB) — go model by model. KEEP only what's actively served or needed. Everything else goes.
- ~/gptq_env/ (6.9GB), ~/gptqmodel_offload/ (4.7GB), ~/sglang-venv/ (9.3GB) — stale experiment venvs. DELETE.
- ~/llama.cpp/ (596MB) — duplicate, not in Development/. DELETE.
- ~/scripts/ — archive useful ones to maestro-mcp or relator.IA docs, then DELETE dir.

### Phase 4: Win-server stale repos and SOAR artifacts
- Evaluate: super-sapiens-crawler, llama.cpp, sglang, SOAR-Toolkit, soar-challenge
- Win-server relator.IA/training/models/ (167GB) — same treatment as GPU-server ~/models/
- Win-server Downloads (10.8GB) — purge

### Phase 5: WSL quarantine
- Check for uncommitted changes in Win-server-WSL relator.IA clone
- Remove ~/Development/relator.IA from WSL
- Clear ~/.cache in WSL
- Remove old Docker image

### Phase 6: Macbook audit
- Run same reconnaissance
- Apply same framework

### Phase 7: Conventions (prevent drift)
- Document a model storage policy: where models live, naming convention, cleanup ownership
- Add to CLAUDE.md / AGENTS.md for ALL projects:
  - "Do NOT download models to ~/.cache or ~/ — use project-designated model directories"
  - "Do NOT create venvs, repos, or scripts in the user home directory"
  - "All logs go in the project's logs/ directory, not user home"
  - "All outputs go in the project's output/ directory"
  - "Never write files with Windows backslash paths from a Unix context"
- Consider a weekly `du` snapshot script logging top-level dir sizes
- Clean up Downloads on both machines

## Rules for the cleanup agent
- **ASK before deleting anything over 1GB.** Present the item, size, and reasoning. Wait for confirmation.
- **git status before removing any repo or project directory.** If uncommitted changes exist, flag them.
- **Do NOT run `docker system prune -a` without listing what will be removed first.**
- **Log everything you delete** to: ~/Development/maestro-mcp/docs/journal/fleet-cleanup-2026-03.md
- **Do NOT delete anything in ~/Development/relator.IA/ or ~/Development/maestro-mcp/ without explicit instruction** — those are active projects with their own cleanup considerations.
