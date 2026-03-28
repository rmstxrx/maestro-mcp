# Fleet Cleanup Log — March 2026

Session started: 2026-03-12

## Decision Framework
- KEEP: actively used by running service or current project phase
- DELETE: archived model family, completed experiment, duplicate, re-downloadable cache, agent scope creep, zero-byte/mangled files, undocumented one-off scripts/envs

## Phase 1: Zero-risk wins

| Host | Item | Size | Action | Timestamp |
|------|------|------|--------|-----------|

## Phase 2: Caches and Docker

| Host | Item | Size | Action | Timestamp |
|------|------|------|--------|-----------|

## Phase 3: GPU-server models and envs

| Host | Item | Size | Action | Timestamp |
|------|------|------|--------|-----------|

## Phase 4: Win-server stale repos and SOAR

| Host | Item | Size | Action | Timestamp |
|------|------|------|--------|-----------|

## Phase 5: WSL quarantine

| Host | Item | Size | Action | Timestamp |
|------|------|------|--------|-----------|

## Phase 6: Mac-laptop audit

| Host | Item | Size | Action | Timestamp |
|------|------|------|--------|-----------|

## Phase 7: Conventions

(documented separately in fleet-conventions.md, deployed 2026-03-13)

### Phase 1 Results (2026-03-12)

**GPU-server:**
| Item | Size | Action |
|------|------|--------|
| ~/download_qwen3next.log | 4K | DELETED |
| ~/qwen3-235b-server.log | 44K | DELETED |
| ~/gptq_log_*.log (3 files) | 80K | DELETED |
| ~/build_cuda_ext.log | 4K | DELETED |
| ~/build_cuda_ext.sh | 4K | DELETED |
| ~/setup_sglang.sh | 4K | DELETED |
| ~/nvidia-workbench/ | 368K | DELETED |
| ~/tiktoken_encodings/ | 5.1M | DELETED |
| /tmp/ruff_test | 39M | DELETED |
| /tmp/test_intake | 19M | DELETED |
| /tmp/sapiens_agu_test | 15M | DELETED |
| /tmp/zip_test | 8.8M | DELETED |

**Win-server:**
| Item | Size | Action |
|------|------|--------|
| Mangled-path logs (3 files) | 0 bytes | DELETED |
| ingest_all_*.log (4 files) | 0 bytes | DELETED |
| .wsl-ssh-boot.log | 2.6K | DELETED |
| openssh_install.log | 0.5K | DELETED |
| openssh_remove.log | 0.1K | DELETED |
| start-sshd.ps1 | 0.1K | DELETED |
| syncthing_stderr.txt | 0K | DELETED |
| syncthing_stdout.txt | 1.9K | DELETED |

### Phase 1 continued — SOAR consolidation + llama.cpp (2026-03-12)

**GPU-server — scripts relocated to soar-challenge/scripts/:**
| Item | Size | Action |
|------|------|--------|
| ~/scripts/sglang-qwen35.sh | 1.2K | MOVED → soar-challenge/scripts/ (paths fixed by agent) |
| ~/scripts/sglang-smoke-test.sh | 1.8K | MOVED → soar-challenge/scripts/ |
| ~/scripts/gptq_quantize_sala.py | 5.7K | MOVED → soar-challenge/scripts/ (paths fixed by agent) |

**GPU-server — venvs moved into soar-challenge/:**
| Item | Size | Action |
|------|------|--------|
| ~/sglang-venv/ | 9.4GB | MOVED → soar-challenge/sglang-venv/ |
| ~/gptq_env/ | 6.9GB | MOVED → soar-challenge/gptq_env/ |
| ~/gptqmodel_offload/ | 4.7GB | MOVED → soar-challenge/gptqmodel_offload/ |

**GPU-server — llama.cpp relocated:**
| Item | Size | Action |
|------|------|--------|
| ~/llama.cpp/ | 596MB | MOVED → ~/Development/llama.cpp/ |

**Win-server — llama.cpp:** Already in C:\Users\youruser\Development\llama.cpp — no action needed.

**Agent debrief:** soar-challenge/docs/journal/debriefs/2026-03-12-fix-script-paths.md

### Phase 2 Results (2026-03-12)

**GPU-server — HF cache eviction (~116GB):**
| Item | Size | Action |
|------|------|--------|
| unsloth/Nemotron-3-Nano-30B-A3B | 59GB | DELETED |
| openai/gpt-oss-20b | 39GB | DELETED (required sudo) |
| nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B-NVFP4 | 19GB | DELETED |
| Remaining: DeepSeek-OCR, e5-base, Docling, MiniLM | 8.1GB | KEPT (active) |

**Win-server — HF cache eviction (~195GB):**
| Item | Size | Action |
|------|------|--------|
| unsloth/Nemotron-3-Nano-30B-A3B | 58.8GB | DELETED |
| unsloth/qwen3-30b-a3b | 56.9GB | DELETED |
| unsloth/Qwen3-32B-unsloth-bnb-4bit | 36.6GB | DELETED |
| unsloth/Qwen3-30B-A3B-bnb-4bit | 15.6GB | DELETED |
| unsloth/Qwen3-14B-unsloth-bnb-4bit | 10.4GB | DELETED |
| unsloth/qwen3-14b-bnb-4bit | 9.3GB | DELETED |
| unsloth/Qwen3-8B-unsloth-bnb-4bit | 7.0GB | DELETED |
| Remaining: e5-base, MiniLM, embeddinggemma, Docling + stubs | ~4GB | KEPT |

**GPU-server — Docker (~38.7GB):**
| Item | Size | Action |
|------|------|--------|
| tensorrt-llm/release:1.2.0rc1 | 32.2GB | DELETED (image + container) |
| traefik:v2.10.7 | 149MB | DELETED |
| project-relatoria:latest | 4.88GB | DELETED |
| Build cache pruned | 798MB | DELETED |
| Stopped containers (3) | ~1.1GB | DELETED |
| KEPT: vllm cu130-nightly, relatoria-ingest(-ngc), pytorch 26.01+26.02, traefik v3 | | |

**Win-server — Docker (~26.5GB):**
| Item | Size | Action |
|------|------|--------|
| vllm/vllm-openai:v0.8.5 | 26.5GB | DELETED |
| Running container relatoria-vlm-9b | — | UNTOUCHED |

**GPU-server — Other caches:**
| Item | Size | Action |
|------|------|--------|
| pip cache | 4.95GB | PURGED |
| Agent orchestra outputs (108 old files) | 13MB | TRIMMED to last 10 |
| ~/Downloads/ | 463MB | PURGED |

**Phase 2 Total Reclaimed: ~382GB**

### Phase 3 Results (2026-03-13)

**GPU-server — ~/models/ cleanup (451GB → 122GB, reclaimed ~329GB):**

GGUF purge (130GB):
| Item | Size | Action |
|------|------|--------|
| qwen35-122b-a10b-gguf | 71GB | DELETED |
| qwen35-35b-a3b-gguf | 21GB | DELETED |
| qwen35-27b-gguf | 17GB | DELETED |
| qwen35-9b-gguf | 13GB | DELETED |
| qwen35-4b-gguf | 6.2GB | DELETED |
| qwen35-2b-gguf | 3.3GB | DELETED |

Archived/completed models (195GB):
| Item | Size | Action |
|------|------|--------|
| qwen3-235b-a22b | 105GB | DELETED (archived Qwen3, superseded) |
| nemotron-nano-30b | 45GB | DELETED (old experiment) |
| qwen3-next-80b-a3b-instruct | 41GB | DELETED (teacher role complete) |
| GLM-OCR | 2.5GB | DELETED (benchmark done) |
| GOT-OCR-2.0-hf | 1.1GB | DELETED (benchmark done) |
| download_benchmark_models.py | 1.5KB | DELETED |

DeepSeek-OCR removal (12.6GB):
| Item | Size | Action |
|------|------|--------|
| ~/models/DeepSeek-OCR | 6.3GB | DELETED (discarded from plans) |
| HF cache copy | 6.3GB | DELETED (sudo, root-owned blobs) |
| vLLM container relatoria-deepseek-ocr | — | STOPPED and REMOVED |

**Remaining ~/models/ (122GB):**
- Qwen3.5-35B-A3B (67GB) — HF, dev/teacher
- Qwen3.5-9B (19GB) — HF
- MiniCPM-SALA (18GB) — SOAR base
- Qwen3.5-4B (8.8GB) — HF
- MiniCPM-SALA-GPTQ-W4A16 (6GB) — SOAR quantized
- Qwen3.5-2B (4.3GB) — HF

### Phase 4 Results (2026-03-13)

**Win-server — relator.IA/training/models/ purge (147GB):**
| Item | Size | Action |
|------|------|--------|
| checkpoints/qwen3-14b-curriculum-phase1-GGUF | 63.4GB | DELETED |
| checkpoints/qwen3-14b-curriculum-phase1 | 27.5GB | DELETED |
| checkpoints/phase1 + checkpoint-100 | 1.1GB | DELETED |
| sft_v2_qwen3 | 16.1GB | DELETED |
| qwen3-8b-legal-sft-v2-GGUF | 15.3GB | DELETED |
| qwen3-8b-legal-sft-v2 | 15.3GB | DELETED |
| baselines/Qwen3-14B-Q4_K_M.gguf | 8.4GB | DELETED |
| Empty dirs (simpo, dpo, logs) | 0 | DELETED |
Decision: will retrain from scratch; old Qwen3 training artifacts not preserved.

**Win-server — Downloads purge & rename:**
- Purged 10.6GB of installers/executables (46 items)
- Renamed ~50 document files to ASCII-safe convention: `YYYY-MM-DD_descricao-breve.ext`
- iCloud Drive structure surveyed at D:\iCloudDrive\Documents\ (AGU/NPDI, Acadêmico, Personal)
- Files not yet moved to iCloud destinations — rename only, relocation deferred

**Win-server — Stale repos:** KEPT per decision (SOAR may resume)
- super-sapiens-crawler (2.1GB), sglang (30MB), SOAR-Toolkit (70MB), soar-challenge (4.9GB)

**Phase 4 Total Reclaimed: ~158GB**

### Phase 4 Results (2026-03-13)

**Win-server — relator.IA/training/models/ purge (~147GB):**
| Item | Size | Action |
|------|------|--------|
| checkpoints/qwen3-14b-curriculum-phase1-GGUF | 63.4GB | DELETED |
| checkpoints/qwen3-14b-curriculum-phase1 | 27.5GB | DELETED |
| sft_v2_qwen3 | 16.1GB | DELETED |
| qwen3-8b-legal-sft-v2-GGUF | 15.3GB | DELETED |
| qwen3-8b-legal-sft-v2 | 15.3GB | DELETED |
| baselines/Qwen3-14B-Q4_K_M.gguf | 8.4GB | DELETED |
| checkpoints/phase1 + checkpoint-100 | 1.1GB | DELETED |
| Empty dirs (simpo_v1, dpo_v1, dpo_v6, logs) | 0 | DELETED |

Decision: will retrain from scratch — old Qwen3 training outputs not worth preserving.

**Win-server — Downloads installer purge (~10.6GB):**
46 installers/setup files deleted. ~60 work documents remain — pending rename + relocation.

**Win-server — stale repos: KEPT (SOAR will resume)**
- super-sapiens-crawler (2.1GB), sglang (30MB), SOAR-Toolkit (70MB), soar-challenge (4.9GB)

**Phase 4 Total Reclaimed: ~158GB**
