# ADR-0001: Agent Routing Heuristic & Model Selection

- **Status:** Accepted
- **Date:** 2026-03-05
- **Context:** Maestro MCP orchestrates three CLI agents (Claude Code, Codex CLI, Gemini CLI) across a fleet of hosts (Apollyon, Eden, Judas). Usage has been heavily skewed toward Claude Code, underutilizing paid Codex (ChatGPT Pro) and Gemini (AI Ultra) subscriptions. Model defaults in Maestro's tool definitions reference deprecated models (GPT-5.1-Codex-Max, GPT-5-Codex-Mini).

## Decision

### 1. Model Defaults

Maestro's default model parameters must track the current frontier for each agent:

| Agent | Default Model | Fallback | Notes |
|---|---|---|---|
| **Codex CLI** | `gpt-5.3-codex` | `gpt-5.3-codex-spark` (fast) / `gpt-5-codex-mini` (cost) | GPT-5.1 family is deprecated. ChatGPT Pro subscription — always use the frontier. Spark for tight iteration loops, Mini for bulk/mechanical work. |
| **Gemini CLI** | `gemini-3.1-pro` | `gemini-3.1-flash-lite` (speed) | Gemini 3 Pro deprecated March 9, 2026. AI Ultra subscription — always use the frontier. Eden's CLI (0.25.1) predates 3.1 Pro support — must update to ≥0.31.0. |
| **Claude Code** | (uses Anthropic's default) | — | Model selection managed by Anthropic; no override needed. |

### 2. Routing Heuristic

The routing decision is **task-type first, then host-aware**. The orchestrator (Claude chat) selects the agent based on what the task needs, then picks the host that can serve it.

#### By task type

| Task Type | Primary Agent | Why |
|---|---|---|
| **Multi-file refactoring, architectural changes** | Claude Code | Strongest plan→execute reasoning; CLAUDE.md-aware; best at maintaining coherence across files. |
| **Feature implementation, bug fixes, test generation** | Codex | Native compaction for long-running sessions; strongest agentic coding with GPT-5.3-Codex; good Windows support. |
| **Fast interactive edits, tight feedback loops** | Codex (Spark) | GPT-5.3-Codex-Spark: near-instant latency, optimized for rapid iteration. |
| **Large-context codebase analysis, architectural review** | Gemini (analyze) | 1M token context window; read-only by default; ideal for "understand before changing" tasks. |
| **Web research with grounding** | Gemini (research) | Built-in Google Search grounding; no tool overhead; best for current documentation, jurisprudência, regulatory changes. |
| **Document comparison, pattern identification across many files** | Gemini (analyze) | Feed via `context_files`; leverages the full 1M context for cross-file pattern recognition. |
| **Cost-sensitive batch work** | Codex (Mini) | 4x more usage per quota; acceptable quality for mechanical tasks. |

#### By host affinity

| Host | Strengths | Preferred for |
|---|---|---|
| **Apollyon** (DGX Spark, Linux) | Main dev, 128GB unified, all agents available, stable SSH | Default for all agent types; canonical working copies live here. |
| **Eden** (Win11, 5090, 96GB) | Strong GPU, Windows-native | Codex tasks targeting Windows repos (`C:\Users\romul\Development\*`); GPU-adjacent work. Note: `maestro_status` reports offline — use direct tool calls. |
| **Judas** (MBP M3 Max, 36GB) | Portable, macOS-native | Lightweight dispatch, macOS-specific testing. Currently needs CLI updates and PATH fix (see §3). |

### 3. Reasoning Effort Defaults

Both Codex and Gemini support configurable reasoning depth. Since we're on maximum-tier subscriptions (ChatGPT Pro, AI Ultra), the default should favor quality over cost. Scale *down* selectively, not up from a conservative baseline.

#### GPT-5.3-Codex

Levels: `low` → `medium` → `high` → `xhigh`

| Reasoning Effort | Use When |
|---|---|
| `xhigh` | **Default.** Long-running autonomous tasks, complex refactors, anything where correctness matters more than speed. This is what OpenAI benchmarks at. We pay for Pro — use the ceiling. |
| `high` | Fallback when xhigh latency is unacceptable but strong reasoning is still needed. |
| `medium` | Interactive pairing, fast feedback loops. OpenAI's recommended "daily driver." |
| `low` | Mechanical/batch tasks (formatting, boilerplate generation). |

**Maestro default: `xhigh`**. We pay for Pro — use the ceiling. Drop to `high` for moderate tasks, `medium` for Spark-like interactive use.

#### Gemini 3.1 Pro

Levels: `low` → `medium` → `high` (activates Deep Think Mini)

| Thinking Level | Use When |
|---|---|
| `high` | Complex reasoning, legal analysis, architectural review, multi-step planning. Activates Deep Think Mini (77.1% ARC-AGI-2). API default — keep it. |
| `medium` | General-purpose analysis, code review, research synthesis. Equivalent to old 3 Pro's `high`. |
| `low` | Simple file operations, quick lookups, fast grounded search. |

**Maestro default: `high`**. We're paying for Ultra — use Deep Think Mini as the baseline. Drop to `medium` only when latency matters more than depth.

#### Claude Code

Claude Code exposes High/Medium/Low effort settings. Anthropic manages model selection internally — no override needed in Maestro. Default: trust Anthropic's routing.

### 4. Infrastructure Gaps (Action Items)

| Item | Current | Target | Host |
|---|---|---|---|
| Codex CLI version | 0.63.0 | ≥0.107.0 | Judas |
| Gemini CLI version | 0.17.1 | ≥0.31.0 | Judas |
| Gemini CLI version | 0.25.1 | ≥0.31.0 | Eden |
| Maestro SSH PATH | Minimal (`/usr/bin:/bin`) | Source `.zshrc` or set `SendEnv`/`AcceptEnv` | Judas |
| Maestro default Codex model | `gpt-5.1-codex-max` | `gpt-5.3-codex` | All (tool definition) |
| Maestro default Codex fallback | `gpt-5-codex-mini` | Keep as cost fallback | — |
| Maestro default Codex reasoning | (none) | `xhigh` | All (tool definition) |
| Maestro default Gemini thinking | (none) | `high` (Deep Think Mini) | All (tool definition) |

### 5. Delegation Principle

The orchestrator (Claude chat session) should **default to delegating** rather than defaulting to Claude Code. The decision tree:

1. Is this a research/analysis task requiring current information or large context? → **Gemini**
2. Is this a scoped implementation task (feature, bugfix, tests)? → **Codex**
3. Is this an architectural or reasoning-heavy task requiring plan→execute? → **Claude Code**
4. Is this a quick iteration needing sub-second response? → **Codex (Spark)**
5. Ambiguous? → Ask the user.

The bias toward Claude Code exists because it's the path of least resistance from the chat interface. This ADR explicitly corrects that bias.

## Consequences

- Maestro tool definitions must be updated to reflect new default models.
- CLI versions must be updated on Judas and Eden before these routing rules are fully effective.
- The orchestrator should reference this document when deciding which agent to dispatch.
- Model defaults should be reviewed monthly or whenever a new model generation ships.
