# ADR-0002: Single-Shot Dispatch with Filesystem-Mediated State

- **Status:** Accepted
- **Date:** 2026-03-05
- **Supersedes:** — (replaces a retracted proposal for interactive agent sessions via CLI resume)
- **Related:** ADR-0001 (Agent Routing Heuristic)

## Context

Maestro's agent invocation model is single-shot: the orchestrator (Claude chat) composes a complete prompt, dispatches it to an agent (Codex, Claude Code, Gemini), and receives a finished result. There is no mid-flight steering.

An initial proposal (retracted) explored using CLI session resume (`codex exec resume`, `claude --resume`, `gemini --resume`) to enable multi-turn interactive sessions. Investigation revealed this approach is counterproductive:

1. **Resume reloads full conversation history.** Each resumed turn re-sends all prior turns as context. By turn N, the agent spends O(N) context on history replay and has proportionally less capacity for new work. The session eats itself.
2. **Each resume is a cold process restart.** There is no warm process with sub-second latency. Each "turn" pays full CLI startup + context reload (3-10 seconds), making it operationally indistinguishable from sequential dispatches but with worse context economics.
3. **The illusion of interactivity degrades prompt discipline.** When the orchestrator believes it can "fix things in the next message," it front-loads less context into each prompt. But the "next message" isn't cheap — it's a full re-invocation with accumulated baggage. The result is lazier prompts that cost more and produce worse outcomes.
4. **Context compression in time is the actual advantage.** A completed single-shot dispatch compresses its entire reasoning into file edits — the most compact possible representation of its work. The next dispatch reads the codebase with a *full, fresh context window*. The filesystem is lossless inter-turn memory at zero token cost.

## Decision

**Single-shot dispatch is the correct interaction model for Maestro agents.** The `*_execute` and `*_dispatch` tools remain the primary interface. No session/resume abstraction will be built.

Instead, this ADR codifies the patterns that make single-shot dispatch maximally effective.

### Principle: The Filesystem is Shared Memory

When an agent completes a dispatch, every file it created, modified, or deleted persists on disk. The next dispatch inherits this state by reading the codebase — not by replaying conversation history. This means:

- **Each dispatch gets a full context window.** No history tax. A 200K-token window is 200K tokens of *new capacity* on every invocation.
- **Prior work is compressed optimally.** A 50-turn reasoning chain that produced a 200-line module is represented as... a 200-line module. The agent reads the artifact, not the process that created it.
- **State is durable.** Unlike conversation history (which lives in volatile CLI session files), filesystem state survives process crashes, host reboots, and Maestro restarts.

### Principle: Decomposition is the Leverage Point

The quality of outcomes is determined not by the ability to steer mid-flight, but by the quality of task decomposition. The orchestrator's job is to break work into dispatches where each one:

1. **Has a clear, self-contained objective.** "Implement the chunking module with the interface defined in `types.py`" — not "work on the chunking stuff."
2. **Can orient from the filesystem alone.** The agent should be able to read the codebase and understand what exists, what's expected, and where its work fits. If the prompt requires extensive explanation of prior state, the decomposition is wrong — the prior dispatch should have left clearer artifacts.
3. **Produces verifiable output.** Each dispatch should create something the orchestrator can inspect before dispatching the next step: tests that pass, a module that imports correctly, a config that validates.

### Pattern: Sequential Dispatch with Verification Gates

The standard workflow for multi-step implementation:

```
Orchestrator                         Agent              Filesystem
    |                                  |                    |
    |-- Dispatch 1: "Implement X" ---->|                    |
    |                                  |--- writes X.py --->|
    |<-- Result: done, files changed --|                    |
    |                                  |                    |
    | [verify: read X.py, run tests]   |                    |
    |                                  |                    |
    |-- Dispatch 2: "Implement Y,      |                    |
    |   which depends on X" ---------->|--- reads X.py ---->|
    |                                  |--- writes Y.py --->|
    |<-- Result: done ------------------|                    |
    |                                  |                    |
    | [verify: integration test]       |                    |
```

The orchestrator acts as a **verification gate** between dispatches, not a real-time supervisor. This is cheaper, more reliable, and produces better outcomes than attempting to steer a running agent.

### Pattern: Scaffold Before Implement

For complex implementations, the first dispatch should create the structural skeleton — interfaces, type definitions, directory structure, empty modules with docstrings — and the subsequent dispatches fill them in. This is the decomposition equivalent of "writing the table of contents before the chapters."

```
Dispatch 1 (scaffold):  types.py, __init__.py, empty module stubs with signatures
Dispatch 2 (implement): chunker.py (reads types.py for interfaces)
Dispatch 3 (implement): indexer.py (reads types.py + chunker.py)
Dispatch 4 (integrate): main.py wiring, integration tests
```

Each dispatch reads less than it writes, and always has enough context to orient.

### Pattern: Prompt as Specification

Because single-shot gives no opportunity for clarification, the prompt must be complete. Effective prompts for agent dispatch include:

- **Objective.** What the agent must produce (files, tests, changes).
- **Constraints.** What the agent must NOT do (don't modify X, don't introduce dependency Y).
- **Context pointers.** Which files to read for orientation ("see `types.py` for interfaces, `ARCHITECTURE.md` for conventions").
- **Acceptance criteria.** How the orchestrator will verify success ("tests in `test_chunker.py` must pass", "module must import without errors").
- **Scope boundary.** Where to stop ("implement only the public API; internal helpers are for the next dispatch").

A well-structured prompt is both a specification and a contract. If the agent can satisfy the acceptance criteria by reading the codebase and following the prompt, the decomposition is correct.

### Pattern: Course Correction via Re-Dispatch

When a dispatch produces incorrect output, the orchestrator does not "resume and fix." It dispatches a new, self-contained correction:

```
Dispatch N+1: "The implementation in chunker.py has a bug: [describe bug].
Read the current chunker.py. Fix the issue. The correct behavior is [specify].
Run the tests in test_chunker.py to verify the fix."
```

This correction dispatch gets a full context window, reads the faulty file directly, and fixes it without carrying any conversational baggage from Dispatch N. It's often cheaper and more reliable than a resumed session where the agent has to reconcile its prior reasoning with the new instruction.

### Anti-Pattern: Conversational Dispatch

Do **not** compose prompts that assume shared conversational context:

```
BAD:  "Now do the same thing for the indexer module."
GOOD: "Implement the indexer module in src/indexer.py. Follow the same
       patterns used in src/chunker.py (read it for reference). The interface
       is defined in src/types.py — implement IndexerConfig and Indexer classes.
       Tests go in tests/test_indexer.py."
```

Each prompt must be independently comprehensible. The agent has never seen any prior prompt.

## Future Direction: True Interactive Sessions

The single-shot model is correct *given current infrastructure*. True interactive sessions — where the orchestrator observes agent output in real time and injects guidance with sub-second latency — would be genuinely valuable. This requires:

- **PTY multiplexing.** A persistent agent process with managed stdin/stdout, exposing read/write primitives through Maestro's MCP interface.
- **Streaming output.** SSE or WebSocket transport from Maestro to the orchestrator for real-time observation.
- **Interrupt semantics.** The ability to pause agent execution at a clean boundary (e.g., between tool calls) and inject a redirection.

This is architecturally distinct from CLI resume and would be a substantial engineering effort. It remains a desired capability but is explicitly out of scope for the current Maestro architecture. When pursued, it should be designed from first principles as a PTY management layer, not retrofitted onto session resume semantics.

## Consequences

- No new tools are added to Maestro. The existing `*_execute`, `*_dispatch`, `agent_poll`, and `agent_read_output` tools are the complete agent interaction surface.
- The orchestrator (Claude chat) should invest in prompt quality and task decomposition rather than seeking interactive steering.
- Complex implementations should be broken into sequential dispatches with verification gates, where the filesystem carries state between steps.
- The routing heuristic from ADR-0001 applies unchanged.
- CLI session resume remains available as a manual tool for human operators but is not exposed through Maestro's MCP interface.
