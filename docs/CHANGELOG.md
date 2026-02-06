# Changelog

## v0.3.0 (2026-02-06)

### New Features

**L0: Bootstrap File Integrity Monitor**
- New `bootstrap-integrity.ts` module monitors critical bootstrap files for unauthorized modifications
- Tiered protection system with three levels:
  - **Critical** — Files that must never change (e.g., core validation logic). Modifications trigger immediate alerts.
  - **Sensitive** — Files that change rarely and only with explicit intent. Changes are logged and flagged.
  - **Monitored** — Files tracked for audit purposes. Changes are recorded silently.
- Hash-based change detection with configurable check intervals

**L4: Self-Modification Signal Detection**
- New detection patterns for agents attempting to modify their own source code or configuration
- Catches patterns like writing to plugin directories, editing validation logic, overwriting security manifests
- Advisory-only (consistent with L4 design) — flags but does not block

### Bug Workaround

**OpenClaw `gateway_start` Hook Timing Bug**
- **Discovery:** OpenClaw fires `gateway_start` BEFORE external plugins register their hook handlers. Any code in a plugin's `gateway_start` handler never executes — not on cold restart, not on soft reload (SIGUSR1). Confirmed by breadcrumb file test (file was never created). **This affects ALL external plugins using `gateway_start`.**
- **Workaround:** Implemented **lazy initialization pattern** — every command handler and the `before_agent_start` hook now calls `ensureInitialized()` which runs startup logic (session scan/repair) exactly once on first invocation.
- Removed `gateway_start` hook registration entirely. See [OPENCLAW-PLUGIN.md](./OPENCLAW-PLUGIN.md) for details and code examples.

### Test Coverage

- **Before:** 372 tests, 0 failing, 18 test files
- **After:** 492 tests, 0 failing, 21 test files

New test files:
- `tests/integrity/bootstrap-integrity.test.ts` — tiered protection, hash checks, alert triggers
- `tests/signals/self-modification.test.ts` — self-modification pattern detection
- `tests/plugin/lazy-init.test.ts` — lazy initialization correctness, idempotency

---

## v0.1.1 (2026-02-06)

### Bug Fixes

**L0: Session Integrity — validate.ts**
- **Content normalization missing.** All validation functions assumed `msg.content` was always an array, but it can be a string. Added `normalizeContent()` helper to handle both formats. Without this, `getToolUseIds()`, `getToolResultIds()`, `validateToolPairs()`, and every `msg.content.filter(...)` call would crash on string content.
- **Orphaned IDs not reported when no preceding assistant.** When a `tool_result` had no preceding assistant message, the validator reported `missing_preceding_message` but didn't add each tool_result to the `orphanedIds` list. Result: `validate().orphanedIds` was incomplete.

**L0: Session Integrity — checkpoint.ts**
- **Prune timing bug.** `CheckpointManager.commit()` didn't re-prune after committing. Since `prune()` only removes committed checkpoints, and it ran during `create()` (before the checkpoint was committed), newly committed checkpoints could exceed the retention limit. Fix: prune again after commit.

**L4: Signal Detection — scanner.ts**
- **Repetition detection threshold too strict.** `detectRepetition()` required 10+ words to start scanning. Short repetitive strings like `"stop stop stop stop stop"` (5 words) were silently ignored. Lowered minimum to 5 words.

**L4: Signal Detection — patterns.ts**
- **Missing exfiltration patterns.** Added 4 new patterns:
  - HTTP exfil via `fetch`/`curl`/`wget` to suspicious destinations
  - `send ... to https://` instructions
  - Pipe-to-shell: `curl ... | bash`
  - Generic `send/post/upload/exfil ... to webhook/external/remote`

### Test Coverage

- **Before:** 135 tests, 7 failing, 9 test files
- **After:** 372 tests, 0 failing, 18 test files

New test files:
- `tests/integrity/checkpoint.test.ts` — checkpoint manager, pruning, rollback
- `tests/integrity/session-integrity.test.ts` — controller, tool cycles, error recovery
- `tests/capabilities/manifest.test.ts` — manifest parsing, validation, registration
- `tests/capabilities/enforcement.test.ts` — permission checks, context creation, enforcement
- `tests/runtime/isolation.test.ts` — level selection, sandbox config, bubblewrap detection
- `tests/runtime/monitor.test.ts` — metrics, anomaly detection, kill behavior, timeouts
- `tests/signals/emitter.test.ts` — emitter filtering, L3 integration, signal store
- `tests/tagging/sources.test.ts` — source factories, default trust, system sources
- `tests/tagging/tag.test.ts` — tag creation, trust resolution, provenance, serialization

### OpenClaw Core Fix

- Added `validateToolResultPairing()` to OpenClaw's `turns.ts` — removes orphaned tool_results before API calls
- Added auto-reset detection for `unexpected tool_use_id` errors in `agent-runner-execution.ts`
- Wired into validation chain in `attempt.ts` after history limiting

### Plugin Fix

- Moved L0 startup scan from `register()` to `gateway_start` hook — no longer logs on `gateway stop`

## v0.1.0 (2026-02-05)

### Initial Release

- Layer 0: Session Integrity — validate, repair, checkpoint, atomic tool cycles
- Layer 1: Content Tagging — source tracking, trust levels, provenance chains
- Layer 2: Capability Control — skill manifests, policy engine, permission enforcement
- Layer 3: Runtime Security — process isolation, behavioral monitoring, sandbox
- Layer 4: Signal Detection — 50+ attack patterns, advisory-only scanner
- Layer 5: Trust Registry — hash pinning, signature verification, CVE tracking
- OpenClaw L0 plugin deployed with startup scan
- Case study: 3 session corruption incidents (CASE-STUDY-001.md)
