# ClawOS Architecture

## Core Concept: Trust-Aware Data Flow

Every piece of data in an agent system has a source. The fundamental insight:
**if you track where data came from, you can make intelligent decisions about what it's allowed to do.**

Traditional security tries to detect "bad" content. ClawOS takes a different approach:
all content is treated according to its provenance, not its pattern.

## Data Flow

```
User message ──→ [L1 Tag: source=user, trust=community]
                    │
                    ▼
              ┌──────────────┐
              │ L4: Scan for │ ──→ Advisory signals (injection? exfil?)
              │   patterns   │     Feeds into L3 behavioral monitor
              └──────────────┘
                    │
                    ▼
              ┌──────────────┐
              │ L2: Check    │ ──→ Does this skill have permission?
              │ capabilities │     Based on manifest + input trust level
              └──────────────┘
                    │
                    ▼
              ┌──────────────┐
              │ L3: Execute  │ ──→ Sandboxed, monitored, resource-limited
              │ in sandbox   │
              └──────────────┘
                    │
                    ▼
Tool output ──→ [L1 Tag: source=tool:exec, trust=verified]
                    │
                    ▼
              ┌──────────────┐
              │ L0: Validate │ ──→ tool_use/tool_result pairs intact?
              │ session      │     Checkpoint for rollback if needed
              └──────────────┘
                    │
                    ▼
              Anthropic API (clean, validated messages)
```

## Layer Overview

### L0: Session Integrity (Foundation)

**Problem:** Content filters, compaction, and history trimming can corrupt the message array, creating orphaned `tool_result` blocks that brick the agent.

**Solution:** Validate → Repair → Checkpoint → Rollback.

```
src/integrity/
├── types.ts              # Message, Checkpoint, ValidationError types
├── validate.ts           # validateToolPairs, validateCompletion, validateStructure
├── repair.ts             # removeOrphans, removeIncomplete, removeDuplicates
├── checkpoint.ts         # MemoryCheckpointStore, CheckpointManager
└── session-integrity.ts  # SessionIntegrity controller (ties it all together)
```

**Key exports:** `validate()`, `repair()`, `isValid()`, `createSessionIntegrity()`, `createCheckpointManager()`

### L1: Content Tagging

**Problem:** Agent can't distinguish trusted instructions from untrusted tool output.

**Solution:** Tag every piece of data with source, trust level, and provenance chain.

```
src/tagging/
├── types.ts    # TrustLevel, ContentSource, ContentTag, ProvenanceEntry
├── tag.ts      # createTag, resolveTrust, merge, transform, forward, downgrade
└── sources.ts  # userSource, toolSource, skillSource, mcpSource factories
```

**Trust levels:** `owner` > `operator` > `verified` > `community` > `untrusted`

**Key rule:** Trust can never escalate. Combining `verified` + `untrusted` → `untrusted`.

### L2: Capability Control

**Problem:** Skills/tools have implicit unlimited access. A web search skill shouldn't be able to write files.

**Solution:** Skills declare capabilities in manifests. Policy engine enforces them.

```
src/capabilities/
├── types.ts      # Capability, SkillManifest, OperatorPolicy, PermissionResult
├── manifest.ts   # parseManifest, validateManifest, registerManifest
└── policy.ts     # checkPermission, createContext, enforce
```

**Built-in capabilities:** `file_read`, `file_write`, `exec`, `network`, `memory_read`, `memory_write`, `message_send`, `tool_call`

Each capability has a risk level and minimum trust requirement. Operators can override with allow/deny/audit policies.

### L3: Runtime Security

**Problem:** Even permitted operations can be abused (infinite loops, memory bombs, data exfiltration).

**Solution:** Process isolation via bubblewrap + behavioral monitoring + resource limits.

```
src/runtime/
├── types.ts       # IsolationLevel, SandboxConfig, AnomalyRule, SecurityIncident
├── isolation.ts   # selectIsolationLevel, createSandboxConfig, bubblewrap detection
├── monitor.ts     # BehavioralMonitor, DEFAULT_RULES, anomaly detection
└── sandbox.ts     # spawn, execute, killProcess (bubblewrap integration)
```

**Isolation levels:** 0 (none) → 1 (basic) → 2 (strict) → 3 (full bubblewrap)

Mapped from trust: `owner/operator` → 0, `verified` → 1, `community` → 2, `untrusted` → 3

### L4: Signal Detection

**Problem:** Need to flag suspicious patterns without blocking legitimate content.

**Solution:** 50+ regex patterns, advisory-only. Signals inform other layers but never block.

```
src/signals/
├── types.ts             # Signal, PatternDefinition, ScanResult
├── patterns.ts          # INJECTION_PATTERNS, EXFILTRATION_PATTERNS, ENCODING_PATTERNS
├── scanner.ts           # PatternEngine, SignalScanner, detectRepetition
├── emitter.ts           # DefaultSignalEmitter, SignalStore
└── signal-detection.ts  # scanForSignals, hasInjectionSignals, hasExfiltrationSignals
```

**Categories:** `injection`, `exfiltration`, `encoding`, `roleplay`

Each signal has a confidence score (0-1). Emitter can filter by confidence threshold and suppress categories.

### L5: Trust Registry

**Problem:** How do you know a skill hasn't been tampered with? How do you track known vulnerabilities?

**Solution:** Hash pinning, signature verification, CVE tracking.

```
src/registry/
├── types.ts           # TrustEntry, PublisherInfo, VulnerabilityEntry
├── crypto.ts          # calculateHash, verifySignature, key fingerprints
├── store.ts           # RegistryStore, TrustCache
└── trust-registry.ts  # TrustRegistry (register, verify, reportVulnerability)
```

**Workflow:** Register skill with hash → On load, verify hash matches → Check for known CVEs → Verify publisher signature

## Layer Dependencies

```
L5 (Trust Registry) ──────────────── standalone
     │ provides trust metadata to
     ▼
L2 (Capability Control) ◄──── L1 (Content Tagging)
     │ trust-gated permissions       source + trust metadata
     ▼
L3 (Runtime Security) ◄──── L4 (Signal Detection)
     │ isolation + monitoring        advisory signals
     ▼
L0 (Session Integrity) ──────────── standalone (foundation)
```

L0 and L5 are independent. L1-L4 form a connected pipeline.

## Design Principles

1. **Tag, don't filter** — Content is labeled with provenance, not silently dropped
2. **Advisory over blocking** — Signal detection flags, it doesn't gatekeep
3. **Capabilities are explicit** — Denied by default, permitted by manifest
4. **Isolation is proportional** — Lightweight for trusted, heavy for untrusted
5. **Performance is non-negotiable** — <50ms p99 total overhead

## Performance Budget

| Layer | Budget | Approach |
|-------|--------|----------|
| L0: Session Integrity | <5ms | In-memory validation, no I/O during check |
| L1: Content Tagging | <2ms | Metadata attachment only |
| L2: Capability Control | <3ms | In-memory manifest lookup |
| L3: Runtime Security | <10ms | Bubblewrap setup (amortized) |
| L4: Signal Detection | <5ms | Compiled regex + heuristics |
| L5: Trust Registry | <5ms | Cached lookups, async verification |
| **Total** | **<30ms** | Well under 50ms budget |

## Attack Vectors Addressed

| Attack | Layer(s) | Mitigation |
|--------|----------|------------|
| Prompt injection via tool output | L1, L4 | Tagged as untrusted + flagged by patterns |
| Session corruption (orphaned tool_result) | L0 | Validation + auto-repair + checkpoint rollback |
| Malicious skill behavior | L2, L3 | Capability restrictions + process isolation |
| Data exfiltration | L2, L3, L4 | Network gating + output monitoring + pattern detection |
| Supply chain (tampered skills) | L5 | Hash pinning + signature verification |
| Resource exhaustion | L3 | Per-process limits + behavioral anomaly rules |
| Confused deputy | L1 | Trust provenance tracks across boundaries |
| Memory poisoning | L1 | Saved content retains trust tags |

## OpenClaw Integration

Two integration points:

1. **Core fix** — `validateToolResultPairing()` in OpenClaw's `turns.ts`, runs in the message validation chain before every API call
2. **L0 Plugin** — `~/.openclaw/extensions/clawos-l0/`, scans session files on gateway start, validates at runtime

See [OPENCLAW-PLUGIN.md](./OPENCLAW-PLUGIN.md) for details.
