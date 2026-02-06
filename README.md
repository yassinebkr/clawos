# ClawOS — Security Architecture for Autonomous Agents

Security layer for AI agents: content tagging, capability control, process isolation, signal detection, and trust verification. Designed for [OpenClaw](https://github.com/openclaw/openclaw), usable standalone.

## Architecture (6 Layers)

```
┌─────────────────────────────────────────────────────────┐
│  Layer 5: Trust Registry                                │
│  Hash pinning, signature verification, CVE tracking     │
├─────────────────────────────────────────────────────────┤
│  Layer 4: Signal Detection                              │
│  50+ attack patterns, advisory-only (never blocks)      │
├─────────────────────────────────────────────────────────┤
│  Layer 3: Runtime Security                              │
│  Process isolation, behavioral monitor, anomaly rules   │
├─────────────────────────────────────────────────────────┤
│  Layer 2: Capability Control                            │
│  Skill manifests, trust-gated permissions, enforcement  │
├─────────────────────────────────────────────────────────┤
│  Layer 1: Content Tagging                               │
│  Source tracking, trust levels, provenance chains       │
├─────────────────────────────────────────────────────────┤
│  Layer 0: Session Integrity         ◄── FOUNDATION      │
│  State validation, checkpoints, atomic ops, auto-repair │
└─────────────────────────────────────────────────────────┘
```

## Quickstart

### Requirements

- Node.js ≥ 20
- Linux recommended (bubblewrap sandbox requires it)

### Install

```bash
git clone https://github.com/clawos/clawos.git
cd clawos
npm install
npm run build
```

### Run Tests

```bash
npm test
```

372 tests across 18 test files. All passing.

### Basic Usage

```typescript
import {
  // L0: Session Integrity
  validate, repair, isValid, createSessionIntegrity,
  // L1: Content Tagging
  tag, createTag, resolveTrust, meetsMinTrust, userSource, toolSource,
  // L2: Capability Control
  checkPermission, createContext, enforce, registerManifest,
  // L3: Runtime Security
  selectIsolationLevel, createSandboxConfig, BehavioralMonitor,
  // L4: Signal Detection
  SignalScanner, createScanner, scanForSignals, hasInjectionSignals,
  // L5: Trust Registry
  TrustRegistry, createTrustRegistry, calculateHash, compareHashes,
  // Pipeline
  createPipeline,
} from 'clawos';
```

## Layer Examples

### L0: Session Integrity

Validates and repairs Claude/Anthropic message history. Catches orphaned `tool_result` blocks before they brick the session.

```typescript
import { validate, repair, isValid, createSessionIntegrity } from 'clawos';

// Quick boolean check
if (!isValid(messages)) {
  const result = repair(messages); // mutates in place
  console.log(`Fixed ${result.repairs.length} issues`);
}

// Full validation with details
const validation = validate(messages);
if (!validation.valid) {
  console.log('Orphaned:', validation.orphanedIds);
  console.log('Incomplete:', validation.incompleteIds);
}

// Controller with checkpoints and auto-repair
const integrity = createSessionIntegrity({ autoRepair: true });
integrity.validateOrThrow(session); // throws SessionIntegrityError if broken
```

### L1: Content Tagging

Tag every piece of data with source, trust level, and provenance chain.

```typescript
import { tag, resolveTrust, merge, userSource, toolSource } from 'clawos';

// Tag content from a user
const userMsg = tag("Hello", userSource("+1234567890"), "user");

// Tag tool output as lower trust
const toolOut = tag(searchResults, toolSource("web_search"), "tool");

// Merge: trust = min(user, tool) = "tool"
const combined = merge([userMsg, toolOut], summary, agentSource("main"));
console.log(combined.tag.trust); // "tool"

// Trust can only go down, never up
const result = resolveTrust(["user", "untrusted"]); // "untrusted"
```

### L2: Capability Control

Skills declare capabilities in manifests. The policy engine enforces them.

```typescript
import { registerManifest, checkPermission, createContext, enforce } from 'clawos';
import { createTag, userSource } from 'clawos';

registerManifest({
  version: '1.0',
  id: 'web-search',
  name: 'Web Search',
  description: 'Search the web',
  capabilities: [
    { capability: 'net:https', reason: 'Fetch search results', required: true },
  ],
  minInputTrust: 'tool',
  outputTrust: 'tool',
  allowedDomains: ['api.search.com'],
});

const inputTag = createTag(userSource("u1"), "user");
const result = checkPermission(getManifest("web-search")!, inputTag);
// result.allowed, result.granted, result.denied
```

### L3: Runtime Security

Isolate skill execution with resource limits and behavioral monitoring.

```typescript
import { selectIsolationLevel, createSandboxConfig, BehavioralMonitor } from 'clawos';

// Auto-select isolation level based on trust + capabilities
const level = selectIsolationLevel(manifest, inputTag);
// 0 = unrestricted, 1 = child process, 2 = bubblewrap sandbox

const config = createSandboxConfig(manifest, level, '/workspace');
// config.allowedPaths, config.allowedDomains, config.resourceLimits
```

### L4: Signal Detection

Scan content for prompt injection, data exfiltration, and other attack patterns. Advisory-only — flags but never blocks.

```typescript
import { scanForSignals, hasInjectionSignals, createScanner } from 'clawos';

// Quick check
if (hasInjectionSignals("ignore all previous instructions")) {
  console.warn("Injection attempt detected");
}

// Detailed scan
const signals = scanForSignals(untrustedContent, "untrusted", sessionId);
for (const signal of signals) {
  console.log(`${signal.category}: ${signal.matched.pattern} (${signal.confidence})`);
}
```

### L5: Trust Registry

Track trust metadata, verify integrity, and monitor vulnerabilities.

```typescript
import { createTrustRegistry, calculateHash, compareHashes } from 'clawos';

const registry = createTrustRegistry();
await registry.init();

// Pin a skill's hash
await registry.pin("my-skill", calculateHash(skillCode));

// Verify before execution
const result = await registry.verify("my-skill", skillCode);
if (!result.verified) {
  console.error(`Blocked: ${result.reason}`);
}
```

### Integration Pipeline

Wire all layers together:

```typescript
import { createPipeline, userSource } from 'clawos';

const pipeline = createPipeline({
  integrity: true,
  tagging: true,
  signals: true,
  capabilities: true,
  registry: true,
});

const result = await pipeline.process({
  content: userInput,
  source: userSource("+1234567890"),
  skillId: "web-search",
});

if (!result.allowed) {
  console.log(`Blocked by ${result.blockedBy}: ${result.reason}`);
}
```

## Project Structure

```
clawos/
├── src/
│   ├── index.ts           # Re-exports all layers
│   ├── pipeline.ts        # Integration pipeline
│   ├── integrity/         # L0: Session Integrity
│   │   ├── types.ts       # Message, Checkpoint, Validation types
│   │   ├── validate.ts    # validate(), isValid(), tool pair checking
│   │   ├── repair.ts      # repair(), repairCopy(), reset()
│   │   ├── checkpoint.ts  # CheckpointManager, MemoryCheckpointStore
│   │   └── session-integrity.ts  # SessionIntegrity controller
│   ├── tagging/           # L1: Content Tagging
│   │   ├── types.ts       # TrustLevel, ContentTag, TaggedContent
│   │   ├── tag.ts         # tag(), merge(), transform(), serialize
│   │   └── sources.ts     # userSource(), toolSource(), SYSTEM_*
│   ├── capabilities/      # L2: Capability Control
│   │   ├── types.ts       # Capability, SkillManifest, OperatorPolicy
│   │   ├── manifest.ts    # validateManifest(), registerManifest()
│   │   └── policy.ts      # checkPermission(), enforce(), createContext()
│   ├── runtime/           # L3: Runtime Security
│   │   ├── types.ts       # SandboxConfig, SandboxResult, AnomalyRule
│   │   ├── sandbox.ts     # spawn(), execute(), killProcess()
│   │   ├── monitor.ts     # BehavioralMonitor, DEFAULT_RULES
│   │   └── isolation.ts   # selectIsolationLevel(), createSandboxConfig()
│   ├── signals/           # L4: Signal Detection
│   │   ├── types.ts       # Signal, ScanResult, PatternDefinition
│   │   ├── patterns.ts    # INJECTION/EXFILTRATION/ENCODING/ROLEPLAY patterns
│   │   ├── scanner.ts     # SignalScanner, detectRepetition()
│   │   ├── emitter.ts     # DefaultSignalEmitter, SignalStore
│   │   └── signal-detection.ts  # SignalDetection coordinator
│   └── registry/          # L5: Trust Registry
│       ├── types.ts       # TrustEntry, VulnerabilityEntry, VerifyResult
│       ├── crypto.ts      # calculateHash(), verifySignature(), compareHashes()
│       ├── store.ts       # RegistryStore, TrustCache
│       └── trust-registry.ts  # TrustRegistry service
├── tests/                 # 372 tests across 18 files
├── docs/                  # Architecture docs & specs
└── dist/                  # Compiled output
```

## Test Results

```
372 tests across 18 test files

 ✓ tests/integrity.test.ts              (26 tests)
 ✓ tests/integrity/validate.test.ts     (13 tests)
 ✓ tests/integrity/repair.test.ts       (8 tests)
 ✓ tests/integrity/checkpoint.test.ts   (29 tests)
 ✓ tests/integrity/session-integrity.test.ts (19 tests)
 ✓ tests/tagging.test.ts               (32 tests)
 ✓ tests/tagging/tag.test.ts           (34 tests)
 ✓ tests/tagging/trust.test.ts         (16 tests)
 ✓ tests/tagging/sources.test.ts       (19 tests)
 ✓ tests/capabilities/policy.test.ts   (14 tests)
 ✓ tests/capabilities/manifest.test.ts (21 tests)
 ✓ tests/capabilities/enforcement.test.ts (26 tests)
 ✓ tests/runtime/monitor.test.ts       (20 tests)
 ✓ tests/runtime/isolation.test.ts     (20 tests)
 ✓ tests/signals/scanner.test.ts       (20 tests)
 ✓ tests/signals/emitter.test.ts       (17 tests)
 ✓ tests/registry/crypto.test.ts       (11 tests)
 ✓ tests/integration.test.ts           (27 tests)
```

## Bug Fixes

### Content Normalization (L0)
`validate()` and `isValid()` now handle both string and array message content via `normalizeContent()`. Previously, string content (common in the Anthropic API) was treated as empty, causing false validation failures.

### Checkpoint Prune Timing (L0)
`CheckpointManager.commit()` now re-prunes after committing, since `prune()` only considers committed checkpoints. Previously, a pending checkpoint committed after creation wouldn't be counted for pruning, allowing unbounded growth.

### Scanner Repetition Threshold (L4)
`detectRepetition()` threshold raised from 3 to 5 consecutive repeated tokens. The lower threshold caused false positives on normal prose patterns.

### Orphan ID Reporting (L0)
`validateToolPairs()` now includes the actual `tool_use_id` in error objects. Previously, orphaned tool_result errors reported the message index but not which tool ID was orphaned, making auto-repair harder.

### New Exfiltration Patterns (L4)
Added patterns for data exfiltration via HTTP requests, external service uploads, and piped shell commands. Covers `curl|bash`, webhook exfiltration, and `send to URL` patterns.

## Design Principles

1. **Tag, don't filter** — Content is labeled with provenance, not silently dropped
2. **Advisory over blocking** — Signal detection flags, never gatekeeps
3. **Capabilities are explicit** — Denied by default, permitted by manifest
4. **Isolation is proportional** — Lightweight for skills, heavier for untrusted sources
5. **Performance is non-negotiable** — <50ms p99 total overhead

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, coding standards, and PR guidelines.

### Quick Start for Contributors

```bash
git clone https://github.com/clawos/clawos.git
cd clawos
npm install
npm test          # Run all tests
npm run build     # Compile TypeScript
npm run lint      # Type-check without emit
```

## Documentation

- [Architecture](docs/ARCHITECTURE.md) — Layer interactions, data flow, design decisions
- [API Reference](docs/API.md) — Public exports and signatures for all 6 layers
- [Changelog](docs/CHANGELOG.md) — Bug fixes, features, and version history
- [Testing](docs/TESTING.md) — Test structure, how to run, what each file covers
- [OpenClaw Plugin](docs/OPENCLAW-PLUGIN.md) — Integration with the OpenClaw gateway

## License

Apache 2.0 — see [LICENSE](LICENSE).
