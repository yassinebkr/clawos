# API Reference

## Layer 0: Session Integrity

```typescript
import {
  validate, isValid, repair, repairCopy, formatErrors,
  createSessionIntegrity, createCheckpointManager,
  type Message, type SessionAdapter, type IntegrityConfig,
} from 'clawos';
```

### Validation

**`validate(messages: Message[]): IntegrityValidationResult`**
Full validation: structure, tool pairs, tool completion, unique IDs. Returns all errors found.

**`isValid(messages: Message[]): boolean`**
Fast boolean check. Same validations, short-circuits on first failure.

**`validateToolPairs(messages: Message[]): ValidationError[]`**
Checks every `tool_result` has a matching `tool_use` in the preceding assistant message.

**`validateToolCompletion(messages: Message[]): ValidationError[]`**
Checks every `tool_use` (except in the last message) has a following `tool_result`.

**`validateUniqueIds(messages: Message[]): ValidationError[]`**
Checks no `tool_use.id` appears more than once.

**`validateStructure(messages: Message[]): ValidationError[]`**
Checks valid roles and non-empty content.

### Repair

**`repair(messages: Message[]): RepairResult`**
Mutates messages in-place. Removes orphaned tool_results, incomplete tool_uses, duplicate IDs, and empty messages.

**`repairCopy(messages: Message[]): RepairResult`**
Same as `repair()` but on a deep clone. Original array untouched.

**`reset(session: SessionAdapter, options?: ResetOptions): Promise<ResetResult>`**
Resets session to clean state. Optional archive and system message preservation.

### Checkpoint Manager

**`createCheckpointManager(options?): CheckpointManager`**

```typescript
const mgr = createCheckpointManager({ retention: 5, snapshotMessages: true });
const ckpt = await mgr.create(sessionId, messages, 'api_call');
// ... do risky operation ...
await mgr.commit(ckpt.id);
// or rollback:
const restore = await mgr.getRestoreMessages(ckpt.id, currentMessages);
```

### Session Integrity Controller

**`createSessionIntegrity(config?: Partial<IntegrityConfig>): SessionIntegrity`**

```typescript
const si = createSessionIntegrity({ autoRepair: true, verbose: true });
si.validateOrThrow(session);     // throws SessionIntegrityError if invalid
si.isSessionValid(session);       // boolean
const result = await si.executeToolCycle(session, toolUse, executor); // atomic
const recovery = await si.handleError(session, error); // auto-recover
```

---

## Layer 1: Content Tagging

```typescript
import {
  createTag, tag, resolveTrust, meetsMinTrust,
  merge, transform, forward, downgrade,
  userSource, toolSource, skillSource, agentSource, mcpSource,
  type ContentTag, type TrustLevel, type ContentSource,
} from 'clawos';
```

### Tag Creation

**`createTag(source: ContentSource, content?: string): ContentTag`**
Creates a tag with source metadata and initial provenance entry.

**`tag<T>(content: T, source: ContentSource): TaggedContent<T>`**
Wraps any value with a content tag.

### Trust

**`resolveTrust(tag: ContentTag): TrustLevel`**
Resolves effective trust by walking the provenance chain (minimum trust wins).

**`meetsMinTrust(tag: ContentTag, min: TrustLevel): boolean`**
Checks if tag meets a minimum trust threshold.

Trust levels: `owner` > `operator` > `verified` > `community` > `untrusted`

### Provenance

**`transform(tag, action, newSource?): ContentTag`** — Record a transformation.
**`forward(tag, target): ContentTag`** — Record forwarding to another context.
**`merge(tags[]): ContentTag`** — Merge multiple tags (lowest trust wins).
**`downgrade(tag, level, reason): ContentTag`** — Force-lower trust level.
**`traceProvenance(tag): ProvenanceEntry[]`** — Get full provenance chain.
**`hasUntrustedOrigin(tag): boolean`** — Check if any source in chain is untrusted.

### Source Factories

```typescript
userSource(userId, channel?)     // trust: community
toolSource(toolName)             // trust: verified
skillSource(skillId, publisher?) // trust: community
agentSource(agentId)             // trust: verified
mcpSource(serverId, endpoint?)   // trust: untrusted
```

---

## Layer 2: Capability Control

```typescript
import {
  checkPermission, createContext, enforce,
  validateManifest, parseManifest, registerManifest,
  type SkillManifest, type OperatorPolicy, type ExecutionContext,
} from 'clawos';
```

### Manifest

**`validateManifest(manifest: unknown): ValidationResult`**
Validates a skill manifest has required fields and valid capabilities.

**`parseManifest(raw: string | object): SkillManifest`**
Parses and validates a manifest from JSON string or object.

**`registerManifest(manifest: SkillManifest): void`**
Registers a manifest in the global cache for permission lookups.

### Policy Engine

**`checkPermission(skillId, capability, trustLevel, policy?): PermissionResult`**
Checks if a skill has permission for a capability at the given trust level.

**`createContext(skillId, trustLevel, policy?): ExecutionContext`**
Creates an execution context with resolved permissions and resource limits.

**`enforce(context, capability): EnforceResult`**
Enforces a capability check at runtime. Returns `{ allowed, reason }`.

### Capabilities

Built-in capabilities: `file_read`, `file_write`, `exec`, `network`, `memory_read`, `memory_write`, `message_send`, `tool_call`

Each has a risk level and minimum trust requirement.

---

## Layer 3: Runtime Security

```typescript
import {
  selectIsolationLevel, createSandboxConfig,
  BehavioralMonitor, DEFAULT_RULES,
  execute, spawn, killProcess,
  type SandboxConfig, type IsolationLevel,
} from 'clawos';
```

### Isolation

**`selectIsolationLevel(trustLevel): IsolationLevel`**
Maps trust level to isolation: `owner/operator` → 0 (none), `verified` → 1 (basic), `community` → 2 (strict), `untrusted` → 3 (full).

**`createSandboxConfig(level, options?): SandboxConfig`**
Generates sandbox config with appropriate path/network/resource restrictions.

### Behavioral Monitor

```typescript
const monitor = new BehavioralMonitor(config, rules?, onKill?);
monitor.recordMetric('memory', 150);    // Track resource usage
monitor.recordMetric('networkRequest', 1);
monitor.recordMetric('output', 5000);
monitor.checkTimeout();                  // Returns true if exceeded
monitor.isKilled();                      // True if anomaly triggered kill
monitor.getIncidents();                  // Security incidents
monitor.finalize();                      // Final metrics with duration
```

### Sandbox Execution

**`execute(command, config): Promise<SandboxResult>`**
Runs a command in sandbox with resource limits. Uses bubblewrap when available.

**`spawn(command, config): SandboxedProcess`**
Spawns a long-running sandboxed process with I/O streaming.

---

## Layer 4: Signal Detection

```typescript
import {
  SignalScanner, createScanner, scanForSignals,
  hasInjectionSignals, hasExfiltrationSignals,
  DefaultSignalEmitter, SignalStore,
  ALL_PATTERNS, INJECTION_PATTERNS, EXFILTRATION_PATTERNS,
  type Signal, type ScanResult,
} from 'clawos';
```

### Scanning

**`scanForSignals(text, context?): ScanResult`**
Scans text against all 50+ patterns. Returns matched signals with confidence scores.

**`hasInjectionSignals(text): boolean`**
Quick check for injection patterns.

**`hasExfiltrationSignals(text): boolean`**
Quick check for exfiltration patterns.

**`createScanner(config?): SignalScanner`**
Creates a configurable scanner with custom patterns, confidence thresholds, or category filters.

### Signal Emitter

```typescript
const emitter = new DefaultSignalEmitter({
  minConfidence: 0.5,
  suppressCategories: ['encoding'],
  toL3: true,
});
emitter.setL3Monitor(monitor);  // Forward signals to L3
emitter.emit(signal);
emitter.emitBatch(signals);
```

### Signal Store

```typescript
const store = new SignalStore({ maxSignalsPerSession: 100, maxAgeMs: 3600000 });
store.add(signal);
store.getAll(sessionId);
store.getRecent(sessionId, 60000);        // Last 60s
store.getByCategory(sessionId, 'injection');
store.clear(sessionId);
```

### Patterns

50+ patterns across categories: `injection`, `exfiltration`, `encoding`, `roleplay`

---

## Layer 5: Trust Registry

```typescript
import {
  TrustRegistry, createTrustRegistry,
  calculateHash, compareHashes, verifySignature,
  RegistryStore,
  type TrustEntry, type VerifyResult,
} from 'clawos';
```

### Registry

**`createTrustRegistry(config?): TrustRegistry`**

```typescript
const registry = createTrustRegistry({ autoSync: false });

// Register a skill
await registry.register({
  id: 'my-skill',
  type: 'skill',
  trust: 'verified',
  publisher: { name: 'Author', publicKey: '...' },
  version: { current: '1.0.0' },
  hashes: { sha256: await calculateHash(code) },
});

// Verify integrity
const result = await registry.verify('my-skill');
// { valid: true, trust: 'verified', hashMatch: true }

// Check vulnerabilities
await registry.reportVulnerability('my-skill', { cve: 'CVE-2026-0001', severity: 'high' });
const entry = await registry.get('my-skill');
// entry.vulnerability.status === 'vulnerable'
```

### Crypto

**`calculateHash(content: string | Buffer): string`** — SHA-256 hash.
**`hashFile(path: string): Promise<string>`** — Hash a file.
**`hashDirectory(path: string): Promise<string>`** — Hash directory contents.
**`compareHashes(a, b): boolean`** — Timing-safe comparison.
**`verifySignature(data, signature, publicKey): boolean`** — Ed25519 verification.

---

## Pipeline

```typescript
import { createPipeline } from 'clawos';

const pipeline = createPipeline({
  integrity: { autoRepair: true },
  signals: { minConfidence: 0.5 },
  capabilities: { policy: operatorPolicy },
});

const result = await pipeline.process(content, context);
// result.signals — detected patterns
// result.tags — content tags with provenance
// result.permissions — capability check results
// result.integrity — session validation status
```
