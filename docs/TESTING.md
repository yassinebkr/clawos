# Testing

## Quick Start

```bash
npm test                    # Run all tests
npx vitest --watch          # Watch mode
npx vitest run --coverage   # Coverage report
```

## Structure

```
tests/
├── integrity/
│   ├── validate.test.ts       # L0: validation functions, tool pair checks
│   ├── repair.test.ts         # L0: repair, orphan removal, dedup
│   ├── checkpoint.test.ts     # L0: checkpoint CRUD, prune, rollback
│   └── session-integrity.test.ts  # L0: controller, tool cycles, error handling
├── tagging/
│   ├── tag.test.ts            # L1: tag creation, trust, provenance, serialize
│   ├── trust.test.ts          # L1: trust level ordering, resolution
│   └── sources.test.ts        # L1: source factories, default trust levels
├── capabilities/
│   ├── manifest.test.ts       # L2: manifest parse, validate, register
│   ├── policy.test.ts         # L2: policy engine, operator overrides
│   └── enforcement.test.ts    # L2: permission checks, context, enforcement
├── runtime/
│   ├── isolation.test.ts      # L3: isolation levels, sandbox config
│   └── monitor.test.ts        # L3: behavioral monitor, anomaly rules, kill
├── signals/
│   ├── scanner.test.ts        # L4: pattern matching, repetition detection
│   └── emitter.test.ts        # L4: signal emitter, store, L3 integration
├── registry/
│   └── crypto.test.ts         # L5: hash calculation, signature verification
├── tagging.test.ts            # L1: integration-level tagging tests
├── integrity.test.ts          # L0: integration-level integrity tests
└── integration.test.ts        # Full pipeline: multi-layer attack scenarios
```

## Stats

- **18 test files**
- **372 tests**
- **~1s total test time**

## What Each Layer Tests

### L0: Session Integrity (4 files, ~60 tests)
- Validates tool_use/tool_result pairing
- Detects orphaned, incomplete, and duplicate tool IDs
- Repairs corrupt message arrays
- Checkpoint create/commit/rollback/prune lifecycle
- Content normalization (string vs array content)
- SessionIntegrity controller with auto-repair
- Atomic tool cycle execution with rollback

### L1: Content Tagging (3 files, ~50 tests)
- Tag creation with source and provenance
- Trust level ordering (owner > operator > verified > community > untrusted)
- Trust resolution across provenance chains
- Tag merge, transform, forward, downgrade
- Source factories (user, tool, skill, agent, external, mcp)
- Serialization round-trip

### L2: Capability Control (3 files, ~50 tests)
- Manifest parsing and validation
- Required fields enforcement
- Permission checking against trust levels
- Operator policy overrides (allow/deny/audit)
- Execution context creation
- Resource limit enforcement
- Timeout tracking

### L3: Runtime Security (2 files, ~40 tests)
- Isolation level selection based on trust
- Sandbox config generation
- Bubblewrap availability detection
- Metric recording (memory, network, I/O)
- Anomaly rule evaluation and kill triggers
- Timeout detection
- Incident recording

### L4: Signal Detection (2 files, ~40 tests)
- Pattern matching against 50+ injection/exfiltration/encoding patterns
- Repetition detection (consecutive word repeats)
- Confidence filtering
- Category suppression
- Signal store with session isolation, age pruning, capacity limits
- L3 monitor integration
- Batch scanning

### L5: Trust Registry (1 file, ~11 tests)
- SHA-256 hash calculation
- Hash comparison
- Signature verification
- Key fingerprint calculation
- Public key validation

### Integration (1 file, ~20 tests)
- Full pipeline: content flows through L1→L4→L2→L0
- Attack scenarios: injection, exfiltration, multi-layer attacks
- Provenance chain verification across layers

## Configuration

`vitest.config.ts`:
- Test pattern: `tests/**/*.test.ts`
- Legacy `.test.js` files excluded
- Coverage via v8 (excludes `types.ts` and `index.ts`)
- 10s timeout per test
