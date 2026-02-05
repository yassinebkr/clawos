# ClawOS Security Audit

**Date:** February 5, 2026  
**Auditor:** ClawOS Development Team  
**Scope:** All 6 layers (L0-L5)

## Executive Summary

Overall architecture is sound. Found **8 issues** (2 high, 4 medium, 2 low). No critical vulnerabilities. Most issues are edge cases or hardening opportunities.

---

## Layer 0: Session Integrity

### ✅ Strengths
- Proper tool_use/tool_result pairing validation
- Backward iteration in repair prevents cascade issues
- Constant-time operations where possible
- Empty message cleanup after repair

### ⚠️ Issues Found

#### [L0-1] MEDIUM: Race condition in repair + persist
**Location:** `repair.ts` — messages mutated in place  
**Issue:** If two repairs run concurrently on the same session, mutations can interleave.  
**Fix:** Add session lock before repair, or use immutable repair (repairCopy).

```typescript
// Current: mutates in place
export function repair(messages: Message[]): RepairResult

// Recommended: Use repairCopy() in production, or add locking
```

#### [L0-2] LOW: isSystemPromptLike patterns are weak
**Location:** `repair.ts:165-172`  
**Issue:** Heuristic patterns for detecting system prompts could miss custom formats.  
**Fix:** Allow configurable patterns or use explicit markers.

---

## Layer 1: Content Tagging

### ✅ Strengths
- Trust can only decrease, never increase (enforced in `downgrade()`)
- Provenance chain capped at 50 entries (DoS prevention)
- Compact serialization format for transport
- Constant-time trust resolution

### ⚠️ Issues Found

#### [L1-1] MEDIUM: Tag ID generation is predictable
**Location:** `tag.ts:14-17`  
**Issue:** Tag IDs use counter + Math.random() — not cryptographically secure.  
**Risk:** In adversarial contexts, tag IDs could be predicted/forged.  
**Fix:** Use `randomUUID()` from node:crypto instead.

```typescript
// Current
const prefix = Math.random().toString(36).slice(2, 8);
function generateId(): string {
  return `ct_${prefix}_${(++counter).toString(36)}_${Date.now().toString(36)}`;
}

// Recommended
import { randomUUID } from 'node:crypto';
function generateId(): string {
  return `ct_${randomUUID()}`;
}
```

#### [L1-2] LOW: No validation on deserialized tags
**Location:** `tag.ts:deserializeTag()`  
**Issue:** Deserializing a malicious tag payload could inject arbitrary trust levels.  
**Fix:** Validate trust level is one of the allowed values.

```typescript
// Add after parsing
const validTrust = ['system', 'user', 'tool', 'untrusted'];
if (!validTrust.includes(c.tr)) {
  throw new Error(`Invalid trust level: ${c.tr}`);
}
```

---

## Layer 2: Capability Control

### ✅ Strengths
- Defense in depth: multiple check layers (global deny → skill deny → trust → allow)
- Unknown capabilities default to high risk
- Domain/path wildcards properly implemented
- Timeout checks integrated into enforce()

### ⚠️ Issues Found

#### [L2-1] MEDIUM: Path matching regex can be slow
**Location:** `policy.ts:matchesPath()`  
**Issue:** Converting globs to regex on every check is expensive. Malicious patterns could cause ReDoS.  
**Fix:** Pre-compile allowed path patterns, add regex timeout/complexity limit.

```typescript
// Current: compiles regex on every call
const regexStr = pattern
  .replace(/[.+^${}()|[\]\\]/g, '\\$&')
  .replace(/\*\*/g, '⧫')
  .replace(/\*/g, '[^/]*')
  .replace(/⧫/g, '.*');

// Recommended: Pre-compile in createContext(), add RE2 or limit
```

#### [L2-2] MEDIUM: No capability inheritance validation
**Location:** `policy.ts:checkPermission()`  
**Issue:** If a skill declares `fs:write`, it implicitly needs `fs:read` in most cases. No validation that dependencies are declared.  
**Fix:** Add capability dependency graph and validate completeness.

---

## Layer 3: Runtime Security

### ✅ Strengths
- Three isolation levels (inline, process, bubblewrap)
- Resource limits enforced via V8 flags
- Behavioral monitor with incident tracking
- Automatic timeout killing

### ⚠️ Issues Found

#### [L3-1] HIGH: Level 0 (inline) has no isolation
**Location:** `sandbox.ts:executeInline()`  
**Issue:** Level 0 uses `require()` to load skill code directly — no sandbox, skill has full process access.  
**Risk:** Malicious skill could access process memory, env vars, everything.  
**Fix:** 
1. Document Level 0 is only for trusted first-party skills
2. Add warning log when Level 0 is used
3. Consider removing Level 0 entirely

```typescript
// Current
const skill = require(skillPath);  // DANGER: full access

// Recommended: At minimum, log warning
console.warn(`[ClawOS] Level 0 execution has NO isolation — only use for trusted skills`);
```

#### [L3-2] HIGH: Temp directory not secured
**Location:** `sandbox.ts:spawn()`  
**Issue:** Temp directory is created with default permissions. Other users on system could read/write.  
**Fix:** Create with restricted permissions (0o700).

```typescript
// Current
mkdirSync(config.tempDir, { recursive: true });

// Recommended
mkdirSync(config.tempDir, { recursive: true, mode: 0o700 });
```

---

## Layer 4: Signal Detection

### ✅ Strengths
- Advisory-only design (doesn't block, just signals)
- Trust-aware confidence adjustment
- Timeout + max signals limits (DoS prevention)
- Regex lastIndex reset (prevents state leakage)

### ⚠️ Issues Found

#### [L4-1] INFO: Pattern coverage gaps
**Location:** `patterns.ts`  
**Issue:** Missing patterns for:
- Unicode homoglyph attacks ("іgnore" with Cyrillic і)
- Prompt injection via markdown/HTML comments
- Multi-language injections (Chinese, Arabic, etc.)
**Fix:** Add homoglyph normalization, expand pattern library.

---

## Layer 5: Trust Registry

### ✅ Strengths
- Constant-time hash comparison (timing attack prevention)
- Hash + signature verification
- Vulnerability status tracking
- LRU cache with TTL

### ⚠️ Issues Found

#### [L5-1] INFO: Registry file not encrypted
**Location:** `store.ts`  
**Issue:** Trust registry stored as plain JSON. If attacker has file access, they can read/modify trust entries.  
**Mitigation:** File permissions should be restricted (0o600). Consider optional encryption.

---

## Summary Table

| ID | Layer | Severity | Issue | Status |
|----|-------|----------|-------|--------|
| L0-1 | Session Integrity | MEDIUM | Race condition in repair | Fix needed |
| L0-2 | Session Integrity | LOW | Weak system prompt detection | Acceptable |
| L1-1 | Content Tagging | MEDIUM | Predictable tag IDs | Fix needed |
| L1-2 | Content Tagging | LOW | No deserialization validation | Fix needed |
| L2-1 | Capability Control | MEDIUM | ReDoS in path matching | Fix needed |
| L2-2 | Capability Control | MEDIUM | No capability dependencies | Enhancement |
| L3-1 | Runtime Security | HIGH | Level 0 has no isolation | Document + warn |
| L3-2 | Runtime Security | HIGH | Temp dir permissions | Fix needed |
| L4-1 | Signal Detection | INFO | Pattern coverage gaps | Enhancement |
| L5-1 | Trust Registry | INFO | Registry file unencrypted | Acceptable |

---

## Recommended Fixes (Priority Order)

### Immediate (Before Production)
1. **[L3-2]** Fix temp directory permissions
2. **[L3-1]** Add warning for Level 0 execution
3. **[L1-1]** Switch to cryptographic tag IDs

### Short-term
4. **[L0-1]** Add session locking or use immutable repair
5. **[L2-1]** Pre-compile path patterns
6. **[L1-2]** Add deserialization validation

### Long-term
7. **[L2-2]** Implement capability dependency validation
8. **[L4-1]** Expand pattern library
