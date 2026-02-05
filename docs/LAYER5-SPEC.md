# Layer 5: Trust Registry — Specification

## Purpose

Layer 5 maintains trust metadata for skills, MCP servers, and external tools.
It provides signature verification, hash pinning, and vulnerability tracking
to prevent supply chain attacks and ensure code integrity.

**Core guarantees:**
1. Skills/tools can be verified against known-good signatures
2. Hash pinning prevents silent tampering
3. Vulnerability status is tracked and queryable
4. Trust decisions are cached for performance

## Motivation: Supply Chain Security

Agent systems depend on external code:
- **Skills** — First-party and third-party automation scripts
- **MCP Servers** — External tool providers
- **Plugins** — Extensions to the agent runtime

Any of these can be compromised:
- Malicious updates pushed to package registries
- Typosquatting attacks
- Compromised developer accounts
- Man-in-the-middle during download

Layer 5 provides defense-in-depth against these attacks.

## Architecture

```
┌────────────────────────────────────────────────────────────────┐
│                      Trust Registry (L5)                        │
├──────────────────┬──────────────────┬──────────────────────────┤
│   Verification   │   Registry       │   Vulnerability          │
│                  │                  │                          │
│ • Signatures     │ • Trust entries  │ • CVE tracking           │
│ • Hash pinning   │ • Publisher keys │ • Advisory feeds         │
│ • Integrity      │ • Version pins   │ • Auto-disable           │
│   checks         │ • Allowlists     │   on critical            │
└──────────────────┴──────────────────┴──────────────────────────┘
```

## Trust Model

### Trust Levels for External Code

| Level | Meaning | Verification Required |
|-------|---------|----------------------|
| `pinned` | Exact hash match required | Hash verification |
| `signed` | Valid signature from trusted publisher | Signature verification |
| `known` | In registry, no signature | Hash on first use, warn on change |
| `unknown` | Not in registry | User confirmation required |

### Trust Entry

```typescript
interface TrustEntry {
  /** Unique identifier (e.g., skill name, MCP server URL) */
  id: string;

  /** Entry type */
  type: 'skill' | 'mcp-server' | 'plugin' | 'tool';

  /** Trust level */
  trust: 'pinned' | 'signed' | 'known' | 'unknown';

  /** Publisher information */
  publisher?: {
    id: string;
    name: string;
    publicKey?: string;
    verified: boolean;
  };

  /** Version information */
  version?: {
    current: string;
    pinned?: string;
    allowedRange?: string;
  };

  /** Integrity hashes */
  hashes?: {
    sha256?: string;
    sha512?: string;
    algorithm: 'sha256' | 'sha512';
  };

  /** Signature (if signed) */
  signature?: {
    value: string;
    algorithm: 'ed25519' | 'rsa-sha256';
    keyId: string;
    timestamp: number;
  };

  /** Vulnerability status */
  vulnerability?: {
    status: 'none' | 'low' | 'medium' | 'high' | 'critical';
    cves?: string[];
    advisoryUrl?: string;
    lastChecked: number;
  };

  /** Metadata */
  meta: {
    addedAt: number;
    updatedAt: number;
    source: 'manual' | 'registry' | 'auto';
    notes?: string;
  };
}
```

## Verification Flow

### On Skill/Tool Load

```
1. LOOKUP in registry
   ├── Found → Continue to verification
   └── Not found → Check policy
       ├── Policy: block-unknown → DENY
       └── Policy: prompt-unknown → Ask user
           ├── User approves → Add to registry as 'known'
           └── User denies → DENY

2. VERIFY integrity
   ├── trust=pinned → Hash MUST match exactly
   │   ├── Match → Continue
   │   └── Mismatch → DENY + alert
   │
   ├── trust=signed → Signature MUST verify
   │   ├── Valid → Continue
   │   └── Invalid → DENY + alert
   │
   └── trust=known → Hash check (advisory)
       ├── First load → Record hash
       ├── Match → Continue
       └── Mismatch → WARN + ask user

3. CHECK vulnerabilities
   ├── status=critical → DENY (unless override)
   ├── status=high → WARN prominently
   ├── status=medium/low → Log
   └── status=none → Continue

4. ALLOW execution
```

## Hash Pinning

### Pin Management

```typescript
interface PinManager {
  /** Pin a specific version */
  pin(id: string, hash: string, version?: string): Promise<void>;

  /** Unpin (revert to signed/known) */
  unpin(id: string): Promise<void>;

  /** Check if hash matches pin */
  verifyPin(id: string, hash: string): Promise<PinVerifyResult>;

  /** List all pins */
  listPins(): Promise<TrustEntry[]>;

  /** Update pin to new hash (requires confirmation) */
  updatePin(id: string, newHash: string, reason: string): Promise<void>;
}

interface PinVerifyResult {
  valid: boolean;
  expected?: string;
  actual: string;
  mismatch: boolean;
}
```

### Hash Calculation

```typescript
async function calculateHash(
  content: Buffer | string,
  algorithm: 'sha256' | 'sha512' = 'sha256'
): Promise<string> {
  const crypto = await import('node:crypto');
  const hash = crypto.createHash(algorithm);
  hash.update(content);
  return hash.digest('hex');
}

async function hashDirectory(dir: string): Promise<string> {
  // Deterministic hash of directory contents
  // Sort files, hash each, then hash the hashes
  const files = await walkDir(dir);
  files.sort();
  
  const hashes: string[] = [];
  for (const file of files) {
    const content = await readFile(file);
    const hash = await calculateHash(content);
    hashes.push(`${relativePath(dir, file)}:${hash}`);
  }
  
  return calculateHash(hashes.join('\n'));
}
```

## Signature Verification

### Publisher Keys

```typescript
interface PublisherKey {
  /** Key identifier */
  keyId: string;

  /** Publisher ID */
  publisherId: string;

  /** Public key (PEM or base64) */
  publicKey: string;

  /** Key algorithm */
  algorithm: 'ed25519' | 'rsa';

  /** Key status */
  status: 'active' | 'revoked' | 'expired';

  /** Validity period */
  validFrom: number;
  validUntil?: number;

  /** Fingerprint for display */
  fingerprint: string;
}
```

### Signature Verification

```typescript
async function verifySignature(
  content: Buffer | string,
  signature: string,
  publicKey: string,
  algorithm: 'ed25519' | 'rsa-sha256'
): Promise<SignatureVerifyResult> {
  const crypto = await import('node:crypto');

  try {
    const verify = crypto.createVerify(
      algorithm === 'ed25519' ? 'ed25519' : 'RSA-SHA256'
    );
    verify.update(content);
    
    const isValid = verify.verify(publicKey, signature, 'base64');
    
    return {
      valid: isValid,
      algorithm,
      error: isValid ? undefined : 'Signature verification failed',
    };
  } catch (err) {
    return {
      valid: false,
      algorithm,
      error: err instanceof Error ? err.message : String(err),
    };
  }
}

interface SignatureVerifyResult {
  valid: boolean;
  algorithm: string;
  error?: string;
}
```

## Vulnerability Tracking

### Advisory Sources

```typescript
interface AdvisorySource {
  /** Source identifier */
  id: string;

  /** Source name */
  name: string;

  /** Feed URL */
  feedUrl: string;

  /** Last sync time */
  lastSync: number;

  /** Sync interval */
  syncIntervalMs: number;
}

const DEFAULT_SOURCES: AdvisorySource[] = [
  {
    id: 'github-advisory',
    name: 'GitHub Advisory Database',
    feedUrl: 'https://api.github.com/advisories',
    lastSync: 0,
    syncIntervalMs: 3600_000, // 1 hour
  },
  {
    id: 'nvd',
    name: 'National Vulnerability Database',
    feedUrl: 'https://services.nvd.nist.gov/rest/json/cves/2.0',
    lastSync: 0,
    syncIntervalMs: 3600_000,
  },
];
```

### Vulnerability Entry

```typescript
interface VulnerabilityEntry {
  /** CVE or advisory ID */
  id: string;

  /** Severity */
  severity: 'low' | 'medium' | 'high' | 'critical';

  /** CVSS score (0-10) */
  cvssScore?: number;

  /** Affected package/skill */
  affected: {
    id: string;
    versionRange: string;
  };

  /** Description */
  description: string;

  /** Fix information */
  fix?: {
    version: string;
    available: boolean;
  };

  /** References */
  references: string[];

  /** Timestamps */
  publishedAt: number;
  updatedAt: number;
}
```

### Auto-Disable on Critical

```typescript
async function checkAndEnforce(
  entry: TrustEntry,
  policy: VulnerabilityPolicy
): Promise<EnforcementResult> {
  if (!entry.vulnerability) {
    return { action: 'allow' };
  }

  const severity = entry.vulnerability.status;

  switch (severity) {
    case 'critical':
      if (policy.blockCritical) {
        return {
          action: 'block',
          reason: `Critical vulnerability: ${entry.vulnerability.cves?.join(', ')}`,
          advisory: entry.vulnerability.advisoryUrl,
        };
      }
      break;

    case 'high':
      if (policy.blockHigh) {
        return {
          action: 'block',
          reason: `High severity vulnerability detected`,
        };
      }
      if (policy.warnHigh) {
        return {
          action: 'warn',
          reason: `High severity vulnerability: review recommended`,
        };
      }
      break;

    case 'medium':
    case 'low':
      if (policy.logAll) {
        return {
          action: 'log',
          reason: `${severity} severity vulnerability known`,
        };
      }
      break;
  }

  return { action: 'allow' };
}

interface EnforcementResult {
  action: 'allow' | 'warn' | 'block' | 'log';
  reason?: string;
  advisory?: string;
}

interface VulnerabilityPolicy {
  blockCritical: boolean;
  blockHigh: boolean;
  warnHigh: boolean;
  logAll: boolean;
}
```

## Registry Storage

### Local Registry

```typescript
interface RegistryStore {
  /** Get entry by ID */
  get(id: string): Promise<TrustEntry | undefined>;

  /** Set/update entry */
  set(entry: TrustEntry): Promise<void>;

  /** Delete entry */
  delete(id: string): Promise<void>;

  /** List all entries */
  list(filter?: RegistryFilter): Promise<TrustEntry[]>;

  /** Search entries */
  search(query: string): Promise<TrustEntry[]>;

  /** Import from external registry */
  import(entries: TrustEntry[], merge: boolean): Promise<ImportResult>;

  /** Export registry */
  export(): Promise<TrustEntry[]>;
}

interface RegistryFilter {
  type?: TrustEntry['type'];
  trust?: TrustEntry['trust'];
  publisher?: string;
  hasVulnerability?: boolean;
}
```

### File-Based Storage

```typescript
// Registry stored as JSON file
// ~/.clawos/trust-registry.json

interface RegistryFile {
  version: 1;
  updatedAt: number;
  entries: Record<string, TrustEntry>;
  publishers: Record<string, PublisherKey[]>;
  advisories: VulnerabilityEntry[];
}
```

## Configuration

```typescript
interface Layer5Config {
  /** Enable trust registry */
  enabled: boolean;

  /** Registry file path */
  registryPath: string;

  /** Policy for unknown entries */
  unknownPolicy: 'block' | 'prompt' | 'allow-once' | 'allow-remember';

  /** Require signatures for skills */
  requireSignatures: boolean;

  /** Hash algorithm preference */
  hashAlgorithm: 'sha256' | 'sha512';

  /** Vulnerability policy */
  vulnerability: VulnerabilityPolicy;

  /** Advisory sync settings */
  advisorySync: {
    enabled: boolean;
    sources: string[];
    intervalMs: number;
  };

  /** Auto-pin on first use */
  autoPinOnFirstUse: boolean;

  /** Cache settings */
  cache: {
    enabled: boolean;
    ttlMs: number;
    maxEntries: number;
  };
}
```

## API

### Trust Registry Interface

```typescript
interface TrustRegistry {
  /** Verify a skill/tool before execution */
  verify(id: string, content: Buffer | string): Promise<VerifyResult>;

  /** Get trust entry */
  getEntry(id: string): Promise<TrustEntry | undefined>;

  /** Add/update trust entry */
  setEntry(entry: TrustEntry): Promise<void>;

  /** Remove trust entry */
  removeEntry(id: string): Promise<void>;

  /** Pin a specific hash */
  pin(id: string, hash: string, version?: string): Promise<void>;

  /** Unpin */
  unpin(id: string): Promise<void>;

  /** Check for vulnerabilities */
  checkVulnerabilities(id: string): Promise<VulnerabilityEntry[]>;

  /** Sync advisories from sources */
  syncAdvisories(): Promise<SyncResult>;

  /** Register a publisher key */
  registerPublisher(key: PublisherKey): Promise<void>;

  /** Revoke a publisher key */
  revokePublisher(keyId: string, reason: string): Promise<void>;

  /** Export registry for backup/sharing */
  export(): Promise<RegistryExport>;

  /** Import registry entries */
  import(data: RegistryExport, merge: boolean): Promise<ImportResult>;
}
```

### Result Types

```typescript
interface VerifyResult {
  /** Overall verification passed */
  verified: boolean;

  /** Trust level of the entry */
  trust: TrustEntry['trust'] | 'unknown';

  /** Hash verification result */
  hash?: {
    matched: boolean;
    expected?: string;
    actual: string;
  };

  /** Signature verification result */
  signature?: SignatureVerifyResult;

  /** Vulnerability check result */
  vulnerability?: EnforcementResult;

  /** Recommended action */
  action: 'allow' | 'warn' | 'block' | 'prompt';

  /** Reason for action */
  reason?: string;
}

interface SyncResult {
  success: boolean;
  entriesUpdated: number;
  newVulnerabilities: number;
  errors: string[];
}

interface ImportResult {
  success: boolean;
  imported: number;
  skipped: number;
  conflicts: string[];
}

interface RegistryExport {
  version: 1;
  exportedAt: number;
  entries: TrustEntry[];
  publishers: PublisherKey[];
}
```

## Integration Points

### With L2 (Capability Control)

L5 provides trust context for capability decisions:

```typescript
// L2 queries L5 before granting capabilities
async function checkCapability(
  skillId: string,
  capability: string,
  registry: TrustRegistry
): Promise<boolean> {
  const entry = await registry.getEntry(skillId);
  
  // Unknown skills get restricted capabilities
  if (!entry || entry.trust === 'unknown') {
    return isRestrictedCapability(capability) ? false : true;
  }
  
  // Pinned/signed skills get full manifest capabilities
  if (entry.trust === 'pinned' || entry.trust === 'signed') {
    return true; // L2 handles manifest checking
  }
  
  // Known but unsigned: warn on sensitive capabilities
  if (isSensitiveCapability(capability)) {
    logWarning(`Unsigned skill ${skillId} using ${capability}`);
  }
  
  return true;
}
```

### With L3 (Runtime Security)

L5 informs L3's behavioral monitoring:

```typescript
// L3 gets trust context for anomaly detection
interface RuntimeContext {
  trustLevel: TrustEntry['trust'];
  hasVulnerabilities: boolean;
  isSignatureVerified: boolean;
}
```

## Performance

### Budget: 5ms

| Operation | Target | Approach |
|-----------|--------|----------|
| Entry lookup | 1ms | In-memory cache |
| Hash verification | 2ms | Streaming hash |
| Signature verification | 5ms | Cached key lookup |
| Vulnerability check | 1ms | Pre-indexed by ID |

### Caching Strategy

```typescript
class TrustCache {
  private cache: Map<string, CacheEntry> = new Map();
  private maxEntries: number;
  private ttlMs: number;

  get(id: string): TrustEntry | undefined {
    const entry = this.cache.get(id);
    if (!entry) return undefined;
    
    if (Date.now() > entry.expiresAt) {
      this.cache.delete(id);
      return undefined;
    }
    
    return entry.value;
  }

  set(id: string, value: TrustEntry): void {
    // LRU eviction if at capacity
    if (this.cache.size >= this.maxEntries) {
      const oldest = this.findOldest();
      if (oldest) this.cache.delete(oldest);
    }
    
    this.cache.set(id, {
      value,
      expiresAt: Date.now() + this.ttlMs,
      accessedAt: Date.now(),
    });
  }
}
```

## Test Cases

### Verification
1. Pinned entry with matching hash → allow
2. Pinned entry with mismatched hash → block
3. Signed entry with valid signature → allow
4. Signed entry with invalid signature → block
5. Known entry, first load → record hash, allow
6. Known entry, hash changed → warn, prompt user
7. Unknown entry, block policy → block
8. Unknown entry, prompt policy → prompt user

### Vulnerability
9. No vulnerabilities → allow
10. Critical vulnerability → block (if policy set)
11. High vulnerability → warn
12. Medium/low → log only

### Registry Operations
13. Add entry → persisted
14. Update entry → version incremented
15. Delete entry → removed
16. Export → valid JSON
17. Import with merge → combines entries
18. Import without merge → replaces all

### Performance
19. 1000 lookups → <1s total
20. Hash 1MB file → <50ms
21. Signature verify → <10ms
