# Layer 2: Capability Control — Specification

## Purpose

Every skill, tool, and MCP server declares what it needs in a **manifest**.
At runtime, the capability controller enforces those declarations:
- A skill that declares `fs:read` cannot write files
- A tool receiving `untrusted` input cannot access `network`
- An MCP server without `credentials` capability cannot read secrets

**Default: deny everything.** Capabilities must be explicitly granted.

## Core Concepts

### Capability
A specific permission to perform an action. Fine-grained but practical.

### Manifest
A declaration file shipped with every skill/tool. Lists:
- What capabilities it needs
- What trust levels it accepts as input
- What resources it accesses
- What it outputs

### Policy
Rules that determine which capabilities are granted based on:
- The manifest declarations
- The trust level of the current input
- The operator's configuration (overrides)

## Capability Taxonomy

Organized by domain. Each capability has a scope (broad) and action (specific).

```
filesystem:
  fs:read          — Read files
  fs:write         — Write/create files
  fs:delete        — Delete files
  fs:temp          — Use temp directory only

network:
  net:http         — Make HTTP requests
  net:https        — Make HTTPS requests
  net:dns          — DNS lookups
  net:listen       — Bind a port

process:
  proc:exec        — Execute commands
  proc:spawn       — Spawn child processes
  proc:signal      — Send signals to processes

environment:
  env:read         — Read environment variables
  env:secrets      — Access credentials/API keys

data:
  data:memory      — Read/write agent memory files
  data:database    — Access databases
  data:clipboard   — Access clipboard

agent:
  agent:message    — Send messages to channels
  agent:spawn      — Spawn sub-agents
  agent:session    — Access session history

system:
  sys:info         — Read system info (hostname, OS, etc.)
  sys:time         — Access current time
  sys:crypto       — Use cryptographic functions
```

## Manifest Schema

```typescript
interface SkillManifest {
  /** Manifest format version */
  version: '1.0';

  /** Skill identifier (unique) */
  id: string;

  /** Human-readable name */
  name: string;

  /** What this skill does */
  description: string;

  /** Author/publisher */
  author?: string;

  /** Required capabilities */
  capabilities: CapabilityDeclaration[];

  /** Minimum trust level for input */
  minInputTrust: TrustLevel;

  /** Trust level of this skill's output */
  outputTrust: TrustLevel;

  /** Resource limits */
  limits?: ResourceLimits;

  /** Optional: domains this skill can access (if net:http/https declared) */
  allowedDomains?: string[];

  /** Optional: file paths this skill can access (if fs:* declared) */
  allowedPaths?: string[];
}

interface CapabilityDeclaration {
  /** Capability identifier (e.g., 'fs:read', 'net:https') */
  capability: string;

  /** Why this capability is needed (shown to operator for approval) */
  reason: string;

  /** Is this capability required or optional? */
  required: boolean;
}

interface ResourceLimits {
  /** Max execution time in ms */
  timeoutMs?: number;

  /** Max memory in MB */
  maxMemoryMb?: number;

  /** Max output size in bytes */
  maxOutputBytes?: number;

  /** Max number of HTTP requests per invocation */
  maxHttpRequests?: number;

  /** Max file size that can be read/written in bytes */
  maxFileSizeBytes?: number;
}
```

### Example: Weather Skill Manifest

```json
{
  "version": "1.0",
  "id": "skill:weather",
  "name": "Weather",
  "description": "Get current weather and forecasts",
  "capabilities": [
    {
      "capability": "net:https",
      "reason": "Fetches weather data from wttr.in API",
      "required": true
    }
  ],
  "minInputTrust": "untrusted",
  "outputTrust": "tool",
  "limits": {
    "timeoutMs": 10000,
    "maxHttpRequests": 3,
    "maxMemoryMb": 50
  },
  "allowedDomains": ["wttr.in"]
}
```

### Example: File Manager Skill Manifest

```json
{
  "version": "1.0",
  "id": "skill:file-manager",
  "name": "File Manager",
  "description": "Read, write, and organize files in workspace",
  "capabilities": [
    {
      "capability": "fs:read",
      "reason": "Reads files in workspace",
      "required": true
    },
    {
      "capability": "fs:write",
      "reason": "Creates and updates files",
      "required": true
    },
    {
      "capability": "fs:delete",
      "reason": "Removes files when requested",
      "required": false
    }
  ],
  "minInputTrust": "user",
  "outputTrust": "tool",
  "limits": {
    "maxFileSizeBytes": 10485760
  },
  "allowedPaths": ["/home/*/workspace/**"]
}
```

## Trust-Gated Capabilities

Certain capabilities are only available above a trust threshold:

| Capability | Minimum Trust | Rationale |
|-----------|--------------|-----------|
| fs:read | tool | Don't let untrusted content trigger file reads |
| fs:write | user | Only human-initiated actions can write |
| fs:delete | user | Destructive — requires human intent |
| net:http/https | tool | Tools can fetch, but untrusted can't trigger requests |
| proc:exec | user | Command execution requires human intent |
| env:secrets | user | Credential access requires human intent |
| agent:message | user | Sending messages requires human intent |
| agent:spawn | user | Spawning agents requires human intent |
| sys:info | untrusted | Safe, read-only system info |
| sys:time | untrusted | Safe, current time |

## Policy Engine

### Evaluation Flow

```
Skill invoked with input
        │
        ▼
[1] Load skill manifest
        │
        ▼
[2] Check input trust ≥ manifest.minInputTrust
        │ NO → DENY (input trust too low)
        ▼ YES
[3] For each declared capability:
        │
        ├─ Is capability in operator's deny list? → DENY
        ├─ Does input trust meet capability minimum? → If NO, DENY
        ├─ Is capability in operator's allow list? → GRANT
        └─ Is capability declared + required? → GRANT (if approved)
        │
        ▼
[4] Check resource limits
        │
        ▼
[5] Execute with granted capabilities only
        │
        ▼
[6] Tag output with manifest.outputTrust
```

### Operator Overrides

Operators can configure:

```typescript
interface OperatorPolicy {
  /** Global deny list — these capabilities are never granted */
  globalDeny?: string[];

  /** Global allow list — these capabilities are always granted */
  globalAllow?: string[];

  /** Per-skill overrides */
  skills?: Record<string, SkillOverride>;

  /** Require operator approval for first-time capability grants */
  requireApproval?: boolean;

  /** Auto-approve capabilities below this risk level */
  autoApproveBelow?: 'low' | 'medium' | 'high';
}

interface SkillOverride {
  /** Capabilities to deny for this skill */
  deny?: string[];

  /** Capabilities to grant for this skill */
  allow?: string[];

  /** Override resource limits */
  limits?: Partial<ResourceLimits>;

  /** Block this skill entirely */
  blocked?: boolean;
}
```

## API

### Core Functions

```typescript
/** Load and validate a skill manifest */
function loadManifest(path: string): SkillManifest;
function validateManifest(manifest: unknown): ValidationResult;

/** Check if a skill invocation is allowed */
function checkPermission(
  manifest: SkillManifest,
  inputTag: ContentTag,
  policy: OperatorPolicy,
): PermissionResult;

/** Create a capability-restricted execution context */
function createContext(
  manifest: SkillManifest,
  grantedCapabilities: string[],
  limits: ResourceLimits,
): ExecutionContext;

/** Enforce capability at runtime (called before each restricted operation) */
function enforce(
  context: ExecutionContext,
  capability: string,
  details?: Record<string, unknown>,
): EnforceResult;
```

### Types

```typescript
interface PermissionResult {
  allowed: boolean;
  granted: string[];       // Capabilities that were granted
  denied: string[];        // Capabilities that were denied
  reasons: string[];       // Human-readable explanations
  requiresApproval: string[]; // Capabilities needing operator approval
}

interface EnforceResult {
  allowed: boolean;
  reason?: string;
}

interface ExecutionContext {
  skillId: string;
  grantedCapabilities: Set<string>;
  limits: ResourceLimits;
  usage: ResourceUsage;     // Track actual resource use
  inputTrust: TrustLevel;
}

interface ResourceUsage {
  startTime: number;
  memoryPeakMb: number;
  httpRequestCount: number;
  bytesRead: number;
  bytesWritten: number;
}
```

## Performance Target

- Manifest loading: <1ms (cached after first load)
- Permission check: <1ms
- Runtime enforcement: <0.5ms per check
- Total Layer 2 overhead: <3ms p99

## Test Cases

### Permission Checks
1. Skill with matching capabilities + sufficient trust → allowed
2. Skill with undeclared capability attempt → denied
3. Input trust below manifest.minInputTrust → denied
4. Operator deny override blocks declared capability → denied
5. Operator allow override grants optional capability → allowed
6. Blocked skill → denied regardless of capabilities

### Trust Gating
7. fs:write with untrusted input → denied
8. fs:write with user input → allowed (if declared)
9. net:https with tool-level input → allowed
10. proc:exec with tool-level input → denied (needs user)

### Resource Limits
11. Execution exceeding timeoutMs → killed
12. HTTP requests exceeding maxHttpRequests → blocked
13. File read exceeding maxFileSizeBytes → blocked

### Manifest Validation
14. Missing required fields → validation error
15. Unknown capability → warning (forward-compatible)
16. Invalid version → error
