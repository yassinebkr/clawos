# Layer 3: Runtime Security — Specification

## Purpose

Enforce security at the process level. Even if a skill's code tries to break out
of its declared capabilities, the runtime prevents it:

- **Process isolation** — skills run in restricted child processes
- **Behavioral bounds** — anomaly detection catches unexpected patterns
- **Resource enforcement** — hard limits on CPU, memory, time, I/O

This is the "belt and suspenders" layer. Layer 2 (capabilities) is the belt —
it controls what the skill *should* do. Layer 3 is the suspenders — it prevents
what the skill *tries to do anyway*.

## Architecture

```
┌──────────────────────────────────────────────────┐
│  Skill Invocation                                │
│                                                  │
│  ┌──────────────┐    ┌────────────────────────┐  │
│  │ ClawOS Host  │    │  Sandboxed Process     │  │
│  │              │◄──►│  (bubblewrap/seccomp)  │  │
│  │  - Enforce   │IPC │  - Skill code runs     │  │
│  │  - Monitor   │    │  - Limited syscalls     │  │
│  │  - Kill      │    │  - No network (unless   │  │
│  │              │    │    capability granted)   │  │
│  └──────────────┘    └────────────────────────┘  │
│                                                  │
│  ┌──────────────────────────────────────────┐    │
│  │ Behavioral Monitor                       │    │
│  │  - Track syscall patterns                │    │
│  │  - Detect anomalies                      │    │
│  │  - Rate limiting                         │    │
│  │  - Alert / throttle / kill               │    │
│  └──────────────────────────────────────────┘    │
└──────────────────────────────────────────────────┘
```

## Isolation Levels

Three tiers, matching the risk profile:

### Level 0: Unrestricted (system trust)
- No isolation — runs in the main process
- Used for: OpenClaw internals, system-trust operations
- When: inputTrust = system AND skill is built-in

### Level 1: Lightweight Isolation (default for skills)
- Separate Node.js worker or child process
- Resource limits via OS (ulimit, cgroups if available)
- Filesystem: chroot to workspace + allowed paths only
- Network: controlled via capability enforcement (Layer 2)
- When: standard skills with declared capabilities

### Level 2: Full Sandbox (untrusted / MCP servers)
- Process isolation via bubblewrap (bwrap) when available
- Syscall filtering via seccomp
- Network namespace isolation
- Filesystem: read-only root, writable temp only
- When: untrusted input, MCP server execution, high-risk skills

## Sandbox Profiles

### Default Profile (Level 1)
```
Allowed:
  - Read: /usr, /lib, /etc/resolv.conf, /etc/hosts, workspace paths
  - Write: /tmp/clawos-<skillId>-<runId>/
  - Network: outbound only, to allowed domains
  - Syscalls: standard set minus dangerous ones

Blocked:
  - Write to /etc, /usr, /home (except workspace)
  - Raw socket creation
  - ptrace, mount, chroot, reboot
  - Module loading
  - setuid/setgid
```

### Strict Profile (Level 2)
```
Allowed:
  - Read: /usr/lib, /lib (shared libraries only)
  - Write: /tmp/clawos-sandbox-<runId>/ only
  - Network: blocked by default, allowed per capability
  - Syscalls: minimal whitelist

Blocked:
  - Everything not explicitly allowed
  - All filesystem writes outside sandbox
  - All network unless net:* capability granted
  - Process creation unless proc:* capability
```

## Behavioral Monitoring

Track runtime patterns and flag anomalies:

### Metrics Tracked
- **Syscall frequency** — sudden spike = potential exploit
- **File access patterns** — accessing unexpected paths
- **Network patterns** — connecting to undeclared domains
- **Memory growth** — gradual leak or sudden spike
- **CPU usage** — sustained 100% = mining or infinite loop
- **Output size** — generating excessive output

### Response Actions
1. **Log** — record for audit trail
2. **Throttle** — slow down the process
3. **Alert** — notify operator
4. **Kill** — terminate immediately

### Anomaly Rules
```typescript
interface AnomalyRule {
  metric: string;          // What to watch
  threshold: number;       // Trigger point
  window: number;          // Time window (ms)
  action: 'log' | 'throttle' | 'alert' | 'kill';
}
```

Default rules:
- CPU > 95% for > 5s → throttle
- Memory > limit → kill
- Syscalls > 10000/s → alert
- Unexpected path access → log + alert
- Output > maxOutputBytes → kill

## Process Lifecycle

```
1. PREPARE
   ├── Load manifest
   ├── Check permissions (Layer 2)
   ├── Select isolation level
   └── Create sandbox profile

2. SPAWN
   ├── Create child process / worker
   ├── Apply sandbox restrictions
   ├── Set resource limits
   └── Start behavioral monitor

3. EXECUTE
   ├── Send input (tagged content)
   ├── Skill runs in sandbox
   ├── Monitor enforces limits
   └── Collect output

4. COMPLETE
   ├── Validate output size
   ├── Tag output (Layer 1)
   ├── Record metrics
   └── Clean up sandbox

5. ERROR / TIMEOUT
   ├── Kill process
   ├── Record incident
   ├── Clean up sandbox
   └── Return error (tagged as system trust)
```

## API

```typescript
/** Isolation level for a skill execution */
type IsolationLevel = 0 | 1 | 2;

/** Sandbox configuration derived from manifest + policy */
interface SandboxConfig {
  level: IsolationLevel;
  allowedPaths: PathRule[];
  allowedDomains: string[];
  allowedSyscalls?: string[];
  resourceLimits: ResourceLimits;
  tempDir: string;
  env: Record<string, string>;
}

/** A sandboxed process handle */
interface SandboxedProcess {
  pid: number;
  skillId: string;
  config: SandboxConfig;
  context: ExecutionContext;
  status: 'running' | 'completed' | 'killed' | 'error' | 'timeout';
  startTime: number;

  /** Send input to the process */
  send(data: TaggedContent): void;

  /** Kill the process */
  kill(reason: string): void;

  /** Wait for completion */
  wait(timeoutMs?: number): Promise<SandboxResult>;
}

/** Result of a sandboxed execution */
interface SandboxResult {
  success: boolean;
  output?: TaggedContent;
  error?: string;
  metrics: ExecutionMetrics;
  incidents: SecurityIncident[];
}

/** Runtime metrics from the execution */
interface ExecutionMetrics {
  durationMs: number;
  peakMemoryMb: number;
  cpuTimeMs: number;
  syscallCount: number;
  networkRequests: number;
  bytesRead: number;
  bytesWritten: number;
  outputBytes: number;
}

/** Security incident logged during execution */
interface SecurityIncident {
  timestamp: number;
  severity: 'info' | 'warning' | 'critical';
  type: string;
  message: string;
  details?: Record<string, unknown>;
}
```

## Core Functions

```typescript
/** Determine isolation level for a skill + input */
function selectIsolationLevel(
  manifest: SkillManifest,
  inputTag: ContentTag,
  policy: OperatorPolicy,
): IsolationLevel;

/** Create sandbox configuration */
function createSandboxConfig(
  manifest: SkillManifest,
  context: ExecutionContext,
  level: IsolationLevel,
): SandboxConfig;

/** Spawn a sandboxed process */
function spawn(
  skillPath: string,
  config: SandboxConfig,
  context: ExecutionContext,
): SandboxedProcess;

/** Run a skill in sandbox and return result */
function execute(
  skillPath: string,
  input: TaggedContent,
  manifest: SkillManifest,
  policy: OperatorPolicy,
): Promise<SandboxResult>;
```

## Performance Budget

| Operation | Target | Approach |
|-----------|--------|----------|
| Level 0 (no isolation) | 0ms | Direct function call |
| Level 1 (worker) | 5ms setup | Node.js worker_threads |
| Level 2 (bwrap) | 15ms setup | bubblewrap process spawn |
| Monitoring overhead | <2ms/check | Async metric collection |
| Total Layer 3 | <10ms p99 | Level 1 is the common case |

## Platform Support

| Feature | Linux | macOS | Windows |
|---------|-------|-------|---------|
| Level 0 (unrestricted) | ✅ | ✅ | ✅ |
| Level 1 (worker) | ✅ | ✅ | ✅ |
| Level 2 (bwrap) | ✅ | ❌ (fallback to L1) | ❌ (fallback to L1) |
| seccomp filtering | ✅ | ❌ | ❌ |
| cgroups limits | ✅ | ❌ (ulimit) | ❌ |

Non-Linux platforms fall back to Level 1 with OS-level resource limits.

## Test Cases

1. Level 0: runs inline, no isolation overhead
2. Level 1: worker process respects resource limits
3. Level 1: worker can access allowed paths only
4. Level 2: sandboxed process cannot access filesystem outside sandbox
5. Level 2: network blocked when capability not granted
6. Timeout: process killed after timeoutMs
7. Memory limit: process killed when exceeding maxMemoryMb
8. Output limit: execution stops when output exceeds maxOutputBytes
9. Incident logging: unexpected path access logged
10. Clean shutdown: temp files cleaned up after execution
