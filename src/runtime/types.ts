/**
 * ClawOS Layer 3: Runtime Security — Type Definitions
 */

import type { TrustLevel } from '../tagging/types';
import type { TaggedContent, ContentTag } from '../tagging/types';
import type { ResourceLimits, ExecutionContext, SkillManifest, OperatorPolicy } from '../capabilities/types';

// ─── Isolation Levels ────────────────────────────────────────

/**
 * 0 = unrestricted (system trust, inline execution)
 * 1 = lightweight (worker/child process, resource limits)
 * 2 = full sandbox (bubblewrap, syscall filtering, namespace isolation)
 */
export type IsolationLevel = 0 | 1 | 2;

// ─── Sandbox Configuration ───────────────────────────────────

export interface PathRule {
  /** Path or glob pattern */
  path: string;
  /** Read, write, or both */
  mode: 'read' | 'write' | 'readwrite';
}

export interface SandboxConfig {
  /** Isolation level */
  level: IsolationLevel;

  /** Filesystem paths accessible */
  allowedPaths: PathRule[];

  /** Network domains accessible */
  allowedDomains: string[];

  /** Resource limits */
  resourceLimits: ResourceLimits;

  /** Writable temp directory for this execution */
  tempDir: string;

  /** Environment variables to pass */
  env: Record<string, string>;

  /** Working directory inside sandbox */
  cwd: string;
}

// ─── Execution Results ───────────────────────────────────────

export interface ExecutionMetrics {
  /** Wall clock duration */
  durationMs: number;

  /** Peak memory usage */
  peakMemoryMb: number;

  /** CPU time consumed */
  cpuTimeMs: number;

  /** Number of network requests made */
  networkRequests: number;

  /** Bytes read from filesystem */
  bytesRead: number;

  /** Bytes written to filesystem */
  bytesWritten: number;

  /** Output size in bytes */
  outputBytes: number;
}

export type IncidentSeverity = 'info' | 'warning' | 'critical';

export interface SecurityIncident {
  /** When it happened */
  timestamp: number;

  /** How serious */
  severity: IncidentSeverity;

  /** Category */
  type: string;

  /** Human-readable description */
  message: string;

  /** Additional data */
  details?: Record<string, unknown>;
}

export type ProcessStatus = 'pending' | 'running' | 'completed' | 'killed' | 'error' | 'timeout';

export interface SandboxResult {
  /** Did the execution succeed? */
  success: boolean;

  /** Output (if successful) */
  output?: string;

  /** Error message (if failed) */
  error?: string;

  /** Exit code */
  exitCode?: number;

  /** Runtime metrics */
  metrics: ExecutionMetrics;

  /** Security incidents detected */
  incidents: SecurityIncident[];

  /** Final process status */
  status: ProcessStatus;
}

// ─── Behavioral Monitoring ───────────────────────────────────

export type AnomalyAction = 'log' | 'throttle' | 'alert' | 'kill';

export interface AnomalyRule {
  /** Unique rule ID */
  id: string;

  /** What to watch */
  metric: string;

  /** Threshold value */
  threshold: number;

  /** Time window in ms (0 = instantaneous) */
  windowMs: number;

  /** What to do when triggered */
  action: AnomalyAction;

  /** Human-readable description */
  description: string;
}

// ─── Process Handle ──────────────────────────────────────────

export interface SandboxedProcess {
  /** OS process ID */
  pid: number;

  /** Unique run ID */
  runId: string;

  /** Skill being executed */
  skillId: string;

  /** Sandbox configuration */
  config: SandboxConfig;

  /** Current status */
  status: ProcessStatus;

  /** When execution started */
  startTime: number;

  /** Collected incidents */
  incidents: SecurityIncident[];

  /** Collected metrics (updated periodically) */
  metrics: ExecutionMetrics;
}
