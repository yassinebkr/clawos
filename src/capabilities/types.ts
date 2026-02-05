/**
 * ClawOS Layer 2: Capability Control — Type Definitions
 *
 * Every skill/tool declares capabilities in a manifest.
 * The policy engine decides what's granted based on trust + operator config.
 */

import type { TrustLevel } from '../tagging/types';

// ─── Capabilities ────────────────────────────────────────────

/** All recognized capability identifiers */
export type Capability =
  // Filesystem
  | 'fs:read' | 'fs:write' | 'fs:delete' | 'fs:temp'
  // Network
  | 'net:http' | 'net:https' | 'net:dns' | 'net:listen'
  // Process
  | 'proc:exec' | 'proc:spawn' | 'proc:signal'
  // Environment
  | 'env:read' | 'env:secrets'
  // Data
  | 'data:memory' | 'data:database' | 'data:clipboard'
  // Agent
  | 'agent:message' | 'agent:spawn' | 'agent:session'
  // System
  | 'sys:info' | 'sys:time' | 'sys:crypto'
  // Wildcard for forward compatibility
  | (string & {});

/** Minimum trust level required for each capability */
export const CAPABILITY_MIN_TRUST: Record<string, TrustLevel> = {
  // Filesystem
  'fs:read': 'tool',
  'fs:write': 'user',
  'fs:delete': 'user',
  'fs:temp': 'tool',

  // Network
  'net:http': 'tool',
  'net:https': 'tool',
  'net:dns': 'tool',
  'net:listen': 'user',

  // Process
  'proc:exec': 'user',
  'proc:spawn': 'user',
  'proc:signal': 'user',

  // Environment
  'env:read': 'tool',
  'env:secrets': 'user',

  // Data
  'data:memory': 'tool',
  'data:database': 'tool',
  'data:clipboard': 'user',

  // Agent
  'agent:message': 'user',
  'agent:spawn': 'user',
  'agent:session': 'tool',

  // System
  'sys:info': 'untrusted',
  'sys:time': 'untrusted',
  'sys:crypto': 'tool',
};

// ─── Risk Levels ─────────────────────────────────────────────

export type RiskLevel = 'low' | 'medium' | 'high';

/** Risk level for each capability (for auto-approval decisions) */
export const CAPABILITY_RISK: Record<string, RiskLevel> = {
  'sys:info': 'low',
  'sys:time': 'low',
  'sys:crypto': 'low',
  'fs:temp': 'low',
  'net:dns': 'low',

  'fs:read': 'medium',
  'net:http': 'medium',
  'net:https': 'medium',
  'env:read': 'medium',
  'data:memory': 'medium',
  'data:database': 'medium',
  'agent:session': 'medium',

  'fs:write': 'high',
  'fs:delete': 'high',
  'net:listen': 'high',
  'proc:exec': 'high',
  'proc:spawn': 'high',
  'proc:signal': 'high',
  'env:secrets': 'high',
  'data:clipboard': 'high',
  'agent:message': 'high',
  'agent:spawn': 'high',
};

// ─── Manifest ────────────────────────────────────────────────

export interface CapabilityDeclaration {
  /** Capability identifier */
  capability: string;

  /** Why this capability is needed */
  reason: string;

  /** Is this required for the skill to function? */
  required: boolean;
}

export interface ResourceLimits {
  /** Max execution time in ms */
  timeoutMs?: number;

  /** Max memory in MB */
  maxMemoryMb?: number;

  /** Max output size in bytes */
  maxOutputBytes?: number;

  /** Max HTTP requests per invocation */
  maxHttpRequests?: number;

  /** Max file size for read/write in bytes */
  maxFileSizeBytes?: number;
}

export interface SkillManifest {
  /** Manifest format version */
  version: '1.0';

  /** Unique skill identifier */
  id: string;

  /** Human-readable name */
  name: string;

  /** Description of what this skill does */
  description: string;

  /** Author/publisher */
  author?: string;

  /** Required and optional capabilities */
  capabilities: CapabilityDeclaration[];

  /** Minimum trust level for input content */
  minInputTrust: TrustLevel;

  /** Trust level assigned to this skill's output */
  outputTrust: TrustLevel;

  /** Resource limits */
  limits?: ResourceLimits;

  /** Allowed network domains (when net:http/https declared) */
  allowedDomains?: string[];

  /** Allowed file paths (when fs:* declared), supports globs */
  allowedPaths?: string[];
}

// ─── Policy ──────────────────────────────────────────────────

export interface SkillOverride {
  /** Deny these capabilities for this skill */
  deny?: string[];

  /** Allow these additional capabilities */
  allow?: string[];

  /** Override resource limits */
  limits?: Partial<ResourceLimits>;

  /** Block this skill entirely */
  blocked?: boolean;
}

export interface OperatorPolicy {
  /** Capabilities that are never granted to any skill */
  globalDeny?: string[];

  /** Capabilities that are always granted to any skill */
  globalAllow?: string[];

  /** Per-skill overrides */
  skills?: Record<string, SkillOverride>;

  /** Require operator approval for first-time grants */
  requireApproval?: boolean;

  /** Auto-approve capabilities at or below this risk level */
  autoApproveBelow?: RiskLevel;
}

// ─── Results ─────────────────────────────────────────────────

export interface PermissionResult {
  /** Is the skill allowed to execute? */
  allowed: boolean;

  /** Capabilities that were granted */
  granted: string[];

  /** Capabilities that were denied */
  denied: string[];

  /** Human-readable explanations */
  reasons: string[];

  /** Capabilities needing operator approval before grant */
  requiresApproval: string[];
}

export interface EnforceResult {
  /** Is this specific action allowed? */
  allowed: boolean;

  /** Reason for denial (if denied) */
  reason?: string;
}

// ─── Execution Context ───────────────────────────────────────

export interface ResourceUsage {
  startTime: number;
  httpRequestCount: number;
  bytesRead: number;
  bytesWritten: number;
  outputBytes: number;
}

export interface ExecutionContext {
  /** Skill being executed */
  skillId: string;

  /** Capabilities granted for this execution */
  grantedCapabilities: Set<string>;

  /** Active resource limits */
  limits: ResourceLimits;

  /** Current resource usage */
  usage: ResourceUsage;

  /** Trust level of the input that triggered this execution */
  inputTrust: TrustLevel;

  /** Allowed domains (from manifest) */
  allowedDomains?: string[];

  /** Allowed paths (from manifest) */
  allowedPaths?: string[];
}

// ─── Validation ──────────────────────────────────────────────

export interface ValidationResult {
  valid: boolean;
  errors: string[];
  warnings: string[];
}
