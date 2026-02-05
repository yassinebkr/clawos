/**
 * ClawOS Layer 3: Isolation Level Selection & Sandbox Configuration
 *
 * Determines how isolated a skill execution should be based on
 * manifest, input trust, and operator policy.
 */

import type { SkillManifest, OperatorPolicy } from '../capabilities/types';
import type { ContentTag, TrustLevel } from '../tagging/types';
import { TRUST_RANK } from '../tagging/types';
import type { IsolationLevel, SandboxConfig, PathRule } from './types';
import { randomBytes } from 'node:crypto';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

// ─── Isolation Level Selection ───────────────────────────────

/**
 * Determine isolation level based on manifest, input trust, and policy.
 *
 * Rules:
 * - system trust + built-in skill → Level 0 (unrestricted)
 * - user/tool trust + standard skill → Level 1 (worker)
 * - untrusted input OR high-risk capabilities → Level 2 (sandbox)
 * - MCP server → always Level 2
 */
export function selectIsolationLevel(
  manifest: SkillManifest,
  inputTag: ContentTag,
  policy?: OperatorPolicy,
): IsolationLevel {
  // Check for per-skill forced isolation level
  const skillOverride = policy?.skills?.[manifest.id];
  if (skillOverride && 'isolationLevel' in skillOverride) {
    return (skillOverride as any).isolationLevel as IsolationLevel;
  }

  // MCP servers always get full sandbox
  if (manifest.id.startsWith('mcp:')) {
    return 2;
  }

  // Untrusted input → full sandbox
  if (inputTag.trust === 'untrusted') {
    return 2;
  }

  // High-risk capabilities → full sandbox
  const highRisk = ['proc:exec', 'proc:spawn', 'net:listen', 'env:secrets'];
  const hasHighRisk = manifest.capabilities.some(
    (c) => highRisk.includes(c.capability),
  );
  if (hasHighRisk) {
    return 2;
  }

  // System trust built-in → unrestricted
  if (inputTag.trust === 'system' && manifest.id.startsWith('builtin:')) {
    return 0;
  }

  // Default: lightweight isolation
  return 1;
}

// ─── Sandbox Configuration ───────────────────────────────────

/** Default system paths that are always readable */
const SYSTEM_READ_PATHS: PathRule[] = [
  { path: '/usr/lib', mode: 'read' },
  { path: '/usr/share', mode: 'read' },
  { path: '/lib', mode: 'read' },
  { path: '/etc/resolv.conf', mode: 'read' },
  { path: '/etc/hosts', mode: 'read' },
  { path: '/etc/ssl/certs', mode: 'read' },
];

/**
 * Generate a unique run ID.
 */
function generateRunId(): string {
  return randomBytes(8).toString('hex');
}

/**
 * Create sandbox configuration for a skill execution.
 */
export function createSandboxConfig(
  manifest: SkillManifest,
  level: IsolationLevel,
  workspacePath?: string,
): SandboxConfig {
  const runId = generateRunId();
  const tempDir = join(tmpdir(), `clawos-${manifest.id.replace(/[^a-zA-Z0-9]/g, '-')}-${runId}`);

  // Build allowed paths based on isolation level
  const allowedPaths: PathRule[] = [];

  if (level === 0) {
    // Unrestricted — no path limits
  } else if (level === 1) {
    // Lightweight — system paths + workspace + declared paths
    allowedPaths.push(...SYSTEM_READ_PATHS);
    allowedPaths.push({ path: tempDir, mode: 'readwrite' });

    if (workspacePath) {
      allowedPaths.push({ path: workspacePath, mode: 'readwrite' });
    }

    // Add manifest-declared paths
    if (manifest.allowedPaths) {
      for (const p of manifest.allowedPaths) {
        allowedPaths.push({ path: p, mode: 'readwrite' });
      }
    }
  } else {
    // Full sandbox — minimal paths
    allowedPaths.push(
      { path: '/usr/lib', mode: 'read' },
      { path: '/lib', mode: 'read' },
      { path: '/etc/ssl/certs', mode: 'read' },
      { path: tempDir, mode: 'readwrite' },
    );
  }

  // Determine allowed domains
  const allowedDomains = manifest.allowedDomains || [];

  // Build environment (minimal)
  const env: Record<string, string> = {
    NODE_ENV: 'production',
    CLAWOS_SKILL_ID: manifest.id,
    CLAWOS_RUN_ID: runId,
    CLAWOS_TEMP_DIR: tempDir,
    CLAWOS_ISOLATION_LEVEL: String(level),
    HOME: tempDir, // Redirect HOME to temp
    TMPDIR: tempDir,
    PATH: '/usr/local/bin:/usr/bin:/bin',
  };

  return {
    level,
    allowedPaths,
    allowedDomains,
    resourceLimits: {
      timeoutMs: manifest.limits?.timeoutMs ?? 30000,
      maxMemoryMb: manifest.limits?.maxMemoryMb ?? 256,
      maxOutputBytes: manifest.limits?.maxOutputBytes ?? 1048576,
      maxHttpRequests: manifest.limits?.maxHttpRequests ?? 10,
      maxFileSizeBytes: manifest.limits?.maxFileSizeBytes ?? 10485760,
    },
    tempDir,
    env,
    cwd: tempDir,
  };
}

/**
 * Check if bubblewrap is available on this system.
 */
export function isBubblewrapAvailable(): boolean {
  try {
    const { execSync } = require('node:child_process');
    execSync('which bwrap', { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
}

/**
 * Get effective isolation level (falls back to Level 1 if bwrap unavailable).
 */
export function effectiveLevel(requested: IsolationLevel): IsolationLevel {
  if (requested === 2 && !isBubblewrapAvailable()) {
    return 1; // Fallback
  }
  return requested;
}
