/**
 * ClawOS Layer 2: Policy Engine
 *
 * Evaluates whether a skill invocation is allowed based on:
 * - Skill manifest declarations
 * - Input content trust level
 * - Operator policy (overrides, deny/allow lists)
 * - Capability minimum trust requirements
 */

import type {
  SkillManifest,
  OperatorPolicy,
  PermissionResult,
  EnforceResult,
  ExecutionContext,
  ResourceLimits,
  ResourceUsage,
  RiskLevel,
} from './types';
import { CAPABILITY_MIN_TRUST, CAPABILITY_RISK } from './types';
import type { ContentTag, TrustLevel } from '../tagging/types';
import { TRUST_RANK } from '../tagging/types';
import { meetsMinTrust } from '../tagging/tag';

// ─── Risk Level Comparison ───────────────────────────────────

const RISK_RANK: Record<RiskLevel, number> = {
  low: 0,
  medium: 1,
  high: 2,
};

function riskAtOrBelow(capability: string, threshold: RiskLevel): boolean {
  const risk = CAPABILITY_RISK[capability] || 'high'; // Unknown = high risk
  return RISK_RANK[risk] <= RISK_RANK[threshold];
}

// ─── Permission Checking ─────────────────────────────────────

/** Default policy: no overrides, approval required for high-risk */
const DEFAULT_POLICY: OperatorPolicy = {
  globalDeny: [],
  globalAllow: [],
  skills: {},
  requireApproval: false,
  autoApproveBelow: 'medium',
};

/**
 * Check if a skill invocation is allowed.
 *
 * Evaluates the manifest's declared capabilities against:
 * 1. Input trust level
 * 2. Capability minimum trust requirements
 * 3. Operator policy (deny/allow lists, per-skill overrides)
 *
 * Returns detailed result with granted/denied lists and reasons.
 */
export function checkPermission(
  manifest: SkillManifest,
  inputTag: ContentTag,
  policy: OperatorPolicy = DEFAULT_POLICY,
): PermissionResult {
  const granted: string[] = [];
  const denied: string[] = [];
  const reasons: string[] = [];
  const requiresApproval: string[] = [];

  const skillOverride = policy.skills?.[manifest.id];

  // Check if skill is blocked entirely
  if (skillOverride?.blocked) {
    return {
      allowed: false,
      granted: [],
      denied: manifest.capabilities.map((c) => c.capability),
      reasons: [`Skill "${manifest.id}" is blocked by operator policy`],
      requiresApproval: [],
    };
  }

  // Check input trust meets manifest minimum
  if (!meetsMinTrust(inputTag.trust, manifest.minInputTrust)) {
    return {
      allowed: false,
      granted: [],
      denied: manifest.capabilities.map((c) => c.capability),
      reasons: [
        `Input trust "${inputTag.trust}" is below manifest minimum "${manifest.minInputTrust}"`,
      ],
      requiresApproval: [],
    };
  }

  // Evaluate each declared capability
  for (const decl of manifest.capabilities) {
    const cap = decl.capability;
    let capGranted = false;
    let capReason = '';

    // 1. Global deny takes priority
    if (policy.globalDeny?.includes(cap)) {
      capReason = `"${cap}" is in global deny list`;
    }
    // 2. Per-skill deny
    else if (skillOverride?.deny?.includes(cap)) {
      capReason = `"${cap}" is denied for skill "${manifest.id}"`;
    }
    // 3. Check trust-gated minimum
    else if (!meetsCapabilityTrust(cap, inputTag.trust)) {
      capReason = `"${cap}" requires trust "${CAPABILITY_MIN_TRUST[cap] || 'unknown'}", input has "${inputTag.trust}"`;
    }
    // 4. Global allow
    else if (policy.globalAllow?.includes(cap)) {
      capGranted = true;
      capReason = `"${cap}" is in global allow list`;
    }
    // 5. Per-skill allow
    else if (skillOverride?.allow?.includes(cap)) {
      capGranted = true;
      capReason = `"${cap}" is explicitly allowed for skill "${manifest.id}"`;
    }
    // 6. Auto-approve based on risk level
    else if (policy.autoApproveBelow && riskAtOrBelow(cap, policy.autoApproveBelow)) {
      capGranted = true;
      capReason = `"${cap}" auto-approved (risk: ${CAPABILITY_RISK[cap] || 'unknown'})`;
    }
    // 7. Requires operator approval
    else if (policy.requireApproval) {
      capReason = `"${cap}" requires operator approval`;
      requiresApproval.push(cap);
    }
    // 8. Default: grant if declared (no approval required)
    else {
      capGranted = true;
      capReason = `"${cap}" granted (declared in manifest)`;
    }

    if (capGranted) {
      granted.push(cap);
    } else {
      denied.push(cap);

      // If this was a required capability, the whole skill is blocked
      if (decl.required && !requiresApproval.includes(cap)) {
        reasons.push(`Required capability denied: ${capReason}`);
      }
    }

    reasons.push(capReason);
  }

  // Skill is allowed if no required capabilities were denied
  const requiredDenied = manifest.capabilities
    .filter((c) => c.required && denied.includes(c.capability) && !requiresApproval.includes(c.capability));

  return {
    allowed: requiredDenied.length === 0 && requiresApproval.length === 0,
    granted,
    denied,
    reasons,
    requiresApproval,
  };
}

/**
 * Check if input trust level meets the minimum for a capability.
 */
function meetsCapabilityTrust(capability: string, inputTrust: TrustLevel): boolean {
  const minTrust = CAPABILITY_MIN_TRUST[capability];
  if (!minTrust) return true; // Unknown capability — no trust restriction
  return TRUST_RANK[inputTrust] >= TRUST_RANK[minTrust];
}

// ─── Execution Context ───────────────────────────────────────

/**
 * Create an execution context for a skill invocation.
 * This context is passed to enforce() during execution.
 */
export function createContext(
  manifest: SkillManifest,
  grantedCapabilities: string[],
  inputTrust: TrustLevel,
  limitsOverride?: Partial<ResourceLimits>,
): ExecutionContext {
  const limits: ResourceLimits = {
    timeoutMs: 30000,       // Default 30s
    maxMemoryMb: 256,        // Default 256MB
    maxOutputBytes: 1048576, // Default 1MB
    maxHttpRequests: 10,     // Default 10
    maxFileSizeBytes: 10485760, // Default 10MB
    ...manifest.limits,
    ...limitsOverride,
  };

  return {
    skillId: manifest.id,
    grantedCapabilities: new Set(grantedCapabilities),
    limits,
    usage: {
      startTime: Date.now(),
      httpRequestCount: 0,
      bytesRead: 0,
      bytesWritten: 0,
      outputBytes: 0,
    },
    inputTrust,
    allowedDomains: manifest.allowedDomains,
    allowedPaths: manifest.allowedPaths,
  };
}

// ─── Runtime Enforcement ─────────────────────────────────────

/**
 * Enforce a capability check at runtime.
 *
 * Called before each restricted operation during skill execution.
 * Checks capability grant + resource limits + domain/path restrictions.
 *
 * @param context - The execution context
 * @param capability - The capability being exercised
 * @param details - Optional details (domain, path, bytes, etc.)
 */
export function enforce(
  context: ExecutionContext,
  capability: string,
  details?: Record<string, unknown>,
): EnforceResult {
  // 1. Check capability is granted
  if (!context.grantedCapabilities.has(capability)) {
    return {
      allowed: false,
      reason: `Capability "${capability}" not granted for skill "${context.skillId}"`,
    };
  }

  // 2. Check timeout
  if (context.limits.timeoutMs) {
    const elapsed = Date.now() - context.usage.startTime;
    if (elapsed > context.limits.timeoutMs) {
      return {
        allowed: false,
        reason: `Execution timeout: ${elapsed}ms > ${context.limits.timeoutMs}ms limit`,
      };
    }
  }

  // 3. Domain restriction (for net:http/https)
  if ((capability === 'net:http' || capability === 'net:https') && details?.domain) {
    if (context.allowedDomains && context.allowedDomains.length > 0) {
      const domain = String(details.domain);
      if (!matchesDomain(domain, context.allowedDomains)) {
        return {
          allowed: false,
          reason: `Domain "${domain}" not in allowed list: [${context.allowedDomains.join(', ')}]`,
        };
      }
    }
  }

  // 4. HTTP request count
  if ((capability === 'net:http' || capability === 'net:https') && context.limits.maxHttpRequests) {
    context.usage.httpRequestCount++;
    if (context.usage.httpRequestCount > context.limits.maxHttpRequests) {
      return {
        allowed: false,
        reason: `HTTP request limit exceeded: ${context.usage.httpRequestCount} > ${context.limits.maxHttpRequests}`,
      };
    }
  }

  // 5. Path restriction (for fs:*)
  if (capability.startsWith('fs:') && details?.path) {
    if (context.allowedPaths && context.allowedPaths.length > 0) {
      const path = String(details.path);
      if (!matchesPath(path, context.allowedPaths)) {
        return {
          allowed: false,
          reason: `Path "${path}" not in allowed list: [${context.allowedPaths.join(', ')}]`,
        };
      }
    }
  }

  // 6. File size check
  if ((capability === 'fs:read' || capability === 'fs:write') && details?.bytes) {
    const bytes = Number(details.bytes);
    if (context.limits.maxFileSizeBytes && bytes > context.limits.maxFileSizeBytes) {
      return {
        allowed: false,
        reason: `File size ${bytes} exceeds limit ${context.limits.maxFileSizeBytes}`,
      };
    }
    if (capability === 'fs:read') context.usage.bytesRead += bytes;
    if (capability === 'fs:write') context.usage.bytesWritten += bytes;
  }

  return { allowed: true };
}

/**
 * Check if execution has exceeded its time limit.
 */
export function hasTimedOut(context: ExecutionContext): boolean {
  if (!context.limits.timeoutMs) return false;
  return (Date.now() - context.usage.startTime) > context.limits.timeoutMs;
}

/**
 * Get remaining time before timeout (ms). Returns 0 if already timed out.
 */
export function remainingTime(context: ExecutionContext): number {
  if (!context.limits.timeoutMs) return Infinity;
  const remaining = context.limits.timeoutMs - (Date.now() - context.usage.startTime);
  return Math.max(0, remaining);
}

// ─── Helpers ─────────────────────────────────────────────────

/**
 * Simple domain matching. Supports exact match and wildcard subdomains.
 * "*.example.com" matches "api.example.com" but not "example.com"
 * "example.com" matches exactly "example.com"
 */
function matchesDomain(domain: string, allowed: string[]): boolean {
  const d = domain.toLowerCase();
  for (const pattern of allowed) {
    const p = pattern.toLowerCase();
    if (p === d) return true;
    if (p.startsWith('*.')) {
      const suffix = p.slice(1); // ".example.com"
      if (d.endsWith(suffix)) return true;
    }
  }
  return false;
}

/**
 * Simple path matching. Supports:
 * - Exact match: "/home/user/file.txt"
 * - Wildcard directory: "/home/* /workspace/**" (matches anything under workspace)
 * - Single wildcard: "/home/* /config" (matches one level)
 */
function matchesPath(path: string, allowed: string[]): boolean {
  for (const pattern of allowed) {
    if (pattern === path) return true;

    // Convert glob to regex (simple version)
    const regexStr = pattern
      .replace(/[.+^${}()|[\]\\]/g, '\\$&') // Escape special chars
      .replace(/\*\*/g, '⧫')                 // Placeholder for **
      .replace(/\*/g, '[^/]*')               // * = anything except /
      .replace(/⧫/g, '.*');                  // ** = anything

    try {
      if (new RegExp(`^${regexStr}$`).test(path)) return true;
    } catch {
      // Invalid pattern — skip
    }
  }
  return false;
}
