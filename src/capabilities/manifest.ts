/**
 * ClawOS Layer 2: Manifest Loading & Validation
 *
 * Validates skill manifests and provides caching.
 */

import type { SkillManifest, ValidationResult } from './types';
import { TRUST_LEVELS } from '../tagging/types';

// ─── Validation ──────────────────────────────────────────────

/**
 * Validate a manifest object.
 * Returns errors (fatal) and warnings (non-fatal).
 */
export function validateManifest(input: unknown): ValidationResult {
  const errors: string[] = [];
  const warnings: string[] = [];

  if (!input || typeof input !== 'object') {
    return { valid: false, errors: ['Manifest must be an object'], warnings };
  }

  const m = input as Record<string, unknown>;

  // Version
  if (m.version !== '1.0') {
    errors.push(`Unsupported manifest version: ${String(m.version)} (expected "1.0")`);
  }

  // Required string fields
  for (const field of ['id', 'name', 'description'] as const) {
    if (typeof m[field] !== 'string' || (m[field] as string).trim() === '') {
      errors.push(`Missing or empty required field: ${field}`);
    }
  }

  // Trust levels
  for (const field of ['minInputTrust', 'outputTrust'] as const) {
    if (!TRUST_LEVELS.includes(m[field] as any)) {
      errors.push(`Invalid ${field}: ${String(m[field])} (must be one of: ${TRUST_LEVELS.join(', ')})`);
    }
  }

  // Capabilities
  if (!Array.isArray(m.capabilities)) {
    errors.push('capabilities must be an array');
  } else {
    for (let i = 0; i < m.capabilities.length; i++) {
      const cap = m.capabilities[i];
      if (!cap || typeof cap !== 'object') {
        errors.push(`capabilities[${i}] must be an object`);
        continue;
      }
      if (typeof cap.capability !== 'string' || cap.capability.trim() === '') {
        errors.push(`capabilities[${i}].capability must be a non-empty string`);
      } else if (!cap.capability.includes(':')) {
        warnings.push(`capabilities[${i}].capability "${cap.capability}" doesn't follow domain:action format`);
      }
      if (typeof cap.reason !== 'string') {
        errors.push(`capabilities[${i}].reason must be a string`);
      }
      if (typeof cap.required !== 'boolean') {
        errors.push(`capabilities[${i}].required must be a boolean`);
      }
    }
  }

  // Limits (optional)
  if (m.limits !== undefined) {
    if (typeof m.limits !== 'object' || m.limits === null) {
      errors.push('limits must be an object');
    } else {
      const limits = m.limits as Record<string, unknown>;
      const numFields = ['timeoutMs', 'maxMemoryMb', 'maxOutputBytes', 'maxHttpRequests', 'maxFileSizeBytes'];
      for (const f of numFields) {
        if (limits[f] !== undefined && (typeof limits[f] !== 'number' || (limits[f] as number) <= 0)) {
          errors.push(`limits.${f} must be a positive number`);
        }
      }
    }
  }

  // Allowed domains (optional)
  if (m.allowedDomains !== undefined) {
    if (!Array.isArray(m.allowedDomains)) {
      errors.push('allowedDomains must be an array of strings');
    } else {
      for (const d of m.allowedDomains) {
        if (typeof d !== 'string') {
          errors.push('Each allowedDomains entry must be a string');
          break;
        }
      }
    }
  }

  // Allowed paths (optional)
  if (m.allowedPaths !== undefined) {
    if (!Array.isArray(m.allowedPaths)) {
      errors.push('allowedPaths must be an array of strings');
    }
  }

  // Author (optional)
  if (m.author !== undefined && typeof m.author !== 'string') {
    warnings.push('author should be a string');
  }

  return { valid: errors.length === 0, errors, warnings };
}

// ─── Manifest Cache ──────────────────────────────────────────

const manifestCache = new Map<string, SkillManifest>();

/**
 * Parse and validate a manifest from a JSON string.
 * Returns the validated manifest or throws.
 */
export function parseManifest(json: string): SkillManifest {
  const parsed = JSON.parse(json);
  const result = validateManifest(parsed);

  if (!result.valid) {
    throw new Error(`Invalid manifest:\n  ${result.errors.join('\n  ')}`);
  }

  return parsed as SkillManifest;
}

/**
 * Register a manifest in the cache.
 */
export function registerManifest(manifest: SkillManifest): void {
  const result = validateManifest(manifest);
  if (!result.valid) {
    throw new Error(`Invalid manifest for ${manifest.id}:\n  ${result.errors.join('\n  ')}`);
  }
  manifestCache.set(manifest.id, manifest);
}

/**
 * Get a cached manifest by skill ID.
 */
export function getManifest(skillId: string): SkillManifest | undefined {
  return manifestCache.get(skillId);
}

/**
 * Clear the manifest cache.
 */
export function clearManifestCache(): void {
  manifestCache.clear();
}

/**
 * List all registered skill IDs.
 */
export function listRegisteredSkills(): string[] {
  return Array.from(manifestCache.keys());
}
