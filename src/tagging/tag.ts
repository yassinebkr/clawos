/**
 * ClawOS Layer 1: Content Tagging — Core Implementation
 *
 * Functions for creating, merging, checking, and serializing content tags.
 * Designed for <2ms overhead in the hot path.
 */

import { randomUUID } from 'node:crypto';
import {
  type ContentTag,
  type ContentSource,
  type TaggedContent,
  type TrustLevel,
  type ProvenanceEntry,
  type ProvenanceAction,
  type CompactTag,
  TRUST_RANK,
} from './types';

// ─── ID Generation ───────────────────────────────────────────

/** Generate a cryptographically secure unique tag ID */
function generateId(): string {
  return `ct_${randomUUID()}`;
}

// ─── Tag Creation ────────────────────────────────────────────

/**
 * Create a fresh content tag for new content.
 *
 * @param source - What produced this content
 * @param trust - Trust level
 * @param meta - Optional metadata
 */
export function createTag(
  source: ContentSource,
  trust: TrustLevel,
  meta?: Record<string, unknown>,
): ContentTag {
  const now = Date.now();
  return {
    id: generateId(),
    source,
    trust,
    provenance: [
      {
        source,
        trust,
        action: 'created',
        timestamp: now,
      },
    ],
    timestamp: now,
    ...(meta ? { meta } : {}),
  };
}

/**
 * Wrap content with a fresh tag.
 *
 * @example
 * const msg = tag("Hello world", { kind: 'user', id: '+33616058433' }, 'user');
 */
export function tag<T>(
  data: T,
  source: ContentSource,
  trust: TrustLevel,
  meta?: Record<string, unknown>,
): TaggedContent<T> {
  return {
    data,
    tag: createTag(source, trust, meta),
  };
}

// ─── Trust Resolution ────────────────────────────────────────

/**
 * Resolve trust level from multiple inputs.
 * Trust = minimum of all inputs (most restrictive wins).
 *
 * @example
 * resolveTrust(['user', 'tool']) // → 'tool'
 * resolveTrust(['system', 'untrusted']) // → 'untrusted'
 */
export function resolveTrust(levels: TrustLevel[]): TrustLevel {
  if (levels.length === 0) return 'untrusted';

  let min: TrustLevel = levels[0];
  for (let i = 1; i < levels.length; i++) {
    if (TRUST_RANK[levels[i]] < TRUST_RANK[min]) {
      min = levels[i];
    }
  }
  return min;
}

/**
 * Check if a trust level meets a minimum requirement.
 *
 * @example
 * meetsMinTrust('user', 'tool') // → true (user > tool)
 * meetsMinTrust('tool', 'user') // → false (tool < user)
 */
export function meetsMinTrust(
  actual: TrustLevel,
  required: TrustLevel,
): boolean {
  return TRUST_RANK[actual] >= TRUST_RANK[required];
}

/**
 * Check if tagged content meets minimum trust level.
 */
export function contentMeetsMinTrust<T>(
  content: TaggedContent<T>,
  required: TrustLevel,
): boolean {
  return meetsMinTrust(content.tag.trust, required);
}

// ─── Tag Composition ─────────────────────────────────────────

/** Maximum provenance chain depth to prevent runaway chains */
const MAX_PROVENANCE_DEPTH = 50;

/**
 * Merge multiple tagged contents into one.
 * Resulting trust = minimum of all inputs.
 * Provenance chains are concatenated and capped.
 *
 * @param contents - Input tagged contents
 * @param mergedData - The new combined data
 * @param agent - Source representing the agent doing the merge
 */
export function merge<T>(
  contents: TaggedContent[],
  mergedData: T,
  agent: ContentSource,
): TaggedContent<T> {
  const inputTags = contents.map((c) => c.tag);
  const trust = resolveTrust(inputTags.map((t) => t.trust));
  const now = Date.now();

  // Collect provenance from all inputs, deduped by tag ID
  const seen = new Set<string>();
  const provenance: ProvenanceEntry[] = [];

  for (const t of inputTags) {
    for (const entry of t.provenance) {
      const key = `${entry.source.kind}:${entry.source.id}:${entry.action}:${entry.timestamp}`;
      if (!seen.has(key)) {
        seen.add(key);
        provenance.push(entry);
      }
    }
  }

  // Cap provenance depth
  const cappedProvenance = provenance.length > MAX_PROVENANCE_DEPTH
    ? provenance.slice(-MAX_PROVENANCE_DEPTH)
    : provenance;

  // Add the merge step
  cappedProvenance.push({
    source: agent,
    trust,
    action: 'merged',
    timestamp: now,
  });

  return {
    data: mergedData,
    tag: {
      id: generateId(),
      source: agent,
      trust,
      provenance: cappedProvenance,
      timestamp: now,
    },
  };
}

/**
 * Transform tagged content (new data, same provenance chain + transform step).
 */
export function transform<T, U>(
  content: TaggedContent<T>,
  newData: U,
  transformer: ContentSource,
  action: ProvenanceAction = 'transformed',
): TaggedContent<U> {
  const now = Date.now();
  const provenance = [...content.tag.provenance];

  if (provenance.length < MAX_PROVENANCE_DEPTH) {
    provenance.push({
      source: transformer,
      trust: content.tag.trust,
      action,
      timestamp: now,
    });
  }

  return {
    data: newData,
    tag: {
      id: generateId(),
      source: transformer,
      trust: content.tag.trust, // Trust doesn't change on transform
      provenance,
      timestamp: now,
    },
  };
}

/**
 * Forward content through a boundary (preserves trust, records the hop).
 */
export function forward<T>(
  content: TaggedContent<T>,
  via: ContentSource,
): TaggedContent<T> {
  return transform(content, content.data, via, 'forwarded');
}

/**
 * Downgrade trust level (e.g., when content enters untrusted context).
 * Trust can only go down, never up.
 */
export function downgrade<T>(
  content: TaggedContent<T>,
  newTrust: TrustLevel,
  reason?: string,
): TaggedContent<T> {
  if (TRUST_RANK[newTrust] >= TRUST_RANK[content.tag.trust]) {
    // Can't upgrade trust — return unchanged
    return content;
  }

  return {
    data: content.data,
    tag: {
      ...content.tag,
      id: generateId(),
      trust: newTrust,
      meta: {
        ...content.tag.meta,
        ...(reason ? { downgradeReason: reason } : {}),
      },
    },
  };
}

// ─── Provenance Inspection ───────────────────────────────────

/**
 * Get human-readable provenance trace.
 *
 * @example
 * traceProvenance(content)
 * // → "user:+336... (created, trust=user) → tool:web_search (transformed, trust=tool)"
 */
export function traceProvenance(content: TaggedContent): string {
  return content.tag.provenance
    .map((entry) => {
      const src = entry.source.label || `${entry.source.kind}:${entry.source.id}`;
      return `${src} (${entry.action}, trust=${entry.trust})`;
    })
    .join(' → ');
}

/**
 * Check if content has any untrusted sources in its provenance.
 */
export function hasUntrustedOrigin(content: TaggedContent): boolean {
  return content.tag.provenance.some((e) => e.trust === 'untrusted');
}

/**
 * Get all unique sources that contributed to this content.
 */
export function getSources(content: TaggedContent): ContentSource[] {
  const seen = new Set<string>();
  const sources: ContentSource[] = [];

  for (const entry of content.tag.provenance) {
    const key = `${entry.source.kind}:${entry.source.id}`;
    if (!seen.has(key)) {
      seen.add(key);
      sources.push(entry.source);
    }
  }

  return sources;
}

// ─── Serialization ───────────────────────────────────────────

/**
 * Serialize a tag to compact wire format.
 * Minimized keys for transport efficiency.
 */
export function serializeTag(t: ContentTag): string {
  const compact: CompactTag = {
    ct: '1.0',
    id: t.id,
    src: {
      k: t.source.kind,
      id: t.source.id,
      ...(t.source.label ? { l: t.source.label } : {}),
    },
    tr: t.trust,
    pv: t.provenance.map((e) => ({
      src: {
        k: e.source.kind,
        id: e.source.id,
        ...(e.source.label ? { l: e.source.label } : {}),
      },
      tr: e.trust,
      act: e.action,
      ts: e.timestamp,
    })),
    ts: t.timestamp,
    ...(t.meta ? { m: t.meta } : {}),
  };

  return JSON.stringify(compact);
}

/** Valid trust levels for validation */
const VALID_TRUST_LEVELS = ['system', 'user', 'tool', 'untrusted'];

/**
 * Deserialize a tag from compact wire format.
 * Validates trust levels to prevent injection of invalid trust.
 */
export function deserializeTag(serialized: string): ContentTag {
  const c: CompactTag = JSON.parse(serialized);

  if (c.ct !== '1.0') {
    throw new Error(`Unsupported tag version: ${c.ct}`);
  }

  // Validate trust level
  if (!VALID_TRUST_LEVELS.includes(c.tr)) {
    throw new Error(`Invalid trust level: ${c.tr}`);
  }

  // Validate provenance trust levels
  for (const e of c.pv) {
    if (!VALID_TRUST_LEVELS.includes(e.tr)) {
      throw new Error(`Invalid provenance trust level: ${e.tr}`);
    }
  }

  return {
    id: c.id,
    source: {
      kind: c.src.k,
      id: c.src.id,
      ...(c.src.l ? { label: c.src.l } : {}),
    },
    trust: c.tr as TrustLevel,
    provenance: c.pv.map((e) => ({
      source: {
        kind: e.src.k,
        id: e.src.id,
        ...(e.src.l ? { label: e.src.l } : {}),
      },
      trust: e.tr as TrustLevel,
      action: e.act,
      timestamp: e.ts,
    })),
    timestamp: c.ts,
    ...(c.m ? { meta: c.m } : {}),
  };
}
