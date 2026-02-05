/**
 * ClawOS Layer 1: Content Tagging — Type Definitions
 *
 * Every piece of data in an agent system gets tagged with source,
 * trust level, and provenance chain. This is the foundation.
 */

// ─── Trust Levels ────────────────────────────────────────────

/** Trust levels ordered from highest to lowest */
export type TrustLevel = 'system' | 'user' | 'tool' | 'untrusted';

/** Numeric ranking for trust comparison (higher = more trusted) */
export const TRUST_RANK: Record<TrustLevel, number> = {
  system: 3,
  user: 2,
  tool: 1,
  untrusted: 0,
} as const;

/** All trust levels in descending order */
export const TRUST_LEVELS: readonly TrustLevel[] = [
  'system', 'user', 'tool', 'untrusted',
] as const;

// ─── Content Source ──────────────────────────────────────────

/** What kind of entity produced the content */
export type SourceKind = 'system' | 'user' | 'tool' | 'agent' | 'external';

/** Identifies who/what produced a piece of content */
export interface ContentSource {
  /** Source type */
  kind: SourceKind;

  /** Unique identifier (user ID, tool name, agent ID, URL, etc.) */
  id: string;

  /** Human-readable label (optional) */
  label?: string;
}

// ─── Provenance ──────────────────────────────────────────────

/** What happened to the content at this step */
export type ProvenanceAction =
  | 'created'       // Content was originally produced
  | 'transformed'   // Content was modified (summarized, reformatted, etc.)
  | 'merged'        // Multiple contents were combined
  | 'forwarded'     // Content was passed through unchanged
  | 'cached';       // Content was stored and retrieved

/** One step in the provenance chain */
export interface ProvenanceEntry {
  /** Source that touched the content */
  source: ContentSource;

  /** Trust level at this point in the chain */
  trust: TrustLevel;

  /** What happened */
  action: ProvenanceAction;

  /** When this happened (unix ms) */
  timestamp: number;
}

// ─── Content Tag ─────────────────────────────────────────────

/** Security tag attached to every piece of content */
export interface ContentTag {
  /** Unique tag ID for tracking */
  id: string;

  /** What produced this content */
  source: ContentSource;

  /** Current trust level */
  trust: TrustLevel;

  /** Chain of sources that contributed to this content */
  provenance: ProvenanceEntry[];

  /** When this tag was created (unix ms) */
  timestamp: number;

  /** Optional metadata (tool-specific, layer-specific, etc.) */
  meta?: Record<string, unknown>;
}

// ─── Tagged Content ──────────────────────────────────────────

/** Content wrapped with its security tag */
export interface TaggedContent<T = string> {
  /** The actual content */
  data: T;

  /** Security tag */
  tag: ContentTag;
}

// ─── Compact Serialization ───────────────────────────────────

/** Compact wire format for tags (minimized keys for transport) */
export interface CompactTag {
  /** Version */
  ct: '1.0';
  /** Tag ID */
  id: string;
  /** Source */
  src: { k: SourceKind; id: string; l?: string };
  /** Trust */
  tr: TrustLevel;
  /** Provenance */
  pv: Array<{
    src: { k: SourceKind; id: string; l?: string };
    tr: TrustLevel;
    act: ProvenanceAction;
    ts: number;
  }>;
  /** Timestamp */
  ts: number;
  /** Metadata */
  m?: Record<string, unknown>;
}
