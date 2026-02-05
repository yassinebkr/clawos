/**
 * ClawOS Layer 1: Content Tagging
 *
 * Foundation layer — every piece of data gets tagged with source,
 * trust level, and provenance chain.
 */

export type {
  TrustLevel,
  SourceKind,
  ContentSource,
  ProvenanceAction,
  ProvenanceEntry,
  ContentTag,
  TaggedContent,
  CompactTag,
} from './types';

export { TRUST_RANK, TRUST_LEVELS } from './types';

export {
  createTag,
  tag,
  resolveTrust,
  meetsMinTrust,
  contentMeetsMinTrust,
  merge,
  transform,
  forward,
  downgrade,
  traceProvenance,
  hasUntrustedOrigin,
  getSources,
  serializeTag,
  deserializeTag,
} from './tag';

export {
  SYSTEM_OPENCLAW,
  SYSTEM_PROMPT,
  SYSTEM_CLAWOS,
  SYSTEM_HEARTBEAT,
  SYSTEM_CRON,
  userSource,
  toolSource,
  skillSource,
  agentSource,
  externalSource,
  mcpSource,
  DEFAULT_TRUST,
  defaultTrustFor,
} from './sources';
