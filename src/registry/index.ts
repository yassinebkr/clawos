/**
 * ClawOS Layer 5: Trust Registry
 *
 * Maintains trust metadata for skills, MCP servers, and external tools.
 * Provides signature verification, hash pinning, and vulnerability tracking
 * to prevent supply chain attacks and ensure code integrity.
 *
 * @module
 */

// Types
export type {
  TrustLevel,
  EntryType,
  TrustEntry,
  PublisherInfo,
  VersionInfo,
  HashInfo,
  SignatureInfo,
  VulnerabilityStatus,
  EntryMeta,
  PublisherKey,
  VulnerabilityEntry,
  VulnerabilityPolicy,
  VerifyResult,
  SignatureVerifyResult,
  EnforcementResult,
  RegistryFilter,
  SyncResult,
  ImportResult,
  RegistryExport,
  RegistryFile,
  Layer5Config,
} from "./types.js";

// Crypto utilities
export {
  calculateHash,
  hashFile,
  hashDirectory,
  compareHashes,
  verifySignature,
  calculateKeyFingerprint,
  isValidPublicKey,
  normalizePublicKey,
} from "./crypto.js";

// Storage
export {
  RegistryStore,
  TrustCache,
  type RegistryStats,
} from "./store.js";

// Main Service
export {
  TrustRegistry,
  getTrustRegistry,
  createTrustRegistry,
} from "./trust-registry.js";
