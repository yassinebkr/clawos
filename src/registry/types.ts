/**
 * ClawOS Layer 5: Trust Registry — Type Definitions
 */

// ============================================================================
// Trust Levels
// ============================================================================

export type TrustLevel = "pinned" | "signed" | "known" | "unknown";

export type EntryType = "skill" | "mcp-server" | "plugin" | "tool";

// ============================================================================
// Trust Entry
// ============================================================================

export interface TrustEntry {
  /** Unique identifier (e.g., skill name, MCP server URL) */
  id: string;

  /** Entry type */
  type: EntryType;

  /** Trust level */
  trust: TrustLevel;

  /** Publisher information */
  publisher?: PublisherInfo;

  /** Version information */
  version?: VersionInfo;

  /** Integrity hashes */
  hashes?: HashInfo;

  /** Signature (if signed) */
  signature?: SignatureInfo;

  /** Vulnerability status */
  vulnerability?: VulnerabilityStatus;

  /** Metadata */
  meta: EntryMeta;
}

export interface PublisherInfo {
  id: string;
  name: string;
  publicKey?: string;
  verified: boolean;
}

export interface VersionInfo {
  current: string;
  pinned?: string;
  allowedRange?: string;
}

export interface HashInfo {
  sha256?: string;
  sha512?: string;
  algorithm: "sha256" | "sha512";
}

export interface SignatureInfo {
  value: string;
  algorithm: "ed25519" | "rsa-sha256";
  keyId: string;
  timestamp: number;
}

export interface VulnerabilityStatus {
  status: "none" | "low" | "medium" | "high" | "critical";
  cves?: string[];
  advisoryUrl?: string;
  lastChecked: number;
}

export interface EntryMeta {
  addedAt: number;
  updatedAt: number;
  source: "manual" | "registry" | "auto";
  notes?: string;
}

// ============================================================================
// Publisher Keys
// ============================================================================

export interface PublisherKey {
  /** Key identifier */
  keyId: string;

  /** Publisher ID */
  publisherId: string;

  /** Public key (PEM or base64) */
  publicKey: string;

  /** Key algorithm */
  algorithm: "ed25519" | "rsa";

  /** Key status */
  status: "active" | "revoked" | "expired";

  /** Validity period */
  validFrom: number;
  validUntil?: number;

  /** Fingerprint for display */
  fingerprint: string;
}

// ============================================================================
// Vulnerability
// ============================================================================

export interface VulnerabilityEntry {
  /** CVE or advisory ID */
  id: string;

  /** Severity */
  severity: "low" | "medium" | "high" | "critical";

  /** CVSS score (0-10) */
  cvssScore?: number;

  /** Affected package/skill */
  affected: {
    id: string;
    versionRange: string;
  };

  /** Description */
  description: string;

  /** Fix information */
  fix?: {
    version: string;
    available: boolean;
  };

  /** References */
  references: string[];

  /** Timestamps */
  publishedAt: number;
  updatedAt: number;
}

export interface VulnerabilityPolicy {
  blockCritical: boolean;
  blockHigh: boolean;
  warnHigh: boolean;
  logAll: boolean;
}

// ============================================================================
// Verification Results
// ============================================================================

export interface VerifyResult {
  /** Overall verification passed */
  verified: boolean;

  /** Trust level of the entry */
  trust: TrustLevel | "unknown";

  /** Hash verification result */
  hash?: {
    matched: boolean;
    expected?: string;
    actual: string;
  };

  /** Signature verification result */
  signature?: SignatureVerifyResult;

  /** Vulnerability check result */
  vulnerability?: EnforcementResult;

  /** Recommended action */
  action: "allow" | "warn" | "block" | "prompt";

  /** Reason for action */
  reason?: string;
}

export interface SignatureVerifyResult {
  valid: boolean;
  algorithm: string;
  error?: string;
}

export interface EnforcementResult {
  action: "allow" | "warn" | "block" | "log";
  reason?: string;
  advisory?: string;
}

// ============================================================================
// Registry Operations
// ============================================================================

export interface RegistryFilter {
  type?: EntryType;
  trust?: TrustLevel;
  publisher?: string;
  hasVulnerability?: boolean;
}

export interface SyncResult {
  success: boolean;
  entriesUpdated: number;
  newVulnerabilities: number;
  errors: string[];
}

export interface ImportResult {
  success: boolean;
  imported: number;
  skipped: number;
  conflicts: string[];
}

export interface RegistryExport {
  version: 1;
  exportedAt: number;
  entries: TrustEntry[];
  publishers: PublisherKey[];
}

// ============================================================================
// Storage
// ============================================================================

export interface RegistryFile {
  version: 1;
  updatedAt: number;
  entries: Record<string, TrustEntry>;
  publishers: Record<string, PublisherKey>;
  vulnerabilities: VulnerabilityEntry[];
}

// ============================================================================
// Configuration
// ============================================================================

export interface Layer5Config {
  /** Enable trust registry */
  enabled: boolean;

  /** Registry file path */
  registryPath: string;

  /** Policy for unknown entries */
  unknownPolicy: "block" | "prompt" | "allow-once" | "allow-remember";

  /** Require signatures for skills */
  requireSignatures: boolean;

  /** Hash algorithm preference */
  hashAlgorithm: "sha256" | "sha512";

  /** Vulnerability policy */
  vulnerability: VulnerabilityPolicy;

  /** Auto-pin on first use */
  autoPinOnFirstUse: boolean;

  /** Cache settings */
  cache: {
    enabled: boolean;
    ttlMs: number;
    maxEntries: number;
  };
}
