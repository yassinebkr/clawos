/**
 * ClawOS Layer 5: Trust Registry — Main Service
 */

import { randomUUID } from "node:crypto";
import type {
  TrustEntry,
  TrustLevel,
  EntryType,
  PublisherKey,
  VulnerabilityEntry,
  VulnerabilityPolicy,
  VerifyResult,
  EnforcementResult,
  RegistryFilter,
  RegistryExport,
  ImportResult,
  SyncResult,
  Layer5Config,
} from "./types.js";
import { RegistryStore, TrustCache, type RegistryStats } from "./store.js";
import {
  calculateHash,
  hashFile,
  hashDirectory,
  compareHashes,
  verifySignature,
  calculateKeyFingerprint,
} from "./crypto.js";

// ============================================================================
// Trust Registry Service
// ============================================================================

export class TrustRegistry {
  private store: RegistryStore;
  private cache: TrustCache;
  private config: Layer5Config;
  private initialized: boolean = false;

  constructor(config?: Partial<Layer5Config>) {
    this.config = {
      enabled: config?.enabled ?? true,
      registryPath:
        config?.registryPath ?? "~/.clawos/trust-registry.json".replace(
          "~",
          process.env.HOME || ""
        ),
      unknownPolicy: config?.unknownPolicy ?? "prompt",
      requireSignatures: config?.requireSignatures ?? false,
      hashAlgorithm: config?.hashAlgorithm ?? "sha256",
      vulnerability: config?.vulnerability ?? {
        blockCritical: true,
        blockHigh: false,
        warnHigh: true,
        logAll: true,
      },
      autoPinOnFirstUse: config?.autoPinOnFirstUse ?? false,
      cache: config?.cache ?? {
        enabled: true,
        ttlMs: 60_000,
        maxEntries: 1000,
      },
    };

    this.store = new RegistryStore(this.config.registryPath);
    this.cache = new TrustCache(this.config.cache);
  }

  /**
   * Initialize the registry (load from disk).
   */
  async init(): Promise<void> {
    if (this.initialized) return;
    await this.store.load();
    this.initialized = true;
  }

  /**
   * Save any pending changes.
   */
  async save(): Promise<void> {
    await this.store.save();
  }

  // ============================================================================
  // Verification
  // ============================================================================

  /**
   * Verify a skill/tool before execution.
   */
  async verify(
    id: string,
    content: Buffer | string
  ): Promise<VerifyResult> {
    await this.init();

    // Check cache first
    let entry = this.cache.get(id);
    if (!entry) {
      entry = this.store.get(id);
      if (entry && this.config.cache.enabled) {
        this.cache.set(id, entry);
      }
    }

    // Calculate content hash
    const actualHash = calculateHash(content, this.config.hashAlgorithm);

    // Handle unknown entry
    if (!entry) {
      return this.handleUnknown(id, actualHash);
    }

    // Verify based on trust level
    const result: VerifyResult = {
      verified: false,
      trust: entry.trust,
      action: "allow",
    };

    // Hash verification
    if (entry.hashes) {
      const expectedHash =
        this.config.hashAlgorithm === "sha256"
          ? entry.hashes.sha256
          : entry.hashes.sha512;

      if (expectedHash) {
        const matched = compareHashes(expectedHash, actualHash);
        result.hash = {
          matched,
          expected: expectedHash,
          actual: actualHash,
        };

        if (entry.trust === "pinned" && !matched) {
          result.verified = false;
          result.action = "block";
          result.reason = "Hash mismatch for pinned entry";
          return result;
        }

        if (!matched && entry.trust === "known") {
          result.action = "warn";
          result.reason = "Hash changed since last verification";
        }
      }
    }

    // Signature verification
    if (entry.signature && entry.publisher?.publicKey) {
      const sigResult = verifySignature(
        content,
        entry.signature.value,
        entry.publisher.publicKey,
        entry.signature.algorithm
      );
      result.signature = sigResult;

      if (entry.trust === "signed" && !sigResult.valid) {
        result.verified = false;
        result.action = "block";
        result.reason = `Signature verification failed: ${sigResult.error}`;
        return result;
      }
    } else if (this.config.requireSignatures && entry.trust !== "pinned") {
      result.verified = false;
      result.action = "block";
      result.reason = "Signature required but not present";
      return result;
    }

    // Vulnerability check
    if (entry.vulnerability) {
      const vulnResult = this.checkVulnerabilityPolicy(entry);
      result.vulnerability = vulnResult;

      if (vulnResult.action === "block") {
        result.verified = false;
        result.action = "block";
        result.reason = vulnResult.reason;
        return result;
      }

      if (vulnResult.action === "warn") {
        result.action = "warn";
        result.reason = vulnResult.reason;
      }
    }

    // All checks passed
    result.verified = true;
    if (result.action !== "warn") {
      result.action = "allow";
    }

    return result;
  }

  /**
   * Verify a directory (skill folder).
   */
  async verifyDirectory(id: string, dirPath: string): Promise<VerifyResult> {
    const hash = await hashDirectory(dirPath, this.config.hashAlgorithm);
    return this.verify(id, hash);
  }

  /**
   * Verify a file.
   */
  async verifyFile(id: string, filePath: string): Promise<VerifyResult> {
    const hash = await hashFile(filePath, this.config.hashAlgorithm);
    return this.verify(id, hash);
  }

  private handleUnknown(id: string, hash: string): VerifyResult {
    const result: VerifyResult = {
      verified: false,
      trust: "unknown",
      hash: { matched: false, actual: hash },
      action: "prompt",
    };

    switch (this.config.unknownPolicy) {
      case "block":
        result.action = "block";
        result.reason = "Unknown entry blocked by policy";
        break;
      case "allow-once":
        result.verified = true;
        result.action = "allow";
        result.reason = "Unknown entry allowed (one-time)";
        break;
      case "allow-remember":
        // Auto-add to registry
        this.addEntry({
          id,
          type: "skill",
          trust: "known",
          hashes: {
            [this.config.hashAlgorithm]: hash,
            algorithm: this.config.hashAlgorithm,
          },
          meta: {
            addedAt: Date.now(),
            updatedAt: Date.now(),
            source: "auto",
          },
        });
        result.verified = true;
        result.action = "allow";
        result.reason = "Unknown entry added to registry";
        break;
      case "prompt":
      default:
        result.action = "prompt";
        result.reason = "Unknown entry requires user approval";
        break;
    }

    return result;
  }

  private checkVulnerabilityPolicy(entry: TrustEntry): EnforcementResult {
    if (!entry.vulnerability || entry.vulnerability.status === "none") {
      return { action: "allow" };
    }

    const severity = entry.vulnerability.status;
    const policy = this.config.vulnerability;

    switch (severity) {
      case "critical":
        if (policy.blockCritical) {
          return {
            action: "block",
            reason: `Critical vulnerability: ${entry.vulnerability.cves?.join(", ") || "unknown"}`,
            advisory: entry.vulnerability.advisoryUrl,
          };
        }
        break;

      case "high":
        if (policy.blockHigh) {
          return {
            action: "block",
            reason: "High severity vulnerability detected",
          };
        }
        if (policy.warnHigh) {
          return {
            action: "warn",
            reason: "High severity vulnerability: review recommended",
          };
        }
        break;

      case "medium":
      case "low":
        if (policy.logAll) {
          return {
            action: "log",
            reason: `${severity} severity vulnerability known`,
          };
        }
        break;
    }

    return { action: "allow" };
  }

  // ============================================================================
  // Entry Management
  // ============================================================================

  /**
   * Get trust entry.
   */
  async getEntry(id: string): Promise<TrustEntry | undefined> {
    await this.init();
    return this.store.get(id);
  }

  /**
   * Add/update trust entry.
   */
  async addEntry(entry: TrustEntry): Promise<void> {
    await this.init();
    this.store.set(entry);
    this.cache.invalidate(entry.id);
    await this.save();
  }

  /**
   * Remove trust entry.
   */
  async removeEntry(id: string): Promise<boolean> {
    await this.init();
    const removed = this.store.delete(id);
    if (removed) {
      this.cache.invalidate(id);
      await this.save();
    }
    return removed;
  }

  /**
   * List entries with optional filter.
   */
  async listEntries(filter?: RegistryFilter): Promise<TrustEntry[]> {
    await this.init();
    return this.store.list(filter);
  }

  /**
   * Search entries.
   */
  async searchEntries(query: string): Promise<TrustEntry[]> {
    await this.init();
    return this.store.search(query);
  }

  // ============================================================================
  // Pinning
  // ============================================================================

  /**
   * Pin a specific hash.
   */
  async pin(id: string, hash: string, version?: string): Promise<void> {
    await this.init();

    let entry = this.store.get(id);
    if (!entry) {
      // Create new entry
      entry = {
        id,
        type: "skill",
        trust: "pinned",
        hashes: {
          [this.config.hashAlgorithm]: hash,
          algorithm: this.config.hashAlgorithm,
        },
        version: version ? { current: version, pinned: version } : undefined,
        meta: {
          addedAt: Date.now(),
          updatedAt: Date.now(),
          source: "manual",
        },
      };
    } else {
      // Update existing entry
      entry.trust = "pinned";
      entry.hashes = {
        ...entry.hashes,
        [this.config.hashAlgorithm]: hash,
        algorithm: this.config.hashAlgorithm,
      };
      if (version) {
        entry.version = { ...entry.version, current: version, pinned: version };
      }
    }

    this.store.set(entry);
    this.cache.invalidate(id);
    await this.save();
  }

  /**
   * Unpin (revert to known).
   */
  async unpin(id: string): Promise<void> {
    await this.init();

    const entry = this.store.get(id);
    if (entry && entry.trust === "pinned") {
      entry.trust = "known";
      if (entry.version) {
        delete entry.version.pinned;
      }
      this.store.set(entry);
      this.cache.invalidate(id);
      await this.save();
    }
  }

  // ============================================================================
  // Publishers
  // ============================================================================

  /**
   * Register a publisher key.
   */
  async registerPublisher(key: PublisherKey): Promise<void> {
    await this.init();

    // Calculate fingerprint if not provided
    if (!key.fingerprint) {
      key.fingerprint = calculateKeyFingerprint(key.publicKey);
    }

    this.store.setPublisher(key);
    await this.save();
  }

  /**
   * Revoke a publisher key.
   */
  async revokePublisher(keyId: string, reason: string): Promise<void> {
    await this.init();

    const key = this.store.getPublisher(keyId);
    if (key) {
      key.status = "revoked";
      this.store.setPublisher(key);
      await this.save();
    }
  }

  /**
   * Get publisher key.
   */
  async getPublisher(keyId: string): Promise<PublisherKey | undefined> {
    await this.init();
    return this.store.getPublisher(keyId);
  }

  /**
   * List all publishers.
   */
  async listPublishers(): Promise<PublisherKey[]> {
    await this.init();
    return this.store.listPublishers();
  }

  // ============================================================================
  // Vulnerabilities
  // ============================================================================

  /**
   * Check for vulnerabilities affecting an entry.
   */
  async checkVulnerabilities(id: string): Promise<VulnerabilityEntry[]> {
    await this.init();
    return this.store.getVulnerabilities(id);
  }

  /**
   * Add a vulnerability entry.
   */
  async addVulnerability(vuln: VulnerabilityEntry): Promise<void> {
    await this.init();
    this.store.addVulnerability(vuln);

    // Update affected entry's vulnerability status
    const entry = this.store.get(vuln.affected.id);
    if (entry) {
      entry.vulnerability = {
        status: vuln.severity,
        cves: [vuln.id],
        lastChecked: Date.now(),
      };
      this.store.set(entry);
      this.cache.invalidate(entry.id);
    }

    await this.save();
  }

  /**
   * Sync advisories (placeholder - would fetch from real sources).
   */
  async syncAdvisories(): Promise<SyncResult> {
    // In a real implementation, this would fetch from advisory sources
    // For now, just return a placeholder result
    return {
      success: true,
      entriesUpdated: 0,
      newVulnerabilities: 0,
      errors: [],
    };
  }

  // ============================================================================
  // Import/Export
  // ============================================================================

  /**
   * Export registry.
   */
  async export(): Promise<RegistryExport> {
    await this.init();
    return this.store.export();
  }

  /**
   * Import registry entries.
   */
  async import(data: RegistryExport, merge: boolean): Promise<ImportResult> {
    await this.init();
    const result = this.store.import(data, merge);
    this.cache.clear();
    await this.save();
    return result;
  }

  // ============================================================================
  // Utilities
  // ============================================================================

  /**
   * Get registry statistics.
   */
  async getStats(): Promise<RegistryStats> {
    await this.init();
    return this.store.getStats();
  }

  /**
   * Get current configuration.
   */
  getConfig(): Layer5Config {
    return { ...this.config };
  }

  /**
   * Update configuration.
   */
  configure(config: Partial<Layer5Config>): void {
    Object.assign(this.config, config);
  }
}

// ============================================================================
// Default Instance
// ============================================================================

let defaultInstance: TrustRegistry | null = null;

export function getTrustRegistry(): TrustRegistry {
  if (!defaultInstance) {
    defaultInstance = new TrustRegistry();
  }
  return defaultInstance;
}

export function createTrustRegistry(
  config?: Partial<Layer5Config>
): TrustRegistry {
  return new TrustRegistry(config);
}
