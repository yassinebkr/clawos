/**
 * ClawOS Layer 5: Trust Registry — Storage Layer
 */

import { readFile, writeFile, mkdir } from "node:fs/promises";
import { dirname } from "node:path";
import type {
  TrustEntry,
  PublisherKey,
  VulnerabilityEntry,
  RegistryFile,
  RegistryFilter,
  RegistryExport,
  ImportResult,
} from "./types.js";

// ============================================================================
// Registry Store
// ============================================================================

export class RegistryStore {
  private data: RegistryFile;
  private filePath: string;
  private dirty: boolean = false;

  constructor(filePath: string) {
    this.filePath = filePath;
    this.data = {
      version: 1,
      updatedAt: Date.now(),
      entries: {},
      publishers: {},
      vulnerabilities: [],
    };
  }

  /**
   * Load registry from file.
   */
  async load(): Promise<void> {
    try {
      const content = await readFile(this.filePath, "utf-8");
      const parsed = JSON.parse(content) as RegistryFile;

      // Validate version
      if (parsed.version !== 1) {
        throw new Error(`Unsupported registry version: ${parsed.version}`);
      }

      this.data = parsed;
      this.dirty = false;
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") {
        // File doesn't exist, start fresh
        this.dirty = true;
      } else {
        throw err;
      }
    }
  }

  /**
   * Save registry to file.
   */
  async save(): Promise<void> {
    if (!this.dirty) return;

    this.data.updatedAt = Date.now();

    await mkdir(dirname(this.filePath), { recursive: true });
    await writeFile(this.filePath, JSON.stringify(this.data, null, 2));
    this.dirty = false;
  }

  /**
   * Get entry by ID.
   */
  get(id: string): TrustEntry | undefined {
    return this.data.entries[id];
  }

  /**
   * Set/update entry.
   */
  set(entry: TrustEntry): void {
    entry.meta.updatedAt = Date.now();
    this.data.entries[entry.id] = entry;
    this.dirty = true;
  }

  /**
   * Delete entry.
   */
  delete(id: string): boolean {
    if (this.data.entries[id]) {
      delete this.data.entries[id];
      this.dirty = true;
      return true;
    }
    return false;
  }

  /**
   * List all entries with optional filter.
   */
  list(filter?: RegistryFilter): TrustEntry[] {
    let entries = Object.values(this.data.entries);

    if (filter) {
      if (filter.type) {
        entries = entries.filter((e) => e.type === filter.type);
      }
      if (filter.trust) {
        entries = entries.filter((e) => e.trust === filter.trust);
      }
      if (filter.publisher) {
        entries = entries.filter((e) => e.publisher?.id === filter.publisher);
      }
      if (filter.hasVulnerability !== undefined) {
        entries = entries.filter((e) => {
          const hasVuln =
            e.vulnerability && e.vulnerability.status !== "none";
          return filter.hasVulnerability ? hasVuln : !hasVuln;
        });
      }
    }

    return entries;
  }

  /**
   * Search entries by ID or publisher name.
   */
  search(query: string): TrustEntry[] {
    const lowerQuery = query.toLowerCase();
    return Object.values(this.data.entries).filter(
      (e) =>
        e.id.toLowerCase().includes(lowerQuery) ||
        e.publisher?.name.toLowerCase().includes(lowerQuery)
    );
  }

  // ============================================================================
  // Publisher Keys
  // ============================================================================

  /**
   * Get publisher key by ID.
   */
  getPublisher(keyId: string): PublisherKey | undefined {
    return this.data.publishers[keyId];
  }

  /**
   * Set publisher key.
   */
  setPublisher(key: PublisherKey): void {
    this.data.publishers[key.keyId] = key;
    this.dirty = true;
  }

  /**
   * Delete publisher key.
   */
  deletePublisher(keyId: string): boolean {
    if (this.data.publishers[keyId]) {
      delete this.data.publishers[keyId];
      this.dirty = true;
      return true;
    }
    return false;
  }

  /**
   * List all publisher keys.
   */
  listPublishers(): PublisherKey[] {
    return Object.values(this.data.publishers);
  }

  /**
   * Find publisher keys by publisher ID.
   */
  findPublisherKeys(publisherId: string): PublisherKey[] {
    return Object.values(this.data.publishers).filter(
      (k) => k.publisherId === publisherId
    );
  }

  // ============================================================================
  // Vulnerabilities
  // ============================================================================

  /**
   * Get vulnerabilities for an entry.
   */
  getVulnerabilities(entryId: string): VulnerabilityEntry[] {
    return this.data.vulnerabilities.filter((v) => v.affected.id === entryId);
  }

  /**
   * Add vulnerability entry.
   */
  addVulnerability(vuln: VulnerabilityEntry): void {
    // Check for duplicate
    const existing = this.data.vulnerabilities.findIndex(
      (v) => v.id === vuln.id
    );
    if (existing >= 0) {
      this.data.vulnerabilities[existing] = vuln;
    } else {
      this.data.vulnerabilities.push(vuln);
    }
    this.dirty = true;
  }

  /**
   * Remove vulnerability entry.
   */
  removeVulnerability(vulnId: string): boolean {
    const index = this.data.vulnerabilities.findIndex((v) => v.id === vulnId);
    if (index >= 0) {
      this.data.vulnerabilities.splice(index, 1);
      this.dirty = true;
      return true;
    }
    return false;
  }

  /**
   * List all vulnerabilities.
   */
  listVulnerabilities(): VulnerabilityEntry[] {
    return [...this.data.vulnerabilities];
  }

  // ============================================================================
  // Import/Export
  // ============================================================================

  /**
   * Export registry for backup/sharing.
   */
  export(): RegistryExport {
    return {
      version: 1,
      exportedAt: Date.now(),
      entries: Object.values(this.data.entries),
      publishers: Object.values(this.data.publishers),
    };
  }

  /**
   * Import registry entries.
   */
  import(data: RegistryExport, merge: boolean): ImportResult {
    const result: ImportResult = {
      success: true,
      imported: 0,
      skipped: 0,
      conflicts: [],
    };

    if (!merge) {
      // Replace all entries
      this.data.entries = {};
      this.data.publishers = {};
    }

    // Import entries
    for (const entry of data.entries) {
      if (merge && this.data.entries[entry.id]) {
        // Check for conflict
        const existing = this.data.entries[entry.id];
        if (existing.meta.updatedAt > entry.meta.updatedAt) {
          result.skipped++;
          result.conflicts.push(`${entry.id}: local is newer`);
          continue;
        }
      }
      this.data.entries[entry.id] = entry;
      result.imported++;
    }

    // Import publishers
    for (const pub of data.publishers) {
      if (merge && this.data.publishers[pub.keyId]) {
        result.skipped++;
        continue;
      }
      this.data.publishers[pub.keyId] = pub;
    }

    this.dirty = true;
    return result;
  }

  // ============================================================================
  // Utilities
  // ============================================================================

  /**
   * Get registry statistics.
   */
  getStats(): RegistryStats {
    const entries = Object.values(this.data.entries);
    return {
      totalEntries: entries.length,
      byType: {
        skill: entries.filter((e) => e.type === "skill").length,
        "mcp-server": entries.filter((e) => e.type === "mcp-server").length,
        plugin: entries.filter((e) => e.type === "plugin").length,
        tool: entries.filter((e) => e.type === "tool").length,
      },
      byTrust: {
        pinned: entries.filter((e) => e.trust === "pinned").length,
        signed: entries.filter((e) => e.trust === "signed").length,
        known: entries.filter((e) => e.trust === "known").length,
        unknown: entries.filter((e) => e.trust === "unknown").length,
      },
      totalPublishers: Object.keys(this.data.publishers).length,
      totalVulnerabilities: this.data.vulnerabilities.length,
      lastUpdated: this.data.updatedAt,
    };
  }
}

export interface RegistryStats {
  totalEntries: number;
  byType: Record<string, number>;
  byTrust: Record<string, number>;
  totalPublishers: number;
  totalVulnerabilities: number;
  lastUpdated: number;
}

// ============================================================================
// Cache Layer
// ============================================================================

export class TrustCache {
  private cache: Map<string, CacheEntry<TrustEntry>> = new Map();
  private maxEntries: number;
  private ttlMs: number;

  constructor(options?: { maxEntries?: number; ttlMs?: number }) {
    this.maxEntries = options?.maxEntries ?? 1000;
    this.ttlMs = options?.ttlMs ?? 60_000; // 1 minute default
  }

  get(id: string): TrustEntry | undefined {
    const entry = this.cache.get(id);
    if (!entry) return undefined;

    if (Date.now() > entry.expiresAt) {
      this.cache.delete(id);
      return undefined;
    }

    entry.accessedAt = Date.now();
    return entry.value;
  }

  set(id: string, value: TrustEntry): void {
    // LRU eviction if at capacity
    if (this.cache.size >= this.maxEntries) {
      const oldest = this.findOldest();
      if (oldest) this.cache.delete(oldest);
    }

    this.cache.set(id, {
      value,
      expiresAt: Date.now() + this.ttlMs,
      accessedAt: Date.now(),
    });
  }

  invalidate(id: string): void {
    this.cache.delete(id);
  }

  clear(): void {
    this.cache.clear();
  }

  private findOldest(): string | undefined {
    let oldestKey: string | undefined;
    let oldestTime = Infinity;

    for (const [key, entry] of this.cache) {
      if (entry.accessedAt < oldestTime) {
        oldestTime = entry.accessedAt;
        oldestKey = key;
      }
    }

    return oldestKey;
  }
}

interface CacheEntry<T> {
  value: T;
  expiresAt: number;
  accessedAt: number;
}
