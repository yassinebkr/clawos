/**
 * ClawOS Layer 0: Bootstrap File Integrity Monitor
 *
 * Monitors protected workspace files (SOUL.md, AGENTS.md, etc.) for
 * unauthorized modifications. Detects changes by comparing SHA-256
 * snapshots of protected files across time.
 *
 * No external dependencies — uses only node:crypto, node:fs/promises, node:path.
 */

import { createHash } from "node:crypto";
import { readFile, stat, realpath } from "node:fs/promises";
import { resolve, basename, join } from "node:path";

// ─── Types ───────────────────────────────────────────────────

export type ProtectionTier = "critical" | "sensitive" | "monitored";

export interface ProtectedFile {
  name: string;
  tier: ProtectionTier;
  patterns: string[];
}

export interface FileSnapshot {
  path: string;
  name: string;
  hash: string;
  size: number;
  mtime: number;
  tier: ProtectionTier;
}

export interface IntegritySnapshot {
  timestamp: number;
  workspaceDir: string;
  files: Map<string, FileSnapshot>;
}

export interface ChangeEvent {
  file: string;
  path: string;
  tier: ProtectionTier;
  changeType: "modified" | "deleted" | "created";
  previousHash?: string;
  currentHash?: string;
  previousSize?: number;
  currentSize?: number;
  detectedAt: number;
}

// ─── Protected File Registry ─────────────────────────────────

const PROTECTED_FILES: ProtectedFile[] = [
  // Tier 1 — Critical: always alert user
  { name: "SOUL.md", tier: "critical", patterns: ["SOUL.md"] },
  { name: "AGENTS.md", tier: "critical", patterns: ["AGENTS.md"] },

  // Tier 2 — Sensitive: alert user
  { name: "USER.md", tier: "sensitive", patterns: ["USER.md"] },
  { name: "IDENTITY.md", tier: "sensitive", patterns: ["IDENTITY.md"] },
  { name: "BOOTSTRAP.md", tier: "sensitive", patterns: ["BOOTSTRAP.md"] },

  // Tier 3 — Monitored: log only
  { name: "HEARTBEAT.md", tier: "monitored", patterns: ["HEARTBEAT.md"] },
  { name: "TOOLS.md", tier: "monitored", patterns: ["TOOLS.md"] },
];

// ─── Functions ───────────────────────────────────────────────

/**
 * Returns the list of protected files and their tiers.
 */
export function getProtectedFiles(): ProtectedFile[] {
  return [...PROTECTED_FILES];
}

/**
 * Normalizes a file path to an absolute path within the workspace context.
 * Handles relative paths, absolute paths, ./ prefix, trailing slashes.
 */
export function normalizePath(
  workspaceDir: string,
  filePath: string,
): string {
  const trimmed = filePath.replace(/\/+$/, "");
  return resolve(workspaceDir, trimmed);
}

/**
 * Checks if a given path targets a protected file.
 * Handles direct names, absolute paths, relative paths, ./ prefix,
 * path traversal, and case-insensitive basename matching.
 */
export function isProtectedPath(
  workspaceDir: string,
  filePath: string,
): { protected: boolean; file?: ProtectedFile } {
  const normalized = normalizePath(workspaceDir, filePath);
  const base = basename(normalized).toLowerCase();

  for (const pf of PROTECTED_FILES) {
    if (pf.name.toLowerCase() === base) {
      return { protected: true, file: pf };
    }
  }

  return { protected: false };
}

/**
 * Computes SHA-256 hash of a file's contents.
 */
async function hashFile(filePath: string): Promise<string> {
  const content = await readFile(filePath);
  return createHash("sha256").update(content).digest("hex");
}

/**
 * Creates a snapshot of all protected files that exist in the workspace.
 * Resolves symlinks via fs.realpath(). Skips missing files gracefully.
 */
export async function createSnapshot(
  workspaceDir: string,
): Promise<IntegritySnapshot> {
  const resolvedDir = resolve(workspaceDir);
  const files = new Map<string, FileSnapshot>();

  for (const pf of PROTECTED_FILES) {
    const filePath = join(resolvedDir, pf.name);

    try {
      // Resolve symlinks to get the real path
      const realPath = await realpath(filePath);
      const fileStat = await stat(realPath);
      const hash = await hashFile(realPath);

      files.set(pf.name, {
        path: realPath,
        name: pf.name,
        hash,
        size: fileStat.size,
        mtime: fileStat.mtimeMs,
        tier: pf.tier,
      });
    } catch {
      // File doesn't exist or is inaccessible — skip
    }
  }

  return {
    timestamp: Date.now(),
    workspaceDir: resolvedDir,
    files,
  };
}

/**
 * Compares two snapshots and returns a list of changes.
 * Detects: modified (hash changed), deleted, created.
 */
export function compareSnapshots(
  previous: IntegritySnapshot,
  current: IntegritySnapshot,
): ChangeEvent[] {
  const changes: ChangeEvent[] = [];
  const now = Date.now();

  // Check for modified and deleted files
  for (const [name, prevSnap] of previous.files) {
    const currSnap = current.files.get(name);

    if (!currSnap) {
      // Deleted
      changes.push({
        file: name,
        path: prevSnap.path,
        tier: prevSnap.tier,
        changeType: "deleted",
        previousHash: prevSnap.hash,
        previousSize: prevSnap.size,
        detectedAt: now,
      });
    } else if (currSnap.hash !== prevSnap.hash) {
      // Modified
      changes.push({
        file: name,
        path: currSnap.path,
        tier: currSnap.tier,
        changeType: "modified",
        previousHash: prevSnap.hash,
        currentHash: currSnap.hash,
        previousSize: prevSnap.size,
        currentSize: currSnap.size,
        detectedAt: now,
      });
    }
  }

  // Check for created files
  for (const [name, currSnap] of current.files) {
    if (!previous.files.has(name)) {
      changes.push({
        file: name,
        path: currSnap.path,
        tier: currSnap.tier,
        changeType: "created",
        currentHash: currSnap.hash,
        currentSize: currSnap.size,
        detectedAt: now,
      });
    }
  }

  return changes;
}

/**
 * Formats change events into a human-readable alert string.
 * Tier icons: critical ⚠️, sensitive 🔔, monitored 📝
 */
export function formatChangeAlert(changes: ChangeEvent[]): string {
  if (changes.length === 0) {
    return "No changes detected.";
  }

  const tierIcon: Record<ProtectionTier, string> = {
    critical: "⚠️",
    sensitive: "🔔",
    monitored: "📝",
  };

  const lines = changes.map((change) => {
    const icon = tierIcon[change.tier];
    const action = change.changeType.toUpperCase();
    return `${icon} [${change.tier}] ${change.file} — ${action}`;
  });

  return [
    `Integrity alert: ${changes.length} change(s) detected`,
    "",
    ...lines,
  ].join("\n");
}
