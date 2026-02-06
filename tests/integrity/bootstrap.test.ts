/**
 * Layer 0: Bootstrap File Integrity Monitor — Tests
 *
 * Covers snapshot creation, comparison, path detection, and alert formatting.
 */

import { describe, it, expect, afterAll } from "vitest";
import { writeFile, mkdir, rm, symlink } from "node:fs/promises";
import { join } from "node:path";
import { createHash } from "node:crypto";
import {
  getProtectedFiles,
  createSnapshot,
  compareSnapshots,
  normalizePath,
  isProtectedPath,
  formatChangeAlert,
} from "../../src/integrity/bootstrap";
import type {
  IntegritySnapshot,
  FileSnapshot,
  ChangeEvent,
  ProtectionTier,
} from "../../src/integrity/bootstrap";

// ─── Test Workspace Setup ────────────────────────────────────

const TEST_DIR = `/tmp/clawos-bootstrap-test-${Date.now()}`;

async function setupWorkspace(files: Record<string, string>): Promise<string> {
  const dir = join(TEST_DIR, `ws-${Math.random().toString(36).slice(2, 8)}`);
  await mkdir(dir, { recursive: true });
  for (const [name, content] of Object.entries(files)) {
    await writeFile(join(dir, name), content, "utf-8");
  }
  return dir;
}

function sha256(content: string): string {
  return createHash("sha256").update(content).digest("hex");
}

function makeSnapshot(
  workspaceDir: string,
  files: Map<string, FileSnapshot>,
  timestamp?: number,
): IntegritySnapshot {
  return { timestamp: timestamp ?? Date.now(), workspaceDir, files };
}

afterAll(async () => {
  await rm(TEST_DIR, { recursive: true, force: true });
});

// ─── createSnapshot ──────────────────────────────────────────

describe("createSnapshot", () => {
  it("hashes existing protected files", async () => {
    const dir = await setupWorkspace({
      "SOUL.md": "I am the soul",
      "AGENTS.md": "Agent rules",
    });

    const snap = await createSnapshot(dir);

    expect(snap.files.size).toBe(2);

    const soul = snap.files.get("SOUL.md")!;
    expect(soul).toBeDefined();
    expect(soul.hash).toBe(sha256("I am the soul"));
    expect(soul.name).toBe("SOUL.md");
    expect(soul.size).toBeGreaterThan(0);
    expect(soul.tier).toBe("critical");

    const agents = snap.files.get("AGENTS.md")!;
    expect(agents.hash).toBe(sha256("Agent rules"));
  });

  it("skips missing files gracefully", async () => {
    const dir = await setupWorkspace({ "SOUL.md": "soul only" });

    const snap = await createSnapshot(dir);

    expect(snap.files.has("SOUL.md")).toBe(true);
    expect(snap.files.has("AGENTS.md")).toBe(false);
    expect(snap.files.has("USER.md")).toBe(false);
  });

  it("handles empty workspace (no protected files exist)", async () => {
    const dir = await setupWorkspace({});

    const snap = await createSnapshot(dir);

    expect(snap.files.size).toBe(0);
    expect(snap.workspaceDir).toBeTruthy();
    expect(snap.timestamp).toBeGreaterThan(0);
  });
});

// ─── compareSnapshots ────────────────────────────────────────

describe("compareSnapshots", () => {
  it("detects modified, deleted, and created files", () => {
    const dir = "/workspace";

    const prev = makeSnapshot(
      dir,
      new Map<string, FileSnapshot>([
        [
          "SOUL.md",
          { path: `${dir}/SOUL.md`, name: "SOUL.md", hash: "aaa", size: 10, mtime: 1000, tier: "critical" },
        ],
        [
          "USER.md",
          { path: `${dir}/USER.md`, name: "USER.md", hash: "bbb", size: 20, mtime: 1000, tier: "sensitive" },
        ],
      ]),
    );

    const curr = makeSnapshot(
      dir,
      new Map<string, FileSnapshot>([
        [
          "SOUL.md",
          { path: `${dir}/SOUL.md`, name: "SOUL.md", hash: "xxx", size: 15, mtime: 2000, tier: "critical" },
        ],
        [
          "HEARTBEAT.md",
          { path: `${dir}/HEARTBEAT.md`, name: "HEARTBEAT.md", hash: "ccc", size: 5, mtime: 2000, tier: "monitored" },
        ],
      ]),
    );

    const changes = compareSnapshots(prev, curr);

    const modified = changes.find((c) => c.changeType === "modified");
    expect(modified).toBeDefined();
    expect(modified!.file).toBe("SOUL.md");
    expect(modified!.previousHash).toBe("aaa");
    expect(modified!.currentHash).toBe("xxx");

    const deleted = changes.find((c) => c.changeType === "deleted");
    expect(deleted).toBeDefined();
    expect(deleted!.file).toBe("USER.md");

    const created = changes.find((c) => c.changeType === "created");
    expect(created).toBeDefined();
    expect(created!.file).toBe("HEARTBEAT.md");
  });

  it("returns empty array for identical snapshots", () => {
    const dir = "/workspace";
    const files = new Map<string, FileSnapshot>([
      [
        "SOUL.md",
        { path: `${dir}/SOUL.md`, name: "SOUL.md", hash: "aaa", size: 10, mtime: 1000, tier: "critical" },
      ],
    ]);

    const prev = makeSnapshot(dir, files);
    const curr = makeSnapshot(dir, new Map(files));

    const changes = compareSnapshots(prev, curr);
    expect(changes).toEqual([]);
  });
});

// ─── isProtectedPath ─────────────────────────────────────────

describe("isProtectedPath", () => {
  const ws = "/home/nonbios/.openclaw/workspace";

  it("matches SOUL.md with various path formats", () => {
    expect(isProtectedPath(ws, "SOUL.md").protected).toBe(true);
    expect(isProtectedPath(ws, "./SOUL.md").protected).toBe(true);
    expect(isProtectedPath(ws, `${ws}/SOUL.md`).protected).toBe(true);
  });

  it("performs case-insensitive basename matching", () => {
    expect(isProtectedPath(ws, "soul.md").protected).toBe(true);
    expect(isProtectedPath(ws, "Soul.MD").protected).toBe(true);
    expect(isProtectedPath(ws, "SOUL.MD").protected).toBe(true);
  });

  it("returns false for non-protected files", () => {
    expect(isProtectedPath(ws, "README.md").protected).toBe(false);
    expect(isProtectedPath(ws, "package.json").protected).toBe(false);
    expect(isProtectedPath(ws, "src/index.ts").protected).toBe(false);
  });

  it("handles path traversal (../workspace/SOUL.md)", () => {
    const result = isProtectedPath(ws, "../workspace/SOUL.md");
    expect(result.protected).toBe(true);
    expect(result.file!.name).toBe("SOUL.md");
  });

  it("returns the correct ProtectedFile metadata", () => {
    const result = isProtectedPath(ws, "AGENTS.md");
    expect(result.protected).toBe(true);
    expect(result.file!.name).toBe("AGENTS.md");
    expect(result.file!.tier).toBe("critical");
  });
});

// ─── normalizePath ───────────────────────────────────────────

describe("normalizePath", () => {
  const ws = "/home/user/workspace";

  it("normalizes various path formats", () => {
    expect(normalizePath(ws, "SOUL.md")).toBe(`${ws}/SOUL.md`);
    expect(normalizePath(ws, "./SOUL.md")).toBe(`${ws}/SOUL.md`);
    expect(normalizePath(ws, `${ws}/SOUL.md`)).toBe(`${ws}/SOUL.md`);
    expect(normalizePath(ws, "../workspace/SOUL.md")).toBe(
      "/home/user/workspace/SOUL.md",
    );
  });

  it("strips trailing slashes", () => {
    expect(normalizePath(ws, "subdir/")).toBe(`${ws}/subdir`);
  });
});

// ─── formatChangeAlert ──────────────────────────────────────

describe("formatChangeAlert", () => {
  it("uses correct emoji per tier", () => {
    const changes: ChangeEvent[] = [
      {
        file: "SOUL.md",
        path: "/ws/SOUL.md",
        tier: "critical",
        changeType: "modified",
        detectedAt: Date.now(),
      },
    ];
    const alert = formatChangeAlert(changes);
    expect(alert).toContain("⚠️");
    expect(alert).toContain("SOUL.md");
    expect(alert).toContain("MODIFIED");
  });

  it("handles mixed tiers", () => {
    const changes: ChangeEvent[] = [
      {
        file: "SOUL.md",
        path: "/ws/SOUL.md",
        tier: "critical",
        changeType: "modified",
        detectedAt: Date.now(),
      },
      {
        file: "USER.md",
        path: "/ws/USER.md",
        tier: "sensitive",
        changeType: "deleted",
        detectedAt: Date.now(),
      },
      {
        file: "HEARTBEAT.md",
        path: "/ws/HEARTBEAT.md",
        tier: "monitored",
        changeType: "created",
        detectedAt: Date.now(),
      },
    ];

    const alert = formatChangeAlert(changes);
    expect(alert).toContain("⚠️");
    expect(alert).toContain("🔔");
    expect(alert).toContain("📝");
    expect(alert).toContain("3 change(s) detected");
  });

  it("returns friendly message for no changes", () => {
    expect(formatChangeAlert([])).toBe("No changes detected.");
  });
});

// ─── Protection Tiers ────────────────────────────────────────

describe("Protection tiers", () => {
  const files = getProtectedFiles();

  it("SOUL.md is critical", () => {
    const soul = files.find((f) => f.name === "SOUL.md");
    expect(soul).toBeDefined();
    expect(soul!.tier).toBe("critical");
  });

  it("USER.md is sensitive", () => {
    const user = files.find((f) => f.name === "USER.md");
    expect(user).toBeDefined();
    expect(user!.tier).toBe("sensitive");
  });

  it("HEARTBEAT.md is monitored", () => {
    const hb = files.find((f) => f.name === "HEARTBEAT.md");
    expect(hb).toBeDefined();
    expect(hb!.tier).toBe("monitored");
  });
});

// ─── Symlink Handling ────────────────────────────────────────

describe("Symlink handling", () => {
  it("follows symlinks to real path", async () => {
    const realDir = join(TEST_DIR, `real-${Date.now()}`);
    const linkDir = join(TEST_DIR, `link-${Date.now()}`);

    await mkdir(realDir, { recursive: true });
    await mkdir(linkDir, { recursive: true });

    // Write real file
    const content = "symlinked soul";
    await writeFile(join(realDir, "SOUL.md"), content, "utf-8");

    // Create symlink in the link workspace pointing to the real file
    await symlink(join(realDir, "SOUL.md"), join(linkDir, "SOUL.md"));

    const snap = await createSnapshot(linkDir);
    const soul = snap.files.get("SOUL.md");

    expect(soul).toBeDefined();
    expect(soul!.hash).toBe(sha256(content));
    // The resolved path should point to the real file, not the symlink
    expect(soul!.path).toBe(join(realDir, "SOUL.md"));
  });
});
