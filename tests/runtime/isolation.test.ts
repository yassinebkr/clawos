/**
 * Layer 3: Runtime Security — Isolation Tests
 */

import { describe, it, expect } from "vitest";
import {
  selectIsolationLevel,
  createSandboxConfig,
  effectiveLevel,
} from "../../src/runtime/isolation";
import { createTag } from "../../src/tagging/tag";
import { userSource, externalSource, toolSource } from "../../src/tagging/sources";
import type { SkillManifest } from "../../src/capabilities/types";

const baseManifest: SkillManifest = {
  version: "1.0",
  id: "test-skill",
  name: "Test",
  description: "Test skill",
  capabilities: [{ capability: "fs:read", reason: "Read", required: true }],
  minInputTrust: "tool",
  outputTrust: "tool",
};

describe("selectIsolationLevel", () => {
  it("returns Level 2 for untrusted input", () => {
    const tag = createTag(externalSource("web"), "untrusted");
    const level = selectIsolationLevel(baseManifest, tag);
    expect(level).toBe(2);
  });

  it("returns Level 2 for MCP server skills", () => {
    const manifest = { ...baseManifest, id: "mcp:test-server" };
    const tag = createTag(userSource("u1"), "user");
    expect(selectIsolationLevel(manifest, tag)).toBe(2);
  });

  it("returns Level 2 for high-risk capabilities", () => {
    const manifest: SkillManifest = {
      ...baseManifest,
      capabilities: [{ capability: "proc:exec", reason: "Execute", required: true }],
    };
    const tag = createTag(userSource("u1"), "user");
    expect(selectIsolationLevel(manifest, tag)).toBe(2);
  });

  it("returns Level 0 for system trust builtin skills", () => {
    const manifest = { ...baseManifest, id: "builtin:core" };
    const tag = createTag(userSource("u1"), "system");
    expect(selectIsolationLevel(manifest, tag)).toBe(0);
  });

  it("returns Level 1 for standard user trust skills", () => {
    const tag = createTag(userSource("u1"), "user");
    expect(selectIsolationLevel(baseManifest, tag)).toBe(1);
  });

  it("returns Level 1 for tool trust skills", () => {
    const tag = createTag(toolSource("t1"), "tool");
    expect(selectIsolationLevel(baseManifest, tag)).toBe(1);
  });

  it("respects per-skill isolation override", () => {
    const tag = createTag(userSource("u1"), "user");
    const policy = {
      skills: { "test-skill": { isolationLevel: 2 } },
    };
    expect(selectIsolationLevel(baseManifest, tag, policy as any)).toBe(2);
  });
});

describe("createSandboxConfig", () => {
  it("creates config with correct isolation level", () => {
    const config = createSandboxConfig(baseManifest, 1);
    expect(config.level).toBe(1);
  });

  it("sets up temp directory", () => {
    const config = createSandboxConfig(baseManifest, 1);
    expect(config.tempDir).toContain("clawos-");
    expect(config.tempDir).toContain("test-skill");
  });

  it("Level 0 has no path restrictions", () => {
    const config = createSandboxConfig(baseManifest, 0);
    expect(config.allowedPaths).toHaveLength(0);
  });

  it("Level 1 includes system paths and manifest paths", () => {
    const manifest = { ...baseManifest, allowedPaths: ["/data/*"] };
    const config = createSandboxConfig(manifest, 1);
    expect(config.allowedPaths.length).toBeGreaterThan(0);
    expect(config.allowedPaths.some((p) => p.path === "/data/*")).toBe(true);
  });

  it("Level 2 has minimal paths", () => {
    const config = createSandboxConfig(baseManifest, 2);
    // Only essential system libs + temp
    expect(config.allowedPaths.length).toBeLessThan(6);
    expect(config.allowedPaths.every((p) => p.mode === "read" || p.path === config.tempDir)).toBe(true);
  });

  it("sets resource limits from manifest", () => {
    const manifest = { ...baseManifest, limits: { timeoutMs: 5000, maxMemoryMb: 64 } };
    const config = createSandboxConfig(manifest, 1);
    expect(config.resourceLimits.timeoutMs).toBe(5000);
    expect(config.resourceLimits.maxMemoryMb).toBe(64);
  });

  it("uses defaults when manifest has no limits", () => {
    const config = createSandboxConfig(baseManifest, 1);
    expect(config.resourceLimits.timeoutMs).toBe(30000);
    expect(config.resourceLimits.maxMemoryMb).toBe(256);
  });

  it("sets environment variables", () => {
    const config = createSandboxConfig(baseManifest, 1);
    expect(config.env.NODE_ENV).toBe("production");
    expect(config.env.CLAWOS_SKILL_ID).toBe("test-skill");
    expect(config.env.CLAWOS_ISOLATION_LEVEL).toBe("1");
  });

  it("uses allowed domains from manifest", () => {
    const manifest = { ...baseManifest, allowedDomains: ["api.example.com"] };
    const config = createSandboxConfig(manifest, 1);
    expect(config.allowedDomains).toEqual(["api.example.com"]);
  });

  it("supports workspace path for Level 1", () => {
    const config = createSandboxConfig(baseManifest, 1, "/home/user/workspace");
    expect(config.allowedPaths.some((p) => p.path === "/home/user/workspace")).toBe(true);
  });
});

describe("effectiveLevel", () => {
  it("returns Level 0 unchanged", () => {
    expect(effectiveLevel(0)).toBe(0);
  });

  it("returns Level 1 unchanged", () => {
    expect(effectiveLevel(1)).toBe(1);
  });

  it("falls back Level 2 to Level 1 when bwrap unavailable", () => {
    // In test environment, bwrap is typically not available
    const level = effectiveLevel(2);
    expect([1, 2]).toContain(level); // Either 1 (fallback) or 2 (if bwrap available)
  });
});
