/**
 * Layer 2: Capability Control — Manifest Tests
 */

import { describe, it, expect, beforeEach } from "vitest";
import {
  validateManifest,
  parseManifest,
  registerManifest,
  getManifest,
  clearManifestCache,
  listRegisteredSkills,
} from "../../src/capabilities/manifest";
import type { SkillManifest } from "../../src/capabilities/types";

const validManifest: SkillManifest = {
  version: "1.0",
  id: "test-skill",
  name: "Test Skill",
  description: "A test skill",
  capabilities: [
    { capability: "fs:read", reason: "Read files", required: true },
  ],
  minInputTrust: "tool",
  outputTrust: "tool",
};

describe("validateManifest", () => {
  it("accepts valid manifest", () => {
    const result = validateManifest(validManifest);
    expect(result.valid).toBe(true);
    expect(result.errors).toHaveLength(0);
  });

  it("rejects null/undefined input", () => {
    expect(validateManifest(null).valid).toBe(false);
    expect(validateManifest(undefined).valid).toBe(false);
  });

  it("rejects non-object input", () => {
    expect(validateManifest("string").valid).toBe(false);
    expect(validateManifest(42).valid).toBe(false);
  });

  it("rejects wrong version", () => {
    const result = validateManifest({ ...validManifest, version: "2.0" });
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes("version"))).toBe(true);
  });

  it("rejects missing required string fields", () => {
    for (const field of ["id", "name", "description"]) {
      const m = { ...validManifest, [field]: "" };
      const result = validateManifest(m);
      expect(result.valid).toBe(false);
    }
  });

  it("rejects invalid trust levels", () => {
    const m = { ...validManifest, minInputTrust: "admin" };
    const result = validateManifest(m);
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes("minInputTrust"))).toBe(true);
  });

  it("rejects non-array capabilities", () => {
    const m = { ...validManifest, capabilities: "invalid" };
    const result = validateManifest(m);
    expect(result.valid).toBe(false);
  });

  it("rejects invalid capability entries", () => {
    const m = {
      ...validManifest,
      capabilities: [{ capability: "", reason: 42, required: "yes" }],
    };
    const result = validateManifest(m);
    expect(result.valid).toBe(false);
    expect(result.errors.length).toBeGreaterThan(0);
  });

  it("warns on non-namespaced capabilities", () => {
    const m = {
      ...validManifest,
      capabilities: [
        { capability: "read", reason: "Read stuff", required: true },
      ],
    };
    const result = validateManifest(m);
    expect(result.valid).toBe(true); // Only a warning
    expect(result.warnings.some((w) => w.includes("domain:action"))).toBe(true);
  });

  it("validates limits when present", () => {
    const m = { ...validManifest, limits: { timeoutMs: -1 } };
    const result = validateManifest(m);
    expect(result.valid).toBe(false);
  });

  it("accepts valid limits", () => {
    const m = { ...validManifest, limits: { timeoutMs: 5000, maxMemoryMb: 128 } };
    const result = validateManifest(m);
    expect(result.valid).toBe(true);
  });

  it("validates allowedDomains", () => {
    const m = { ...validManifest, allowedDomains: "not-an-array" };
    const result = validateManifest(m);
    expect(result.valid).toBe(false);
  });

  it("validates allowedPaths", () => {
    const m = { ...validManifest, allowedPaths: 123 };
    const result = validateManifest(m);
    expect(result.valid).toBe(false);
  });
});

describe("parseManifest", () => {
  it("parses valid JSON manifest", () => {
    const json = JSON.stringify(validManifest);
    const result = parseManifest(json);
    expect(result.id).toBe("test-skill");
  });

  it("throws on invalid manifest JSON", () => {
    expect(() => parseManifest("{invalid}")).toThrow();
  });

  it("throws on structurally invalid manifest", () => {
    expect(() => parseManifest(JSON.stringify({ version: "2.0" }))).toThrow(/Invalid manifest/);
  });
});

describe("manifest cache", () => {
  beforeEach(() => {
    clearManifestCache();
  });

  it("registers and retrieves manifest", () => {
    registerManifest(validManifest);
    expect(getManifest("test-skill")).toBe(validManifest);
  });

  it("returns undefined for unregistered skill", () => {
    expect(getManifest("nonexistent")).toBeUndefined();
  });

  it("throws on invalid manifest registration", () => {
    expect(() =>
      registerManifest({ ...validManifest, version: "2.0" } as any)
    ).toThrow();
  });

  it("lists registered skills", () => {
    registerManifest(validManifest);
    registerManifest({ ...validManifest, id: "other-skill" });
    const skills = listRegisteredSkills();
    expect(skills).toContain("test-skill");
    expect(skills).toContain("other-skill");
  });

  it("clearManifestCache removes all", () => {
    registerManifest(validManifest);
    clearManifestCache();
    expect(getManifest("test-skill")).toBeUndefined();
    expect(listRegisteredSkills()).toHaveLength(0);
  });
});
