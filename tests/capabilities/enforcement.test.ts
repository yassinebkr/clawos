/**
 * Layer 2: Capability Control — Policy & Enforcement Tests
 */

import { describe, it, expect, beforeEach } from "vitest";
import {
  checkPermission,
  createContext,
  enforce,
  hasTimedOut,
  remainingTime,
} from "../../src/capabilities/policy";
import { createTag } from "../../src/tagging/tag";
import { userSource, toolSource, externalSource } from "../../src/tagging/sources";
import type { SkillManifest, OperatorPolicy, ExecutionContext } from "../../src/capabilities/types";

const safeManifest: SkillManifest = {
  version: "1.0",
  id: "safe-skill",
  name: "Safe Skill",
  description: "Safe",
  capabilities: [
    { capability: "fs:read", reason: "Read", required: true },
    { capability: "net:https", reason: "Fetch", required: false },
  ],
  minInputTrust: "tool",
  outputTrust: "tool",
  allowedPaths: ["/tmp/*"],
  allowedDomains: ["api.example.com"],
};

const dangerousManifest: SkillManifest = {
  version: "1.0",
  id: "dangerous-skill",
  name: "Dangerous Skill",
  description: "Dangerous",
  capabilities: [
    { capability: "proc:exec", reason: "Execute commands", required: true },
    { capability: "env:secrets", reason: "Read secrets", required: true },
  ],
  minInputTrust: "user",
  outputTrust: "tool",
};

describe("checkPermission", () => {
  it("allows skill when trust meets minimum", () => {
    const inputTag = createTag(userSource("u1"), "user");
    const result = checkPermission(safeManifest, inputTag);
    expect(result.allowed).toBe(true);
    expect(result.granted).toContain("fs:read");
  });

  it("denies when trust below manifest minimum", () => {
    const inputTag = createTag(externalSource("web"), "untrusted");
    const result = checkPermission(safeManifest, inputTag);
    expect(result.allowed).toBe(false);
    expect(result.reasons.some((r) => r.includes("trust"))).toBe(true);
  });

  it("denies when required capability trust not met", () => {
    const inputTag = createTag(toolSource("t1"), "tool");
    // dangerous-skill requires user trust for proc:exec
    const result = checkPermission(dangerousManifest, inputTag);
    expect(result.allowed).toBe(false);
  });

  it("respects global deny list", () => {
    const inputTag = createTag(userSource("u1"), "user");
    const policy: OperatorPolicy = { globalDeny: ["fs:read"] };
    const result = checkPermission(safeManifest, inputTag, policy);
    expect(result.denied).toContain("fs:read");
    expect(result.allowed).toBe(false); // fs:read is required
  });

  it("respects global allow list", () => {
    const inputTag = createTag(userSource("u1"), "user");
    const policy: OperatorPolicy = { globalAllow: ["fs:read", "net:https"] };
    const result = checkPermission(safeManifest, inputTag, policy);
    expect(result.granted).toContain("fs:read");
    expect(result.granted).toContain("net:https");
  });

  it("per-skill deny overrides", () => {
    const inputTag = createTag(userSource("u1"), "user");
    const policy: OperatorPolicy = {
      skills: { "safe-skill": { deny: ["fs:read"] } },
    };
    const result = checkPermission(safeManifest, inputTag, policy);
    expect(result.denied).toContain("fs:read");
    expect(result.allowed).toBe(false);
  });

  it("per-skill allow overrides", () => {
    const inputTag = createTag(userSource("u1"), "user");
    const policy: OperatorPolicy = {
      skills: { "safe-skill": { allow: ["net:https"] } },
    };
    const result = checkPermission(safeManifest, inputTag, policy);
    expect(result.granted).toContain("net:https");
  });

  it("blocks skill entirely when blocked flag set", () => {
    const inputTag = createTag(userSource("u1"), "user");
    const policy: OperatorPolicy = {
      skills: { "safe-skill": { blocked: true } },
    };
    const result = checkPermission(safeManifest, inputTag, policy);
    expect(result.allowed).toBe(false);
    expect(result.reasons.some((r) => r.includes("blocked"))).toBe(true);
  });

  it("requires approval when policy says so", () => {
    const inputTag = createTag(userSource("u1"), "user");
    const policy: OperatorPolicy = {
      requireApproval: true,
      autoApproveBelow: "low",
    };
    const result = checkPermission(safeManifest, inputTag, policy);
    // fs:read is medium risk, above "low" auto-approve
    expect(result.requiresApproval.length).toBeGreaterThan(0);
  });

  it("auto-approves low-risk capabilities", () => {
    const manifest: SkillManifest = {
      version: "1.0",
      id: "info-skill",
      name: "Info",
      description: "Info",
      capabilities: [
        { capability: "sys:info", reason: "Get info", required: true },
        { capability: "sys:time", reason: "Get time", required: true },
      ],
      minInputTrust: "untrusted",
      outputTrust: "tool",
    };
    const inputTag = createTag(externalSource("web"), "untrusted");
    const policy: OperatorPolicy = {
      requireApproval: true,
      autoApproveBelow: "low",
    };
    const result = checkPermission(manifest, inputTag, policy);
    expect(result.granted).toContain("sys:info");
    expect(result.granted).toContain("sys:time");
    expect(result.allowed).toBe(true);
  });

  it("non-required denied capability doesn't block skill", () => {
    const inputTag = createTag(userSource("u1"), "user");
    const policy: OperatorPolicy = { globalDeny: ["net:https"] };
    const result = checkPermission(safeManifest, inputTag, policy);
    // net:https is denied but not required
    expect(result.denied).toContain("net:https");
    expect(result.allowed).toBe(true); // Still allowed (fs:read is granted)
  });
});

describe("createContext", () => {
  it("creates context with correct fields", () => {
    const ctx = createContext(safeManifest, ["fs:read"], "user");
    expect(ctx.skillId).toBe("safe-skill");
    expect(ctx.grantedCapabilities.has("fs:read")).toBe(true);
    expect(ctx.inputTrust).toBe("user");
    expect(ctx.allowedDomains).toEqual(["api.example.com"]);
    expect(ctx.allowedPaths).toEqual(["/tmp/*"]);
  });

  it("uses manifest limits", () => {
    const manifest: SkillManifest = {
      ...safeManifest,
      limits: { timeoutMs: 5000, maxMemoryMb: 64 },
    };
    const ctx = createContext(manifest, ["fs:read"], "user");
    expect(ctx.limits.timeoutMs).toBe(5000);
    expect(ctx.limits.maxMemoryMb).toBe(64);
  });

  it("applies limit overrides", () => {
    const ctx = createContext(safeManifest, ["fs:read"], "user", { timeoutMs: 1000 });
    expect(ctx.limits.timeoutMs).toBe(1000);
  });

  it("initializes usage counters at zero", () => {
    const ctx = createContext(safeManifest, ["fs:read"], "user");
    expect(ctx.usage.httpRequestCount).toBe(0);
    expect(ctx.usage.bytesRead).toBe(0);
    expect(ctx.usage.bytesWritten).toBe(0);
  });
});

describe("enforce", () => {
  let ctx: ExecutionContext;

  beforeEach(() => {
    ctx = createContext(safeManifest, ["fs:read", "net:https"], "user");
  });

  it("allows granted capability", () => {
    const result = enforce(ctx, "fs:read");
    expect(result.allowed).toBe(true);
  });

  it("denies non-granted capability", () => {
    const result = enforce(ctx, "proc:exec");
    expect(result.allowed).toBe(false);
    expect(result.reason).toContain("not granted");
  });

  it("enforces domain restrictions", () => {
    const allowed = enforce(ctx, "net:https", { domain: "api.example.com" });
    expect(allowed.allowed).toBe(true);

    const denied = enforce(ctx, "net:https", { domain: "evil.com" });
    expect(denied.allowed).toBe(false);
    expect(denied.reason).toContain("Domain");
  });

  it("enforces path restrictions", () => {
    const allowed = enforce(ctx, "fs:read", { path: "/tmp/file.txt" });
    expect(allowed.allowed).toBe(true);

    const denied = enforce(ctx, "fs:read", { path: "/etc/passwd" });
    expect(denied.allowed).toBe(false);
    expect(denied.reason).toContain("Path");
  });

  it("tracks HTTP request count", () => {
    for (let i = 0; i < 10; i++) {
      const result = enforce(ctx, "net:https", { domain: "api.example.com" });
      expect(result.allowed).toBe(true);
    }
    // 11th request exceeds default limit of 10
    const result = enforce(ctx, "net:https", { domain: "api.example.com" });
    expect(result.allowed).toBe(false);
    expect(result.reason).toContain("request limit");
  });

  it("enforces file size limits", () => {
    const huge = enforce(ctx, "fs:read", { path: "/tmp/big.dat", bytes: 999999999 });
    expect(huge.allowed).toBe(false);
    expect(huge.reason).toContain("File size");
  });

  it("tracks bytes read/written", () => {
    enforce(ctx, "fs:read", { path: "/tmp/a.txt", bytes: 100 });
    expect(ctx.usage.bytesRead).toBe(100);
  });
});

describe("hasTimedOut", () => {
  it("returns false when within timeout", () => {
    const ctx = createContext(safeManifest, [], "user");
    expect(hasTimedOut(ctx)).toBe(false);
  });

  it("returns false with no timeout limit", () => {
    const ctx = createContext(safeManifest, [], "user", { timeoutMs: undefined });
    expect(hasTimedOut(ctx)).toBe(false);
  });
});

describe("remainingTime", () => {
  it("returns positive time within timeout", () => {
    const ctx = createContext(safeManifest, [], "user", { timeoutMs: 30000 });
    expect(remainingTime(ctx)).toBeGreaterThan(0);
  });

  it("returns Infinity with no timeout", () => {
    const ctx = createContext(safeManifest, [], "user");
    ctx.limits.timeoutMs = undefined;
    expect(remainingTime(ctx)).toBe(Infinity);
  });
});
