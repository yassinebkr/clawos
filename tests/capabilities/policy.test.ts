/**
 * Layer 2: Capability Control — Policy Tests
 *
 * Focus: Permission checks and enforcement
 */

import { describe, it, expect } from "vitest";
import {
  checkPermission,
  createContext,
  enforce,
  hasTimedOut,
} from "../../src/capabilities/policy";
import type { SkillManifest, OperatorPolicy } from "../../src/capabilities/types";
import { createTag } from "../../src/tagging/tag";

const baseManifest: SkillManifest = {
  id: "test-skill",
  name: "Test Skill",
  version: "1.0.0",
  minInputTrust: "user",
  capabilities: [
    { capability: "fs:read", required: true },
    { capability: "net:http", required: false },
  ],
};

describe("checkPermission", () => {
  it("grants capabilities when trust meets requirements", () => {
    const inputTag = createTag({ kind: "user", id: "u1" }, "user");
    const result = checkPermission(baseManifest, inputTag);

    expect(result.allowed).toBe(true);
    expect(result.granted).toContain("fs:read");
  });

  it("denies when input trust below manifest minimum", () => {
    const manifest = { ...baseManifest, minInputTrust: "user" as const };
    const inputTag = createTag({ kind: "tool", id: "t1" }, "tool"); // Lower than user

    const result = checkPermission(manifest, inputTag);

    expect(result.allowed).toBe(false);
    expect(result.reasons.some(r => r.includes("below manifest minimum"))).toBe(true);
  });

  it("respects global deny list", () => {
    const inputTag = createTag({ kind: "user", id: "u1" }, "user");
    const policy: OperatorPolicy = {
      globalDeny: ["fs:read"],
      globalAllow: [],
      skills: {},
      requireApproval: false,
    };

    const result = checkPermission(baseManifest, inputTag, policy);

    expect(result.denied).toContain("fs:read");
    expect(result.allowed).toBe(false); // fs:read is required
  });

  it("respects per-skill blocking", () => {
    const inputTag = createTag({ kind: "user", id: "u1" }, "user");
    const policy: OperatorPolicy = {
      globalDeny: [],
      globalAllow: [],
      skills: { "test-skill": { blocked: true } },
      requireApproval: false,
    };

    const result = checkPermission(baseManifest, inputTag, policy);

    expect(result.allowed).toBe(false);
    expect(result.reasons.some(r => r.includes("blocked by operator"))).toBe(true);
  });

  it("applies auto-approve based on risk level", () => {
    const inputTag = createTag({ kind: "user", id: "u1" }, "user");
    const policy: OperatorPolicy = {
      globalDeny: [],
      globalAllow: [],
      skills: {},
      requireApproval: false,
      autoApproveBelow: "medium",
    };

    const result = checkPermission(baseManifest, inputTag, policy);

    // Low-risk capabilities should be auto-approved
    expect(result.allowed).toBe(true);
  });
});

describe("createContext", () => {
  it("creates context with granted capabilities", () => {
    const ctx = createContext(baseManifest, ["fs:read", "net:http"], "user");

    expect(ctx.grantedCapabilities.has("fs:read")).toBe(true);
    expect(ctx.grantedCapabilities.has("net:http")).toBe(true);
    expect(ctx.grantedCapabilities.has("fs:write")).toBe(false);
  });

  it("applies resource limits", () => {
    const ctx = createContext(baseManifest, [], "user", { timeoutMs: 5000 });

    expect(ctx.limits.timeoutMs).toBe(5000);
  });
});

describe("enforce", () => {
  it("allows granted capabilities", () => {
    const ctx = createContext(baseManifest, ["fs:read"], "user");
    const result = enforce(ctx, "fs:read");

    expect(result.allowed).toBe(true);
  });

  it("denies non-granted capabilities", () => {
    const ctx = createContext(baseManifest, ["fs:read"], "user");
    const result = enforce(ctx, "fs:write");

    expect(result.allowed).toBe(false);
    expect(result.reason).toContain("not granted");
  });

  it("enforces domain restrictions", () => {
    const manifest = { ...baseManifest, allowedDomains: ["api.example.com"] };
    const ctx = createContext(manifest, ["net:http"], "user");

    expect(enforce(ctx, "net:http", { domain: "api.example.com" }).allowed).toBe(true);
    expect(enforce(ctx, "net:http", { domain: "evil.com" }).allowed).toBe(false);
  });

  it("enforces wildcard domains", () => {
    const manifest = { ...baseManifest, allowedDomains: ["*.example.com"] };
    const ctx = createContext(manifest, ["net:http"], "user");

    expect(enforce(ctx, "net:http", { domain: "api.example.com" }).allowed).toBe(true);
    expect(enforce(ctx, "net:http", { domain: "example.com" }).allowed).toBe(false);
    expect(enforce(ctx, "net:http", { domain: "evil.example.com.bad.com" }).allowed).toBe(false);
  });

  it("enforces path restrictions", () => {
    const manifest = { ...baseManifest, allowedPaths: ["/home/user/workspace/**"] };
    const ctx = createContext(manifest, ["fs:read"], "user");

    expect(enforce(ctx, "fs:read", { path: "/home/user/workspace/file.txt" }).allowed).toBe(true);
    expect(enforce(ctx, "fs:read", { path: "/etc/passwd" }).allowed).toBe(false);
  });

  it("tracks HTTP request count", () => {
    const manifest = { ...baseManifest, limits: { maxHttpRequests: 2 } };
    const ctx = createContext(manifest, ["net:http"], "user");

    expect(enforce(ctx, "net:http").allowed).toBe(true);
    expect(enforce(ctx, "net:http").allowed).toBe(true);
    expect(enforce(ctx, "net:http").allowed).toBe(false); // Over limit
  });
});

describe("timeout", () => {
  it("detects timeout", async () => {
    const ctx = createContext(baseManifest, ["fs:read"], "user", { timeoutMs: 10 });

    expect(hasTimedOut(ctx)).toBe(false);

    await new Promise(resolve => setTimeout(resolve, 15));

    expect(hasTimedOut(ctx)).toBe(true);
  });
});
