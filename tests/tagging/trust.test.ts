/**
 * Layer 1: Content Tagging — Trust Tests
 *
 * Focus: Trust propagation rules and security properties
 */

import { describe, it, expect } from "vitest";
import {
  createTag,
  tag,
  resolveTrust,
  meetsMinTrust,
  merge,
  downgrade,
  serializeTag,
  deserializeTag,
} from "../../src/tagging/tag";
import type { TrustLevel } from "../../src/tagging/types";

describe("resolveTrust", () => {
  it("returns minimum trust level", () => {
    expect(resolveTrust(["system", "user"])).toBe("user");
    expect(resolveTrust(["user", "tool"])).toBe("tool");
    expect(resolveTrust(["user", "untrusted"])).toBe("untrusted");
  });

  it("any untrusted source poisons the result", () => {
    expect(resolveTrust(["system", "user", "untrusted"])).toBe("untrusted");
  });

  it("handles single trust level", () => {
    expect(resolveTrust(["system"])).toBe("system");
    expect(resolveTrust(["untrusted"])).toBe("untrusted");
  });

  it("returns untrusted for empty array", () => {
    expect(resolveTrust([])).toBe("untrusted");
  });
});

describe("meetsMinTrust", () => {
  it("system meets all requirements", () => {
    expect(meetsMinTrust("system", "system")).toBe(true);
    expect(meetsMinTrust("system", "user")).toBe(true);
    expect(meetsMinTrust("system", "tool")).toBe(true);
    expect(meetsMinTrust("system", "untrusted")).toBe(true);
  });

  it("untrusted only meets untrusted requirement", () => {
    expect(meetsMinTrust("untrusted", "system")).toBe(false);
    expect(meetsMinTrust("untrusted", "user")).toBe(false);
    expect(meetsMinTrust("untrusted", "tool")).toBe(false);
    expect(meetsMinTrust("untrusted", "untrusted")).toBe(true);
  });

  it("tool meets tool and below", () => {
    expect(meetsMinTrust("tool", "user")).toBe(false);
    expect(meetsMinTrust("tool", "tool")).toBe(true);
    expect(meetsMinTrust("tool", "untrusted")).toBe(true);
  });
});

describe("merge", () => {
  it("result trust is minimum of inputs", () => {
    const userContent = tag("hello", { kind: "user", id: "u1" }, "user");
    const toolContent = tag("world", { kind: "tool", id: "web" }, "tool");

    const merged = merge(
      [userContent, toolContent],
      "hello world",
      { kind: "agent", id: "main" }
    );

    expect(merged.tag.trust).toBe("tool"); // Min of user, tool
  });

  it("preserves provenance from all inputs", () => {
    const a = tag("a", { kind: "user", id: "u1" }, "user");
    const b = tag("b", { kind: "tool", id: "t1" }, "tool");

    const merged = merge([a, b], "ab", { kind: "agent", id: "main" });

    // Should have entries from both sources plus the merge
    expect(merged.tag.provenance.length).toBeGreaterThanOrEqual(3);
  });

  it("caps provenance at MAX_PROVENANCE_DEPTH", () => {
    // Create content with long provenance
    let content = tag("start", { kind: "user", id: "u1" }, "user");

    // Merge 100 times to exceed the limit
    for (let i = 0; i < 100; i++) {
      content = merge([content], `data${i}`, { kind: "agent", id: `agent${i}` });
    }

    // Should be capped at 50
    expect(content.tag.provenance.length).toBeLessThanOrEqual(51);
  });
});

describe("downgrade", () => {
  it("can lower trust level", () => {
    const content = tag("data", { kind: "user", id: "u1" }, "user");
    const downgraded = downgrade(content, "untrusted", "entered unsafe context");

    expect(downgraded.tag.trust).toBe("untrusted");
    expect(downgraded.tag.meta?.downgradeReason).toBe("entered unsafe context");
  });

  it("cannot upgrade trust level", () => {
    const content = tag("data", { kind: "tool", id: "t1" }, "tool");
    const result = downgrade(content, "system"); // Attempting upgrade

    // Should return unchanged
    expect(result.tag.trust).toBe("tool");
  });
});

describe("serialization security", () => {
  it("validates trust level on deserialize", () => {
    const malicious = JSON.stringify({
      ct: "1.0",
      id: "ct_evil",
      src: { k: "attacker", id: "bad" },
      tr: "superadmin", // Invalid trust level
      pv: [],
      ts: Date.now(),
    });

    expect(() => deserializeTag(malicious)).toThrow("Invalid trust level");
  });

  it("validates provenance trust levels", () => {
    const malicious = JSON.stringify({
      ct: "1.0",
      id: "ct_evil",
      src: { k: "user", id: "u1" },
      tr: "user",
      pv: [{ src: { k: "x", id: "y" }, tr: "god_mode", act: "created", ts: 1 }],
      ts: Date.now(),
    });

    expect(() => deserializeTag(malicious)).toThrow("Invalid provenance trust level");
  });

  it("round-trips correctly", () => {
    const original = createTag({ kind: "user", id: "u1" }, "user");
    const serialized = serializeTag(original);
    const restored = deserializeTag(serialized);

    expect(restored.trust).toBe(original.trust);
    expect(restored.source.kind).toBe(original.source.kind);
  });
});

describe("tag ID uniqueness", () => {
  it("generates unique IDs", () => {
    const ids = new Set<string>();
    for (let i = 0; i < 1000; i++) {
      ids.add(createTag({ kind: "user", id: "u1" }, "user").id);
    }
    expect(ids.size).toBe(1000);
  });
});
