/**
 * Layer 1: Content Tagging — Tag Operations Tests
 */

import { describe, it, expect } from "vitest";
import {
  tag,
  createTag,
  resolveTrust,
  meetsMinTrust,
  contentMeetsMinTrust,
  merge,
  transform,
  forward,
  downgrade,
  traceProvenance,
  hasUntrustedOrigin,
  getSources,
  serializeTag,
  deserializeTag,
} from "../../src/tagging/tag";
import { userSource, toolSource, agentSource, externalSource } from "../../src/tagging/sources";
import { TRUST_RANK } from "../../src/tagging/types";

describe("createTag", () => {
  it("generates unique IDs", () => {
    const t1 = createTag(userSource("u1"), "user");
    const t2 = createTag(userSource("u1"), "user");
    expect(t1.id).not.toBe(t2.id);
  });

  it("includes provenance with created action", () => {
    const t = createTag(userSource("u1"), "user");
    expect(t.provenance).toHaveLength(1);
    expect(t.provenance[0].action).toBe("created");
    expect(t.provenance[0].trust).toBe("user");
  });

  it("sets timestamp", () => {
    const before = Date.now();
    const t = createTag(userSource("u1"), "user");
    expect(t.timestamp).toBeGreaterThanOrEqual(before);
  });

  it("includes meta when provided", () => {
    const t = createTag(userSource("u1"), "user", { key: "value" });
    expect(t.meta).toEqual({ key: "value" });
  });

  it("omits meta when not provided", () => {
    const t = createTag(userSource("u1"), "user");
    expect(t.meta).toBeUndefined();
  });
});

describe("tag (wrapper)", () => {
  it("wraps data with tag", () => {
    const result = tag("hello", userSource("u1"), "user");
    expect(result.data).toBe("hello");
    expect(result.tag.trust).toBe("user");
  });

  it("works with non-string data", () => {
    const obj = { x: 1, y: [2, 3] };
    const result = tag(obj, toolSource("api"), "tool");
    expect(result.data).toBe(obj);
    expect(result.tag.source.kind).toBe("tool");
  });
});

describe("resolveTrust", () => {
  it("returns minimum trust", () => {
    expect(resolveTrust(["system", "user", "tool"])).toBe("tool");
  });

  it("returns untrusted for empty input", () => {
    expect(resolveTrust([])).toBe("untrusted");
  });

  it("handles single element", () => {
    expect(resolveTrust(["system"])).toBe("system");
  });

  it("untrusted always wins", () => {
    expect(resolveTrust(["system", "user", "tool", "untrusted"])).toBe("untrusted");
  });
});

describe("meetsMinTrust", () => {
  it("same level meets requirement", () => {
    expect(meetsMinTrust("user", "user")).toBe(true);
  });

  it("higher level meets lower requirement", () => {
    expect(meetsMinTrust("system", "untrusted")).toBe(true);
  });

  it("lower level fails higher requirement", () => {
    expect(meetsMinTrust("untrusted", "system")).toBe(false);
  });
});

describe("merge", () => {
  it("uses minimum trust of inputs", () => {
    const a = tag("A", userSource("u1"), "user");
    const b = tag("B", externalSource("web"), "untrusted");
    const merged = merge([a, b], "AB", agentSource("main"));
    expect(merged.tag.trust).toBe("untrusted");
  });

  it("combines provenance chains", () => {
    const a = tag("A", userSource("u1"), "user");
    const b = tag("B", toolSource("t1"), "tool");
    const merged = merge([a, b], "AB", agentSource("main"));
    expect(merged.tag.provenance.length).toBe(3); // 2 created + 1 merged
    expect(merged.tag.provenance[2].action).toBe("merged");
  });

  it("deduplicates provenance entries", () => {
    const src = userSource("u1");
    const a = tag("A", src, "user");
    // Same source/action/timestamp would deduplicate
    const merged = merge([a, a], "AA", agentSource("main"));
    // Should at least have created + merged
    expect(merged.tag.provenance.length).toBeGreaterThanOrEqual(2);
  });

  it("caps provenance at MAX_PROVENANCE_DEPTH", () => {
    // Create a deeply nested chain
    const contents = [];
    for (let i = 0; i < 60; i++) {
      contents.push(tag(`data${i}`, toolSource(`tool${i}`), "tool"));
    }
    const merged = merge(contents, "merged", agentSource("main"));
    // Should be capped at 50 + 1 merged entry
    expect(merged.tag.provenance.length).toBeLessThanOrEqual(51);
  });
});

describe("transform", () => {
  it("preserves trust level", () => {
    const original = tag("raw", toolSource("api"), "tool");
    const transformed = transform(original, "processed", agentSource("main"));
    expect(transformed.tag.trust).toBe("tool");
  });

  it("extends provenance", () => {
    const original = tag("data", userSource("u1"), "user");
    const t = transform(original, "new", toolSource("processor"));
    expect(t.tag.provenance).toHaveLength(2);
    expect(t.tag.provenance[1].action).toBe("transformed");
  });

  it("supports custom action", () => {
    const original = tag("data", userSource("u1"), "user");
    const t = transform(original, "cached", toolSource("cache"), "cached");
    expect(t.tag.provenance[1].action).toBe("cached");
  });
});

describe("forward", () => {
  it("preserves data and trust", () => {
    const original = tag("secret", userSource("u1"), "user");
    const forwarded = forward(original, agentSource("relay"));
    expect(forwarded.data).toBe("secret");
    expect(forwarded.tag.trust).toBe("user");
  });

  it("records forwarded action in provenance", () => {
    const original = tag("data", toolSource("t1"), "tool");
    const forwarded = forward(original, agentSource("relay"));
    expect(forwarded.tag.provenance[1].action).toBe("forwarded");
  });
});

describe("downgrade", () => {
  it("lowers trust level", () => {
    const content = tag("data", userSource("u1"), "user");
    const d = downgrade(content, "untrusted", "MCP boundary");
    expect(d.tag.trust).toBe("untrusted");
    expect(d.tag.meta?.downgradeReason).toBe("MCP boundary");
  });

  it("cannot upgrade trust level", () => {
    const content = tag("data", externalSource("web"), "untrusted");
    const d = downgrade(content, "system", "nice try");
    expect(d.tag.trust).toBe("untrusted");
    // Returns same object reference
    expect(d).toBe(content);
  });

  it("same trust level returns unchanged", () => {
    const content = tag("data", userSource("u1"), "user");
    const d = downgrade(content, "user");
    expect(d).toBe(content);
  });
});

describe("provenance inspection", () => {
  it("traceProvenance includes source info", () => {
    const content = tag("data", userSource("+33xxx", "Alice"), "user");
    const trace = traceProvenance(content);
    expect(trace).toContain("Alice");
    expect(trace).toContain("created");
  });

  it("hasUntrustedOrigin detects untrusted in chain", () => {
    const safe = tag("safe", userSource("u1"), "user");
    expect(hasUntrustedOrigin(safe)).toBe(false);

    const unsafe = tag("data", externalSource("evil"), "untrusted");
    const merged = merge([safe, unsafe], "combined", agentSource("main"));
    expect(hasUntrustedOrigin(merged)).toBe(true);
  });

  it("getSources returns unique sources", () => {
    const a = tag("A", userSource("u1"), "user");
    const b = tag("B", toolSource("t1"), "tool");
    const merged = merge([a, b], "AB", agentSource("main"));
    const sources = getSources(merged);
    const ids = sources.map((s) => s.id);
    expect(ids).toContain("u1");
    expect(ids).toContain("t1");
    expect(ids).toContain("main");
    // No duplicates
    expect(new Set(ids).size).toBe(ids.length);
  });
});

describe("serialization", () => {
  it("round-trips losslessly", () => {
    const original = createTag(userSource("+33xxx", "Human"), "user", { channel: "whatsapp" });
    const serialized = serializeTag(original);
    const deserialized = deserializeTag(serialized);

    expect(deserialized.id).toBe(original.id);
    expect(deserialized.trust).toBe(original.trust);
    expect(deserialized.source.id).toBe(original.source.id);
    expect(deserialized.source.kind).toBe(original.source.kind);
    expect(deserialized.provenance.length).toBe(original.provenance.length);
    expect(deserialized.meta).toEqual(original.meta);
  });

  it("compact format has short keys", () => {
    const t = createTag(toolSource("web_search"), "tool");
    const json = serializeTag(t);
    const parsed = JSON.parse(json);
    expect(parsed.ct).toBe("1.0");
    expect(parsed).toHaveProperty("src");
    expect(parsed).toHaveProperty("tr");
    expect(parsed).not.toHaveProperty("source");
  });

  it("rejects unknown version", () => {
    expect(() => {
      deserializeTag('{"ct":"99.0","id":"x","src":{"k":"user","id":"x"},"tr":"user","pv":[],"ts":0}');
    }).toThrow(/Unsupported tag version/);
  });

  it("rejects invalid trust level", () => {
    expect(() => {
      deserializeTag('{"ct":"1.0","id":"x","src":{"k":"user","id":"x"},"tr":"admin","pv":[],"ts":0}');
    }).toThrow(/Invalid trust level/);
  });

  it("rejects invalid provenance trust level", () => {
    expect(() => {
      deserializeTag(
        '{"ct":"1.0","id":"x","src":{"k":"user","id":"x"},"tr":"user","pv":[{"src":{"k":"user","id":"x"},"tr":"root","act":"created","ts":0}],"ts":0}'
      );
    }).toThrow(/Invalid provenance trust level/);
  });
});
