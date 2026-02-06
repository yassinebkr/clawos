/**
 * Layer 1: Content Tagging — Source Tests
 */

import { describe, it, expect } from "vitest";
import {
  userSource,
  toolSource,
  skillSource,
  agentSource,
  externalSource,
  mcpSource,
  defaultTrustFor,
  SYSTEM_OPENCLAW,
  SYSTEM_PROMPT,
  SYSTEM_CLAWOS,
  SYSTEM_HEARTBEAT,
  SYSTEM_CRON,
  DEFAULT_TRUST,
} from "../../src/tagging/sources";

describe("system sources", () => {
  it("SYSTEM_OPENCLAW has system kind", () => {
    expect(SYSTEM_OPENCLAW.kind).toBe("system");
    expect(SYSTEM_OPENCLAW.id).toBe("openclaw");
    expect(SYSTEM_OPENCLAW.label).toBeTruthy();
  });

  it("SYSTEM_PROMPT has system kind", () => {
    expect(SYSTEM_PROMPT.kind).toBe("system");
    expect(SYSTEM_PROMPT.id).toBe("system-prompt");
  });

  it("SYSTEM_CLAWOS has system kind", () => {
    expect(SYSTEM_CLAWOS.kind).toBe("system");
    expect(SYSTEM_CLAWOS.id).toBe("clawos");
  });

  it("SYSTEM_HEARTBEAT has system kind", () => {
    expect(SYSTEM_HEARTBEAT.kind).toBe("system");
    expect(SYSTEM_HEARTBEAT.id).toBe("heartbeat");
  });

  it("SYSTEM_CRON has system kind", () => {
    expect(SYSTEM_CRON.kind).toBe("system");
    expect(SYSTEM_CRON.id).toBe("cron");
  });
});

describe("source factories", () => {
  it("userSource creates user source", () => {
    const src = userSource("+1234567890", "Alice");
    expect(src.kind).toBe("user");
    expect(src.id).toBe("+1234567890");
    expect(src.label).toBe("Alice");
  });

  it("userSource uses default label", () => {
    const src = userSource("+1234567890");
    expect(src.label).toBe("User +1234567890");
  });

  it("toolSource creates tool source", () => {
    const src = toolSource("web_search", "Web Search");
    expect(src.kind).toBe("tool");
    expect(src.id).toBe("web_search");
    expect(src.label).toBe("Web Search");
  });

  it("skillSource creates tool source with skill: prefix", () => {
    const src = skillSource("weather");
    expect(src.kind).toBe("tool");
    expect(src.id).toBe("skill:weather");
  });

  it("agentSource creates agent source", () => {
    const src = agentSource("main");
    expect(src.kind).toBe("agent");
    expect(src.id).toBe("main");
  });

  it("externalSource creates external source", () => {
    const src = externalSource("evil.com");
    expect(src.kind).toBe("external");
    expect(src.id).toBe("evil.com");
  });

  it("mcpSource creates external source with mcp: prefix", () => {
    const src = mcpSource("server1");
    expect(src.kind).toBe("external");
    expect(src.id).toBe("mcp:server1");
  });
});

describe("defaultTrustFor", () => {
  it("system → system", () => {
    expect(defaultTrustFor(SYSTEM_OPENCLAW)).toBe("system");
  });

  it("user → user", () => {
    expect(defaultTrustFor(userSource("u1"))).toBe("user");
  });

  it("tool → tool", () => {
    expect(defaultTrustFor(toolSource("t1"))).toBe("tool");
  });

  it("agent → tool", () => {
    expect(defaultTrustFor(agentSource("a1"))).toBe("tool");
  });

  it("external → untrusted", () => {
    expect(defaultTrustFor(externalSource("web"))).toBe("untrusted");
  });

  it("mcp → untrusted (external)", () => {
    expect(defaultTrustFor(mcpSource("server"))).toBe("untrusted");
  });
});

describe("DEFAULT_TRUST mapping", () => {
  it("covers all source kinds", () => {
    const kinds = ["system", "user", "tool", "agent", "external"];
    for (const kind of kinds) {
      expect(DEFAULT_TRUST[kind]).toBeDefined();
    }
  });
});
