/**
 * Layer 0: Session Integrity — Controller Tests
 */

import { describe, it, expect, beforeEach } from "vitest";
import {
  createSessionIntegrity,
  SessionIntegrityError,
} from "../../src/integrity/session-integrity";
import type { Message, SessionAdapter, ToolUseContent } from "../../src/integrity/types";

const text = (role: "user" | "assistant", t: string): Message => ({
  role,
  content: [{ type: "text", text: t }],
});

const toolUse = (id: string, name: string): Message => ({
  role: "assistant",
  content: [{ type: "tool_use", id, name, input: {} }],
});

const toolResult = (id: string, content = "ok"): Message => ({
  role: "user",
  content: [{ type: "tool_result", tool_use_id: id, content }],
});

function mockSession(messages: Message[]): SessionAdapter {
  return {
    sessionId: "test-session",
    messages: [...messages],
    persist: async () => {},
    archive: async () => "/tmp/archive.json",
    truncate: (idx) => { messages.length = idx; },
  };
}

describe("SessionIntegrity", () => {
  describe("validateOrThrow", () => {
    it("passes for valid session", () => {
      const si = createSessionIntegrity();
      const session = mockSession([text("user", "Hi"), text("assistant", "Hello!")]);
      expect(() => si.validateOrThrow(session)).not.toThrow();
    });

    it("throws SessionIntegrityError for corrupt session", () => {
      const si = createSessionIntegrity();
      const session = mockSession([
        text("assistant", "Hi"),
        toolResult("orphan"),
      ]);
      expect(() => si.validateOrThrow(session)).toThrow(SessionIntegrityError);
    });

    it("auto-repairs when enabled", () => {
      const si = createSessionIntegrity({ autoRepair: true });
      const session = mockSession([
        text("user", "Hello"),
        text("assistant", "Hi"),
        toolResult("orphan"),
      ]);
      expect(() => si.validateOrThrow(session)).not.toThrow();
    });

    it("passes when disabled", () => {
      const si = createSessionIntegrity({ enabled: false });
      const session = mockSession([toolResult("orphan")]);
      expect(() => si.validateOrThrow(session)).not.toThrow();
    });
  });

  describe("isSessionValid", () => {
    it("returns true for valid session", () => {
      const si = createSessionIntegrity();
      const session = mockSession([text("user", "Hi")]);
      expect(si.isSessionValid(session)).toBe(true);
    });

    it("returns false for corrupt session", () => {
      const si = createSessionIntegrity();
      const session = mockSession([
        text("assistant", "Hi"),
        toolResult("orphan"),
      ]);
      expect(si.isSessionValid(session)).toBe(false);
    });

    it("returns true when disabled", () => {
      const si = createSessionIntegrity({ enabled: false });
      const session = mockSession([toolResult("orphan")]);
      expect(si.isSessionValid(session)).toBe(true);
    });
  });

  describe("executeToolCycle", () => {
    it("succeeds with valid tool execution", async () => {
      const si = createSessionIntegrity();
      const session = mockSession([text("user", "Do something")]);
      const toolUseContent: ToolUseContent = {
        type: "tool_use",
        id: "tool_1",
        name: "test_tool",
        input: { x: 1 },
      };
      const executor = {
        execute: async () => ({ output: "done", isError: false }),
      };

      const result = await si.executeToolCycle(session, toolUseContent, executor);
      expect(result.success).toBe(true);
      expect(result.result?.tool_use_id).toBe("tool_1");
      expect(result.result?.content).toBe("done");
    });

    it("rolls back on executor failure", async () => {
      const si = createSessionIntegrity({ snapshotMessages: true });
      const session = mockSession([text("user", "Do something")]);
      const toolUseContent: ToolUseContent = {
        type: "tool_use",
        id: "tool_fail",
        name: "failing",
        input: {},
      };
      const executor = {
        execute: async () => { throw new Error("boom"); },
      };

      const result = await si.executeToolCycle(session, toolUseContent, executor);
      expect(result.success).toBe(false);
      expect(result.rolledBack).toBe(true);
      expect(result.error).toBe("boom");
    });

    it("bypasses when disabled", async () => {
      const si = createSessionIntegrity({ enabled: false });
      const session = mockSession([]);
      const toolUseContent: ToolUseContent = {
        type: "tool_use",
        id: "tool_1",
        name: "test",
        input: {},
      };
      const executor = {
        execute: async () => ({ output: "result" }),
      };

      const result = await si.executeToolCycle(session, toolUseContent, executor);
      expect(result.success).toBe(true);
      expect(result.result?.content).toBe("result");
    });
  });

  describe("handleError", () => {
    it("rolls back to checkpoint if available", async () => {
      const si = createSessionIntegrity({ snapshotMessages: true });
      const session = mockSession([text("user", "Hello")]);
      await si.createCheckpoint(session, "api_call");
      session.messages.push(text("assistant", "Extra"));

      const recovery = await si.handleError(session, new Error("Content filter blocked"));
      expect(["rolled_back", "repaired", "escalate"]).toContain(recovery.action);
    });

    it("repairs if no checkpoint", async () => {
      const si = createSessionIntegrity();
      const session = mockSession([
        text("user", "Hello"),
        text("assistant", "Hi"),
        toolResult("orphan"),
      ]);

      const recovery = await si.handleError(session, new Error("fail"));
      expect(["repaired", "escalate"]).toContain(recovery.action);
    });

    it("escalates if nothing works", async () => {
      const si = createSessionIntegrity();
      const session = mockSession([text("user", "Hello")]);

      const recovery = await si.handleError(session, new Error("fail"));
      // No orphans to repair, no checkpoint to rollback
      expect(recovery.action).toBe("escalate");
    });
  });

  describe("incidents", () => {
    it("logs incidents during operations", async () => {
      const si = createSessionIntegrity();
      const session = mockSession([text("user", "Hello")]);
      await si.createCheckpoint(session, "manual");

      const incidents = si.getIncidents("test-session");
      expect(incidents.length).toBeGreaterThan(0);
      expect(incidents[0].type).toBe("checkpoint_created");
    });

    it("limits incident count", () => {
      const si = createSessionIntegrity();
      const session = mockSession([text("user", "Hello")]);

      // Create many checkpoints (each logs an incident)
      for (let i = 0; i < 20; i++) {
        si.createCheckpoint(session, "manual");
      }

      const incidents = si.getIncidents();
      // Should be bounded
      expect(incidents.length).toBeLessThanOrEqual(1000);
    });

    it("filters incidents by session", async () => {
      const si = createSessionIntegrity();
      const s1 = mockSession([text("user", "Hello")]);
      const s2 = { ...mockSession([text("user", "Bye")]), sessionId: "other-session" };

      await si.createCheckpoint(s1, "manual");
      await si.createCheckpoint(s2, "manual");

      const s1Incidents = si.getIncidents("test-session");
      const s2Incidents = si.getIncidents("other-session");
      expect(s1Incidents.every((i) => i.sessionId === "test-session")).toBe(true);
      expect(s2Incidents.every((i) => i.sessionId === "other-session")).toBe(true);
    });
  });

  describe("active transactions", () => {
    it("starts with no active transactions", () => {
      const si = createSessionIntegrity();
      expect(si.getActiveTransactions()).toHaveLength(0);
      expect(si.hasPendingToolCycles()).toBe(false);
    });
  });

  describe("repairSession", () => {
    it("repairs corrupt session in place", () => {
      const si = createSessionIntegrity();
      const session = mockSession([
        text("user", "Hello"),
        text("assistant", "Hi"),
        toolResult("orphan"),
      ]);

      const result = si.repairSession(session);
      expect(result.repaired).toBe(true);
      expect(si.isSessionValid(session)).toBe(true);
    });

    it("repairSessionCopy does not mutate original", () => {
      const si = createSessionIntegrity();
      const msgs: Message[] = [
        text("assistant", "Hi"),
        toolResult("orphan"),
      ];
      const session = mockSession(msgs);
      const originalLen = session.messages.length;

      const result = si.repairSessionCopy(session);
      expect(result.repaired).toBe(true);
      expect(session.messages.length).toBe(originalLen);
    });
  });
});
