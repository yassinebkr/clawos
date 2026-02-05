/**
 * Layer 0: Session Integrity — Repair Tests
 *
 * Focus: Ensuring repair correctly fixes corrupt sessions
 */

import { describe, it, expect } from "vitest";
import { repair, repairCopy } from "../../src/integrity/repair";
import { isValid } from "../../src/integrity/validate";
import type { Message } from "../../src/integrity/types";

const userMsg = (content: any[]): Message => ({ role: "user", content });
const assistantMsg = (content: any[]): Message => ({ role: "assistant", content });
const toolUse = (id: string, name = "test") => ({ type: "tool_use" as const, id, name, input: {} });
const toolResult = (id: string) => ({ type: "tool_result" as const, tool_use_id: id, content: "ok" });
const text = (t: string) => ({ type: "text" as const, text: t });

describe("repair", () => {
  it("removes orphaned tool_results", () => {
    const messages: Message[] = [
      assistantMsg([toolUse("valid")]),
      userMsg([toolResult("valid"), toolResult("orphan")]),
    ];

    const result = repair(messages);

    expect(result.repaired).toBe(true);
    expect(result.repairs.some(r => r.action === "remove_orphan")).toBe(true);
    expect(isValid(messages)).toBe(true);
  });

  it("removes tool_result without ANY preceding assistant message", () => {
    const messages: Message[] = [
      userMsg([toolResult("totally_orphan")]),
    ];

    const result = repair(messages);

    expect(result.repaired).toBe(true);
    // Should either remove the tool_result or the whole message
    expect(result.repairs.length).toBeGreaterThan(0);
  });

  it("removes empty messages after cleanup", () => {
    const messages: Message[] = [
      userMsg([toolResult("orphan")]), // Will be removed, leaving empty message
    ];

    const result = repair(messages);

    expect(result.repaired).toBe(true);
    expect(messages.every(m => m.content.length > 0 || typeof m.content === 'string')).toBe(true);
  });

  it("handles cascading repairs", () => {
    // Complex case: removing one thing could create another issue
    const messages: Message[] = [
      assistantMsg([toolUse("a")]),
      userMsg([toolResult("a"), toolResult("orphan1")]),
      assistantMsg([toolUse("b")]),
      userMsg([toolResult("b"), toolResult("orphan2")]),
    ];

    const result = repair(messages);

    expect(result.repaired).toBe(true);
    expect(isValid(messages)).toBe(true);
  });

  it("removes duplicate tool IDs", () => {
    const messages: Message[] = [
      assistantMsg([toolUse("dup")]),
      userMsg([toolResult("dup")]),
      assistantMsg([toolUse("dup")]), // Duplicate
      userMsg([toolResult("dup")]),
    ];

    const result = repair(messages);

    expect(result.repaired).toBe(true);
    expect(result.repairs.some(r => r.action === "remove_duplicate_id")).toBe(true);
  });

  it("leaves valid sessions unchanged", () => {
    const messages: Message[] = [
      userMsg([text("Hello")]),
      assistantMsg([text("Hi!")]),
      assistantMsg([toolUse("search")]),
      userMsg([toolResult("search")]),
    ];

    const result = repair(messages);

    expect(result.repaired).toBe(false);
    expect(result.repairs).toEqual([]);
  });
});

describe("repairCopy", () => {
  it("does not mutate original messages", () => {
    const original: Message[] = [
      assistantMsg([toolUse("valid")]),
      userMsg([toolResult("valid"), toolResult("orphan")]),
    ];

    const originalLength = original[1].content.length;
    const result = repairCopy(original);

    // Original unchanged
    expect(original[1].content.length).toBe(originalLength);

    // Copy was repaired
    expect(result.repaired).toBe(true);
  });
});

describe("real-world scenario: content filter corruption", () => {
  it("repairs the exact Feb 5 incident pattern", () => {
    // Simulates: assistant had tool_use, content filter stripped it,
    // but tool_result remained in user message
    const messages: Message[] = [
      userMsg([text("Do something")]),
      assistantMsg([text("I'll help")]), // tool_use was STRIPPED by filter
      userMsg([toolResult("toolu_stripped123")]), // This is now orphaned
    ];

    expect(isValid(messages)).toBe(false);

    const result = repair(messages);

    expect(result.repaired).toBe(true);
    expect(isValid(messages)).toBe(true);
    expect(result.repairs.some(r => r.toolId === "toolu_stripped123")).toBe(true);
  });
});
