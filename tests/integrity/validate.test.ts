/**
 * Layer 0: Session Integrity — Validation Tests
 * 
 * Focus: Critical validation paths that prevent session corruption
 */

import { describe, it, expect } from "vitest";
import {
  validate,
  isValid,
  validateToolPairs,
  validateUniqueIds,
} from "../../src/integrity/validate";
import type { Message } from "../../src/integrity/types";

// Helper to create messages
const userMsg = (content: any[]): Message => ({ role: "user", content });
const assistantMsg = (content: any[]): Message => ({ role: "assistant", content });
const toolUse = (id: string, name = "test") => ({ type: "tool_use" as const, id, name, input: {} });
const toolResult = (id: string) => ({ type: "tool_result" as const, tool_use_id: id, content: "ok" });
const text = (t: string) => ({ type: "text" as const, text: t });

describe("validateToolPairs", () => {
  it("passes valid tool_use/tool_result pairs", () => {
    const messages: Message[] = [
      assistantMsg([toolUse("123")]),
      userMsg([toolResult("123")]),
    ];
    expect(validateToolPairs(messages)).toEqual([]);
  });

  it("detects orphaned tool_result (no preceding assistant)", () => {
    const messages: Message[] = [
      userMsg([toolResult("orphan123")]),
    ];
    const errors = validateToolPairs(messages);
    expect(errors.length).toBe(1);
    expect(errors[0].type).toBe("missing_preceding_message");
  });

  it("detects orphaned tool_result (ID mismatch)", () => {
    const messages: Message[] = [
      assistantMsg([toolUse("abc")]),
      userMsg([toolResult("xyz")]), // Different ID
    ];
    const errors = validateToolPairs(messages);
    expect(errors.length).toBe(1);
    expect(errors[0].type).toBe("orphaned_tool_result");
    expect(errors[0].toolId).toBe("xyz");
  });

  it("handles multiple tool calls in one turn", () => {
    const messages: Message[] = [
      assistantMsg([toolUse("a"), toolUse("b"), toolUse("c")]),
      userMsg([toolResult("a"), toolResult("b"), toolResult("c")]),
    ];
    expect(validateToolPairs(messages)).toEqual([]);
  });

  it("detects partial orphans (some match, some don't)", () => {
    const messages: Message[] = [
      assistantMsg([toolUse("a"), toolUse("b")]),
      userMsg([toolResult("a"), toolResult("orphan")]), // "b" missing, "orphan" extra
    ];
    const errors = validateToolPairs(messages);
    expect(errors.some(e => e.toolId === "orphan")).toBe(true);
  });
});

describe("validateUniqueIds", () => {
  it("passes unique IDs", () => {
    const messages: Message[] = [
      assistantMsg([toolUse("a")]),
      userMsg([toolResult("a")]),
      assistantMsg([toolUse("b")]),
      userMsg([toolResult("b")]),
    ];
    expect(validateUniqueIds(messages)).toEqual([]);
  });

  it("detects duplicate tool_use IDs", () => {
    const messages: Message[] = [
      assistantMsg([toolUse("dup")]),
      userMsg([toolResult("dup")]),
      assistantMsg([toolUse("dup")]), // Duplicate!
    ];
    const errors = validateUniqueIds(messages);
    expect(errors.length).toBe(1);
    expect(errors[0].type).toBe("duplicate_tool_id");
  });
});

describe("validate (full)", () => {
  it("returns valid for clean session", () => {
    const messages: Message[] = [
      userMsg([text("Hello")]),
      assistantMsg([text("Hi there!")]),
    ];
    const result = validate(messages);
    expect(result.valid).toBe(true);
    expect(result.errors).toEqual([]);
  });

  it("returns valid for complex tool session", () => {
    const messages: Message[] = [
      userMsg([text("Search for cats")]),
      assistantMsg([text("I'll search"), toolUse("search1", "web_search")]),
      userMsg([toolResult("search1")]),
      assistantMsg([text("Found results"), toolUse("read1", "read")]),
      userMsg([toolResult("read1")]),
      assistantMsg([text("Here's what I found")]),
    ];
    const result = validate(messages);
    expect(result.valid).toBe(true);
  });

  it("aggregates all errors", () => {
    const messages: Message[] = [
      userMsg([toolResult("orphan1")]), // Orphan
      assistantMsg([toolUse("dup")]),
      userMsg([toolResult("dup")]),
      assistantMsg([toolUse("dup")]), // Duplicate
      userMsg([toolResult("orphan2")]), // Another orphan
    ];
    const result = validate(messages);
    expect(result.valid).toBe(false);
    expect(result.orphanedIds).toContain("orphan1");
    expect(result.orphanedIds).toContain("orphan2");
  });
});

describe("isValid (fast path)", () => {
  it("returns true for valid session", () => {
    const messages: Message[] = [
      assistantMsg([toolUse("x")]),
      userMsg([toolResult("x")]),
    ];
    expect(isValid(messages)).toBe(true);
  });

  it("returns false for orphaned tool_result", () => {
    const messages: Message[] = [
      assistantMsg([toolUse("a")]),
      userMsg([toolResult("b")]), // Wrong ID
    ];
    expect(isValid(messages)).toBe(false);
  });

  it("is faster than full validate for quick checks", () => {
    // Generate a large valid session
    const messages: Message[] = [];
    for (let i = 0; i < 100; i++) {
      messages.push(assistantMsg([toolUse(`tool${i}`)]));
      messages.push(userMsg([toolResult(`tool${i}`)]));
    }

    const start1 = performance.now();
    isValid(messages);
    const fast = performance.now() - start1;

    const start2 = performance.now();
    validate(messages);
    const full = performance.now() - start2;

    // isValid should be at least as fast (usually faster)
    expect(fast).toBeLessThanOrEqual(full * 2);
  });
});
