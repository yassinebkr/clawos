/**
 * Layer 0: Session Integrity — Checkpoint Tests
 */

import { describe, it, expect, beforeEach } from "vitest";
import {
  createCheckpointManager,
  MemoryCheckpointStore,
  hashMessages,
  generateCheckpointId,
} from "../../src/integrity/checkpoint";
import type { Message, Checkpoint } from "../../src/integrity/types";

const text = (role: "user" | "assistant", t: string): Message => ({
  role,
  content: [{ type: "text", text: t }],
});

describe("hashMessages", () => {
  it("returns consistent hash for same messages", () => {
    const msgs: Message[] = [text("user", "Hello")];
    expect(hashMessages(msgs)).toBe(hashMessages(msgs));
  });

  it("returns different hash for different messages", () => {
    const a: Message[] = [text("user", "Hello")];
    const b: Message[] = [text("user", "Goodbye")];
    expect(hashMessages(a)).not.toBe(hashMessages(b));
  });

  it("returns a 16-char hex string", () => {
    const hash = hashMessages([text("user", "test")]);
    expect(hash).toMatch(/^[0-9a-f]{16}$/);
  });

  it("handles empty array", () => {
    const hash = hashMessages([]);
    expect(hash).toBeTruthy();
    expect(hash.length).toBe(16);
  });
});

describe("generateCheckpointId", () => {
  it("generates unique IDs", () => {
    const ids = new Set(Array.from({ length: 100 }, () => generateCheckpointId()));
    expect(ids.size).toBe(100);
  });

  it("starts with ckpt_ prefix", () => {
    expect(generateCheckpointId()).toMatch(/^ckpt_/);
  });
});

describe("MemoryCheckpointStore", () => {
  let store: MemoryCheckpointStore;

  beforeEach(() => {
    store = new MemoryCheckpointStore();
  });

  it("creates checkpoint with correct fields", async () => {
    const msgs: Message[] = [text("user", "Hello")];
    const ckpt = await store.create("sess1", msgs, "api_call");

    expect(ckpt.sessionId).toBe("sess1");
    expect(ckpt.messageIndex).toBe(1);
    expect(ckpt.operation).toBe("api_call");
    expect(ckpt.state).toBe("pending");
    expect(ckpt.contentHash).toBeTruthy();
    expect(ckpt.id).toMatch(/^ckpt_/);
    expect(ckpt.timestamp).toBeGreaterThan(0);
  });

  it("creates snapshot when requested", async () => {
    const msgs: Message[] = [text("user", "Hello")];
    const ckpt = await store.create("sess1", msgs, "api_call", { snapshot: true });

    expect(ckpt.snapshot).toBeDefined();
    expect(ckpt.snapshot).toHaveLength(1);
    // Snapshot should be a copy
    msgs.push(text("assistant", "Hi"));
    expect(ckpt.snapshot).toHaveLength(1);
  });

  it("does not create snapshot by default", async () => {
    const ckpt = await store.create("sess1", [], "api_call");
    expect(ckpt.snapshot).toBeUndefined();
  });

  it("includes meta when provided", async () => {
    const ckpt = await store.create("sess1", [], "tool_cycle", { meta: { toolId: "t1" } });
    expect(ckpt.meta).toEqual({ toolId: "t1" });
  });

  it("retrieves checkpoint by ID", async () => {
    const ckpt = await store.create("sess1", [], "api_call");
    const retrieved = await store.get(ckpt.id);
    expect(retrieved?.id).toBe(ckpt.id);
  });

  it("returns undefined for unknown ID", async () => {
    const result = await store.get("nonexistent");
    expect(result).toBeUndefined();
  });

  it("gets latest checkpoint for session", async () => {
    const ckpt1 = await store.create("sess1", [], "api_call");
    const ckpt2 = await store.create("sess1", [], "tool_cycle");

    const latest = await store.getLatest("sess1");
    expect(latest?.id).toBe(ckpt2.id);
  });

  it("returns undefined for session with no checkpoints", async () => {
    const latest = await store.getLatest("nonexistent");
    expect(latest).toBeUndefined();
  });

  it("lists all checkpoints for session", async () => {
    await store.create("sess1", [], "api_call");
    await store.create("sess1", [], "tool_cycle");
    await store.create("sess2", [], "api_call");

    const sess1List = await store.list("sess1");
    expect(sess1List).toHaveLength(2);

    const sess2List = await store.list("sess2");
    expect(sess2List).toHaveLength(1);
  });

  it("commits checkpoint", async () => {
    const ckpt = await store.create("sess1", [], "api_call");
    expect(ckpt.state).toBe("pending");

    await store.commit(ckpt.id);
    const retrieved = await store.get(ckpt.id);
    expect(retrieved?.state).toBe("committed");
  });

  it("marks checkpoint as rolled back", async () => {
    const ckpt = await store.create("sess1", [], "api_call");
    await store.markRolledBack(ckpt.id);

    const retrieved = await store.get(ckpt.id);
    expect(retrieved?.state).toBe("rolled_back");
  });

  it("prune removes oldest committed checkpoints", async () => {
    for (let i = 0; i < 5; i++) {
      const ckpt = await store.create("sess1", [], "api_call");
      await store.commit(ckpt.id);
    }

    const pruned = await store.prune("sess1", 2);
    expect(pruned).toBe(3);

    const remaining = await store.list("sess1");
    expect(remaining.filter((c) => c.state === "committed")).toHaveLength(2);
  });

  it("prune does not remove pending checkpoints", async () => {
    const committed = await store.create("sess1", [], "api_call");
    await store.commit(committed.id);
    const pending = await store.create("sess1", [], "tool_cycle");
    // pending stays pending

    await store.prune("sess1", 1);
    const remaining = await store.list("sess1");
    expect(remaining.some((c) => c.id === pending.id)).toBe(true);
  });

  it("clear removes all checkpoints for session", async () => {
    await store.create("sess1", [], "api_call");
    await store.create("sess1", [], "tool_cycle");

    const cleared = await store.clear("sess1");
    expect(cleared).toBe(2);

    const remaining = await store.list("sess1");
    expect(remaining).toHaveLength(0);
  });

  it("clear returns 0 for nonexistent session", async () => {
    const cleared = await store.clear("nonexistent");
    expect(cleared).toBe(0);
  });
});

describe("CheckpointManager", () => {
  it("creates and commits checkpoints", async () => {
    const manager = createCheckpointManager();
    const msgs: Message[] = [text("user", "Hello")];

    const ckpt = await manager.create("sess1", msgs, "api_call");
    expect(ckpt.state).toBe("pending");

    await manager.commit(ckpt.id);
    const latest = await manager.getLatest("sess1");
    expect(latest?.state).toBe("committed");
  });

  it("auto-prunes on commit with retention", async () => {
    const manager = createCheckpointManager({ retention: 2 });

    for (let i = 0; i < 5; i++) {
      const ckpt = await manager.create("sess1", [], "api_call");
      await manager.commit(ckpt.id);
    }

    const list = await manager.list("sess1");
    expect(list.filter((c) => c.state === "committed").length).toBeLessThanOrEqual(2);
  });

  it("getRestoreMessages returns snapshot if available", async () => {
    const manager = createCheckpointManager({ snapshotMessages: true });
    const original: Message[] = [text("user", "Hello")];

    const ckpt = await manager.create("sess1", original, "tool_cycle");

    const current: Message[] = [...original, text("assistant", "Hi"), text("user", "How are you?")];
    const restore = await manager.getRestoreMessages(ckpt.id, current);

    expect(restore).toBeDefined();
    expect(restore!.messages).toHaveLength(1);
    expect(restore!.removed).toBe(2);
  });

  it("getRestoreMessages uses truncation without snapshot", async () => {
    const manager = createCheckpointManager({ snapshotMessages: false });
    const original: Message[] = [text("user", "Hello")];

    const ckpt = await manager.create("sess1", original, "api_call");

    const current: Message[] = [...original, text("assistant", "Hi")];
    const restore = await manager.getRestoreMessages(ckpt.id, current);

    expect(restore).toBeDefined();
    expect(restore!.messages).toHaveLength(1);
    expect(restore!.removed).toBe(1);
  });

  it("getRestoreMessages returns undefined for tampered prefix", async () => {
    const manager = createCheckpointManager({ snapshotMessages: false });
    const original: Message[] = [text("user", "Hello")];

    const ckpt = await manager.create("sess1", original, "api_call");

    // Tamper with the first message
    const current: Message[] = [text("user", "TAMPERED"), text("assistant", "Hi")];
    const restore = await manager.getRestoreMessages(ckpt.id, current);

    expect(restore).toBeUndefined();
  });

  it("getRestoreMessages returns undefined for unknown checkpoint", async () => {
    const manager = createCheckpointManager();
    const restore = await manager.getRestoreMessages("nonexistent", []);
    expect(restore).toBeUndefined();
  });

  it("markRolledBack changes state", async () => {
    const manager = createCheckpointManager();
    const ckpt = await manager.create("sess1", [], "api_call");
    await manager.markRolledBack(ckpt.id);

    const list = await manager.list("sess1");
    expect(list[0].state).toBe("rolled_back");
  });

  it("clear removes all for session", async () => {
    const manager = createCheckpointManager();
    await manager.create("sess1", [], "api_call");
    await manager.create("sess1", [], "tool_cycle");

    const cleared = await manager.clear("sess1");
    expect(cleared).toBe(2);

    const list = await manager.list("sess1");
    expect(list).toHaveLength(0);
  });
});
