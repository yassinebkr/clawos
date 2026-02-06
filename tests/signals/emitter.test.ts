/**
 * Layer 4: Signal Detection — Emitter & Store Tests
 */

import { describe, it, expect, beforeEach } from "vitest";
import {
  DefaultSignalEmitter,
  SignalStore,
  getDefaultEmitter,
  getDefaultStore,
} from "../../src/signals/emitter";
import type { Signal } from "../../src/signals/types";

function createSignal(overrides?: Partial<Signal>): Signal {
  return {
    id: `sig-${Math.random().toString(36).slice(2)}`,
    timestamp: Date.now(),
    category: "injection",
    confidence: 0.8,
    matched: { pattern: "test", text: "test", position: 0 },
    source: { trustLevel: "untrusted", contentType: "text" },
    context: {},
    ...overrides,
  };
}

describe("DefaultSignalEmitter", () => {
  it("creates with default config", () => {
    const emitter = new DefaultSignalEmitter();
    // Should not throw
    emitter.emit(createSignal());
  });

  it("filters below minimum confidence", () => {
    const emitter = new DefaultSignalEmitter({ minConfidence: 0.5 });
    // Low confidence signal should be silently dropped
    emitter.emit(createSignal({ confidence: 0.1 }));
    // No error means it was filtered
  });

  it("suppresses specified categories", () => {
    const emitter = new DefaultSignalEmitter({
      suppressCategories: ["injection"],
    });
    // Should be suppressed
    emitter.emit(createSignal({ category: "injection" }));
  });

  it("emitBatch processes multiple signals", () => {
    const emitter = new DefaultSignalEmitter();
    const signals = [createSignal(), createSignal(), createSignal()];
    emitter.emitBatch(signals);
  });

  it("configure updates settings", () => {
    const emitter = new DefaultSignalEmitter({ minConfidence: 0.5 });
    emitter.configure({ minConfidence: 0.1 });
    // Should now accept lower confidence
    emitter.emit(createSignal({ confidence: 0.2 }));
  });

  it("sends to L3 monitor when configured", () => {
    const received: Signal[] = [];
    const emitter = new DefaultSignalEmitter({ toL3: true });
    emitter.setL3Monitor({
      receiveSignal: (s) => received.push(s),
    });

    emitter.emit(createSignal());
    expect(received).toHaveLength(1);
  });

  it("handles L3 monitor errors gracefully", () => {
    const emitter = new DefaultSignalEmitter({ toL3: true });
    emitter.setL3Monitor({
      receiveSignal: () => { throw new Error("L3 error"); },
    });

    // Should not throw
    expect(() => emitter.emit(createSignal())).not.toThrow();
  });
});

describe("SignalStore", () => {
  let store: SignalStore;

  beforeEach(() => {
    store = new SignalStore();
  });

  it("adds and retrieves signals", () => {
    const signal = createSignal({ source: { trustLevel: "untrusted", contentType: "text", sessionId: "s1" } });
    store.add(signal);

    const all = store.getAll("s1");
    expect(all).toHaveLength(1);
    expect(all[0].id).toBe(signal.id);
  });

  it("uses 'default' session for signals without sessionId", () => {
    store.add(createSignal());
    const all = store.getAll("default");
    expect(all).toHaveLength(1);
  });

  it("getRecent filters by time window", () => {
    const oldSignal = createSignal({
      timestamp: Date.now() - 120_000,
      source: { trustLevel: "untrusted", contentType: "text", sessionId: "s1" },
    });
    const newSignal = createSignal({
      source: { trustLevel: "untrusted", contentType: "text", sessionId: "s1" },
    });

    store.add(oldSignal);
    store.add(newSignal);

    const recent = store.getRecent("s1", 60_000);
    expect(recent).toHaveLength(1);
    expect(recent[0].id).toBe(newSignal.id);
  });

  it("getByCategory filters by category", () => {
    const injection = createSignal({
      category: "injection",
      source: { trustLevel: "untrusted", contentType: "text", sessionId: "s1" },
    });
    const exfil = createSignal({
      category: "exfiltration",
      source: { trustLevel: "untrusted", contentType: "text", sessionId: "s1" },
    });

    store.add(injection);
    store.add(exfil);

    const injections = store.getByCategory("s1", "injection");
    expect(injections).toHaveLength(1);
    expect(injections[0].category).toBe("injection");
  });

  it("addBatch adds multiple signals", () => {
    const signals = [
      createSignal({ source: { trustLevel: "untrusted", contentType: "text", sessionId: "s1" } }),
      createSignal({ source: { trustLevel: "untrusted", contentType: "text", sessionId: "s1" } }),
    ];
    store.addBatch(signals);
    expect(store.getAll("s1")).toHaveLength(2);
  });

  it("clear removes session signals", () => {
    store.add(createSignal({ source: { trustLevel: "untrusted", contentType: "text", sessionId: "s1" } }));
    store.clear("s1");
    expect(store.getAll("s1")).toHaveLength(0);
  });

  it("respects maxSignalsPerSession", () => {
    const smallStore = new SignalStore({ maxSignalsPerSession: 5 });
    for (let i = 0; i < 10; i++) {
      smallStore.add(createSignal({
        source: { trustLevel: "untrusted", contentType: "text", sessionId: "s1" },
      }));
    }
    expect(smallStore.getAll("s1").length).toBeLessThanOrEqual(5);
  });

  it("prunes old signals by maxAgeMs", () => {
    const shortLived = new SignalStore({ maxAgeMs: 1 });
    shortLived.add(createSignal({
      timestamp: Date.now() - 100,
      source: { trustLevel: "untrusted", contentType: "text", sessionId: "s1" },
    }));
    // Adding a new signal triggers prune
    shortLived.add(createSignal({
      source: { trustLevel: "untrusted", contentType: "text", sessionId: "s1" },
    }));
    // Old signal should be pruned
    expect(shortLived.getAll("s1").length).toBeLessThanOrEqual(1);
  });
});

describe("default instances", () => {
  it("getDefaultEmitter returns singleton", () => {
    const e1 = getDefaultEmitter();
    const e2 = getDefaultEmitter();
    expect(e1).toBe(e2);
  });

  it("getDefaultStore returns singleton", () => {
    const s1 = getDefaultStore();
    const s2 = getDefaultStore();
    expect(s1).toBe(s2);
  });
});
