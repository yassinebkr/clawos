/**
 * ClawOS Layer 4: Signal Detection — Signal Emitter
 */

import { appendFileSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";
import type { Signal, SignalEmitter, EmitterConfig } from "./types.js";

// ============================================================================
// Default Emitter
// ============================================================================

export class DefaultSignalEmitter implements SignalEmitter {
  private config: EmitterConfig;
  private l3Monitor?: L3Monitor;

  constructor(config?: Partial<EmitterConfig>) {
    this.config = {
      toL3: config?.toL3 ?? true,
      toLog: config?.toLog ?? false,
      logPath: config?.logPath,
      toMetrics: config?.toMetrics ?? false,
      minConfidence: config?.minConfidence ?? 0.3,
      suppressCategories: config?.suppressCategories,
    };
  }

  configure(config: Partial<EmitterConfig>): void {
    Object.assign(this.config, config);
  }

  setL3Monitor(monitor: L3Monitor): void {
    this.l3Monitor = monitor;
  }

  emit(signal: Signal): void {
    // Check minimum confidence
    if (signal.confidence < this.config.minConfidence) {
      return;
    }

    // Check suppression
    if (this.config.suppressCategories?.includes(signal.category)) {
      return;
    }

    // Send to L3
    if (this.config.toL3 && this.l3Monitor) {
      try {
        this.l3Monitor.receiveSignal(signal);
      } catch {
        // L3 errors shouldn't break signal emission
      }
    }

    // Log
    if (this.config.toLog && this.config.logPath) {
      try {
        mkdirSync(dirname(this.config.logPath), { recursive: true });
        appendFileSync(this.config.logPath, JSON.stringify(signal) + "\n");
      } catch {
        // Log errors shouldn't break signal emission
      }
    }

    // Metrics (placeholder - would integrate with actual metrics system)
    if (this.config.toMetrics) {
      // incrementMetric('clawos_signals_total', {
      //   category: signal.category,
      //   confidence_bucket: getConfidenceBucket(signal.confidence),
      // });
    }
  }

  emitBatch(signals: Signal[]): void {
    for (const signal of signals) {
      this.emit(signal);
    }
  }
}

// ============================================================================
// L3 Monitor Interface
// ============================================================================

/**
 * Interface for Layer 3 Runtime Monitor to receive signals.
 * L3 implementation will implement this interface.
 */
export interface L3Monitor {
  receiveSignal(signal: Signal): void;
}

// ============================================================================
// Signal Store (for querying recent signals)
// ============================================================================

export class SignalStore {
  private signals: Map<string, Signal[]> = new Map();
  private maxSignalsPerSession: number;
  private maxAgeMs: number;

  constructor(options?: { maxSignalsPerSession?: number; maxAgeMs?: number }) {
    this.maxSignalsPerSession = options?.maxSignalsPerSession ?? 1000;
    this.maxAgeMs = options?.maxAgeMs ?? 3600_000; // 1 hour default
  }

  add(signal: Signal): void {
    const sessionId = signal.source.sessionId || "default";
    
    if (!this.signals.has(sessionId)) {
      this.signals.set(sessionId, []);
    }

    const sessionSignals = this.signals.get(sessionId)!;
    sessionSignals.push(signal);

    // Prune old signals
    this.prune(sessionId);
  }

  addBatch(signals: Signal[]): void {
    for (const signal of signals) {
      this.add(signal);
    }
  }

  getRecent(sessionId: string, windowMs: number): Signal[] {
    const sessionSignals = this.signals.get(sessionId) || [];
    const cutoff = Date.now() - windowMs;
    return sessionSignals.filter((s) => s.timestamp >= cutoff);
  }

  getByCategory(sessionId: string, category: string): Signal[] {
    const sessionSignals = this.signals.get(sessionId) || [];
    return sessionSignals.filter((s) => s.category === category);
  }

  getAll(sessionId: string): Signal[] {
    return this.signals.get(sessionId) || [];
  }

  clear(sessionId: string): void {
    this.signals.delete(sessionId);
  }

  private prune(sessionId: string): void {
    const sessionSignals = this.signals.get(sessionId);
    if (!sessionSignals) return;

    const now = Date.now();
    const cutoff = now - this.maxAgeMs;

    // Remove old signals
    const filtered = sessionSignals.filter((s) => s.timestamp >= cutoff);

    // Limit total count
    if (filtered.length > this.maxSignalsPerSession) {
      filtered.splice(0, filtered.length - this.maxSignalsPerSession);
    }

    this.signals.set(sessionId, filtered);
  }
}

// ============================================================================
// Default Instances
// ============================================================================

let defaultEmitter: DefaultSignalEmitter | null = null;
let defaultStore: SignalStore | null = null;

export function getDefaultEmitter(): DefaultSignalEmitter {
  if (!defaultEmitter) {
    defaultEmitter = new DefaultSignalEmitter();
  }
  return defaultEmitter;
}

export function getDefaultStore(): SignalStore {
  if (!defaultStore) {
    defaultStore = new SignalStore();
  }
  return defaultStore;
}
