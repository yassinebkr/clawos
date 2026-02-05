/**
 * ClawOS Layer 4: Signal Detection — Main Coordinator
 */

import type {
  Signal,
  ScanContext,
  ScanResult,
  Layer4Config,
  SignalCategory,
} from "./types.js";
import { SignalScanner, createScanner } from "./scanner.js";
import {
  DefaultSignalEmitter,
  SignalStore,
  getDefaultEmitter,
  getDefaultStore,
  type L3Monitor,
} from "./emitter.js";
import type { TrustLevel, TaggedContent } from "../tagging/types.js";

// ============================================================================
// Signal Detection Service
// ============================================================================

export class SignalDetection {
  private scanner: SignalScanner;
  private emitter: DefaultSignalEmitter;
  private store: SignalStore;
  private config: Layer4Config;

  constructor(config?: Partial<Layer4Config>) {
    this.config = {
      enabled: config?.enabled ?? true,
      patterns: {
        injection: config?.patterns?.injection ?? true,
        exfiltration: config?.patterns?.exfiltration ?? true,
        encoding: config?.patterns?.encoding ?? true,
        roleplay: config?.patterns?.roleplay ?? true,
        repetition: config?.patterns?.repetition ?? true,
        custom: config?.patterns?.custom,
      },
      minConfidence: config?.minConfidence ?? 0.3,
      trustAdjustments: {
        untrusted: config?.trustAdjustments?.untrusted ?? 1.2,
        tool: config?.trustAdjustments?.tool ?? 1.0,
        user: config?.trustAdjustments?.user ?? 0.5,
        system: config?.trustAdjustments?.system ?? 0.1,
      },
      emit: {
        toL3: config?.emit?.toL3 ?? true,
        toLog: config?.emit?.toLog ?? false,
        logPath: config?.emit?.logPath,
        toMetrics: config?.emit?.toMetrics ?? false,
        minConfidence: config?.emit?.minConfidence ?? 0.3,
        suppressCategories: config?.emit?.suppressCategories,
      },
      performance: {
        maxContentLength: config?.performance?.maxContentLength ?? 100_000,
        maxSignalsPerScan: config?.performance?.maxSignalsPerScan ?? 50,
        timeoutMs: config?.performance?.timeoutMs ?? 5,
      },
    };

    this.scanner = createScanner(this.config);
    this.emitter = new DefaultSignalEmitter(this.config.emit);
    this.store = new SignalStore();
  }

  /**
   * Scan content for signals.
   */
  scan(content: string, context: ScanContext): Signal[] {
    if (!this.config.enabled) {
      return [];
    }

    const signals = this.scanner.scan(content, context);

    // Store signals
    this.store.addBatch(signals);

    // Emit signals
    this.emitter.emitBatch(signals);

    return signals;
  }

  /**
   * Scan content with detailed result information.
   */
  scanWithResult(content: string, context: ScanContext): ScanResult {
    if (!this.config.enabled) {
      return {
        signals: [],
        truncated: false,
        timedOut: false,
        durationMs: 0,
      };
    }

    const result = this.scanner.scanWithResult(content, context);

    // Store signals
    this.store.addBatch(result.signals);

    // Emit signals
    this.emitter.emitBatch(result.signals);

    return result;
  }

  /**
   * Scan tagged content (integrates with L1).
   */
  scanTagged(content: TaggedContent): Signal[] {
    const context: ScanContext = {
      trustLevel: content.tag.trust,
      contentType: content.tag.contentType || "text",
      sessionId: content.tag.sessionId,
    };

    return this.scan(String(content.value), context);
  }

  /**
   * Set the L3 Runtime Monitor to receive signals.
   */
  setL3Monitor(monitor: L3Monitor): void {
    this.emitter.setL3Monitor(monitor);
  }

  /**
   * Get recent signals for a session.
   */
  getRecentSignals(sessionId: string, windowMs: number = 60_000): Signal[] {
    return this.store.getRecent(sessionId, windowMs);
  }

  /**
   * Get signals by category for a session.
   */
  getSignalsByCategory(sessionId: string, category: SignalCategory): Signal[] {
    return this.store.getByCategory(sessionId, category);
  }

  /**
   * Check if session has high-confidence signals in recent window.
   */
  hasHighConfidenceSignals(
    sessionId: string,
    windowMs: number = 60_000,
    threshold: number = 0.7
  ): boolean {
    const recent = this.store.getRecent(sessionId, windowMs);
    return recent.some((s) => s.confidence >= threshold);
  }

  /**
   * Get signal summary for a session.
   */
  getSignalSummary(sessionId: string): SignalSummary {
    const signals = this.store.getAll(sessionId);

    const byCategory: Record<string, number> = {};
    let maxConfidence = 0;
    let totalSignals = 0;

    for (const signal of signals) {
      byCategory[signal.category] = (byCategory[signal.category] || 0) + 1;
      maxConfidence = Math.max(maxConfidence, signal.confidence);
      totalSignals++;
    }

    return {
      totalSignals,
      byCategory,
      maxConfidence,
      lastSignalAt: signals.length > 0 ? signals[signals.length - 1].timestamp : null,
    };
  }

  /**
   * Clear signals for a session.
   */
  clearSignals(sessionId: string): void {
    this.store.clear(sessionId);
  }

  /**
   * Update configuration.
   */
  configure(config: Partial<Layer4Config>): void {
    Object.assign(this.config, config);
    if (config.emit) {
      this.emitter.configure(config.emit);
    }
  }

  /**
   * Get current configuration.
   */
  getConfig(): Layer4Config {
    return { ...this.config };
  }
}

// ============================================================================
// Types
// ============================================================================

export interface SignalSummary {
  totalSignals: number;
  byCategory: Record<string, number>;
  maxConfidence: number;
  lastSignalAt: number | null;
}

// ============================================================================
// Default Instance
// ============================================================================

let defaultInstance: SignalDetection | null = null;

export function getSignalDetection(): SignalDetection {
  if (!defaultInstance) {
    defaultInstance = new SignalDetection();
  }
  return defaultInstance;
}

export function createSignalDetection(
  config?: Partial<Layer4Config>
): SignalDetection {
  return new SignalDetection(config);
}

// ============================================================================
// Convenience Functions
// ============================================================================

/**
 * Quick scan for signals (uses default instance).
 */
export function scanForSignals(
  content: string,
  trustLevel: TrustLevel = "untrusted",
  sessionId?: string
): Signal[] {
  return getSignalDetection().scan(content, {
    trustLevel,
    contentType: "text",
    sessionId,
  });
}

/**
 * Check if content contains high-confidence injection signals.
 */
export function hasInjectionSignals(
  content: string,
  trustLevel: TrustLevel = "untrusted",
  threshold: number = 0.6
): boolean {
  const signals = scanForSignals(content, trustLevel);
  return signals.some(
    (s) => s.category === "injection" && s.confidence >= threshold
  );
}

/**
 * Check if content contains exfiltration signals.
 */
export function hasExfiltrationSignals(
  content: string,
  trustLevel: TrustLevel = "untrusted",
  threshold: number = 0.5
): boolean {
  const signals = scanForSignals(content, trustLevel);
  return signals.some(
    (s) => s.category === "exfiltration" && s.confidence >= threshold
  );
}
