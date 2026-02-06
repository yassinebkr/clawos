/**
 * ClawOS Layer 4: Signal Detection — Scanner Implementation
 */

import { randomUUID } from "node:crypto";
import type {
  Signal,
  SignalCategory,
  ScanContext,
  ScanResult,
  Scanner,
  PatternDefinition,
  CompiledPattern,
  Layer4Config,
} from "./types.js";
import {
  INJECTION_PATTERNS,
  EXFILTRATION_PATTERNS,
  ENCODING_PATTERNS,
  ROLEPLAY_PATTERNS,
} from "./patterns.js";

// ============================================================================
// Pattern Engine
// ============================================================================

export class PatternEngine {
  private compiledPatterns: CompiledPattern[] = [];

  constructor(patterns: PatternDefinition[]) {
    for (const def of patterns) {
      this.compiledPatterns.push({
        regex: new RegExp(def.pattern.source, def.pattern.flags + "g"),
        category: def.category,
        weight: def.weight,
        contextCheck: def.contextCheck,
        description: def.description,
      });
    }
  }

  scan(text: string, context: ScanContext, config: ScanConfig): Signal[] {
    const signals: Signal[] = [];
    const deadline = Date.now() + config.timeoutMs;

    for (const pattern of this.compiledPatterns) {
      // Reset regex state
      pattern.regex.lastIndex = 0;

      let match;
      while ((match = pattern.regex.exec(text)) !== null) {
        // Check timeout
        if (Date.now() > deadline) {
          break;
        }

        // Check max signals
        if (signals.length >= config.maxSignals) {
          break;
        }

        // Optional context check
        if (pattern.contextCheck && !pattern.contextCheck(text, match)) {
          continue;
        }

        // Calculate confidence with trust adjustment
        let confidence = pattern.weight;
        confidence *= getTrustMultiplier(context.trustLevel, config);
        confidence = Math.min(Math.max(confidence, 0), 1);

        signals.push({
          id: randomUUID(),
          timestamp: Date.now(),
          category: pattern.category,
          confidence,
          matched: {
            pattern: pattern.description || pattern.regex.source,
            text: match[0],
            position: match.index,
          },
          source: {
            trustLevel: context.trustLevel,
            contentType: context.contentType,
            sessionId: context.sessionId,
          },
          context: {},
        });
      }

      // Check limits after each pattern
      if (Date.now() > deadline || signals.length >= config.maxSignals) {
        break;
      }
    }

    return signals;
  }
}

// ============================================================================
// Repetition Scanner
// ============================================================================

export function detectRepetition(
  text: string,
  context: ScanContext
): Signal | null {
  // Split into tokens (rough approximation)
  const words = text.toLowerCase().split(/\s+/).filter(Boolean);
  if (words.length < 5) return null;

  // Count consecutive repeats
  let maxRepeat = 1;
  let currentRepeat = 1;
  let repeatedWord = "";

  for (let i = 1; i < words.length; i++) {
    if (words[i] === words[i - 1] && words[i].length > 2) {
      currentRepeat++;
      if (currentRepeat > maxRepeat) {
        maxRepeat = currentRepeat;
        repeatedWord = words[i];
      }
    } else {
      currentRepeat = 1;
    }
  }

  // Flag unusual repetition (> 5 consecutive same tokens)
  if (maxRepeat > 5) {
    return {
      id: randomUUID(),
      timestamp: Date.now(),
      category: "repetition",
      confidence: Math.min(0.3 + (maxRepeat - 5) * 0.1, 0.9),
      matched: {
        pattern: "consecutive_repeat",
        text: `"${repeatedWord}" repeated ${maxRepeat} times`,
        position: 0,
      },
      source: {
        trustLevel: context.trustLevel,
        contentType: context.contentType,
        sessionId: context.sessionId,
      },
      context: { repeatCount: maxRepeat },
    };
  }

  // Check overall repetition ratio
  const uniqueRatio = new Set(words).size / words.length;
  if (uniqueRatio < 0.2 && words.length > 20) {
    return {
      id: randomUUID(),
      timestamp: Date.now(),
      category: "repetition",
      confidence: 0.5,
      matched: {
        pattern: "low_unique_ratio",
        text: `${(uniqueRatio * 100).toFixed(1)}% unique words`,
        position: 0,
      },
      source: {
        trustLevel: context.trustLevel,
        contentType: context.contentType,
        sessionId: context.sessionId,
      },
      context: { uniqueRatio },
    };
  }

  return null;
}

// ============================================================================
// Main Scanner
// ============================================================================

interface ScanConfig {
  timeoutMs: number;
  maxSignals: number;
  maxContentLength: number;
  trustAdjustments: {
    untrusted: number;
    tool: number;
    user: number;
    system: number;
  };
}

function getTrustMultiplier(
  trustLevel: string,
  config: ScanConfig
): number {
  switch (trustLevel) {
    case "untrusted":
      return config.trustAdjustments.untrusted;
    case "tool":
      return config.trustAdjustments.tool;
    case "user":
      return config.trustAdjustments.user;
    case "system":
      return config.trustAdjustments.system;
    default:
      return 1.0;
  }
}

export class SignalScanner implements Scanner {
  id = "clawos-l4-scanner";
  categories: SignalCategory[] = [
    "injection",
    "exfiltration",
    "encoding",
    "roleplay",
    "repetition",
  ];

  private patternEngine: PatternEngine;
  private config: ScanConfig;

  constructor(config?: Partial<Layer4Config>) {
    // Build pattern list based on config
    const patterns: PatternDefinition[] = [];

    if (config?.patterns?.injection !== false) {
      patterns.push(...INJECTION_PATTERNS);
    }
    if (config?.patterns?.exfiltration !== false) {
      patterns.push(...EXFILTRATION_PATTERNS);
    }
    if (config?.patterns?.encoding !== false) {
      patterns.push(...ENCODING_PATTERNS);
    }
    if (config?.patterns?.roleplay !== false) {
      patterns.push(...ROLEPLAY_PATTERNS);
    }
    if (config?.patterns?.custom) {
      patterns.push(...config.patterns.custom);
    }

    this.patternEngine = new PatternEngine(patterns);

    this.config = {
      timeoutMs: config?.performance?.timeoutMs ?? 5,
      maxSignals: config?.performance?.maxSignalsPerScan ?? 50,
      maxContentLength: config?.performance?.maxContentLength ?? 100_000,
      trustAdjustments: {
        untrusted: config?.trustAdjustments?.untrusted ?? 1.2,
        tool: config?.trustAdjustments?.tool ?? 1.0,
        user: config?.trustAdjustments?.user ?? 0.5,
        system: config?.trustAdjustments?.system ?? 0.1,
      },
    };
  }

  scan(content: string, context: ScanContext): Signal[] {
    // Skip system-trusted content (nearly zero risk)
    if (context.trustLevel === "system") {
      return [];
    }

    // Truncate if too long
    const toScan =
      content.length > this.config.maxContentLength
        ? content.slice(0, this.config.maxContentLength)
        : content;

    const signals: Signal[] = [];

    // Pattern-based scanning
    signals.push(...this.patternEngine.scan(toScan, context, this.config));

    // Repetition detection
    if (this.config.maxSignals > signals.length) {
      const repetitionSignal = detectRepetition(toScan, context);
      if (repetitionSignal) {
        signals.push(repetitionSignal);
      }
    }

    return signals;
  }

  scanWithResult(content: string, context: ScanContext): ScanResult {
    const startTime = Date.now();

    // Skip system-trusted content
    if (context.trustLevel === "system") {
      return {
        signals: [],
        truncated: false,
        timedOut: false,
        durationMs: Date.now() - startTime,
      };
    }

    const truncated = content.length > this.config.maxContentLength;
    const toScan = truncated
      ? content.slice(0, this.config.maxContentLength)
      : content;

    const signals = this.scan(toScan, context);
    const durationMs = Date.now() - startTime;

    return {
      signals,
      truncated,
      timedOut: durationMs >= this.config.timeoutMs,
      durationMs,
    };
  }
}

// ============================================================================
// Default Instance
// ============================================================================

let defaultScanner: SignalScanner | null = null;

export function getDefaultScanner(): SignalScanner {
  if (!defaultScanner) {
    defaultScanner = new SignalScanner();
  }
  return defaultScanner;
}

export function createScanner(config?: Partial<Layer4Config>): SignalScanner {
  return new SignalScanner(config);
}
