/**
 * ClawOS Layer 4: Signal Detection — Type Definitions
 */

import type { TrustLevel } from "../tagging/types.js";

// ============================================================================
// Signal Categories
// ============================================================================

export type SignalCategory =
  | "injection" // Prompt injection attempts
  | "exfiltration" // Data exfil patterns
  | "encoding" // Obfuscation (base64, hex, etc.)
  | "roleplay" // Role/persona manipulation
  | "override" // System prompt override attempts
  | "repetition" // Unusual repetition (token stuffing)
  | "boundary" // Trust boundary violations
  | "anomaly"; // Statistical anomalies

// ============================================================================
// Signal Structure
// ============================================================================

export interface Signal {
  /** Unique signal ID */
  id: string;

  /** Detection timestamp */
  timestamp: number;

  /** Signal category */
  category: SignalCategory;

  /** Confidence level (0-1) */
  confidence: number;

  /** What matched */
  matched: {
    pattern: string;
    text: string;
    position: number;
  };

  /** Source context */
  source: {
    trustLevel: TrustLevel;
    contentType: string;
    sessionId?: string;
  };

  /** Additional context */
  context: Record<string, unknown>;
}

// ============================================================================
// Pattern Definitions
// ============================================================================

export interface PatternDefinition {
  /** Regex pattern */
  pattern: RegExp;

  /** Signal category */
  category: SignalCategory;

  /** Base weight/confidence (0-1) */
  weight: number;

  /** Optional context check for reducing false positives */
  contextCheck?: (text: string, match: RegExpExecArray) => boolean;

  /** Human-readable description */
  description?: string;
}

export interface CompiledPattern {
  regex: RegExp;
  category: SignalCategory;
  weight: number;
  contextCheck?: (text: string, match: RegExpExecArray) => boolean;
  description?: string;
}

// ============================================================================
// Scanner Interface
// ============================================================================

export interface ScanContext {
  /** Trust level of the content source */
  trustLevel: TrustLevel;

  /** Content type (text, code, structured, etc.) */
  contentType: string;

  /** Session ID for context */
  sessionId?: string;

  /** Previous signals in this session (for correlation) */
  priorSignals?: Signal[];
}

export interface Scanner {
  /** Unique scanner ID */
  id: string;

  /** Categories this scanner detects */
  categories: SignalCategory[];

  /** Scan content and return signals */
  scan(content: string, context: ScanContext): Signal[];
}

// ============================================================================
// Emitter Interface
// ============================================================================

export interface EmitterConfig {
  /** Send to L3 Runtime Security */
  toL3: boolean;

  /** Log to file */
  toLog: boolean;

  /** Log file path */
  logPath?: string;

  /** Emit metrics */
  toMetrics: boolean;

  /** Minimum confidence to emit */
  minConfidence: number;

  /** Categories to suppress */
  suppressCategories?: SignalCategory[];
}

export interface SignalEmitter {
  /** Emit signal to appropriate destinations */
  emit(signal: Signal): void;

  /** Batch emit */
  emitBatch(signals: Signal[]): void;

  /** Configure destinations */
  configure(config: Partial<EmitterConfig>): void;
}

// ============================================================================
// Configuration
// ============================================================================

export interface Layer4Config {
  /** Enable signal detection */
  enabled: boolean;

  /** Pattern sets to load */
  patterns: {
    injection: boolean;
    exfiltration: boolean;
    encoding: boolean;
    roleplay: boolean;
    repetition: boolean;
    custom?: PatternDefinition[];
  };

  /** Minimum confidence to emit signals */
  minConfidence: number;

  /** Trust level adjustments (multipliers) */
  trustAdjustments: {
    untrusted: number;
    tool: number;
    user: number;
    system: number;
  };

  /** Output destinations */
  emit: EmitterConfig;

  /** Performance tuning */
  performance: {
    maxContentLength: number;
    maxSignalsPerScan: number;
    timeoutMs: number;
  };
}

// ============================================================================
// Results
// ============================================================================

export interface ScanResult {
  /** Signals detected */
  signals: Signal[];

  /** Content was truncated */
  truncated: boolean;

  /** Scan timed out */
  timedOut: boolean;

  /** Time taken in ms */
  durationMs: number;
}
