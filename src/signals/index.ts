/**
 * ClawOS Layer 4: Signal Detection
 *
 * Detects suspicious patterns in content that might indicate prompt injection,
 * data exfiltration attempts, or other adversarial behavior. Advisory-only —
 * produces signals that inform other layers but does not block content.
 *
 * @module
 */

// Types
export type {
  Signal,
  SignalCategory,
  ScanContext,
  ScanResult,
  Scanner,
  PatternDefinition,
  CompiledPattern,
  SignalEmitter,
  EmitterConfig,
  Layer4Config,
} from "./types.js";

// Patterns
export {
  INJECTION_PATTERNS,
  EXFILTRATION_PATTERNS,
  ENCODING_PATTERNS,
  ROLEPLAY_PATTERNS,
  SELF_MODIFICATION_PATTERNS,
  ALL_PATTERNS,
  PATTERNS_BY_CATEGORY,
} from "./patterns.js";

// Scanner
export {
  PatternEngine,
  SignalScanner,
  detectRepetition,
  getDefaultScanner,
  createScanner,
} from "./scanner.js";

// Emitter
export {
  DefaultSignalEmitter,
  SignalStore,
  getDefaultEmitter,
  getDefaultStore,
  type L3Monitor,
} from "./emitter.js";

// Main Service
export {
  SignalDetection,
  getSignalDetection,
  createSignalDetection,
  scanForSignals,
  hasInjectionSignals,
  hasExfiltrationSignals,
  type SignalSummary,
} from "./signal-detection.js";
