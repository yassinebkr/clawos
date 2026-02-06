/**
 * ClawOS Integration Pipeline
 *
 * Wires all 6 layers together into a unified security pipeline.
 *
 * Data flow:
 *   Input → L1 (Tag) → L4 (Scan) → L2 (Permission) → L5 (Verify) → L3 (Execute) → Output
 *
 * L0 (Session Integrity) wraps the entire flow.
 */

import type { ContentTag, TaggedContent, ContentSource, TrustLevel } from "./tagging/types.js";
import type { Signal, ScanResult, ScanContext } from "./signals/types.js";
import type { PermissionResult, ExecutionContext, SkillManifest, OperatorPolicy } from "./capabilities/types.js";
import type { VerifyResult, TrustEntry } from "./registry/types.js";
import type { SandboxResult, SandboxConfig } from "./runtime/types.js";
import type { IntegrityValidationResult, Message } from "./integrity/types.js";

import { tag, createTag } from "./tagging/tag.js";
import { userSource, toolSource, skillSource, defaultTrustFor } from "./tagging/index.js";
import { TRUST_RANK } from "./tagging/types.js";
import { SignalScanner, createScanner } from "./signals/scanner.js";
import { checkPermission, createContext, enforce } from "./capabilities/policy.js";
import { registerManifest, getManifest, clearManifestCache } from "./capabilities/manifest.js";
import { createTrustRegistry, TrustRegistry } from "./registry/trust-registry.js";
import { execute, selectIsolationLevel } from "./runtime/index.js";
import { validate, createSessionIntegrity, SessionIntegrity } from "./integrity/index.js";

// ============================================================================
// Types
// ============================================================================

export interface PipelineConfig {
  /** Enable session integrity validation */
  integrity: boolean;
  /** Enable content tagging */
  tagging: boolean;
  /** Enable signal detection */
  signals: boolean;
  /** Enable capability checking */
  capabilities: boolean;
  /** Enable trust registry verification */
  registry: boolean;
  /** Enable sandboxed execution */
  sandbox: boolean;
  /** Block on high-severity signals (default: false, advisory only) */
  blockOnSignals: boolean;
  /** Minimum trust level for execution */
  minTrust: TrustLevel;
  /** Log all pipeline decisions */
  verbose: boolean;
}

export interface PipelineInput {
  /** The content/command to process */
  content: string;
  /** Source of the content */
  source: ContentSource;
  /** Skill requesting execution (if applicable) */
  skillId?: string;
  /** Capability being requested */
  capability?: string;
  /** Target resource (file path, URL, etc.) */
  target?: string;
  /** Session messages for integrity check */
  messages?: Message[];
  /** Additional context */
  metadata?: Record<string, unknown>;
}

export interface PipelineResult {
  /** Whether execution is allowed */
  allowed: boolean;
  /** Reason if blocked */
  reason?: string;
  /** Layer that blocked (if any) */
  blockedBy?: "integrity" | "signals" | "capabilities" | "registry" | "sandbox";
  /** Tagged content */
  tagged?: TaggedContent<string>;
  /** Signal scan results */
  signals?: ScanResult;
  /** Permission check result */
  permission?: PermissionResult;
  /** Trust verification result */
  trust?: VerifyResult;
  /** Execution result (if sandboxed) */
  execution?: SandboxResult;
  /** Timing info */
  timing: {
    total: number;
    integrity?: number;
    tagging?: number;
    signals?: number;
    capabilities?: number;
    registry?: number;
    sandbox?: number;
  };
}

export interface Pipeline {
  /** Process input through all enabled layers */
  process(input: PipelineInput): Promise<PipelineResult>;
  /** Validate session messages (L0 only) */
  validateSession(messages: Message[]): IntegrityValidationResult;
  /** Scan content for signals (L4 only) */
  scanContent(content: string, trustLevel?: TrustLevel): ScanResult;
  /** Check permission for a skill (L2 only) */
  checkCapability(skillId: string, inputTrust: TrustLevel): PermissionResult;
  /** Register a skill manifest */
  registerSkill(manifest: SkillManifest): void;
  /** Get current config */
  getConfig(): PipelineConfig;
}

// ============================================================================
// Default Config
// ============================================================================

export const DEFAULT_PIPELINE_CONFIG: PipelineConfig = {
  integrity: true,
  tagging: true,
  signals: true,
  capabilities: true,
  registry: true,
  sandbox: false, // Disabled by default (requires bwrap)
  blockOnSignals: false, // Advisory only by default
  minTrust: "untrusted",
  verbose: false,
};

// ============================================================================
// Pipeline Implementation
// ============================================================================

export function createPipeline(config: Partial<PipelineConfig> = {}): Pipeline {
  const cfg: PipelineConfig = { ...DEFAULT_PIPELINE_CONFIG, ...config };

  // Initialize components
  const integrity = createSessionIntegrity({ autoRepair: true });
  const scanner = createScanner();
  const registry = createTrustRegistry();
  const operatorPolicy: OperatorPolicy = {};

  const log = cfg.verbose
    ? (msg: string) => console.log(`[ClawOS] ${msg}`)
    : () => {};

  return {
    async process(input: PipelineInput): Promise<PipelineResult> {
      const startTime = Date.now();
      const timing: PipelineResult["timing"] = { total: 0 };

      // ====================================================================
      // Layer 0: Session Integrity
      // ====================================================================
      if (cfg.integrity && input.messages) {
        const t0 = Date.now();
        const validation = validate(input.messages);
        timing.integrity = Date.now() - t0;

        if (!validation.valid) {
          log(`L0: Session integrity failed - ${validation.errors.length} errors`);
          return {
            allowed: false,
            reason: `Session integrity check failed: ${validation.errors[0]?.message}`,
            blockedBy: "integrity",
            timing: { ...timing, total: Date.now() - startTime },
          };
        }
        log("L0: Session integrity OK");
      }

      // ====================================================================
      // Layer 1: Content Tagging
      // ====================================================================
      let tagged: TaggedContent<string> | undefined;
      let contentTag: ContentTag | undefined;

      if (cfg.tagging) {
        const t0 = Date.now();
        // Tag content with trust derived from source kind
        const sourceTrust = defaultTrustFor(input.source);
        tagged = tag(input.content, input.source, sourceTrust);
        contentTag = tagged.tag;
        timing.tagging = Date.now() - t0;

        const trustLevel = contentTag.trust;
        log(`L1: Tagged content, trust=${trustLevel}`);

        // Check minimum trust
        if (cfg.minTrust !== "untrusted") {
          if (TRUST_RANK[trustLevel] < TRUST_RANK[cfg.minTrust]) {
            return {
              allowed: false,
              reason: `Trust level ${trustLevel} below minimum ${cfg.minTrust}`,
              blockedBy: "capabilities",
              tagged,
              timing: { ...timing, total: Date.now() - startTime },
            };
          }
        }
      }

      // ====================================================================
      // Layer 4: Signal Detection
      // ====================================================================
      let signals: ScanResult | undefined;
      if (cfg.signals) {
        const t0 = Date.now();
        const trustLevel = contentTag?.trust || "untrusted";
        const scanContext: ScanContext = {
          trustLevel,
          contentType: "text",
          sessionId: undefined,
        };
        signals = scanner.scanWithResult(input.content, scanContext);
        timing.signals = Date.now() - t0;

        log(`L4: Scanned, ${signals.signals.length} signals found`);

        // Block on high-severity signals if configured
        if (cfg.blockOnSignals && signals.signals.length > 0) {
          const hasHighSeverity = signals.signals.some(
            (s) => s.confidence >= 0.8 && (s.category === "injection" || s.category === "exfiltration")
          );
          if (hasHighSeverity) {
            const critical = signals.signals.filter((s) => s.confidence >= 0.8);
            return {
              allowed: false,
              reason: `High severity signals detected: ${critical.map((s) => s.matched.pattern).join(", ")}`,
              blockedBy: "signals",
              tagged,
              signals,
              timing: { ...timing, total: Date.now() - startTime },
            };
          }
        }
      }

      // ====================================================================
      // Layer 2: Capability Control
      // ====================================================================
      let permission: PermissionResult | undefined;
      if (cfg.capabilities && input.skillId) {
        const t0 = Date.now();
        const manifest = getManifest(input.skillId);

        if (manifest && contentTag) {
          permission = checkPermission(manifest, contentTag, operatorPolicy);
          timing.capabilities = Date.now() - t0;

          log(`L2: Permission check = ${permission.allowed}`);

          if (!permission.allowed) {
            return {
              allowed: false,
              reason: permission.reasons.join("; ") || `Skill ${input.skillId} not allowed`,
              blockedBy: "capabilities",
              tagged,
              signals,
              permission,
              timing: { ...timing, total: Date.now() - startTime },
            };
          }
        } else {
          timing.capabilities = Date.now() - t0;
          log(`L2: No manifest for ${input.skillId}, skipping capability check`);
        }
      }

      // ====================================================================
      // Layer 5: Trust Registry
      // ====================================================================
      let trust: VerifyResult | undefined;
      if (cfg.registry && input.skillId) {
        const t0 = Date.now();
        const entry = await registry.getEntry(input.skillId);
        timing.registry = Date.now() - t0;

        if (entry) {
          log(`L5: Trust entry found, level=${entry.trustLevel}`);
          trust = { verified: true, entry };

          // Check for known vulnerabilities
          if (entry.vulnerabilities?.status === "vulnerable") {
            return {
              allowed: false,
              reason: `Skill has known vulnerabilities: ${entry.vulnerabilities.cves?.join(", ")}`,
              blockedBy: "registry",
              tagged,
              signals,
              permission,
              trust,
              timing: { ...timing, total: Date.now() - startTime },
            };
          }
        } else {
          log(`L5: No trust entry for ${input.skillId}`);
          trust = { verified: false, reason: "No trust entry found" };
        }
      }

      // ====================================================================
      // Layer 3: Runtime Security (Sandbox Execution)
      // ====================================================================
      let execution: SandboxResult | undefined;
      if (cfg.sandbox && input.content) {
        const t0 = Date.now();
        const level = selectIsolationLevel(contentTag);

        try {
          execution = await execute(["echo", input.content], {
            level,
            timeoutMs: 5000,
            memoryLimitMb: 128,
          });
          timing.sandbox = Date.now() - t0;
          log(`L3: Sandboxed execution, exitCode=${execution.exitCode}`);
        } catch (err) {
          timing.sandbox = Date.now() - t0;
          return {
            allowed: false,
            reason: `Sandbox execution failed: ${err}`,
            blockedBy: "sandbox",
            tagged,
            signals,
            permission,
            trust,
            timing: { ...timing, total: Date.now() - startTime },
          };
        }
      }

      // ====================================================================
      // All checks passed
      // ====================================================================
      timing.total = Date.now() - startTime;
      log(`Pipeline complete in ${timing.total}ms - ALLOWED`);

      return {
        allowed: true,
        tagged,
        signals,
        permission,
        trust,
        execution,
        timing,
      };
    },

    validateSession(messages: Message[]): IntegrityValidationResult {
      return validate(messages);
    },

    scanContent(content: string, trustLevel: TrustLevel = "untrusted"): ScanResult {
      const scanContext: ScanContext = {
        trustLevel,
        contentType: "text",
        sessionId: undefined,
      };
      return scanner.scanWithResult(content, scanContext);
    },

    checkCapability(skillId: string, inputTrust: TrustLevel): PermissionResult {
      const manifest = getManifest(skillId);
      if (!manifest) {
        return {
          allowed: false,
          granted: [],
          denied: [],
          reasons: [`Skill "${skillId}" not registered`],
          requiresApproval: [],
        };
      }
      const inputTag = createTag(userSource("system"), inputTrust);
      return checkPermission(manifest, inputTag, operatorPolicy);
    },

    registerSkill(manifest: SkillManifest): void {
      registerManifest(manifest);
    },

    getConfig(): PipelineConfig {
      return { ...cfg };
    },
  };
}

// ============================================================================
// Convenience Exports
// ============================================================================

/** Default pipeline instance */
let defaultPipeline: Pipeline | null = null;

export function getDefaultPipeline(): Pipeline {
  if (!defaultPipeline) {
    defaultPipeline = createPipeline();
  }
  return defaultPipeline;
}

/** Quick check: is this content safe to process? */
export async function isSafe(content: string, source: ContentSource): Promise<boolean> {
  const pipeline = getDefaultPipeline();
  const result = await pipeline.process({ content, source });
  return result.allowed;
}

/** Quick scan: get signals for content */
export function quickScan(content: string): Signal[] {
  const pipeline = getDefaultPipeline();
  return pipeline.scanContent(content).signals;
}

// Re-export for convenience
export { clearManifestCache } from "./capabilities/manifest.js";
