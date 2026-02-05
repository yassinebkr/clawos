/**
 * ClawOS Layer 2: Capability Control
 *
 * Skills declare capabilities in manifests.
 * The policy engine enforces them based on trust + operator config.
 */

export type {
  Capability,
  RiskLevel,
  CapabilityDeclaration,
  ResourceLimits,
  SkillManifest,
  SkillOverride,
  OperatorPolicy,
  PermissionResult,
  EnforceResult,
  ResourceUsage,
  ExecutionContext,
  ValidationResult,
} from './types';

export {
  CAPABILITY_MIN_TRUST,
  CAPABILITY_RISK,
} from './types';

export {
  validateManifest,
  parseManifest,
  registerManifest,
  getManifest,
  clearManifestCache,
  listRegisteredSkills,
} from './manifest';

export {
  checkPermission,
  createContext,
  enforce,
  hasTimedOut,
  remainingTime,
} from './policy';
