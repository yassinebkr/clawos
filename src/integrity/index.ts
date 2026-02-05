/**
 * ClawOS Layer 0: Session Integrity
 *
 * Foundation layer that ensures session state is always consistent,
 * recoverable, and resilient to mid-stream failures.
 *
 * Key features:
 * - Pre-call validation (catches corrupt state before API calls)
 * - Checkpoint system (snapshot state before risky operations)
 * - Atomic tool cycles (complete or rollback, no partial state)
 * - Content filter handling (graceful recovery from blocks)
 * - Repair operations (fix orphaned references automatically)
 *
 * @example
 * ```typescript
 * import { createSessionIntegrity, SessionAdapter } from 'clawos/integrity';
 *
 * const integrity = createSessionIntegrity({ autoRepair: true });
 *
 * // Before API call
 * integrity.validateOrThrow(session);
 *
 * // Atomic tool execution
 * const result = await integrity.executeToolCycle(session, toolUse, executor);
 *
 * // Handle errors
 * const recovery = await integrity.handleError(session, error);
 * ```
 */

// Types
export type {
  // Message types
  MessageRole,
  TextContent,
  ToolUseContent,
  ToolResultContent,
  MessageContent,
  Message,

  // Validation
  ValidationErrorType,
  ValidationError,
  IntegrityValidationResult,

  // Checkpoints
  CheckpointOperation,
  CheckpointState,
  Checkpoint,
  CheckpointStore,

  // Tool cycles
  ToolCycleState,
  ToolCycleTransaction,
  ToolCycleResult,

  // Error handling
  ContentFilterReason,
  ContentFilterError,
  RecoveryAction,
  ErrorRecovery,

  // Repair
  RepairActionType,
  RepairAction,
  RepairResult,

  // Rollback/Reset
  RollbackResult,
  ResetOptions,
  ResetResult,

  // Session adapter
  SessionAdapter,

  // Config
  IntegrityConfig,
  IntegrityIncident,
} from './types';

export { DEFAULT_CONFIG } from './types';

// Validation
export {
  validate,
  isValid,
  formatErrors,
  isToolUse,
  isToolResult,
  getToolUseIds,
  getToolResultIds,
  validateToolPairs,
  validateToolCompletion,
  validateUniqueIds,
  validateStructure,
} from './validate';

// Checkpoints
export {
  hashMessages,
  generateCheckpointId,
  MemoryCheckpointStore,
  CheckpointManager,
  createCheckpointManager,
} from './checkpoint';

// Repair
export {
  repair,
  repairCopy,
  reset,
  rollbackTo,
  formatRepairResult,
} from './repair';

// Main controller
export {
  SessionIntegrity,
  SessionIntegrityError,
  createSessionIntegrity,
  type ToolExecutor,
} from './session-integrity';
