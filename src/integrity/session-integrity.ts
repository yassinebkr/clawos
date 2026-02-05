/**
 * ClawOS Layer 0: Session Integrity Controller
 *
 * Main entry point for session integrity. Provides:
 * - Pre-call validation
 * - Atomic tool cycle execution
 * - Content filter handling
 * - Recovery operations
 */

import type {
  Message,
  ToolUseContent,
  ToolResultContent,
  ToolCycleResult,
  ToolCycleTransaction,
  ContentFilterError,
  ErrorRecovery,
  RepairResult,
  RollbackResult,
  ResetResult,
  ResetOptions,
  SessionAdapter,
  IntegrityConfig,
  IntegrityIncident,
  Checkpoint,
  CheckpointStore,
  DEFAULT_CONFIG,
} from './types';
import { validate, isValid, formatErrors } from './validate';
import { CheckpointManager, MemoryCheckpointStore } from './checkpoint';
import { repair, repairCopy, reset, rollbackTo, formatRepairResult } from './repair';
import { randomBytes } from 'node:crypto';

// ─── Tool Executor Interface ─────────────────────────────────

/**
 * Interface for executing tools. Provided by the host system.
 */
export interface ToolExecutor {
  execute(
    toolName: string,
    input: unknown,
  ): Promise<{ output: string; isError?: boolean }>;
}

// ─── Session Integrity Controller ────────────────────────────

export class SessionIntegrity {
  private checkpointManager: CheckpointManager;
  private incidents: IntegrityIncident[] = [];
  private activeTransactions = new Map<string, ToolCycleTransaction>();

  constructor(
    private config: IntegrityConfig = {
      enabled: true,
      validateBeforeCall: true,
      autoRepair: false,
      checkpointRetention: 5,
      snapshotMessages: false,
      verbose: false,
    },
    checkpointStore?: CheckpointStore,
  ) {
    this.checkpointManager = new CheckpointManager(
      checkpointStore ?? new MemoryCheckpointStore(),
      {
        retention: config.checkpointRetention,
        snapshotMessages: config.snapshotMessages,
      },
    );
  }

  // ─── Validation ──────────────────────────────────────────────

  /**
   * Validate session state before an API call.
   *
   * @returns true if valid, throws if invalid (with details)
   */
  validateOrThrow(session: SessionAdapter): boolean {
    if (!this.config.enabled) return true;

    const result = validate(session.messages);

    if (!result.valid) {
      this.logIncident(session.sessionId, 'validation_failed', formatErrors(result), {
        errors: result.errors,
      });

      if (this.config.autoRepair) {
        const repairResult = this.repairSession(session);
        if (repairResult.repaired) {
          this.log(`Auto-repaired session: ${formatRepairResult(repairResult)}`);
          // Re-validate after repair
          const recheck = validate(session.messages);
          if (!recheck.valid) {
            throw new SessionIntegrityError(
              'Session validation failed after auto-repair',
              result,
            );
          }
          return true;
        }
      }

      throw new SessionIntegrityError('Session validation failed', result);
    }

    return true;
  }

  /**
   * Quick check if session is valid (no throw).
   */
  isSessionValid(session: SessionAdapter): boolean {
    if (!this.config.enabled) return true;
    return isValid(session.messages);
  }

  // ─── Checkpoints ─────────────────────────────────────────────

  /**
   * Create a checkpoint before a risky operation.
   */
  async createCheckpoint(
    session: SessionAdapter,
    operation: 'tool_cycle' | 'api_call' | 'compaction' | 'manual',
    meta?: Record<string, unknown>,
  ): Promise<Checkpoint> {
    const checkpoint = await this.checkpointManager.create(
      session.sessionId,
      session.messages,
      operation,
      meta,
    );

    this.logIncident(session.sessionId, 'checkpoint_created', `Created checkpoint: ${checkpoint.id}`, {
      operation,
      messageIndex: checkpoint.messageIndex,
    });

    return checkpoint;
  }

  /**
   * Commit a checkpoint after successful operation.
   */
  async commitCheckpoint(checkpointId: string, sessionId: string): Promise<void> {
    await this.checkpointManager.commit(checkpointId);
    this.logIncident(sessionId, 'checkpoint_committed', `Committed checkpoint: ${checkpointId}`);
  }

  /**
   * Get the latest checkpoint for a session.
   */
  async getLatestCheckpoint(sessionId: string): Promise<Checkpoint | undefined> {
    return this.checkpointManager.getLatest(sessionId);
  }

  // ─── Atomic Tool Cycle ───────────────────────────────────────

  /**
   * Execute a tool cycle atomically with rollback on failure.
   *
   * This wraps the entire tool_use → execution → tool_result cycle
   * in a transaction that can be rolled back if any step fails.
   */
  async executeToolCycle(
    session: SessionAdapter,
    toolUse: ToolUseContent,
    executor: ToolExecutor,
  ): Promise<ToolCycleResult> {
    if (!this.config.enabled) {
      // Bypass: just execute normally
      const result = await executor.execute(toolUse.name, toolUse.input);
      return {
        success: true,
        result: {
          type: 'tool_result',
          tool_use_id: toolUse.id,
          content: result.output,
          is_error: result.isError,
        },
      };
    }

    // Create checkpoint before the cycle
    const checkpoint = await this.createCheckpoint(session, 'tool_cycle', {
      toolUseId: toolUse.id,
      toolName: toolUse.name,
    });

    const txnId = this.generateTransactionId();
    const transaction: ToolCycleTransaction = {
      id: txnId,
      checkpoint,
      toolUse,
      state: 'pending',
      startTime: Date.now(),
    };

    this.activeTransactions.set(txnId, transaction);

    try {
      // Execute tool
      transaction.state = 'executing';
      const result = await executor.execute(toolUse.name, toolUse.input);

      // Record result
      transaction.state = 'recording';
      const toolResult: ToolResultContent = {
        type: 'tool_result',
        tool_use_id: toolUse.id,
        content: result.output,
        is_error: result.isError,
      };

      // Commit checkpoint
      transaction.state = 'committed';
      await this.commitCheckpoint(checkpoint.id, session.sessionId);

      this.activeTransactions.delete(txnId);

      return {
        success: true,
        result: toolResult,
        transaction,
      };
    } catch (error) {
      // Rollback on failure
      transaction.state = 'rolled_back';
      transaction.error = error instanceof Error ? error.message : String(error);

      await this.rollbackToCheckpoint(session, checkpoint.id);

      this.activeTransactions.delete(txnId);

      return {
        success: false,
        error: transaction.error,
        rolledBack: true,
        transaction,
      };
    }
  }

  // ─── Error Handling ──────────────────────────────────────────

  /**
   * Handle a content filter or API error.
   *
   * Attempts to recover by rolling back to the last checkpoint.
   */
  async handleError(
    session: SessionAdapter,
    error: Error | ContentFilterError,
  ): Promise<ErrorRecovery> {
    const isContentFilter = this.isContentFilterError(error);

    this.logIncident(
      session.sessionId,
      'content_filter',
      `Error during operation: ${error instanceof Error ? error.message : (error as ContentFilterError).message}`,
      { isContentFilter, error: error instanceof Error ? error.stack : error },
    );

    // Try to rollback to last checkpoint
    const checkpoint = await this.getLatestCheckpoint(session.sessionId);

    if (checkpoint) {
      const rollbackResult = await this.rollbackToCheckpoint(session, checkpoint.id);

      if (rollbackResult) {
        return {
          action: 'rolled_back',
          message: `Rolled back ${rollbackResult.messagesRemoved} messages to checkpoint ${checkpoint.id}`,
          checkpoint: checkpoint.id,
          details: {
            messagesRemoved: rollbackResult.messagesRemoved,
            newMessageCount: rollbackResult.newMessageCount,
          },
        };
      }
    }

    // No checkpoint — try repair
    const repairResult = this.repairSession(session);
    if (repairResult.repaired) {
      return {
        action: 'repaired',
        message: `Repaired session: ${repairResult.repairs.length} fixes applied`,
        details: {
          repairs: repairResult.repairs,
        },
      };
    }

    // Can't recover automatically
    return {
      action: 'escalate',
      message: 'Unable to recover automatically. Manual intervention required.',
      details: {
        hasCheckpoint: !!checkpoint,
        repairAttempted: true,
      },
    };
  }

  /**
   * Detect if an error is a content filter block.
   */
  private isContentFilterError(error: Error | ContentFilterError): boolean {
    if ('reason' in error) {
      return ['content_filtered', 'safety_filter'].includes(
        (error as ContentFilterError).reason,
      );
    }

    const message = error.message.toLowerCase();
    return (
      message.includes('content filter') ||
      message.includes('content_filtered') ||
      message.includes('safety') ||
      message.includes('blocked by')
    );
  }

  // ─── Recovery Operations ─────────────────────────────────────

  /**
   * Repair corrupt session state.
   */
  repairSession(session: SessionAdapter): RepairResult {
    const result = repair(session.messages);

    if (result.repaired) {
      this.logIncident(session.sessionId, 'repair', formatRepairResult(result), {
        repairs: result.repairs,
      });
    }

    return result;
  }

  /**
   * Repair without mutating (returns new messages array).
   */
  repairSessionCopy(session: SessionAdapter): RepairResult {
    return repairCopy(session.messages);
  }

  /**
   * Rollback to a specific checkpoint.
   */
  async rollbackToCheckpoint(
    session: SessionAdapter,
    checkpointId: string,
  ): Promise<RollbackResult | undefined> {
    const restoreData = await this.checkpointManager.getRestoreMessages(
      checkpointId,
      session.messages,
    );

    if (!restoreData) {
      this.log(`Cannot rollback to checkpoint ${checkpointId}: integrity mismatch or missing snapshot`);
      return undefined;
    }

    const result = await rollbackTo(session, restoreData.messages);

    const checkpoint = await this.checkpointManager.getLatest(session.sessionId);

    this.logIncident(session.sessionId, 'rollback', `Rolled back to checkpoint ${checkpointId}`, {
      messagesRemoved: result.messagesRemoved,
    });

    await this.checkpointManager.markRolledBack(checkpointId);

    return {
      success: true,
      messagesRemoved: result.messagesRemoved,
      newMessageCount: session.messages.length,
      checkpoint: checkpoint!,
    };
  }

  /**
   * Reset session to clean state.
   */
  async resetSession(
    session: SessionAdapter,
    options?: ResetOptions,
  ): Promise<ResetResult> {
    const result = await reset(session, options);

    // Clear checkpoints
    await this.checkpointManager.clear(session.sessionId);

    this.logIncident(session.sessionId, 'reset', `Session reset: ${options?.reason || 'manual'}`, {
      archived: result.archived,
      archivePath: result.archivePath,
    });

    return result;
  }

  // ─── Incident Logging ────────────────────────────────────────

  private logIncident(
    sessionId: string,
    type: IntegrityIncident['type'],
    message: string,
    details?: Record<string, unknown>,
  ): void {
    const incident: IntegrityIncident = {
      type,
      timestamp: Date.now(),
      sessionId,
      message,
      details,
    };

    this.incidents.push(incident);

    // Keep only recent incidents (prevent memory bloat)
    if (this.incidents.length > 1000) {
      this.incidents = this.incidents.slice(-500);
    }

    if (this.config.verbose) {
      this.log(`[${type}] ${message}`);
    }
  }

  /**
   * Get recent incidents for a session.
   */
  getIncidents(sessionId?: string, limit = 50): IntegrityIncident[] {
    let incidents = this.incidents;

    if (sessionId) {
      incidents = incidents.filter((i) => i.sessionId === sessionId);
    }

    return incidents.slice(-limit);
  }

  // ─── Utilities ───────────────────────────────────────────────

  private generateTransactionId(): string {
    return `txn_${Date.now().toString(36)}_${randomBytes(4).toString('hex')}`;
  }

  private log(message: string): void {
    if (this.config.verbose) {
      console.log(`[ClawOS:L0] ${message}`);
    }
  }

  /**
   * Get active tool cycle transactions.
   */
  getActiveTransactions(): ToolCycleTransaction[] {
    return Array.from(this.activeTransactions.values());
  }

  /**
   * Check if there are any pending tool cycles.
   */
  hasPendingToolCycles(): boolean {
    return this.activeTransactions.size > 0;
  }
}

// ─── Error Class ─────────────────────────────────────────────

export class SessionIntegrityError extends Error {
  constructor(
    message: string,
    public readonly validationResult: ReturnType<typeof validate>,
  ) {
    super(message);
    this.name = 'SessionIntegrityError';
  }
}

// ─── Factory ─────────────────────────────────────────────────

/**
 * Create a session integrity controller with default config.
 */
export function createSessionIntegrity(
  config?: Partial<IntegrityConfig>,
  checkpointStore?: CheckpointStore,
): SessionIntegrity {
  const fullConfig: IntegrityConfig = {
    enabled: true,
    validateBeforeCall: true,
    autoRepair: false,
    checkpointRetention: 5,
    snapshotMessages: false,
    verbose: false,
    ...config,
  };

  return new SessionIntegrity(fullConfig, checkpointStore);
}
