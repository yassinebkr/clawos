/**
 * ClawOS Layer 0: Checkpoint System
 *
 * Creates snapshots before risky operations, enabling rollback on failure.
 * Implements WAL-style checkpointing for session state.
 */

import { createHash, randomBytes } from 'node:crypto';
import type {
  Message,
  Checkpoint,
  CheckpointOperation,
  CheckpointState,
  CheckpointStore,
} from './types';

// ─── Hashing ─────────────────────────────────────────────────

/**
 * Generate a content hash for message array integrity verification.
 * Uses SHA-256 on JSON-serialized messages.
 */
export function hashMessages(messages: Message[]): string {
  const content = JSON.stringify(messages);
  return createHash('sha256').update(content).digest('hex').slice(0, 16);
}

/**
 * Generate a unique checkpoint ID.
 */
export function generateCheckpointId(): string {
  const timestamp = Date.now().toString(36);
  const random = randomBytes(4).toString('hex');
  return `ckpt_${timestamp}_${random}`;
}

// ─── In-Memory Checkpoint Store ──────────────────────────────

/**
 * Simple in-memory checkpoint store.
 * For production, replace with a persistent implementation.
 */
export class MemoryCheckpointStore implements CheckpointStore {
  private checkpoints = new Map<string, Checkpoint>();
  private bySession = new Map<string, string[]>(); // sessionId -> checkpointIds

  async create(
    sessionId: string,
    messages: Message[],
    operation: CheckpointOperation,
    options?: { snapshot?: boolean; meta?: Record<string, unknown> },
  ): Promise<Checkpoint> {
    const checkpoint: Checkpoint = {
      id: generateCheckpointId(),
      sessionId,
      timestamp: Date.now(),
      messageIndex: messages.length,
      contentHash: hashMessages(messages),
      operation,
      state: 'pending',
      ...(options?.snapshot ? { snapshot: [...messages] } : {}),
      ...(options?.meta ? { meta: options.meta } : {}),
    };

    this.checkpoints.set(checkpoint.id, checkpoint);

    // Track by session
    const sessionCheckpoints = this.bySession.get(sessionId) || [];
    sessionCheckpoints.push(checkpoint.id);
    this.bySession.set(sessionId, sessionCheckpoints);

    return checkpoint;
  }

  async get(checkpointId: string): Promise<Checkpoint | undefined> {
    return this.checkpoints.get(checkpointId);
  }

  async getLatest(sessionId: string): Promise<Checkpoint | undefined> {
    const ids = this.bySession.get(sessionId);
    if (!ids || ids.length === 0) return undefined;

    // Get the most recent pending or committed checkpoint
    for (let i = ids.length - 1; i >= 0; i--) {
      const ckpt = this.checkpoints.get(ids[i]);
      if (ckpt && (ckpt.state === 'pending' || ckpt.state === 'committed')) {
        return ckpt;
      }
    }

    return undefined;
  }

  async list(sessionId: string): Promise<Checkpoint[]> {
    const ids = this.bySession.get(sessionId) || [];
    return ids
      .map((id) => this.checkpoints.get(id))
      .filter((c): c is Checkpoint => c !== undefined);
  }

  async commit(checkpointId: string): Promise<void> {
    const ckpt = this.checkpoints.get(checkpointId);
    if (ckpt) {
      ckpt.state = 'committed';
    }
  }

  async markRolledBack(checkpointId: string): Promise<void> {
    const ckpt = this.checkpoints.get(checkpointId);
    if (ckpt) {
      ckpt.state = 'rolled_back';
    }
  }

  async prune(sessionId: string, keepCount: number): Promise<number> {
    const ids = this.bySession.get(sessionId);
    if (!ids || ids.length <= keepCount) return 0;

    // Keep only committed checkpoints for pruning decisions
    const committed = ids.filter((id) => {
      const ckpt = this.checkpoints.get(id);
      return ckpt?.state === 'committed';
    });

    // Prune oldest committed, keeping keepCount
    const toPrune = committed.slice(0, Math.max(0, committed.length - keepCount));

    for (const id of toPrune) {
      this.checkpoints.delete(id);
      const idx = ids.indexOf(id);
      if (idx >= 0) ids.splice(idx, 1);
    }

    return toPrune.length;
  }

  async clear(sessionId: string): Promise<number> {
    const ids = this.bySession.get(sessionId);
    if (!ids) return 0;

    const count = ids.length;
    for (const id of ids) {
      this.checkpoints.delete(id);
    }
    this.bySession.delete(sessionId);

    return count;
  }
}

// ─── Checkpoint Manager ──────────────────────────────────────

/**
 * High-level checkpoint management.
 * Wraps a CheckpointStore with convenience methods.
 */
export class CheckpointManager {
  constructor(
    private store: CheckpointStore,
    private options: { retention: number; snapshotMessages: boolean } = {
      retention: 5,
      snapshotMessages: false,
    },
  ) {}

  /**
   * Create a checkpoint before an operation.
   */
  async create(
    sessionId: string,
    messages: Message[],
    operation: CheckpointOperation,
    meta?: Record<string, unknown>,
  ): Promise<Checkpoint> {
    const checkpoint = await this.store.create(sessionId, messages, operation, {
      snapshot: this.options.snapshotMessages,
      meta,
    });

    // Auto-prune old checkpoints
    await this.store.prune(sessionId, this.options.retention);

    return checkpoint;
  }

  /**
   * Commit a checkpoint after successful operation.
   */
  async commit(checkpointId: string): Promise<void> {
    await this.store.commit(checkpointId);

    // Re-prune after commit since prune only considers committed checkpoints
    const checkpoint = await this.store.get(checkpointId);
    if (checkpoint) {
      await this.store.prune(checkpoint.sessionId, this.options.retention);
    }
  }

  /**
   * Get messages to rollback to from a checkpoint.
   *
   * @returns The messages that should replace the current session,
   *          or undefined if checkpoint has no snapshot and messages changed.
   */
  async getRestoreMessages(
    checkpointId: string,
    currentMessages: Message[],
  ): Promise<{ messages: Message[]; removed: number } | undefined> {
    const checkpoint = await this.store.get(checkpointId);
    if (!checkpoint) return undefined;

    // If we have a snapshot, use it
    if (checkpoint.snapshot) {
      return {
        messages: [...checkpoint.snapshot],
        removed: currentMessages.length - checkpoint.snapshot.length,
      };
    }

    // Otherwise, verify integrity and truncate
    const prefixHash = hashMessages(currentMessages.slice(0, checkpoint.messageIndex));
    if (prefixHash !== checkpoint.contentHash) {
      // Messages before checkpoint have changed — can't safely truncate
      return undefined;
    }

    return {
      messages: currentMessages.slice(0, checkpoint.messageIndex),
      removed: currentMessages.length - checkpoint.messageIndex,
    };
  }

  /**
   * Mark a checkpoint as rolled back.
   */
  async markRolledBack(checkpointId: string): Promise<void> {
    await this.store.markRolledBack(checkpointId);
  }

  /**
   * Get the latest usable checkpoint for a session.
   */
  async getLatest(sessionId: string): Promise<Checkpoint | undefined> {
    return this.store.getLatest(sessionId);
  }

  /**
   * List all checkpoints for a session.
   */
  async list(sessionId: string): Promise<Checkpoint[]> {
    return this.store.list(sessionId);
  }

  /**
   * Clear all checkpoints for a session.
   */
  async clear(sessionId: string): Promise<number> {
    return this.store.clear(sessionId);
  }
}

// ─── Factory ─────────────────────────────────────────────────

/**
 * Create a checkpoint manager with default in-memory store.
 */
export function createCheckpointManager(options?: {
  retention?: number;
  snapshotMessages?: boolean;
  store?: CheckpointStore;
}): CheckpointManager {
  const store = options?.store ?? new MemoryCheckpointStore();
  return new CheckpointManager(store, {
    retention: options?.retention ?? 5,
    snapshotMessages: options?.snapshotMessages ?? false,
  });
}
