/**
 * ClawOS Layer 0: Session Integrity — Type Definitions
 *
 * Ensures session state is always consistent, recoverable, and resilient
 * to mid-stream failures (content filters, API errors, timeouts).
 */

// ─── Message Types (Claude/Anthropic Format) ─────────────────

export type MessageRole = 'user' | 'assistant';

export interface TextContent {
  type: 'text';
  text: string;
}

export interface ToolUseContent {
  type: 'tool_use';
  /** Unique tool call ID (e.g., "toolu_01ABC...") */
  id: string;
  /** Tool name */
  name: string;
  /** Tool input parameters */
  input: unknown;
}

export interface ToolResultContent {
  type: 'tool_result';
  /** Must match a tool_use.id in the preceding assistant message */
  tool_use_id: string;
  /** Result content (string or structured) */
  content: string | Array<{ type: 'text'; text: string }>;
  /** Whether the tool execution errored */
  is_error?: boolean;
}

export type MessageContent = TextContent | ToolUseContent | ToolResultContent;

export interface Message {
  role: MessageRole;
  content: MessageContent[];
}

// ─── Validation ──────────────────────────────────────────────

export type ValidationErrorType =
  | 'orphaned_tool_result'     // tool_result without matching tool_use
  | 'incomplete_tool_use'      // tool_use without following tool_result
  | 'duplicate_tool_id'        // same tool ID used multiple times
  | 'missing_preceding_message'// tool_result without preceding assistant message
  | 'empty_message'            // message with no content
  | 'invalid_structure';       // malformed message structure

export interface ValidationError {
  type: ValidationErrorType;
  message: string;
  messageIndex?: number;
  toolId?: string;
}

export interface IntegrityValidationResult {
  valid: boolean;
  errors: ValidationError[];
  /** Tool IDs that are orphaned (tool_result without tool_use) */
  orphanedIds: string[];
  /** Tool IDs that are incomplete (tool_use without tool_result) */
  incompleteIds: string[];
}

// ─── Checkpoints ─────────────────────────────────────────────

export type CheckpointOperation =
  | 'tool_cycle'
  | 'api_call'
  | 'compaction'
  | 'manual';

export type CheckpointState =
  | 'pending'
  | 'committed'
  | 'rolled_back'
  | 'expired';

export interface Checkpoint {
  /** Unique checkpoint ID */
  id: string;
  /** Session this checkpoint belongs to */
  sessionId: string;
  /** When created */
  timestamp: number;
  /** Message index at checkpoint (messages before this are "safe") */
  messageIndex: number;
  /** SHA-256 hash of messages[0..messageIndex] for integrity */
  contentHash: string;
  /** What operation this checkpoint precedes */
  operation: CheckpointOperation;
  /** Current state */
  state: CheckpointState;
  /** Optional: full message snapshot for fast rollback */
  snapshot?: Message[];
  /** Optional: metadata about the operation */
  meta?: Record<string, unknown>;
}

export interface CheckpointStore {
  /** Create a new checkpoint */
  create(
    sessionId: string,
    messages: Message[],
    operation: CheckpointOperation,
    options?: { snapshot?: boolean; meta?: Record<string, unknown> },
  ): Promise<Checkpoint>;

  /** Get a checkpoint by ID */
  get(checkpointId: string): Promise<Checkpoint | undefined>;

  /** Get the latest checkpoint for a session */
  getLatest(sessionId: string): Promise<Checkpoint | undefined>;

  /** List all checkpoints for a session */
  list(sessionId: string): Promise<Checkpoint[]>;

  /** Commit a checkpoint (operation succeeded) */
  commit(checkpointId: string): Promise<void>;

  /** Mark a checkpoint as rolled back */
  markRolledBack(checkpointId: string): Promise<void>;

  /** Prune old committed checkpoints, keeping N most recent */
  prune(sessionId: string, keepCount: number): Promise<number>;

  /** Clear all checkpoints for a session */
  clear(sessionId: string): Promise<number>;
}

// ─── Tool Cycle Transaction ──────────────────────────────────

export type ToolCycleState =
  | 'pending'      // Checkpoint created, tool_use recorded
  | 'executing'    // Tool is running
  | 'recording'    // Tool finished, recording result
  | 'committed'    // Cycle complete, persisted
  | 'rolled_back'; // Cycle failed, rolled back

export interface ToolCycleTransaction {
  /** Unique transaction ID */
  id: string;
  /** Associated checkpoint */
  checkpoint: Checkpoint;
  /** Tool use that started this cycle */
  toolUse: ToolUseContent;
  /** Current state */
  state: ToolCycleState;
  /** When the cycle started */
  startTime: number;
  /** Error if failed */
  error?: string;
}

export interface ToolCycleResult {
  success: boolean;
  /** The tool result (if successful) */
  result?: ToolResultContent;
  /** Error message (if failed) */
  error?: string;
  /** Whether a rollback occurred */
  rolledBack?: boolean;
  /** Transaction details */
  transaction?: ToolCycleTransaction;
}

// ─── Content Filter Handling ─────────────────────────────────

export type ContentFilterReason =
  | 'content_filtered'    // Anthropic content filter
  | 'safety_filter'       // OpenAI safety filter
  | 'rate_limited'        // May look like filter in some cases
  | 'unknown';

export interface ContentFilterError {
  reason: ContentFilterReason;
  message: string;
  /** Provider-specific error details */
  providerError?: unknown;
  /** Was this mid-tool-cycle? */
  duringToolCycle?: boolean;
}

export type RecoveryAction =
  | 'rolled_back'       // Rolled back to checkpoint
  | 'repaired'          // Fixed orphaned references
  | 'reset'             // Session was reset
  | 'escalate';         // Needs manual intervention

export interface ErrorRecovery {
  action: RecoveryAction;
  message: string;
  /** Checkpoint that was rolled back to */
  checkpoint?: string;
  /** Details about what was done */
  details?: Record<string, unknown>;
}

// ─── Repair Operations ───────────────────────────────────────

export type RepairActionType =
  | 'remove_orphan'           // Removed orphaned tool_result
  | 'remove_incomplete'       // Removed incomplete tool_use
  | 'remove_empty_message'    // Removed message with no content
  | 'remove_duplicate_id';    // Removed duplicate tool ID

export interface RepairAction {
  action: RepairActionType;
  messageIndex: number;
  toolId?: string;
  description?: string;
}

export interface RepairResult {
  repaired: boolean;
  /** Actions taken */
  repairs: RepairAction[];
  /** Resulting messages after repair */
  messages: Message[];
  /** Original message count */
  originalCount: number;
  /** New message count */
  newCount: number;
}

// ─── Rollback ────────────────────────────────────────────────

export interface RollbackResult {
  success: boolean;
  /** Number of messages removed */
  messagesRemoved: number;
  /** New message count */
  newMessageCount: number;
  /** Checkpoint that was restored */
  checkpoint: Checkpoint;
}

// ─── Reset ───────────────────────────────────────────────────

export interface ResetOptions {
  /** Archive the session before reset */
  archive?: boolean;
  /** Reason for reset (logged) */
  reason?: string;
  /** Keep system messages */
  keepSystemMessages?: boolean;
}

export interface ResetResult {
  success: boolean;
  /** Whether session was archived */
  archived: boolean;
  /** Archive path (if archived) */
  archivePath?: string;
  /** Messages remaining after reset */
  remainingMessages: number;
}

// ─── Session Interface ───────────────────────────────────────

/**
 * Minimal session interface that Layer 0 operates on.
 * This is what Layer 0 expects from the host system (e.g., OpenClaw).
 */
export interface SessionAdapter {
  /** Unique session identifier */
  readonly sessionId: string;

  /** Current messages in the session */
  messages: Message[];

  /** Persist current message state */
  persist(): Promise<void>;

  /** Archive session to a backup location */
  archive(): Promise<string>;

  /** Truncate messages to a specific index */
  truncate(index: number): void;
}

// ─── Configuration ───────────────────────────────────────────

export interface IntegrityConfig {
  /** Enable integrity checks (default: true) */
  enabled: boolean;

  /** Validate before every API call (default: true) */
  validateBeforeCall: boolean;

  /** Attempt auto-repair on validation failure (default: false) */
  autoRepair: boolean;

  /** Number of committed checkpoints to retain (default: 5) */
  checkpointRetention: number;

  /** Store full message snapshots in checkpoints (default: false) */
  snapshotMessages: boolean;

  /** Log all integrity events (default: false) */
  verbose: boolean;
}

export const DEFAULT_CONFIG: IntegrityConfig = {
  enabled: true,
  validateBeforeCall: true,
  autoRepair: false,
  checkpointRetention: 5,
  snapshotMessages: false,
  verbose: false,
};

// ─── Incidents ───────────────────────────────────────────────

export type IncidentType =
  | 'validation_failed'
  | 'content_filter'
  | 'checkpoint_created'
  | 'checkpoint_committed'
  | 'rollback'
  | 'repair'
  | 'reset';

export interface IntegrityIncident {
  type: IncidentType;
  timestamp: number;
  sessionId: string;
  message: string;
  details?: Record<string, unknown>;
}
