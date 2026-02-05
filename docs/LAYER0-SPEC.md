# Layer 0: Session Integrity — Specification

## Purpose

Layer 0 ensures that agent session state is always consistent, recoverable, and
resilient to mid-stream failures. It sits beneath all other ClawOS layers and
provides the foundation for reliable agent operation.

**Core guarantees:**
1. Tool call cycles are atomic (complete or rollback)
2. Session history is always API-valid
3. Corrupt state is detected and repairable
4. External failures don't corrupt persistent state

## Motivation: The 7-Hour Outage

See [CASE-STUDY-001](./CASE-STUDY-001.md) for the incident that motivated this layer.

**TL;DR:** A content filter blocked a response mid-tool-call, leaving an orphaned
`tool_result` in session history. Every subsequent API call failed validation,
making the agent unresponsive for 7+ hours until manual intervention.

## Architecture

```
┌────────────────────────────────────────────────────────────────┐
│                     Session Integrity                          │
├──────────────────┬──────────────────┬─────────────────────────┤
│   Validation     │   Checkpoints    │   Recovery              │
│                  │                  │                         │
│ • Message pairs  │ • Pre-operation  │ • Rollback to safe      │
│ • Tool use/result│   snapshots      │ • Repair orphans        │
│ • Provenance     │ • Atomic commits │ • Rebuild from source   │
│   consistency    │ • WAL-style log  │ • Graceful degradation  │
└──────────────────┴──────────────────┴─────────────────────────┘
```

## Core Concepts

### 1. Message Pair Validation

The Anthropic API requires strict message structure:
- Every `tool_result` must have a matching `tool_use` in the preceding assistant message
- Tool use IDs must match exactly
- Order must be preserved

Layer 0 validates this **before** sending to the API.

### 2. Checkpoints

Before any potentially-failing operation (tool execution, API call), create a
checkpoint. If the operation fails mid-stream, rollback to the checkpoint.

### 3. Atomic Tool Cycles

A tool cycle consists of:
1. Assistant generates `tool_use` block
2. Tool executes
3. `tool_result` is recorded

This entire cycle must be atomic:
- If any step fails, the entire cycle is rolled back
- Partial state (tool_use without tool_result, or vice versa) never persists

### 4. Recovery Modes

When corruption is detected, Layer 0 offers recovery options:
- **Repair**: Fix orphaned references by removing unpaired messages
- **Rollback**: Restore from the last valid checkpoint
- **Reset**: Clear session and start fresh (last resort)

## Message Types

Following Claude/Anthropic message format:

```typescript
interface Message {
  role: 'user' | 'assistant';
  content: MessageContent[];
}

type MessageContent =
  | TextContent
  | ToolUseContent
  | ToolResultContent;

interface ToolUseContent {
  type: 'tool_use';
  id: string;           // e.g., "toolu_01ABC..."
  name: string;
  input: unknown;
}

interface ToolResultContent {
  type: 'tool_result';
  tool_use_id: string;  // Must match a tool_use.id
  content: string;
  is_error?: boolean;
}
```

## Validation Rules

### Rule 1: Tool Result Must Have Tool Use

Every `tool_result` in a user message must reference a `tool_use` that exists
in the immediately preceding assistant message.

```typescript
function validateToolPairs(messages: Message[]): ValidationResult {
  for (let i = 0; i < messages.length; i++) {
    const msg = messages[i];
    if (msg.role !== 'user') continue;

    const toolResults = msg.content.filter(c => c.type === 'tool_result');
    if (toolResults.length === 0) continue;

    // Previous message must be assistant with matching tool_use blocks
    const prevMsg = messages[i - 1];
    if (!prevMsg || prevMsg.role !== 'assistant') {
      return { valid: false, error: 'tool_result without preceding assistant message' };
    }

    const toolUseIds = new Set(
      prevMsg.content
        .filter(c => c.type === 'tool_use')
        .map(c => c.id)
    );

    for (const result of toolResults) {
      if (!toolUseIds.has(result.tool_use_id)) {
        return {
          valid: false,
          error: `Orphaned tool_result: ${result.tool_use_id}`,
          orphanedIds: [result.tool_use_id],
        };
      }
    }
  }

  return { valid: true };
}
```

### Rule 2: Tool Use Must Have Tool Result

Every `tool_use` in an assistant message (except the last) must have a
corresponding `tool_result` in the following user message.

```typescript
function validateToolCompletion(messages: Message[]): ValidationResult {
  for (let i = 0; i < messages.length - 1; i++) {
    const msg = messages[i];
    if (msg.role !== 'assistant') continue;

    const toolUses = msg.content.filter(c => c.type === 'tool_use');
    if (toolUses.length === 0) continue;

    const nextMsg = messages[i + 1];
    if (!nextMsg || nextMsg.role !== 'user') {
      // Last message can have pending tool_use (current turn)
      if (i === messages.length - 1) continue;
      return { valid: false, error: 'tool_use without following user message' };
    }

    const resultIds = new Set(
      nextMsg.content
        .filter(c => c.type === 'tool_result')
        .map(c => c.tool_use_id)
    );

    for (const use of toolUses) {
      if (!resultIds.has(use.id)) {
        return {
          valid: false,
          error: `Incomplete tool_use: ${use.id}`,
          incompleteIds: [use.id],
        };
      }
    }
  }

  return { valid: true };
}
```

### Rule 3: No Duplicate Tool IDs

Tool use IDs must be unique within a session.

```typescript
function validateUniqueIds(messages: Message[]): ValidationResult {
  const seen = new Set<string>();

  for (const msg of messages) {
    for (const content of msg.content) {
      if (content.type === 'tool_use') {
        if (seen.has(content.id)) {
          return { valid: false, error: `Duplicate tool_use id: ${content.id}` };
        }
        seen.add(content.id);
      }
    }
  }

  return { valid: true };
}
```

## Checkpoint System

### Checkpoint Structure

```typescript
interface Checkpoint {
  /** Unique checkpoint ID */
  id: string;

  /** Session ID this checkpoint belongs to */
  sessionId: string;

  /** Timestamp of checkpoint creation */
  timestamp: number;

  /** Message index at checkpoint (exclusive — messages before this index) */
  messageIndex: number;

  /** Hash of messages for integrity verification */
  contentHash: string;

  /** What operation this checkpoint precedes */
  operation: 'tool_cycle' | 'compaction' | 'api_call' | 'manual';

  /** Optional: snapshot of messages (for fast rollback) */
  snapshot?: Message[];
}
```

### Checkpoint Lifecycle

```
1. CREATE CHECKPOINT
   ├── Record current message index
   ├── Hash current messages
   ├── Store checkpoint metadata
   └── Optionally snapshot messages

2. OPERATION BEGINS
   ├── Tool execution starts
   └── Or: API call initiated

3a. OPERATION SUCCEEDS
    ├── Checkpoint becomes "committed"
    ├── Old checkpoints can be pruned
    └── Continue normal operation

3b. OPERATION FAILS
    ├── Detect failure (content filter, API error, timeout)
    ├── ROLLBACK to checkpoint
    │   ├── Restore message index
    │   ├── Remove messages added since checkpoint
    │   └── Clear any partial state
    └── Surface error to user (not to API)
```

### Checkpoint Storage

```typescript
interface CheckpointStore {
  /** Create a new checkpoint */
  create(sessionId: string, operation: string): Promise<Checkpoint>;

  /** Commit a checkpoint (operation succeeded) */
  commit(checkpointId: string): Promise<void>;

  /** Rollback to a checkpoint (operation failed) */
  rollback(checkpointId: string): Promise<RollbackResult>;

  /** Get the latest valid checkpoint for a session */
  getLatest(sessionId: string): Promise<Checkpoint | undefined>;

  /** Prune old committed checkpoints */
  prune(sessionId: string, keepCount: number): Promise<number>;
}
```

## Atomic Tool Cycle

### The Problem

A tool cycle can fail at multiple points:
1. After `tool_use` is recorded, but before tool executes
2. During tool execution
3. After tool executes, but before `tool_result` is recorded
4. After `tool_result` is recorded, but before API acknowledges

Each failure point can leave inconsistent state.

### The Solution: Transaction Wrapper

```typescript
interface ToolCycleTransaction {
  /** Unique transaction ID */
  id: string;

  /** Associated checkpoint */
  checkpoint: Checkpoint;

  /** Tool use block that started this cycle */
  toolUse: ToolUseContent;

  /** Current state */
  state: 'pending' | 'executing' | 'recording' | 'committed' | 'rolled_back';
}

async function executeToolCycle(
  session: Session,
  toolUse: ToolUseContent,
  executor: ToolExecutor,
): Promise<ToolCycleResult> {
  // 1. Create checkpoint before the cycle
  const checkpoint = await session.checkpoint.create('tool_cycle');

  const txn: ToolCycleTransaction = {
    id: generateId(),
    checkpoint,
    toolUse,
    state: 'pending',
  };

  try {
    // 2. Record tool_use (but don't persist yet)
    txn.state = 'pending';

    // 3. Execute tool
    txn.state = 'executing';
    const result = await executor.execute(toolUse.name, toolUse.input);

    // 4. Record tool_result
    txn.state = 'recording';
    const toolResult: ToolResultContent = {
      type: 'tool_result',
      tool_use_id: toolUse.id,
      content: result.output,
      is_error: result.isError,
    };

    // 5. Persist both tool_use and tool_result atomically
    await session.persistToolCycle(toolUse, toolResult);

    // 6. Commit checkpoint
    txn.state = 'committed';
    await session.checkpoint.commit(checkpoint.id);

    return { success: true, result: toolResult };
  } catch (error) {
    // Rollback on any failure
    txn.state = 'rolled_back';
    await session.checkpoint.rollback(checkpoint.id);

    return {
      success: false,
      error: error instanceof Error ? error.message : String(error),
      rolledBack: true,
    };
  }
}
```

## Content Filter Handling

### Detection

Content filter blocks manifest as:
- Anthropic: `"error": { "type": "content_filtered" }` or HTTP 400 with specific message
- OpenAI: `"finish_reason": "content_filter"`

### Recovery

When a content filter is detected:

```typescript
async function handleContentFilter(
  session: Session,
  error: ContentFilterError,
): Promise<ContentFilterRecovery> {
  // 1. Get active checkpoint
  const checkpoint = await session.checkpoint.getLatest();

  if (!checkpoint) {
    // No checkpoint — session may be partially corrupt
    return {
      action: 'validate_and_repair',
      message: 'Content filtered with no checkpoint. Validating session state.',
    };
  }

  // 2. Rollback to checkpoint
  const rollbackResult = await session.checkpoint.rollback(checkpoint.id);

  // 3. Log incident
  await session.logIncident({
    type: 'content_filter',
    timestamp: Date.now(),
    checkpoint: checkpoint.id,
    rolledBack: rollbackResult.messagesRemoved,
  });

  return {
    action: 'rolled_back',
    message: `Content filter triggered. Rolled back ${rollbackResult.messagesRemoved} messages.`,
    checkpoint: checkpoint.id,
  };
}
```

## Recovery Operations

### Repair: Fix Orphaned References

```typescript
async function repairOrphans(messages: Message[]): Promise<RepairResult> {
  const repairs: RepairAction[] = [];

  // Pass 1: Find orphaned tool_results and remove them
  for (let i = messages.length - 1; i >= 0; i--) {
    const msg = messages[i];
    if (msg.role !== 'user') continue;

    const prevMsg = messages[i - 1];
    const validToolUseIds = new Set(
      prevMsg?.role === 'assistant'
        ? prevMsg.content.filter(c => c.type === 'tool_use').map(c => c.id)
        : []
    );

    msg.content = msg.content.filter(c => {
      if (c.type !== 'tool_result') return true;
      if (validToolUseIds.has(c.tool_use_id)) return true;

      repairs.push({
        action: 'remove_orphan',
        messageIndex: i,
        toolUseId: c.tool_use_id,
      });
      return false;
    });

    // If message is now empty, remove it
    if (msg.content.length === 0) {
      messages.splice(i, 1);
      repairs.push({ action: 'remove_empty_message', messageIndex: i });
    }
  }

  // Pass 2: Find incomplete tool_uses and remove them
  for (let i = 0; i < messages.length - 1; i++) {
    const msg = messages[i];
    if (msg.role !== 'assistant') continue;

    const nextMsg = messages[i + 1];
    const resultIds = new Set(
      nextMsg?.role === 'user'
        ? nextMsg.content.filter(c => c.type === 'tool_result').map(c => c.tool_use_id)
        : []
    );

    msg.content = msg.content.filter(c => {
      if (c.type !== 'tool_use') return true;
      if (resultIds.has(c.id)) return true;

      repairs.push({
        action: 'remove_incomplete',
        messageIndex: i,
        toolUseId: c.id,
      });
      return false;
    });
  }

  return {
    repaired: repairs.length > 0,
    repairs,
    messages,
  };
}
```

### Rollback: Restore from Checkpoint

```typescript
async function rollbackToCheckpoint(
  session: Session,
  checkpointId: string,
): Promise<RollbackResult> {
  const checkpoint = await session.checkpoint.get(checkpointId);
  if (!checkpoint) {
    throw new Error(`Checkpoint not found: ${checkpointId}`);
  }

  // Verify checkpoint integrity
  const currentHash = hashMessages(session.messages.slice(0, checkpoint.messageIndex));
  if (currentHash !== checkpoint.contentHash) {
    throw new Error('Checkpoint integrity mismatch — messages were modified');
  }

  // Truncate to checkpoint
  const removed = session.messages.length - checkpoint.messageIndex;
  session.messages.length = checkpoint.messageIndex;

  // Persist truncated state
  await session.persist();

  return {
    success: true,
    messagesRemoved: removed,
    newMessageCount: session.messages.length,
  };
}
```

### Reset: Clear and Start Fresh

```typescript
async function resetSession(
  session: Session,
  options: ResetOptions = {},
): Promise<ResetResult> {
  // Archive current state (for debugging)
  if (options.archive) {
    await session.archive();
  }

  // Clear all messages except system prompt
  const systemMessages = session.messages.filter(m =>
    m.role === 'user' && m.content.some(c => c.type === 'text' && c.isSystemPrompt)
  );

  session.messages = systemMessages;

  // Clear all checkpoints
  await session.checkpoint.clear();

  // Persist clean state
  await session.persist();

  return {
    success: true,
    archived: options.archive ?? false,
    remainingMessages: session.messages.length,
  };
}
```

## API

### Session Integrity Interface

```typescript
interface SessionIntegrity {
  /** Validate session state before API call */
  validate(session: Session): ValidationResult;

  /** Create a checkpoint before an operation */
  checkpoint(session: Session, operation: string): Promise<Checkpoint>;

  /** Execute a tool cycle atomically */
  executeToolCycle(
    session: Session,
    toolUse: ToolUseContent,
    executor: ToolExecutor,
  ): Promise<ToolCycleResult>;

  /** Handle content filter or API error */
  handleError(session: Session, error: Error): Promise<ErrorRecovery>;

  /** Repair corrupt session state */
  repair(session: Session): Promise<RepairResult>;

  /** Rollback to a checkpoint */
  rollback(session: Session, checkpointId: string): Promise<RollbackResult>;

  /** Reset session (last resort) */
  reset(session: Session, options?: ResetOptions): Promise<ResetResult>;
}
```

### Result Types

```typescript
interface ValidationResult {
  valid: boolean;
  error?: string;
  orphanedIds?: string[];
  incompleteIds?: string[];
}

interface ToolCycleResult {
  success: boolean;
  result?: ToolResultContent;
  error?: string;
  rolledBack?: boolean;
}

interface ErrorRecovery {
  action: 'rolled_back' | 'repaired' | 'reset' | 'escalate';
  message: string;
  checkpoint?: string;
  details?: Record<string, unknown>;
}

interface RepairResult {
  repaired: boolean;
  repairs: RepairAction[];
  messages: Message[];
}

interface RollbackResult {
  success: boolean;
  messagesRemoved: number;
  newMessageCount: number;
}
```

## Integration with OpenClaw

### Hook Points

Layer 0 integrates with OpenClaw at these points:

1. **Before API Call** (`before_agent_start`)
   - Validate session state
   - Create checkpoint
   - Reject if validation fails

2. **Tool Execution** (`before_tool_call` / `after_tool_call`)
   - Wrap in atomic transaction
   - Rollback on failure

3. **API Response** (`agent_end`)
   - Detect content filter
   - Handle partial responses
   - Commit or rollback checkpoint

4. **Session Load** (`session_start`)
   - Validate on load
   - Offer repair if corrupt

### Configuration

```typescript
interface Layer0Config {
  /** Enable session integrity checks */
  enabled: boolean;

  /** Validate before every API call */
  validateBeforeCall: boolean;

  /** Auto-repair on validation failure */
  autoRepair: boolean;

  /** Keep N committed checkpoints */
  checkpointRetention: number;

  /** Snapshot messages in checkpoints (uses more storage) */
  snapshotMessages: boolean;

  /** Log all integrity events */
  verbose: boolean;
}
```

## Performance Target

| Operation | Target | Approach |
|-----------|--------|----------|
| Validation | <5ms | In-memory scan, no I/O |
| Checkpoint create | <10ms | Async write, return immediately |
| Checkpoint commit | <5ms | Metadata update only |
| Rollback | <20ms | Truncate + persist |
| Repair | <50ms | In-memory transform + persist |

Total Layer 0 overhead: **<20ms p99** for normal operations.

## Test Cases

### Validation
1. Valid session with no tools → passes
2. Valid session with matched tool_use/tool_result → passes
3. Orphaned tool_result → fails, identifies orphan
4. Incomplete tool_use → fails, identifies incomplete
5. Duplicate tool IDs → fails

### Checkpoint/Rollback
6. Create checkpoint → checkpoint exists
7. Commit checkpoint → checkpoint marked committed
8. Rollback → messages truncated to checkpoint
9. Rollback with corrupted checkpoint → error

### Atomic Tool Cycle
10. Successful tool execution → tool_use and tool_result persisted
11. Tool execution fails → rollback, no partial state
12. Content filter during tool → rollback, clean state

### Recovery
13. Repair orphaned tool_result → removed
14. Repair incomplete tool_use → removed
15. Reset session → clean state, archived

### Integration
16. API call with valid session → proceeds
17. API call with corrupt session → blocked, repair offered
18. Content filter mid-stream → rollback, user notified
