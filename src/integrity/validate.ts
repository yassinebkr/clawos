/**
 * ClawOS Layer 0: Session Validation
 *
 * Validates message history for API compatibility and consistency.
 * Catches corrupt state before it reaches the API.
 */

import type {
  Message,
  MessageContent,
  ToolUseContent,
  ToolResultContent,
  IntegrityValidationResult,
  ValidationError,
} from './types';

// ─── Content Normalization ───────────────────────────────────

/**
 * Normalize message content to array format.
 * Handles both string content and array content.
 */
function normalizeContent(content: MessageContent[] | string | undefined): MessageContent[] {
  if (!content) return [];
  if (typeof content === 'string') {
    return [{ type: 'text', text: content }];
  }
  if (!Array.isArray(content)) return [];
  return content;
}

// ─── Content Type Guards ─────────────────────────────────────

export function isToolUse(content: MessageContent): content is ToolUseContent {
  return content.type === 'tool_use';
}

export function isToolResult(content: MessageContent): content is ToolResultContent {
  return content.type === 'tool_result';
}

// ─── Extract Tool IDs ────────────────────────────────────────

/**
 * Extract all tool_use IDs from an assistant message.
 */
export function getToolUseIds(message: Message): string[] {
  if (message.role !== 'assistant') return [];
  const content = normalizeContent(message.content as MessageContent[] | string);
  return content.filter(isToolUse).map((c) => c.id);
}

/**
 * Extract all tool_use_ids from tool_result blocks in a user message.
 */
export function getToolResultIds(message: Message): string[] {
  if (message.role !== 'user') return [];
  const content = normalizeContent(message.content as MessageContent[] | string);
  return content.filter(isToolResult).map((c) => c.tool_use_id);
}

// ─── Validation Functions ────────────────────────────────────

/**
 * Validate that every tool_result has a matching tool_use.
 *
 * Rule: Each tool_result in a user message must reference a tool_use.id
 * that exists in the immediately preceding assistant message.
 */
export function validateToolPairs(messages: Message[]): ValidationError[] {
  const errors: ValidationError[] = [];

  for (let i = 0; i < messages.length; i++) {
    const msg = messages[i];
    if (msg.role !== 'user') continue;

    const content = normalizeContent(msg.content as MessageContent[] | string);
    const toolResults = content.filter(isToolResult);
    if (toolResults.length === 0) continue;

    // Check that previous message exists and is assistant
    const prevMsg = messages[i - 1];
    if (!prevMsg || prevMsg.role !== 'assistant') {
      // No valid preceding assistant message — all tool_results are orphaned
      if (!prevMsg) {
        errors.push({
          type: 'missing_preceding_message',
          message: `Message ${i} has tool_result(s) but no preceding message`,
          messageIndex: i,
        });
      } else {
        errors.push({
          type: 'missing_preceding_message',
          message: `Message ${i} has tool_result(s) but preceding message is not assistant`,
          messageIndex: i,
        });
      }
      // Also report each tool_result as orphaned
      for (const result of toolResults) {
        errors.push({
          type: 'orphaned_tool_result',
          message: `Orphaned tool_result: ${result.tool_use_id} has no matching tool_use`,
          messageIndex: i,
          toolId: result.tool_use_id,
        });
      }
      continue;
    }

    // Get valid tool_use IDs from preceding assistant message
    const validToolUseIds = new Set(getToolUseIds(prevMsg));

    // Check each tool_result references a valid tool_use
    for (const result of toolResults) {
      if (!validToolUseIds.has(result.tool_use_id)) {
        errors.push({
          type: 'orphaned_tool_result',
          message: `Orphaned tool_result: ${result.tool_use_id} has no matching tool_use`,
          messageIndex: i,
          toolId: result.tool_use_id,
        });
      }
    }
  }

  return errors;
}

/**
 * Validate that every tool_use (except in the last message) has a tool_result.
 *
 * Rule: If an assistant message contains tool_use blocks, the following
 * user message must contain tool_result blocks for all of them.
 * Exception: The last assistant message may have pending tool_uses.
 */
export function validateToolCompletion(messages: Message[]): ValidationError[] {
  const errors: ValidationError[] = [];

  for (let i = 0; i < messages.length; i++) {
    const msg = messages[i];
    if (msg.role !== 'assistant') continue;

    const content = normalizeContent(msg.content as MessageContent[] | string);
    const toolUses = content.filter(isToolUse);
    if (toolUses.length === 0) continue;

    // If this is the last message, tool_uses are allowed to be pending
    if (i === messages.length - 1) continue;

    // Check that next message exists and is user
    const nextMsg = messages[i + 1];
    if (!nextMsg || nextMsg.role !== 'user') {
      // All tool_uses are incomplete
      for (const use of toolUses) {
        errors.push({
          type: 'incomplete_tool_use',
          message: `Incomplete tool_use: ${use.id} has no following tool_result`,
          messageIndex: i,
          toolId: use.id,
        });
      }
      continue;
    }

    // Get tool_result IDs from following user message
    const resultIds = new Set(getToolResultIds(nextMsg));

    // Check each tool_use has a result
    for (const use of toolUses) {
      if (!resultIds.has(use.id)) {
        errors.push({
          type: 'incomplete_tool_use',
          message: `Incomplete tool_use: ${use.id} has no following tool_result`,
          messageIndex: i,
          toolId: use.id,
        });
      }
    }
  }

  return errors;
}

/**
 * Validate that tool IDs are unique within the session.
 *
 * Rule: Each tool_use.id must appear exactly once in the entire history.
 */
export function validateUniqueIds(messages: Message[]): ValidationError[] {
  const errors: ValidationError[] = [];
  const seen = new Map<string, number>(); // toolId -> first messageIndex

  for (let i = 0; i < messages.length; i++) {
    const msg = messages[i];
    if (msg.role !== 'assistant') continue;

    for (const content of msg.content) {
      if (!isToolUse(content)) continue;

      const existing = seen.get(content.id);
      if (existing !== undefined) {
        errors.push({
          type: 'duplicate_tool_id',
          message: `Duplicate tool_use id: ${content.id} (first at message ${existing}, duplicate at ${i})`,
          messageIndex: i,
          toolId: content.id,
        });
      } else {
        seen.set(content.id, i);
      }
    }
  }

  return errors;
}

/**
 * Validate message structure (non-empty content, valid roles).
 */
export function validateStructure(messages: Message[]): ValidationError[] {
  const errors: ValidationError[] = [];

  for (let i = 0; i < messages.length; i++) {
    const msg = messages[i];

    // Check role is valid
    if (msg.role !== 'user' && msg.role !== 'assistant') {
      errors.push({
        type: 'invalid_structure',
        message: `Invalid role at message ${i}: ${msg.role}`,
        messageIndex: i,
      });
      continue;
    }

    // Check content exists and is non-empty (handles both string and array)
    const content = normalizeContent(msg.content as MessageContent[] | string);
    if (content.length === 0) {
      errors.push({
        type: 'empty_message',
        message: `Empty message at index ${i}`,
        messageIndex: i,
      });
    }
  }

  return errors;
}

// ─── Main Validation Function ────────────────────────────────

/**
 * Perform full validation of session messages.
 *
 * Checks:
 * 1. Message structure (valid roles, non-empty content)
 * 2. Tool pairs (every tool_result has matching tool_use)
 * 3. Tool completion (every tool_use has following tool_result, except last)
 * 4. Unique IDs (no duplicate tool_use.id)
 *
 * @returns IntegrityValidationResult with all errors found
 */
export function validate(messages: Message[]): IntegrityValidationResult {
  const allErrors: ValidationError[] = [];

  // Run all validations
  allErrors.push(...validateStructure(messages));
  allErrors.push(...validateToolPairs(messages));
  allErrors.push(...validateToolCompletion(messages));
  allErrors.push(...validateUniqueIds(messages));

  // Extract specific ID lists for convenience
  const orphanedIds = allErrors
    .filter((e) => e.type === 'orphaned_tool_result')
    .map((e) => e.toolId!)
    .filter(Boolean);

  const incompleteIds = allErrors
    .filter((e) => e.type === 'incomplete_tool_use')
    .map((e) => e.toolId!)
    .filter(Boolean);

  return {
    valid: allErrors.length === 0,
    errors: allErrors,
    orphanedIds,
    incompleteIds,
  };
}

/**
 * Quick check: is this session valid for an API call?
 * Faster than full validate() when you just need a boolean.
 */
export function isValid(messages: Message[]): boolean {
  // Check structure first (fast)
  for (const msg of messages) {
    if (msg.role !== 'user' && msg.role !== 'assistant') return false;
    const content = normalizeContent(msg.content as MessageContent[] | string);
    if (content.length === 0) return false;
  }

  // Check tool pairs
  for (let i = 0; i < messages.length; i++) {
    const msg = messages[i];
    if (msg.role !== 'user') continue;

    const content = normalizeContent(msg.content as MessageContent[] | string);
    const toolResults = content.filter(isToolResult);
    if (toolResults.length === 0) continue;

    const prevMsg = messages[i - 1];
    if (!prevMsg || prevMsg.role !== 'assistant') return false;

    const validIds = new Set(getToolUseIds(prevMsg));
    for (const result of toolResults) {
      if (!validIds.has(result.tool_use_id)) return false;
    }
  }

  // Check tool completion (except last message)
  for (let i = 0; i < messages.length - 1; i++) {
    const msg = messages[i];
    if (msg.role !== 'assistant') continue;

    const content = normalizeContent(msg.content as MessageContent[] | string);
    const toolUses = content.filter(isToolUse);
    if (toolUses.length === 0) continue;

    const nextMsg = messages[i + 1];
    if (!nextMsg || nextMsg.role !== 'user') return false;

    const resultIds = new Set(getToolResultIds(nextMsg));
    for (const use of toolUses) {
      if (!resultIds.has(use.id)) return false;
    }
  }

  // Check unique IDs
  const seen = new Set<string>();
  for (const msg of messages) {
    if (msg.role !== 'assistant') continue;
    const content = normalizeContent(msg.content as MessageContent[] | string);
    for (const c of content) {
      if (isToolUse(c)) {
        if (seen.has(c.id)) return false;
        seen.add(c.id);
      }
    }
  }

  return true;
}

/**
 * Format validation errors as a human-readable string.
 */
export function formatErrors(result: IntegrityValidationResult): string {
  if (result.valid) return 'Session is valid';

  const lines = ['Session validation failed:'];

  for (const error of result.errors) {
    const loc = error.messageIndex !== undefined ? ` [msg ${error.messageIndex}]` : '';
    const id = error.toolId ? ` (${error.toolId})` : '';
    lines.push(`  • ${error.type}${loc}${id}: ${error.message}`);
  }

  if (result.orphanedIds.length > 0) {
    lines.push(`  Orphaned tool_results: ${result.orphanedIds.join(', ')}`);
  }

  if (result.incompleteIds.length > 0) {
    lines.push(`  Incomplete tool_uses: ${result.incompleteIds.join(', ')}`);
  }

  return lines.join('\n');
}
