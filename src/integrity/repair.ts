/**
 * ClawOS Layer 0: Session Repair
 *
 * Fixes corrupt session state by removing orphaned references
 * and incomplete tool cycles.
 */

import type {
  Message,
  MessageContent,
  RepairAction,
  RepairResult,
  ResetOptions,
  ResetResult,
  SessionAdapter,
} from './types';
import { isToolUse, isToolResult, getToolUseIds, getToolResultIds } from './validate';

// ─── Repair Functions ────────────────────────────────────────

/**
 * Remove orphaned tool_results (tool_result without matching tool_use).
 *
 * Scans backward to handle cascading orphans correctly.
 */
function removeOrphanedToolResults(messages: Message[]): RepairAction[] {
  const repairs: RepairAction[] = [];

  // Scan backward so index shifts don't affect later iterations
  for (let i = messages.length - 1; i >= 0; i--) {
    const msg = messages[i];
    if (msg.role !== 'user') continue;

    const toolResults = msg.content.filter(isToolResult);
    if (toolResults.length === 0) continue;

    // Get valid tool_use IDs from preceding message
    const prevMsg = messages[i - 1];
    const validToolUseIds = new Set(
      prevMsg?.role === 'assistant' ? getToolUseIds(prevMsg) : [],
    );

    // Filter out orphaned tool_results
    const originalLength = msg.content.length;
    msg.content = msg.content.filter((content) => {
      if (!isToolResult(content)) return true;
      if (validToolUseIds.has(content.tool_use_id)) return true;

      repairs.push({
        action: 'remove_orphan',
        messageIndex: i,
        toolId: content.tool_use_id,
        description: `Removed orphaned tool_result: ${content.tool_use_id}`,
      });
      return false;
    });

    // If message is now empty, mark for removal
    if (msg.content.length === 0 && originalLength > 0) {
      repairs.push({
        action: 'remove_empty_message',
        messageIndex: i,
        description: 'Removed empty user message after orphan cleanup',
      });
    }
  }

  return repairs;
}

/**
 * Remove incomplete tool_uses (tool_use without following tool_result).
 *
 * Only removes from messages that are NOT the last assistant message
 * (last message may have pending tool calls).
 */
function removeIncompleteToolUses(messages: Message[]): RepairAction[] {
  const repairs: RepairAction[] = [];

  // Find the last assistant message index
  let lastAssistantIndex = -1;
  for (let i = messages.length - 1; i >= 0; i--) {
    if (messages[i].role === 'assistant') {
      lastAssistantIndex = i;
      break;
    }
  }

  // Scan backward
  for (let i = messages.length - 2; i >= 0; i--) {
    const msg = messages[i];
    if (msg.role !== 'assistant') continue;

    // Skip the last assistant message (pending tool calls are OK)
    if (i === lastAssistantIndex) continue;

    const toolUses = msg.content.filter(isToolUse);
    if (toolUses.length === 0) continue;

    // Get result IDs from following user message
    const nextMsg = messages[i + 1];
    const resultIds = new Set(
      nextMsg?.role === 'user' ? getToolResultIds(nextMsg) : [],
    );

    // Filter out incomplete tool_uses
    const originalLength = msg.content.length;
    msg.content = msg.content.filter((content) => {
      if (!isToolUse(content)) return true;
      if (resultIds.has(content.id)) return true;

      repairs.push({
        action: 'remove_incomplete',
        messageIndex: i,
        toolId: content.id,
        description: `Removed incomplete tool_use: ${content.id}`,
      });
      return false;
    });

    // If message is now empty, mark for removal
    if (msg.content.length === 0 && originalLength > 0) {
      repairs.push({
        action: 'remove_empty_message',
        messageIndex: i,
        description: 'Removed empty assistant message after incomplete cleanup',
      });
    }
  }

  return repairs;
}

/**
 * Remove duplicate tool IDs (keep the first occurrence).
 */
function removeDuplicateToolIds(messages: Message[]): RepairAction[] {
  const repairs: RepairAction[] = [];
  const seen = new Set<string>();

  for (let i = 0; i < messages.length; i++) {
    const msg = messages[i];
    if (msg.role !== 'assistant') continue;

    msg.content = msg.content.filter((content) => {
      if (!isToolUse(content)) return true;

      if (seen.has(content.id)) {
        repairs.push({
          action: 'remove_duplicate_id',
          messageIndex: i,
          toolId: content.id,
          description: `Removed duplicate tool_use: ${content.id}`,
        });
        return false;
      }

      seen.add(content.id);
      return true;
    });
  }

  return repairs;
}

/**
 * Remove empty messages from the array.
 * Called after other repairs may have emptied messages.
 */
function removeEmptyMessages(messages: Message[]): RepairAction[] {
  const repairs: RepairAction[] = [];

  for (let i = messages.length - 1; i >= 0; i--) {
    const msg = messages[i];
    if (!msg.content || msg.content.length === 0) {
      messages.splice(i, 1);
      repairs.push({
        action: 'remove_empty_message',
        messageIndex: i,
        description: `Removed empty ${msg.role} message`,
      });
    }
  }

  return repairs;
}

// ─── Main Repair Function ────────────────────────────────────

/**
 * Repair corrupt session messages.
 *
 * Performs the following repairs in order:
 * 1. Remove orphaned tool_results
 * 2. Remove incomplete tool_uses
 * 3. Remove duplicate tool IDs
 * 4. Remove empty messages
 *
 * @param messages - Messages to repair (mutated in place)
 * @returns RepairResult with actions taken
 */
export function repair(messages: Message[]): RepairResult {
  const originalCount = messages.length;
  const allRepairs: RepairAction[] = [];

  // Make a working copy to avoid mutation issues during iteration
  // (We'll apply changes to the original array at the end)

  // Pass 1: Remove orphaned tool_results
  allRepairs.push(...removeOrphanedToolResults(messages));

  // Pass 2: Remove incomplete tool_uses
  allRepairs.push(...removeIncompleteToolUses(messages));

  // Pass 3: Remove duplicate tool IDs
  allRepairs.push(...removeDuplicateToolIds(messages));

  // Pass 4: Remove empty messages (final cleanup)
  allRepairs.push(...removeEmptyMessages(messages));

  return {
    repaired: allRepairs.length > 0,
    repairs: allRepairs,
    messages,
    originalCount,
    newCount: messages.length,
  };
}

/**
 * Create a repaired copy of messages without mutating the original.
 */
export function repairCopy(messages: Message[]): RepairResult {
  // Deep clone messages
  const copy: Message[] = JSON.parse(JSON.stringify(messages));
  return repair(copy);
}

// ─── Reset Function ──────────────────────────────────────────

/**
 * Reset a session to a clean state.
 *
 * Options:
 * - archive: Save current state before reset
 * - keepSystemMessages: Preserve system-level messages
 * - reason: Logged reason for reset
 */
export async function reset(
  session: SessionAdapter,
  options: ResetOptions = {},
): Promise<ResetResult> {
  const { archive = false, keepSystemMessages = false, reason } = options;

  let archivePath: string | undefined;

  // Archive if requested
  if (archive) {
    archivePath = await session.archive();
  }

  // Determine what to keep
  let remainingMessages: Message[];

  if (keepSystemMessages) {
    // Keep only messages that look like system prompts
    // (This is a heuristic — adjust based on your system)
    remainingMessages = session.messages.filter((msg) => {
      if (msg.role !== 'user') return false;
      // Check for system-like content
      return msg.content.some(
        (c) => c.type === 'text' && 'text' in c && isSystemPromptLike(c.text),
      );
    });
  } else {
    remainingMessages = [];
  }

  // Apply reset
  session.messages.length = 0;
  session.messages.push(...remainingMessages);

  // Persist
  await session.persist();

  return {
    success: true,
    archived: archive,
    archivePath,
    remainingMessages: session.messages.length,
  };
}

/**
 * Heuristic to detect system prompt-like messages.
 * Adjust patterns based on your system's conventions.
 */
function isSystemPromptLike(text: string): boolean {
  const patterns = [
    /^you are/i,
    /^system:/i,
    /^instructions:/i,
    /^<system>/i,
    /^\[system\]/i,
  ];
  return patterns.some((p) => p.test(text.trim()));
}

// ─── Rollback Helper ─────────────────────────────────────────

/**
 * Rollback session to a specific message count.
 * Used by the checkpoint system.
 */
export async function rollbackTo(
  session: SessionAdapter,
  targetMessages: Message[],
): Promise<{ messagesRemoved: number }> {
  const removed = session.messages.length - targetMessages.length;

  // Replace messages
  session.messages.length = 0;
  session.messages.push(...targetMessages);

  // Persist
  await session.persist();

  return { messagesRemoved: removed };
}

// ─── Utility ─────────────────────────────────────────────────

/**
 * Format repair result as a human-readable string.
 */
export function formatRepairResult(result: RepairResult): string {
  if (!result.repaired) {
    return 'No repairs needed';
  }

  const lines = [
    `Repaired session: ${result.originalCount} → ${result.newCount} messages`,
    `Actions taken (${result.repairs.length}):`,
  ];

  for (const action of result.repairs) {
    const loc = `[msg ${action.messageIndex}]`;
    const id = action.toolId ? ` (${action.toolId})` : '';
    lines.push(`  • ${action.action}${loc}${id}: ${action.description || ''}`);
  }

  return lines.join('\n');
}
