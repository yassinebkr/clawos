#!/usr/bin/env npx tsx
/**
 * OpenClaw Session Repair Tool
 * 
 * Repairs corrupted session JSONL files by removing orphaned tool_results.
 * This addresses the "unexpected tool_use_id" error that can brick sessions.
 * 
 * Usage:
 *   npx tsx repair-session.ts <session-file.jsonl>
 *   npx tsx repair-session.ts ~/.openclaw/agents/main/sessions/<uuid>.jsonl
 * 
 * Options:
 *   --dry-run    Show what would be fixed without modifying
 *   --backup     Create a backup before modifying (default: true)
 *   --no-backup  Skip backup creation
 */

import { readFileSync, writeFileSync, existsSync, copyFileSync } from 'node:fs';
import { basename, dirname, join } from 'node:path';

// ─── Types ───────────────────────────────────────────────────

interface ToolCall {
  type: 'toolCall';
  id: string;
  name: string;
  arguments: unknown;
}

interface ToolResult {
  type: 'toolResult';
  toolCallId: string;
  toolName: string;
  content: unknown[];
  isError: boolean;
}

interface MessageContent {
  type: string;
  id?: string;
  toolCallId?: string;
  [key: string]: unknown;
}

interface Message {
  role: string;
  content: MessageContent[];
}

interface SessionEntry {
  type: string;
  id?: string;
  parentId?: string | null;
  timestamp?: string;
  message?: Message | {
    role: string;
    content: unknown[];
    toolCallId?: string;
    toolName?: string;
  };
  [key: string]: unknown;
}

interface RepairAction {
  lineNumber: number;
  entryId: string;
  action: 'remove' | 'keep';
  reason: string;
  toolId?: string;
}

// ─── Parsing ─────────────────────────────────────────────────

function parseSessionFile(filePath: string): { entries: SessionEntry[]; lines: string[] } {
  const content = readFileSync(filePath, 'utf-8');
  const lines = content.trim().split('\n');
  const entries: SessionEntry[] = [];

  for (const line of lines) {
    if (!line.trim()) continue;
    try {
      entries.push(JSON.parse(line));
    } catch {
      console.warn(`Warning: Could not parse line: ${line.slice(0, 100)}...`);
    }
  }

  return { entries, lines };
}

// ─── Validation ──────────────────────────────────────────────

function findToolCalls(entry: SessionEntry): string[] {
  if (entry.type !== 'message') return [];
  const msg = entry.message;
  if (!msg || msg.role !== 'assistant') return [];
  if (!Array.isArray(msg.content)) return [];

  return msg.content
    .filter((c: MessageContent) => c.type === 'toolCall')
    .map((c: MessageContent) => c.id as string)
    .filter(Boolean);
}

function findToolResultIds(entry: SessionEntry): string[] {
  // Check if it's a toolResult message type
  if (entry.type === 'message' && entry.message?.role === 'toolResult') {
    const toolCallId = (entry.message as { toolCallId?: string }).toolCallId;
    return toolCallId ? [toolCallId] : [];
  }
  return [];
}

function validateSession(entries: SessionEntry[]): {
  valid: boolean;
  issues: RepairAction[];
} {
  const issues: RepairAction[] = [];
  
  // Build a map of valid tool call IDs from assistant messages
  const validToolCallIds = new Set<string>();
  
  // First pass: collect all tool call IDs from assistant messages
  for (let i = 0; i < entries.length; i++) {
    const entry = entries[i];
    const toolCalls = findToolCalls(entry);
    for (const id of toolCalls) {
      validToolCallIds.add(id);
    }
  }

  // Second pass: check that all tool results reference valid tool calls
  // and that each tool_result's preceding message contains the tool_use
  for (let i = 0; i < entries.length; i++) {
    const entry = entries[i];
    const toolResultIds = findToolResultIds(entry);

    for (const toolCallId of toolResultIds) {
      // Check if this tool call ID exists at all
      if (!validToolCallIds.has(toolCallId)) {
        issues.push({
          lineNumber: i + 1,
          entryId: entry.id || `line-${i}`,
          action: 'remove',
          reason: `Orphaned tool_result: ${toolCallId} has no matching tool_use in any assistant message`,
          toolId: toolCallId,
        });
        continue;
      }

      // Check if the immediately preceding assistant message has this tool call
      let foundValidPreceding = false;
      for (let j = i - 1; j >= 0; j--) {
        const prevEntry = entries[j];
        if (prevEntry.type === 'message') {
          if (prevEntry.message?.role === 'assistant') {
            const prevToolCalls = findToolCalls(prevEntry);
            if (prevToolCalls.includes(toolCallId)) {
              foundValidPreceding = true;
            }
            break; // Stop at first assistant message
          }
        }
      }

      if (!foundValidPreceding) {
        issues.push({
          lineNumber: i + 1,
          entryId: entry.id || `line-${i}`,
          action: 'remove',
          reason: `tool_result ${toolCallId} — matching tool_use not in immediately preceding assistant message`,
          toolId: toolCallId,
        });
      }
    }
  }

  return {
    valid: issues.length === 0,
    issues,
  };
}

// ─── Repair ──────────────────────────────────────────────────

function repairSession(
  entries: SessionEntry[],
  lines: string[],
  issues: RepairAction[],
): { repairedLines: string[]; removedCount: number } {
  const linesToRemove = new Set(issues.map(i => i.lineNumber - 1)); // Convert to 0-indexed
  
  const repairedLines = lines.filter((_, idx) => !linesToRemove.has(idx));
  
  return {
    repairedLines,
    removedCount: linesToRemove.size,
  };
}

// ─── Main ────────────────────────────────────────────────────

function main() {
  const args = process.argv.slice(2);
  
  if (args.length === 0 || args.includes('--help') || args.includes('-h')) {
    console.log(`
OpenClaw Session Repair Tool

Repairs corrupted session JSONL files by removing orphaned tool_results.

Usage:
  npx tsx repair-session.ts <session-file.jsonl> [options]

Options:
  --dry-run     Show what would be fixed without modifying
  --backup      Create a backup before modifying (default)
  --no-backup   Skip backup creation
  --help, -h    Show this help

Examples:
  # Check a session for issues (dry run)
  npx tsx repair-session.ts ~/.openclaw/agents/main/sessions/*.jsonl --dry-run

  # Repair current main session
  npx tsx repair-session.ts ~/.openclaw/agents/main/sessions/$(cat ~/.openclaw/agents/main/sessions/sessions.json | jq -r '."agent:main:main".sessionId').jsonl
`);
    process.exit(0);
  }

  const dryRun = args.includes('--dry-run');
  const noBackup = args.includes('--no-backup');
  const filePath = args.find(a => !a.startsWith('--'));

  if (!filePath) {
    console.error('Error: No session file specified');
    process.exit(1);
  }

  if (!existsSync(filePath)) {
    console.error(`Error: File not found: ${filePath}`);
    process.exit(1);
  }

  console.log(`\n🔍 Analyzing session: ${basename(filePath)}\n`);

  const { entries, lines } = parseSessionFile(filePath);
  console.log(`   Total entries: ${entries.length}`);
  console.log(`   Total lines: ${lines.length}`);

  const { valid, issues } = validateSession(entries);

  if (valid) {
    console.log('\n✅ Session is valid — no repairs needed\n');
    process.exit(0);
  }

  console.log(`\n⚠️  Found ${issues.length} issue(s):\n`);

  for (const issue of issues) {
    console.log(`   Line ${issue.lineNumber}: ${issue.reason}`);
    if (issue.toolId) {
      console.log(`      Tool ID: ${issue.toolId}`);
    }
  }

  if (dryRun) {
    console.log('\n🔬 Dry run — no changes made\n');
    process.exit(0);
  }

  // Create backup
  if (!noBackup) {
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const backupPath = `${filePath}.backup.${timestamp}`;
    copyFileSync(filePath, backupPath);
    console.log(`\n📦 Backup created: ${basename(backupPath)}`);
  }

  // Repair
  const { repairedLines, removedCount } = repairSession(entries, lines, issues);

  writeFileSync(filePath, repairedLines.join('\n') + '\n');

  console.log(`\n✅ Repaired session:`);
  console.log(`   Removed ${removedCount} corrupt entries`);
  console.log(`   New line count: ${repairedLines.length}`);
  console.log(`\n🔄 Restart OpenClaw gateway to apply changes\n`);
}

main();
