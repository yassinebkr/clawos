/**
 * ClawOS Layer 1: Predefined Content Sources
 *
 * Common source factories for typical agent system entities.
 * Use these instead of creating ContentSource objects manually.
 */

import type { ContentSource, TrustLevel } from './types';

// ─── System Sources ──────────────────────────────────────────

/** OpenClaw platform internals */
export const SYSTEM_OPENCLAW: ContentSource = {
  kind: 'system',
  id: 'openclaw',
  label: 'OpenClaw Platform',
};

/** System prompt source */
export const SYSTEM_PROMPT: ContentSource = {
  kind: 'system',
  id: 'system-prompt',
  label: 'System Prompt',
};

/** ClawOS security layer itself */
export const SYSTEM_CLAWOS: ContentSource = {
  kind: 'system',
  id: 'clawos',
  label: 'ClawOS Security',
};

/** Heartbeat / scheduler */
export const SYSTEM_HEARTBEAT: ContentSource = {
  kind: 'system',
  id: 'heartbeat',
  label: 'Heartbeat',
};

/** Cron job */
export const SYSTEM_CRON: ContentSource = {
  kind: 'system',
  id: 'cron',
  label: 'Cron Scheduler',
};

// ─── Source Factories ────────────────────────────────────────

/** Create a user source from phone number or ID */
export function userSource(id: string, label?: string): ContentSource {
  return { kind: 'user', id, label: label || `User ${id}` };
}

/** Create a tool source */
export function toolSource(toolName: string, label?: string): ContentSource {
  return { kind: 'tool', id: toolName, label: label || toolName };
}

/** Create a skill source */
export function skillSource(skillName: string, label?: string): ContentSource {
  return { kind: 'tool', id: `skill:${skillName}`, label: label || `Skill: ${skillName}` };
}

/** Create an agent source */
export function agentSource(agentId: string, label?: string): ContentSource {
  return { kind: 'agent', id: agentId, label: label || `Agent ${agentId}` };
}

/** Create an external source (web, API, MCP server, etc.) */
export function externalSource(id: string, label?: string): ContentSource {
  return { kind: 'external', id, label: label || id };
}

/** Create an MCP server source */
export function mcpSource(serverName: string, label?: string): ContentSource {
  return { kind: 'external', id: `mcp:${serverName}`, label: label || `MCP: ${serverName}` };
}

// ─── Default Trust Mapping ───────────────────────────────────

/** Default trust level for each source kind */
export const DEFAULT_TRUST: Record<ContentSource['kind'], TrustLevel> = {
  system: 'system',
  user: 'user',
  tool: 'tool',
  agent: 'tool',       // Agent output is tool-level (derived from inputs)
  external: 'untrusted', // External sources are untrusted by default
};

/** Get default trust level for a source */
export function defaultTrustFor(source: ContentSource): TrustLevel {
  return DEFAULT_TRUST[source.kind];
}
