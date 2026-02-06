# ClawOS — OpenClaw Integration

## Overview

ClawOS integrates with OpenClaw at two levels:

1. **L0 Plugin** — Session integrity validation via OpenClaw's plugin system
2. **Core Fix** — `validateToolResultPairing()` added directly to OpenClaw's validation chain

Both work together for defense-in-depth: the core fix prevents most corruption silently, the plugin catches anything that slips through.

## The Problem

When Claude's content filter triggers mid-tool-call, or when session history is truncated by compaction/pruning, orphaned `tool_result` blocks can reference `tool_use` IDs that no longer exist. The Anthropic API rejects these with:

```
400: messages.N.content.X: unexpected tool_use_id found in tool_result blocks: toolu_xxx
```

This bricks the agent until the session is manually cleared.

## Solution: Two Layers of Defense

### Layer 1: OpenClaw Core Fix (`validateToolResultPairing`)

Added to `src/agents/pi-embedded-helpers/turns.ts`:

```typescript
export function validateToolResultPairing(messages: AgentMessage[]): AgentMessage[] {
  // Iterates through messages
  // Tracks tool_use/toolCall IDs from each assistant message
  // Removes any toolResult that references a non-existent ID
  // Handles both internal format (toolCall/toolCallId) and API format (tool_use/tool_use_id)
}
```

**Wired into the validation chain** in `attempt.ts`:
```
sanitizeSessionHistory → validateGeminiTurns → validateAnthropicTurns → limitHistoryTurns → validateToolResultPairing → replaceMessages
```

Runs after `limitHistoryTurns` — the most likely point where orphans are created (history trimming removes an assistant message but leaves its tool results).

**Auto-reset fallback** in `agent-runner-execution.ts`:
If the error still occurs despite validation, the session auto-resets (same mechanism as role ordering errors).

### Layer 2: ClawOS L0 Plugin

Location: `~/.openclaw/extensions/clawos-l0/index.ts`

**Hooks:**
- `gateway_start` — Scans and repairs ALL session JSONL files on disk
- `before_agent_start` — Validates in-memory messages before API call (advisory)

**Commands:**
- `/l0-status` — Show scan results and health
- `/l0-scan` — Trigger manual scan and repair

## Plugin Configuration

In `openclaw.json`:
```json
{
  "plugins": {
    "entries": {
      "clawos-l0": {
        "enabled": true,
        "config": {
          "repairStrategy": "remove_orphans",
          "logLevel": "info"
        }
      }
    }
  }
}
```

## How the Plugin Works

### Startup Scan (gateway_start hook)

```
Gateway starts → gateway_start hook fires → scanAndRepairAllSessions()
  ├── Find all .jsonl files in ~/.openclaw/agents/*/sessions/
  ├── For each file:
  │   ├── Parse JSONL entries
  │   ├── Find toolResult messages
  │   ├── Check each toolCallId against preceding assistant's toolCall IDs
  │   ├── If orphaned: backup file, remove orphaned entries, write repaired
  │   └── Log results
  └── Report: "N sessions, M issues found, K repaired"
```

**Important:** Uses `gateway_start` hook (not `register()`) so it only runs when the gateway starts, not on `gateway stop` or other CLI commands.

### Runtime Validation (before_agent_start hook)

```
User message → before_agent_start hook → validateToolPairing(messages)
  ├── If valid: continue normally
  └── If invalid: log incident, prepend warning to context
      (Plugin can't modify messages — it's advisory only)
```

The runtime hook is advisory because the plugin API only allows `prependContext` and `systemPrompt` modifications, not direct message array edits. The core fix handles actual repair.

## Repair Strategies

| Strategy | Behavior |
|----------|----------|
| `remove_orphans` | Delete tool_result entries with no matching tool_use (default, safest) |
| `reconstruct` | Placeholder — not implemented yet |
| `truncate` | Placeholder — not implemented yet |

## JSONL Format

OpenClaw uses an internal format distinct from the Anthropic API:

```jsonl
{"type":"message","message":{"role":"assistant","content":[{"type":"toolCall","id":"toolu_xxx","name":"exec","arguments":{...}}]}}
{"type":"message","message":{"role":"toolResult","toolCallId":"toolu_xxx","toolName":"exec","content":[{"type":"text","text":"..."}]}}
```

The plugin validates `toolCallId` against preceding `toolCall.id` entries. The core fix validates both internal format (`toolCall`/`toolCallId`) and API format (`tool_use`/`tool_use_id`).

## Incident Logging

On corruption detection, the plugin writes:
```
~/.openclaw/logs/l0-runtime-incident-{timestamp}.json
```

Contents:
```json
{
  "timestamp": "2026-02-05T21:20:00.000Z",
  "sessionKey": "agent:main:main",
  "issues": [
    {
      "type": "orphaned_tool_result",
      "toolUseId": "toolu_xxx",
      "messageIndex": 148,
      "description": "..."
    }
  ],
  "action": "detected_at_runtime"
}
```

## Performance

- Startup scan: <100ms for typical session count
- Runtime validation: <5ms per agent turn
- Zero overhead when sessions are healthy

## Future: L1-L5 Plugins

The same plugin architecture can integrate remaining layers:
- **L1 plugin** — Tag inbound messages with source/trust metadata
- **L2 plugin** — Enforce capability manifests on tool calls via `before_tool_call` hook
- **L4 plugin** — Scan inbound content for injection patterns via `message_received` hook
- **L5 plugin** — Verify skill integrity on load

## ⚠️ The `gateway_start` Hook Timing Bug

### Discovery

OpenClaw fires the `gateway_start` hook **before** external plugins have registered their hook handlers. The lifecycle is:

1. Gateway loads plugin manifests
2. Gateway emits `gateway_start` ← **fires here**
3. Plugins' `register()` is called, which registers hook handlers
4. Gateway continues startup

This means any external plugin that registers a `gateway_start` handler in `register()` will **never** see that hook fire. The hook has already been emitted by the time the handler is registered. This was confirmed empirically — a breadcrumb file written inside a `gateway_start` handler was never created, not on cold restart and not on soft reload (SIGUSR1).

**This affects ALL external plugins using `gateway_start`, not just ClawOS.**

### Workaround: Lazy Initialization Pattern

Instead of relying on `gateway_start` to initialize state, use **lazy initialization** — check if state has been initialized at the top of every command handler and hook, and self-initialize on first call.

```typescript
// ❌ Broken: gateway_start never fires for external plugins
plugin.hook("gateway_start", async () => {
  await scanAndRepairAllSessions();  // Never executes
  state.initialized = true;
});

// ✅ Working: Lazy init in every entry point
async function ensureInitialized() {
  if (state.initialized) return;
  await scanAndRepairAllSessions();
  state.initialized = true;
}

plugin.command("/l0-status", async (ctx) => {
  await ensureInitialized();  // First call triggers init
  // ... command logic
});

plugin.command("/l0-scan", async (ctx) => {
  await ensureInitialized();
  // ... command logic
});

plugin.hook("before_agent_start", async (ctx) => {
  await ensureInitialized();
  // ... validation logic
});
```

The `ensureInitialized()` guard is idempotent — it runs the startup logic exactly once, on whichever entry point is hit first. Subsequent calls are a no-op.

### Current Status

As of v0.3.0, the ClawOS plugin uses lazy initialization exclusively. The `gateway_start` hook registration has been removed.

## References

- [CASE-STUDY-001.md](./CASE-STUDY-001.md) — 3 incidents that motivated this
- [LAYER0-SPEC.md](./LAYER0-SPEC.md) — Full L0 specification
- [CHANGELOG.md](./CHANGELOG.md) — Bug fixes and improvements
