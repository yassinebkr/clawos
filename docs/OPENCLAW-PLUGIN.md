# ClawOS Session Integrity Plugin for OpenClaw

## Overview

This plugin integrates ClawOS Layer 0 (Session Integrity) into OpenClaw to prevent session corruption from orphaned `tool_result` blocks — a critical bug that caused 7+ hours of agent downtime on Feb 5, 2026.

## The Problem

When Claude's content filter triggers mid-response, it can produce malformed session history:

```
assistant: [tool_use id="abc123"]     ← This gets stripped by filter
user: [tool_result tool_use_id="abc123"]  ← This remains, now orphaned
```

The orphaned `tool_result` references a `tool_use` that doesn't exist, causing the Anthropic API to reject all subsequent requests with:

```
400: messages.21.content.0.tool_use_id: Could not find tool_use block with id xyz
```

**Result:** Agent is completely bricked until manual intervention.

## The Solution

Layer 0 validates session integrity before every API call:

1. **Tool Pair Validation** — Every `tool_result` must have a matching `tool_use`
2. **Orphan Detection** — Identifies broken references
3. **Auto-Repair** — Removes orphaned blocks or reconstructs missing pairs
4. **Checkpointing** — WAL-style recovery points for atomic operations

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    OpenClaw Gateway                      │
├─────────────────────────────────────────────────────────┤
│  before_api_call hook                                    │
│       │                                                  │
│       ▼                                                  │
│  ┌─────────────────────────────────────────────────┐    │
│  │         ClawOS Layer 0 Plugin                    │    │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────┐  │    │
│  │  │  Validator  │→ │  Repairer   │→ │Checkpoint│  │    │
│  │  └─────────────┘  └─────────────┘  └─────────┘  │    │
│  └─────────────────────────────────────────────────┘    │
│       │                                                  │
│       ▼                                                  │
│  Anthropic API (clean, validated messages)               │
└─────────────────────────────────────────────────────────┘
```

## Components

### Core Layer 0 Modules (`~/clawos-dev/src/integrity/`)

| File | Purpose |
|------|---------|
| `types.ts` | Type definitions for sessions, checkpoints, validation results |
| `validate.ts` | Validates tool_use/tool_result pairing |
| `repair.ts` | Auto-repairs orphaned blocks |
| `checkpoint.ts` | WAL-style atomic checkpointing |
| `session-integrity.ts` | Main coordinator class |

### Plugin Entry Point

```typescript
// plugins/clawos-l0/index.ts
import { SessionIntegrity } from '~/clawos-dev/src/integrity';

export default {
  name: 'clawos-session-integrity',
  version: '0.1.0',
  
  hooks: {
    // Validate & repair before every API call
    before_api_call: async (ctx) => {
      const integrity = new SessionIntegrity(ctx.session);
      const result = await integrity.validate();
      
      if (!result.valid) {
        console.warn(`[ClawOS L0] Repairing session: ${result.issues.length} issues`);
        await integrity.repair();
      }
      
      return ctx; // Continue with clean session
    },
    
    // Checkpoint after successful tool execution
    after_tool_call: async (ctx) => {
      const integrity = new SessionIntegrity(ctx.session);
      await integrity.checkpoint();
      return ctx;
    }
  }
};
```

## Validation Rules

### Rule 1: Tool Result Pairing
Every `tool_result` block must reference a `tool_use` block that:
- Exists in the immediately preceding `assistant` message
- Has a matching `id`

### Rule 2: No Duplicate IDs
Each `tool_use` ID must be unique within a session.

### Rule 3: Temporal Ordering
Tool results must appear after their corresponding tool uses.

## Repair Strategies

When validation fails, Layer 0 can:

1. **Remove Orphans** — Delete `tool_result` blocks with no matching `tool_use`
2. **Reconstruct** — Add placeholder `tool_use` for critical orphaned results
3. **Truncate** — Roll back to last known-good checkpoint

Default strategy: **Remove Orphans** (safest, loses minimal context)

## Configuration

```yaml
# openclaw.yaml
plugins:
  clawos-l0:
    enabled: true
    repair_strategy: remove_orphans  # remove_orphans | reconstruct | truncate
    checkpoint_interval: 5           # checkpoint every N tool calls
    log_level: warn                  # debug | info | warn | error
```

## Installation

```bash
# From clawos-dev directory
cd ~/clawos-dev
npm run build

# Link to OpenClaw plugins
ln -s ~/clawos-dev/dist/plugins/openclaw-l0 ~/.openclaw/plugins/clawos-l0
```

## Monitoring

The plugin emits events for observability:

| Event | Description |
|-------|-------------|
| `l0:validation:pass` | Session validated successfully |
| `l0:validation:fail` | Validation failed, repair needed |
| `l0:repair:start` | Repair operation beginning |
| `l0:repair:complete` | Repair finished with result |
| `l0:checkpoint:created` | New checkpoint saved |

## Performance

- **Validation latency:** <5ms for typical sessions
- **Repair latency:** <20ms (depends on session size)
- **Memory overhead:** ~2KB per checkpoint

Target: <50ms total overhead per API call (well under budget).

## Incident Response

If Layer 0 detects corruption it cannot auto-repair:

1. Plugin logs full diagnostic to `~/.openclaw/logs/l0-incident-{timestamp}.json`
2. Notifies operator via configured channel
3. Falls back to checkpoint recovery if available
4. As last resort, preserves corrupted session for manual analysis

## Testing

```bash
cd ~/clawos-dev
npm test -- --grep "Layer 0"

# Test with known-bad session
npm run test:corruption -- fixtures/orphaned-tool-result.jsonl
```

## References

- [CASE-STUDY-001.md](./CASE-STUDY-001.md) — Feb 5, 2026 incident analysis
- [LAYER0-SPEC.md](./LAYER0-SPEC.md) — Full Layer 0 specification
- [OpenClaw Hooks](file:///usr/lib/node_modules/openclaw/docs/hooks.md) — Plugin hook reference

---

*This plugin is part of ClawOS — an open-source security framework for autonomous agents.*
