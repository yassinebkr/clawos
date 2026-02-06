# L2 Enforcement Plan

## Goal

Make ClawOS Layer 2 (Capability Control) actually enforce permissions on tool calls,
not just advisory. When a tool call doesn't match its manifest, block it.

## Current State

- **L2 code exists**: `checkPermission()`, `enforce()`, `validateManifest()`, `registerManifest()`
- **Plugin hooks available**: `gateway_start`, `before_agent_start`, `message_received`, `tool_result_persist`
- **Missing hook**: `before_tool_call` — defined in hook runner but NOT wired into the agent runner
- **Missing data**: tools don't ship capability manifests

## Architecture

```
Tool call requested by LLM
        │
        ▼
[before_tool_call hook]     ◄── NEEDS WIRING (Phase 1)
        │
        ├── L2: Check manifest
        │     Does this tool have a manifest?
        │     Does the manifest allow this capability?
        │     Does the input trust level meet the minimum?
        │
        ├── Result: { block: true/false, blockReason: string }
        │
        ▼
[Tool executes or is blocked]
        │
        ▼
[after_tool_call hook]      ◄── Already defined, not wired
        │
        ▼
[tool_result_persist hook]  ◄── Already working (L1 tagging)
```

## Phases

### Phase 1: Wire `before_tool_call` in OpenClaw (upstream patch)

**File**: `openclaw/dist/agents/pi-embedded-runner/run/attempt.js`

The hook runner already has `runBeforeToolCall()` which returns:
```typescript
{ params?: object, block?: boolean, blockReason?: string }
```

**Where to insert**: In the tool execution pipeline, after the LLM requests a tool
call but before the tool handler runs. The tool dispatch currently happens inside
the Anthropic SDK's streaming callback.

**Approach**: Find where tool results are collected (the same place
`tool_result_persist` is called via `session-tool-result-guard-wrapper.js`) and
add a `before_tool_call` invocation just before the tool handler executes.

**Key files to patch**:
- `src/agents/pi-embedded-runner/run/attempt.ts` — main agent run loop
- `src/agents/pi-embedded-subscribe.handlers.ts` — streaming event handlers
- `src/agents/session-tool-result-guard-wrapper.ts` — where tool results are captured

**Hook contract** (already defined in `plugins/hooks.js`):
```typescript
// Event passed to before_tool_call
{
  toolName: string,
  toolCallId: string,
  params: object,          // tool input parameters
}

// Context
{
  agentId: string,
  sessionKey: string,
  workspaceDir?: string,
}

// Return value
{
  params?: object,         // modified params (optional)
  block?: boolean,         // true = deny the tool call
  blockReason?: string,    // reason shown in tool_result error
}
```

### Phase 2: Define tool manifests for built-in tools

Create manifest files for each OpenClaw built-in tool. These declare what
capabilities each tool needs.

**Location**: `~/.openclaw/extensions/clawos/manifests/`

**Example manifests**:

```typescript
// exec — highest risk
{
  id: "exec",
  name: "Shell Execution",
  capabilities: ["proc:exec", "fs:read", "fs:write", "net:http"],
  riskLevel: "critical",
  minInputTrust: "owner",     // Only owner-trust input can trigger exec
  outputTrust: "verified",
}

// read — low risk
{
  id: "read",
  name: "File Read",
  capabilities: ["fs:read"],
  riskLevel: "low",
  minInputTrust: "community",
  outputTrust: "verified",
}

// write — medium risk
{
  id: "write",
  name: "File Write",
  capabilities: ["fs:write"],
  riskLevel: "medium",
  minInputTrust: "verified",
  outputTrust: "verified",
}

// web_fetch — medium risk
{
  id: "web_fetch",
  name: "Web Fetch",
  capabilities: ["net:https"],
  riskLevel: "medium",
  minInputTrust: "community",
  outputTrust: "untrusted",    // Web content is untrusted
}

// web_search — medium risk
{
  id: "web_search",
  name: "Web Search",
  capabilities: ["net:https"],
  riskLevel: "medium",
  minInputTrust: "community",
  outputTrust: "untrusted",
}

// message — high risk (sends externally)
{
  id: "message",
  name: "Send Message",
  capabilities: ["message:send"],
  riskLevel: "high",
  minInputTrust: "owner",
  outputTrust: "verified",
}

// gateway — critical (modifies system)
{
  id: "gateway",
  name: "Gateway Control",
  capabilities: ["system:admin"],
  riskLevel: "critical",
  minInputTrust: "owner",
  outputTrust: "verified",
}

// cron — high risk (schedules future actions)
{
  id: "cron",
  name: "Cron Scheduler",
  capabilities: ["system:schedule"],
  riskLevel: "high",
  minInputTrust: "owner",
  outputTrust: "verified",
}

// browser — high risk
{
  id: "browser",
  name: "Browser Control",
  capabilities: ["net:https", "fs:read"],
  riskLevel: "high",
  minInputTrust: "verified",
  outputTrust: "untrusted",
}

// nodes — high risk (controls physical devices)
{
  id: "nodes",
  name: "Node Control",
  capabilities: ["device:control"],
  riskLevel: "high",
  minInputTrust: "owner",
  outputTrust: "verified",
}
```

### Phase 3: Wire L2 into the ClawOS plugin

Add `before_tool_call` handler to `~/.openclaw/extensions/clawos/index.ts`:

```typescript
api.registerHook("before_tool_call", async (event, ctx) => {
  const { toolName, params } = event;

  // 1. Look up manifest for this tool
  const manifest = getManifest(toolName);
  if (!manifest) {
    // No manifest = no enforcement (permissive by default)
    // Log for visibility
    logger.debug?.(`[ClawOS L2] No manifest for tool "${toolName}", allowing`);
    return {};
  }

  // 2. Resolve input trust level from L1 tags
  const inputTrust = resolveCurrentTrust(ctx);

  // 3. Check permission
  const permission = checkPermission(manifest, inputTag, operatorPolicy);

  if (!permission.allowed) {
    logger.warn(
      `[ClawOS L2] BLOCKED: ${toolName} — ${permission.reasons.join("; ")}`
    );
    return {
      block: true,
      blockReason: `[ClawOS L2] Tool "${toolName}" blocked: ${permission.reasons[0]}`,
    };
  }

  // 4. Log allowed call
  logger.debug?.(`[ClawOS L2] Allowed: ${toolName} (trust=${inputTrust})`);
  return {};
});
```

### Phase 4: Operator policy configuration

Add L2 policy to the plugin config:

```json
{
  "plugins": {
    "entries": {
      "clawos": {
        "config": {
          "layers": {
            "capabilities": true
          },
          "capabilities": {
            "mode": "enforce",       // "enforce" | "audit" | "off"
            "defaultAllow": true,    // Allow tools without manifests?
            "overrides": {
              "exec": "audit",       // Log but don't block
              "gateway": "enforce"   // Always enforce
            }
          }
        }
      }
    }
  }
}
```

Modes:
- **enforce**: Block disallowed tool calls
- **audit**: Log violations but allow (transition period)
- **off**: Disabled

### Phase 5: Sub-agent enforcement

Sub-agents should have stricter defaults:

```typescript
// In before_tool_call handler
const isSubagent = ctx.sessionKey?.includes(":subagent:");
if (isSubagent) {
  // Stricter trust requirement for sub-agents
  // Sub-agent input trust is "verified" (from main agent), not "owner"
  // This means tools requiring "owner" trust (exec, message, gateway)
  // are blocked by default in sub-agents
}
```

This gives us capability-based sub-agent restriction without needing per-spawn config.

## Dependencies

| Phase | Dependency | Status |
|-------|-----------|--------|
| 1 | OpenClaw agent runner patch | Needs PR or local patch |
| 2 | Manifest definitions | We control this |
| 3 | Plugin hook handler | We control this (after Phase 1) |
| 4 | Config schema update | We control this |
| 5 | Sub-agent session key detection | Already works (string check) |

## Risks

- **Phase 1 is the blocker**: Patching OpenClaw's agent runner is non-trivial.
  The tool dispatch happens inside the Anthropic SDK streaming callback. We need
  to intercept between "LLM requests tool" and "tool executes". Could PR upstream
  or maintain a local patch.

- **Breaking existing workflows**: Strict enforcement could block legitimate tool
  calls. The "audit" mode in Phase 4 is critical for a safe rollout.

- **Manifest coverage**: Tools without manifests pass through unchecked. Need to
  define manifests for ALL tools before switching to enforce mode with
  `defaultAllow: false`.

## Timeline Estimate

- Phase 1: 2-4 hours (understanding tool dispatch, writing patch, testing)
- Phase 2: 1 hour (manifest definitions)
- Phase 3: 1-2 hours (plugin handler + tests)
- Phase 4: 30 min (config schema)
- Phase 5: 1 hour (sub-agent logic + tests)

**Total: ~1 day of focused work**, blocked on Phase 1 (upstream patch).

## Success Criteria

1. `before_tool_call` fires for every tool invocation (main + sub-agents)
2. Tools with manifests are checked against input trust level
3. Blocked calls return a clear error to the LLM (it can explain to the user)
4. Audit mode logs all would-be violations without blocking
5. Sub-agents have stricter defaults than main agent
6. `/clawos` command shows L2 enforcement status
