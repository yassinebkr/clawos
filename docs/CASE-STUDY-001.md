# Case Study 001: Session Corruption from Content Filter Block

**Date**: February 5, 2026
**Duration of Outage**: ~7 hours (11:39 - 18:50)
**Impact**: Complete agent unresponsiveness

## Incident Summary

During ClawOS development (phases 2-3), the agent became completely unresponsive.
Every message sent by the user resulted in the same API error, making the agent
unreachable for over 7 hours.

## Timeline

### First Incident (7+ hours)

```
11:38  User: "Add the missing docs then go ahead for next phase"
11:39  [openclaw] LLM request rejected: Output blocked by content filtering policy
11:44  User attempts multiple messages — all fail with tool_use_id error
11:54  User: "Help me improve our first phases..."
       [openclaw] LLM request rejected: messages.302.content.1: unexpected 
       `tool_use_id` found in `tool_result` blocks: toolu_01KCKcNdNjS4fjQF8uAE8ADS.
       Each `tool_result` block must have a corresponding `tool_use` block in 
       the previous message.
12:16  User: "Gilbert?" — same error
12:17  Multiple retry attempts — all fail
17:15  User returns, tries again — still failing
17:45  Still failing
18:50  User manually fixed session state, agent responsive again
```

### Second Incident (same day)

```
19:14  User requests implementation of Layer 0
19:23  [openclaw] LLM request rejected: messages.32.content.4: unexpected 
       `tool_use_id` found in `tool_result` blocks: toolu_01FmDVgwTwmVKwRQZBdQE1Nk.
       Each `tool_result` block must have a corresponding `tool_use` block in 
       the previous message.
```

**Note**: The second incident proves that:
1. The problem is systemic, not a one-off
2. Even with the Layer 0 code written, it's not integrated into OpenClaw
3. Manual session repair is not a sustainable fix

## Root Cause Analysis

### The Trigger: Content Filter Block

At 11:39, the Anthropic API's content filter blocked the model's output mid-response.
The request was **partially processed** — the model had initiated a tool call, but
the response was blocked before completion.

### The Corruption: Orphaned Tool Result

The session history ended up in a state where:
1. A `tool_result` message existed with ID `toolu_01KCKcNdNjS4fjQF8uAE8ADS`
2. The corresponding `tool_use` block was either:
   - Never recorded (aborted mid-write)
   - Truncated during history compaction (message 302 = long conversation)

### The Failure Mode: API Validation

The Anthropic API strictly validates that every `tool_result` must have a matching
`tool_use` in the immediately preceding message. Once the history was corrupt:
- Every subsequent API call included the corrupt history
- Every call failed with the same validation error
- The session was effectively bricked

### Why Recovery Was Hard

1. **No automatic detection** — OpenClaw didn't validate tool_use/tool_result pairs
2. **No checkpoint/rollback** — No way to revert to a known-good state
3. **No graceful degradation** — Content filter block didn't clean up partial state
4. **Manual intervention required** — User had to manually fix/clear session state

## Lessons Learned

### 1. API Operations Need Atomicity

Tool call cycles (tool_use → execution → tool_result) should be atomic:
- Either the entire cycle completes and is persisted
- Or nothing is persisted

### 2. Content Filter is a Mid-Stream Abort

Content filtering can abort at any point in the response stream. Systems must
handle this as a rollback trigger, not just an error to log.

### 3. Validation Must Happen Before Send

Corrupt history should be detected and repaired **before** sending to the API,
not discovered via API rejection.

### 4. Long Conversations Are Fragile

At 302 messages, the conversation was long. History truncation/compaction can
create orphaned references if not done carefully.

## Impact Assessment

- **User impact**: 7+ hours of complete service unavailability
- **Data loss**: Conversation context from the corrupted session
- **Trust impact**: User frustrated, had to debug infrastructure instead of building

## Recommended Mitigations

### Immediate (Layer 0: Session Integrity)

1. **Pre-send validation**: Validate tool_use/tool_result consistency before API calls
2. **Checkpoint system**: Snapshot state before tool execution, rollback on failure
3. **Content filter recovery**: Detect content blocks and cleanly abort tool cycles

### Structural (Architecture)

1. **Atomic tool cycles**: Treat tool_use → tool_result as a transaction
2. **History integrity checks**: Validate history on load, not just on send
3. **Graceful degradation**: If history is corrupt, offer repair options

## Connection to ClawOS

This incident occurred **while building ClawOS** — a security architecture for agents.
The irony: we were building defenses against prompt injection and capability abuse,
but were taken down by a simpler infrastructure failure.

This case study motivates **Layer 0: Session Integrity** — a foundational layer
that sits beneath ClawOS's content tagging and capability control. Without session
integrity, all other security measures are moot.

### Layer 0 Scope

```
┌─────────────────────────────────────────────────────────────┐
│  Layer 5: Trust Registry                                    │
├─────────────────────────────────────────────────────────────┤
│  Layer 4: Signal Detection                                  │
├─────────────────────────────────────────────────────────────┤
│  Layer 3: Runtime Security                                  │
├─────────────────────────────────────────────────────────────┤
│  Layer 2: Capability Control                                │
├─────────────────────────────────────────────────────────────┤
│  Layer 1: Content Tagging                                   │
├─────────────────────────────────────────────────────────────┤
│  Layer 0: Session Integrity          ◄── NEW FOUNDATION     │
│  State validation, checkpoints, atomic operations, recovery │
└─────────────────────────────────────────────────────────────┘
```

Layer 0 ensures that:
- Session state is always consistent
- Operations are atomic (complete or rollback)
- Corrupt state is detected and repairable
- External failures (content filters, API errors) don't corrupt state

---

## Resolution

### Immediate Fix: Session Repair Tool

A repair tool was created at `tools/repair-session.ts` that can fix corrupted JSONL sessions:

```bash
# Check a session (dry run)
npx tsx tools/repair-session.ts ~/.openclaw/agents/main/sessions/<uuid>.jsonl --dry-run

# Repair a session
npx tsx tools/repair-session.ts ~/.openclaw/agents/main/sessions/<uuid>.jsonl

# Find current session UUID from sessions.json
cat ~/.openclaw/agents/main/sessions/sessions.json | jq -r '."agent:main:main".sessionId'
```

After repair, restart the OpenClaw gateway.

### Long-term: ClawOS Layer 0 Integration

The full Layer 0 implementation provides:
- Pre-send validation (catches corruption before API calls)
- Checkpoint system (rollback on failure)
- Auto-repair capability
- Content filter handling

Integration with OpenClaw requires either:
1. OpenClaw plugin using the `tool_result_persist` hook
2. Upstream contribution to OpenClaw core
3. Wrapper script that validates sessions on startup

---

*"The best security architecture is useless if the foundation can crack."*
