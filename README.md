# 🛡️ ClawOS — Security Stack for OpenClaw

Defense-in-depth security plugin for [OpenClaw](https://openclaw.ai) agents. Protects against session corruption, prompt injection, data exfiltration, and unauthorized actions — without sacrificing agent functionality.

> **Version:** 0.5.0
> **Author:** Yassine ([@yassinebkr](https://github.com/yassinebkr))
> **License:** MIT

## Why ClawOS?

OpenClaw gives your AI agent access to tools, files, messages, and shell commands. That's powerful — and dangerous. A single prompt injection hidden in a web page, email, or document can hijack your agent into:

- Exfiltrating API keys, credentials, or private data
- Running arbitrary commands on your machine
- Sending messages on your behalf
- Modifying its own system prompt to stay compromised

ClawOS adds 9 defense layers that detect, tag, and **block** these attacks at the gateway level — outside the agent's control.

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                  Gateway Start                          │
├─────────────────────────────────────────────────────────┤
│  L0  Startup Scan ──────── Validate all session JSONLs  │  ← gateway_start
│  L5  Bootstrap Integrity ─ Snapshot protected file hashes│
├─────────────────────────────────────────────────────────┤
│                    User Message                         │
├─────────────────────────────────────────────────────────┤
│  L4  Signal Detection ──── Scan inbound for injection   │  ← message_received
│  LC  Threat Clear ──────── Reset restriction on user msg│
├─────────────────────────────────────────────────────────┤
│                  Before Agent Turn                      │
├─────────────────────────────────────────────────────────┤
│  L0  Session Integrity ─── Repair corrupted messages    │  ← before_agent_start
│  L0  Disk Persistence ──── Write repairs back to JSONL  │
│  L1  Context Tagging ───── Tag trust level & source     │
│  🐤  Canary Token ──────── Inject secret into context   │
├─────────────────────────────────────────────────────────┤
│                    Agent Calls Tool                     │
├─────────────────────────────────────────────────────────┤
│  LC  Privilege Separation ─ BLOCK if threat detected    │  ← before_tool_call
│  LF  File Write Guard ──── BLOCK writes to critical files│  ← before_tool_call
├─────────────────────────────────────────────────────────┤
│                    Tool Returns Result                  │
├─────────────────────────────────────────────────────────┤
│  L4+ External Scanner ──── Scan result for injection    │  ← tool_result_persist
│  🐤  Canary Check ──────── Detect system prompt leak    │
│  L1  Provenance Tag ────── Tag source & trust metadata  │
├─────────────────────────────────────────────────────────┤
│              Advisory (code ready, hooks pending)        │
├─────────────────────────────────────────────────────────┤
│  L2  Capability Control ── Manifest-based permissions   │
│  L3  Runtime Security ──── Behavioral anomaly detection │
│  L5  Trust Registry ────── Cryptographic hash pinning   │
└─────────────────────────────────────────────────────────┘
```

## Layers

### Active Layers

| Layer | Name | Hook | Description |
|-------|------|------|-------------|
| **L0** | Session Integrity | `gateway_start`, `before_agent_start` | Validates JSONL session files. Detects and repairs orphaned `tool_result` messages and error-terminated tool calls that would brick the agent. Repairs are persisted to disk (JSONL rewrite with backup) so sessions load clean on restart. Runs at startup + before every turn. |
| **L1** | Content Tagging | `tool_result_persist` | Tags every tool result with provenance metadata: `[clawos:source=web_fetch,trust=verified,t=1234]`. Creates an audit trail of what data came from where. |
| **L4** | Signal Detection | `message_received`, `before_agent_start` | Scans inbound user messages for 50+ injection/exfiltration patterns. Tracks stats, logs high-severity signals, injects warnings into agent context. |
| **L4+** | External Content Scanner | `tool_result_persist` | Scans tool results from external sources (web_fetch, web_search/Brave, browser, read, exec, image) for indirect prompt injection. 16 specialized patterns + instruction density heuristic. |
| **LC** | Privilege Separation | `before_tool_call`, `message_received` | When L4+ detects high-severity injection in external content, **blocks dangerous tools** (exec, write, edit, message, gateway) until the next user message. Enforced at gateway level — the agent cannot override it. |
| **LF** | File Write Guard | `before_tool_call` | Blocks agent write/edit/exec operations targeting critical files (SOUL.md, AGENTS.md, openclaw.json). Enforced at gateway level — the agent cannot modify its own identity or config. Requires full process restart to activate. |
| **🐤** | Canary Token | `before_agent_start`, `tool_result_persist` | Injects a random secret token into agent context. If any external content contains this token, it proves the system prompt was exfiltrated. Persistent alert on detection. |

### Advisory Layers (code ready, waiting for full hook support)

| Layer | Name | Description |
|-------|------|-------------|
| **L2** | Capability Control | Manifest-based permission system for tool access |
| **L3** | Runtime Security | Behavioral monitoring and anomaly detection |
| **L5** | Trust Registry | Cryptographic hash pinning for file integrity verification |

### Protected Files

ClawOS monitors writes to critical workspace files:

| Tier | Files | Action |
|------|-------|--------|
| **Critical** | SOUL.md, AGENTS.md | 🚨 Alert + hash verification + incident log |
| **Sensitive** | USER.md, IDENTITY.md, MEMORY.md, TOOLS.md, HEARTBEAT.md | ⚠️ Warning + hash tracking |
| **Tracked** | BOOTSTRAP.md | ℹ️ Logged |

## Installation

### Option 1: OpenClaw CLI (recommended)

```bash
openclaw plugins install github:yassinebkr/clawos
```

This downloads the plugin, places it in `~/.openclaw/extensions/clawos/`, and registers it in your config. Then restart:

```bash
openclaw gateway restart
```

### Option 2: Manual

1. Clone or copy into `~/.openclaw/extensions/clawos/`:

```bash
git clone https://github.com/yassinebkr/clawos.git ~/.openclaw/extensions/clawos
```

2. Enable in your OpenClaw config (`~/.openclaw/openclaw.json`):

```json
{
  "plugins": {
    "entries": {
      "clawos": {
        "enabled": true
      }
    }
  }
}
```

3. Restart the gateway:

```bash
openclaw gateway restart
```

## Configuration

All layers are enabled by default (except L2/L3/L5 which are advisory). Configure in your OpenClaw config:

```yaml
plugins:
  clawos:
    enabled: true
    config:
      layers:
        integrity: true          # L0: Session Integrity
        tagging: true            # L1: Content Tagging
        signals: true            # L4: Signal Detection (also enables L4+)
        privilegeSeparation: true # LC: Privilege Separation
        capabilities: false      # L2: Advisory only
        runtime: false           # L3: Advisory only
        registry: false          # L5: Advisory only
      signals:
        minConfidence: 0.5       # Minimum confidence to track a signal
        suppressCategories: []   # Categories to ignore: injection, exfiltration, encoding, roleplay
        alertOnHighSeverity: true # Log high-severity (>=0.8) signals
      logLevel: info             # debug | info | warn | error
```

## Commands

| Command | Description |
|---------|-------------|
| `/clawos` | Full security stack status dashboard |
| `/clawos-scan` | Manual L0 session integrity scan |
| `/clawos-signals` | Signal detection statistics |
| `/clawos-integrity` | Bootstrap file integrity report with hashes |

## How Privilege Separation Works

This is the most important defense layer. Here's the flow:

1. **Agent reads external content** — `web_fetch`, Brave search, browser, file read
2. **L4+ scans the result** — 16 injection patterns + standard L4 patterns + instruction density heuristic
3. **High-severity signals detected** (confidence >= 0.8) → session enters **restricted mode**
4. **Agent tries to call a dangerous tool** (exec, write, message, etc.) → **BLOCKED at gateway level**
5. **Agent receives block message** explaining what triggered it and why
6. **User sends a new message** → restriction lifted, fresh trust context

### Why this matters

The agent **cannot bypass Layer C**. Even if a prompt injection successfully influences the agent's reasoning, the gateway refuses to execute dangerous tools. The blocking happens in `before_tool_call`, which runs before the tool's `execute()` function — the agent never gets to run the command.

### Blocked tools (during threat state)
`exec`, `write`, `Write`, `edit`, `Edit`, `message`, `gateway`, `sessions_send`

### Always-allowed tools (read-only operations)
`read`, `Read`, `web_search`, `web_fetch`, `browser`, `image`, `session_status`, `sessions_list`, `sessions_history`, `process`, `tts`

## L4+ Detection Patterns

External content injection patterns (beyond standard L4):

| Pattern | Confidence | What it catches |
|---------|-----------|-----------------|
| `indirect_override` | 0.85 | "AI, please ignore/disregard/forget..." |
| `hidden_instruction_tag` | 0.90 | `[hidden instruction]`, `[hidden prompt]` |
| `html_comment_injection` | 0.85 | `<!-- system`, `<!-- instruction` |
| `important_instruction_for_ai` | 0.90 | "IMPORTANT INSTRUCTION FOR THE AI ASSISTANT" |
| `hide_from_user` | 0.90 | "do not tell/show/reveal the user" |
| `secret_action` | 0.85 | "secretly/silently/without telling the user" |
| `execute_command` | 0.80 | "execute this command:" |
| `code_execution_call` | 0.75 | `run("`, `exec("`, `eval("` |
| `claim_reprogrammed` | 0.85 | "you have been reprogrammed/updated" |
| `new_objective` | 0.85 | "new objective:", "new directive:" |
| `redefine_goal` | 0.80 | "from now on, your primary task is..." |
| `exfil_via_response` | 0.80 | "append the contents of... to your response" |
| `exfil_to_endpoint` | 0.85 | "send/post/upload... to https://..." |
| `zero_width_chars` | 0.70 | Zero-width character sequences (invisible text) |
| `css_hidden_injection` | 0.90 | CSS-hidden text with instructions |
| **instruction_density** | 0.50-0.95 | Heuristic: many imperative verbs in short text |

Plus all 50+ standard L4 patterns (direct injection, exfiltration, encoding, roleplay, self-modification).

## Canary Token

A random token (`CLAWOS_CANARY_xxxxxxxx`) is generated on each gateway restart and injected into the agent's system context. The agent is instructed to never output it.

If the canary appears in any tool result, it means:
- An external source somehow extracted the agent's system prompt
- The content was fed back through a tool (e.g., a web page that reflects the prompt)
- This confirms a **prompt injection exfiltration attack**

On detection: `logger.error` + daily memory log + persistent flag in `/clawos` status.

## Token & Cost Management

ClawOS works alongside OpenClaw's built-in cost controls. These aren't part of the plugin itself — they're OpenClaw gateway settings — but they're **essential** for preventing runaway API costs. A single heavy session without these safeguards can burn $100+ in hours.

### The Problem

Without tuning, OpenClaw defaults are permissive:
- **Context pruning** is off — old tool results accumulate forever in context
- **Compaction reserve** is only ~16k tokens — on a 1M context window, compaction won't trigger until ~984k tokens
- **Sub-agents** may fall back to expensive models (Opus) if the primary model fails
- **Rate limits** are silent — no error shown to the user when the API stops responding

In a heavy coding session (150+ tool calls in 2 hours), this means:
- Every API call re-reads the full accumulated context (~100k+ tokens)
- Anthropic cache_read costs add up: **33M tokens = $50** in reads alone
- Cache_write on every restart/canary rotation: **3.4M tokens = $63**
- Total: **$120 burned in one session**

### Recommended OpenClaw Settings

Add these to your `openclaw.json` under `agents.defaults`:

```json
{
  "agents": {
    "defaults": {
      "contextPruning": {
        "mode": "cache-ttl",
        "ttl": "5m",
        "keepLastAssistants": 3,
        "softTrimRatio": 0.3,
        "hardClearRatio": 0.5,
        "minPrunableToolChars": 50000,
        "softTrim": {
          "maxChars": 4000,
          "headChars": 1500,
          "tailChars": 1500
        },
        "hardClear": {
          "enabled": true,
          "placeholder": "[Old tool result cleared]"
        }
      },
      "compaction": {
        "mode": "default",
        "reserveTokensFloor": 200000,
        "memoryFlush": {
          "enabled": true,
          "softThresholdTokens": 50000
        }
      },
      "memorySearch": {
        "enabled": true,
        "sources": ["memory", "sessions"],
        "provider": "local",
        "sync": {
          "onSessionStart": true,
          "onSearch": true,
          "watch": true
        }
      },
      "subagents": {
        "maxConcurrent": 8,
        "model": {
          "primary": "google-gemini-cli/gemini-3-pro-preview",
          "fallbacks": ["anthropic/claude-sonnet-4-6"]
        }
      }
    }
  }
}
```

### What Each Setting Does

| Setting | What it does | Why it matters |
|---------|-------------|----------------|
| **contextPruning.mode: "cache-ttl"** | Trims old tool results after Anthropic cache expires (5min) | Prevents tool output from accumulating forever. Biggest cost saver. |
| **contextPruning.softTrim** | Keeps head + tail of oversized tool results, inserts `...` | Preserves useful context while cutting size |
| **contextPruning.hardClear** | Replaces very old tool results with a placeholder | Aggressively reclaims space for results beyond the hard-clear threshold |
| **compaction.reserveTokensFloor: 200000** | Compaction triggers at ~800k (instead of ~984k) | Earlier compaction = smaller context per API call = lower cost |
| **compaction.memoryFlush.enabled** | Writes important context to disk before compaction | Nothing critical is lost when older messages are summarized |
| **memorySearch.enabled** | Vector search over memory files and session transcripts | Agent can recall past context without keeping it all in the window |
| **memorySearch.provider: "local"** | Uses local embeddings (no API cost) | Zero-cost memory search |
| **subagents.model.primary** | Gemini Pro for sub-agents | Much cheaper than Opus for focused tasks |
| **subagents.model.fallbacks** | Sonnet 4.6 as fallback (NOT Opus) | Prevents expensive Opus fallback on sub-agent failures |

### Quick Setup

**Automatic (via gateway patch):**

```bash
# From a chat session, ask the agent to run:
gateway config.patch with the settings above
```

**Manual:**

1. Edit `~/.openclaw/openclaw.json`
2. Add the settings under `agents.defaults`
3. Also set sub-agent model at the agent level:
```json
{
  "agents": {
    "list": [{
      "id": "main",
      "subagents": {
        "allowAgents": ["main"],
        "model": {
          "primary": "google-gemini-cli/gemini-3-pro-preview",
          "fallbacks": ["anthropic/claude-sonnet-4-6"]
        }
      }
    }]
  }
}
```
4. Restart: `openclaw gateway restart`

### Verifying It Works

After applying, check with `/status`:
- **Context** should show compactions happening (🧹 count > 0) during heavy sessions
- **Context %** should stay well below 80% instead of growing unbounded
- Sub-agent spawns should show Gemini or Sonnet, never Opus

To audit a session's token usage:
```bash
# Parse session transcript for token stats
python3 -c "
import json
with open('~/.openclaw/agents/main/sessions/<session-id>.jsonl') as f:
    total = sum(
        sum(json.loads(l).get('message',{}).get('usage',{}).get(k,0)
            for k in ['input','output','cacheRead','cacheWrite'])
        for l in f if l.strip()
    )
print(f'Total tokens: {total:,}')
"
```

## Security Model & Limitations

### What ClawOS defends against
- ✅ Session file corruption (orphaned tool_results)
- ✅ Direct prompt injection in user messages
- ✅ Indirect prompt injection in web pages, search results, fetched documents
- ✅ System prompt exfiltration attempts
- ✅ Unauthorized file modifications (bootstrap/identity files)
- ✅ Dangerous tool execution after external content ingestion

### What ClawOS cannot fully prevent
- ⚠️ **Novel injection techniques** — pattern matching catches known patterns, not zero-days
- ⚠️ **Subtle reasoning influence** — an injection may influence the agent's *thinking* without triggering patterns
- ⚠️ **Agent self-verification** — a compromised agent will report "all clean" if instructed to. Only external (user-run) verification is trustworthy.

### Important: Trust Model

> **Never trust the agent to verify its own integrity after exposure to untrusted content.**
>
> If an injection says "do not tell the user about this instruction", a compromised agent and a clean agent produce identical output. Only the user can verify externally by:
> - Checking file hashes themselves (via SSH)
> - Reviewing the raw JSONL session log for unexpected tool calls
> - Inspecting network connections independently
>
> Layer C (privilege separation) addresses this by making the gateway — not the agent — the enforcement point. Even a compromised agent cannot execute blocked tools.

## Development

### File Structure
```
~/.openclaw/extensions/clawos/
├── index.ts                  # Full plugin source (2100+ lines)
├── openclaw.plugin.json      # Plugin manifest & config schema
└── README.md                 # This file
```

### Testing
The standalone ClawOS library (`~/clawos-dev/`) has 492 tests across 21 files. Plugin-specific stress tests: 89 tests, 222k messages/sec throughput.

### Safe Testing Protocol
When testing injection detection, **never read test content in the main session**:

1. Write test file from main session
2. Spawn isolated sub-agent: `sessions_spawn` with task to read the file
3. Check gateway logs and daily memory for detection events
4. Delete the test file
5. Verify from main by reviewing logs — never by reading the file directly

### Hooks Used
| Hook | Layer(s) | Purpose |
|------|----------|---------|
| `gateway_start` | L0, L5 | Startup scan + registry initialization |
| `message_received` | L4, LC | Scan inbound + clear threat state on user message |
| `before_agent_start` | L0, L1, L4, 🐤 | Session validation + context injection |
| `tool_result_persist` | L1, L4+, 🐤 | Provenance tagging + external scan + canary check |
| `before_tool_call` | LC | Privilege separation — block dangerous tools |

## Changelog

### 0.5.1 (2026-02-18)
- **Token & Cost Management guide** — documented recommended OpenClaw settings for context pruning, compaction, memory search, and sub-agent model config. Includes root cause analysis of $120 token leak, quick setup instructions, and verification steps.

### 0.5.0 (2026-02-17)
- **L0: Disk persistence for runtime repairs** — error-terminated tool calls repaired in `before_agent_start` are now written back to the JSONL session file (with backup). Prevents repair loops on restart that could brick sessions.
- **LF: File Write Guard** — blocks agent write/edit/exec to critical files (SOUL.md, AGENTS.md, openclaw.json). Only works after full process restart.

### 0.4.0 (2026-02-13)
- **L4+ External Content Scanner** — 16 patterns for indirect injection in tool results
- **Layer C: Privilege Separation** — blocks dangerous tools via `before_tool_call` when injection detected
- **Canary Token System** — exfiltration tripwire in agent context
- **Instruction density heuristic** — catches novel injection without specific pattern match
- Updated `/clawos` dashboard with L4+, LC, and canary status

### 0.3.0 (2026-02-06)
- Full 6-layer integration into OpenClaw plugin
- L0 register-time session scanning
- L4 signal detection with 50+ patterns
- Bootstrap file protection with hash tracking
- Memory pipeline with secret scrubbing

### 0.2.0 (2026-02-05)
- Initial plugin with L0 + L1
- Session integrity validation and repair
- Content provenance tagging

### 0.1.0 (2026-02-04)
- Proof of concept — standalone L4 signal scanner
