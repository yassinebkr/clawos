# Layer 1: Content Tagging — Specification

## Purpose

Every piece of data flowing through an agent system gets tagged with:
- **Source**: where it came from (who/what produced it)
- **Trust level**: how much it should be trusted (`system` | `user` | `tool` | `untrusted`)
- **Provenance**: the chain of transformations it went through

This is the foundation all other layers depend on.

## Tag Schema

```typescript
interface ContentTag {
  /** Unique tag ID for tracking */
  id: string;

  /** What produced this content */
  source: ContentSource;

  /** Trust level (determines what this content can influence) */
  trust: TrustLevel;

  /** Chain of sources that contributed to this content */
  provenance: ProvenanceEntry[];

  /** When this tag was created */
  timestamp: number;

  /** Optional metadata */
  meta?: Record<string, unknown>;
}

type TrustLevel = 'system' | 'user' | 'tool' | 'untrusted';

interface ContentSource {
  /** Source type */
  kind: 'system' | 'user' | 'tool' | 'agent' | 'external';

  /** Identifier (user ID, tool name, agent ID, URL, etc.) */
  id: string;

  /** Human-readable label */
  label?: string;
}

interface ProvenanceEntry {
  /** Source that touched this content */
  source: ContentSource;

  /** Trust level at this point in the chain */
  trust: TrustLevel;

  /** What happened (created, transformed, merged, etc.) */
  action: 'created' | 'transformed' | 'merged' | 'forwarded' | 'cached';

  /** Timestamp */
  timestamp: number;
}
```

## Tagged Content Wrapper

```typescript
interface TaggedContent<T = string> {
  /** The actual content */
  data: T;

  /** Security tag */
  tag: ContentTag;
}
```

## Trust Resolution

When multiple tagged contents are combined (e.g., agent generates output from multiple inputs):

```typescript
function resolveTrust(inputs: ContentTag[]): TrustLevel {
  const levels: Record<TrustLevel, number> = {
    system: 3,
    user: 2,
    tool: 1,
    untrusted: 0,
  };

  // Trust = minimum of all inputs (most restrictive wins)
  let minLevel: TrustLevel = 'system';
  for (const input of inputs) {
    if (levels[input.trust] < levels[minLevel]) {
      minLevel = input.trust;
    }
  }
  return minLevel;
}
```

## Tagging Points in OpenClaw

Where tags get applied in the message/execution flow:

### 1. Incoming Messages
```
User WhatsApp message → tag(source=user:+33xxx, trust=user)
System prompt         → tag(source=system:openclaw, trust=system)
Heartbeat             → tag(source=system:heartbeat, trust=system)
```

### 2. Tool Execution
```
Tool call request     → tag(source=agent:main, trust=<inherited>)
Tool output           → tag(source=tool:web_search, trust=tool)
External API response → tag(source=external:api.example.com, trust=untrusted)
```

### 3. Skill Execution
```
Skill input           → tag preserved from caller
Skill output          → tag(source=tool:skill:weather, trust=tool,
                            provenance=[...input_provenance, skill_execution])
```

### 4. MCP Server Communication
```
MCP request           → tag preserved + capability check
MCP response          → tag(source=external:mcp:server_name,
                            trust=<from_registry_tier>)
```

### 5. Memory Operations
```
Memory write          → tag preserved (written with original trust)
Memory read           → tag restored (content retains original trust level)
```

## API

### Core Functions

```typescript
/** Create a fresh tag for new content */
function createTag(source: ContentSource, trust: TrustLevel): ContentTag;

/** Wrap content with a tag */
function tag<T>(data: T, source: ContentSource, trust: TrustLevel): TaggedContent<T>;

/** Combine multiple tagged contents (trust = min of inputs) */
function merge<T>(contents: TaggedContent[], mergedData: T): TaggedContent<T>;

/** Check if content meets minimum trust level */
function meetsMinTrust(content: TaggedContent, minLevel: TrustLevel): boolean;

/** Extract provenance chain as human-readable string */
function traceProvenance(content: TaggedContent): string;

/** Serialize tag for transport (e.g., across process boundaries) */
function serializeTag(tag: ContentTag): string;

/** Deserialize tag */
function deserializeTag(serialized: string): ContentTag;
```

### Middleware Pattern (for OpenClaw integration)

```typescript
interface TaggingMiddleware {
  /** Tag incoming messages before they reach the agent */
  onMessage(message: RawMessage): TaggedContent<RawMessage>;

  /** Tag tool outputs before they're returned to the agent */
  onToolOutput(toolName: string, output: unknown): TaggedContent<unknown>;

  /** Tag agent responses before they're sent */
  onAgentResponse(response: string, inputTags: ContentTag[]): TaggedContent<string>;

  /** Verify trust level before allowing an action */
  checkTrust(content: TaggedContent, requiredLevel: TrustLevel): boolean;
}
```

## Storage & Transport

Tags must survive:
1. **In-memory passing** — zero-copy, just metadata attachment
2. **Process boundaries** — serialized as compact JSON header
3. **Persistence** — stored alongside content in memory files, DB, etc.
4. **Network transport** — included in MCP protocol messages

### Serialization Format

Compact JSON for transport, human-readable for debugging:

```json
{
  "ct": "1.0",
  "id": "tag_abc123",
  "src": {"k": "user", "id": "+33616058433"},
  "tr": "user",
  "pv": [
    {"src": {"k": "user", "id": "+33616058433"}, "tr": "user", "act": "created", "ts": 1738706400}
  ],
  "ts": 1738706400
}
```

Compact keys to minimize overhead in high-frequency scenarios.

## Performance Target

- Tag creation: <0.1ms
- Trust resolution: <0.1ms
- Serialization: <0.5ms
- Total Layer 1 overhead: <2ms p99

## Test Cases

### Trust Propagation
1. User message → tool call → tool output → agent response
   - Expected: agent response trust = `tool` (not `user`)

2. User message + web scrape content → agent response
   - Expected: agent response trust = `untrusted`

3. System prompt + user message → agent response (no tools)
   - Expected: agent response trust = `user`

4. Cached memory (originally untrusted) read back
   - Expected: trust = `untrusted` (preserved from original)

### Edge Cases
5. Empty provenance chain → error (everything must have a source)
6. Self-referential provenance → capped at depth 50
7. Tag serialization round-trip → lossless
8. Concurrent tag creation → unique IDs guaranteed
