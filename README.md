# ClawOS — Security Architecture for Autonomous Agents

Production-ready, open-source security layer that solves prompt injection, capability control, and agent isolation.

## Architecture (6 Layers)

```
┌─────────────────────────────────────────────────────────┐
│  Layer 5: Trust Registry                                │
│  Verified sources, signed manifests, vuln scanning      │
├─────────────────────────────────────────────────────────┤
│  Layer 4: Signal Detection                              │
│  Pattern matching + heuristics (advisory, never blocks) │
├─────────────────────────────────────────────────────────┤
│  Layer 3: Runtime Security                              │
│  Process isolation, behavioral bounds, anomaly monitor  │
├─────────────────────────────────────────────────────────┤
│  Layer 2: Capability Control                            │
│  Skill manifests, permission enforcement, action gating │
├─────────────────────────────────────────────────────────┤
│  Layer 1: Content Tagging                               │
│  Source tracking, trust levels, provenance propagation  │
├─────────────────────────────────────────────────────────┤
│  Layer 0: Session Integrity         ◄── FOUNDATION      │
│  State validation, checkpoints, atomic ops, recovery    │
└─────────────────────────────────────────────────────────┘
```

## Design Principles

1. **Tag, don't filter** — Content is labeled with provenance, not silently dropped
2. **Advisory over blocking** — Signal detection flags, it doesn't gatekeep
3. **Capabilities are explicit** — Everything is denied by default, permitted by manifest
4. **Isolation is proportional** — Lightweight for skills, heavier for untrusted MCP servers
5. **Performance is non-negotiable** — <50ms p99 total overhead, <500MB memory

## Project Structure

```
clawos/
├── src/
│   ├── integrity/      # Layer 0: Session Integrity
│   ├── tagging/        # Layer 1: Content Tagging
│   ├── capabilities/   # Layer 2: Capability Control
│   ├── runtime/        # Layer 3: Runtime Security
│   ├── signals/        # Layer 4: Signal Detection
│   └── registry/       # Layer 5: Trust Registry
├── tests/              # Test suites per layer
├── docs/               # Architecture docs & specs
└── examples/           # Integration examples
```

## Implementation Roadmap

| Phase | Layer | Timeline | Status |
|-------|-------|----------|--------|
| 0 | Session Integrity | Week 0 | ✅ Complete |
| 1a | Content Tagging | Weeks 1-3 | ✅ Complete |
| 1b | Capability Control | Weeks 3-6 | ✅ Complete |
| 2a | Runtime Security | Weeks 7-12 | ✅ Complete |
| 2b | Signal Detection | Weeks 10-12 | 📋 Planned |
| 3  | Trust Registry | Weeks 13+ | 📋 Planned |

## Technical Constraints

- Local execution (no external API dependencies for core)
- Linux primary target (Debian/Ubuntu)
- Node.js runtime (matches OpenClaw)
- Apache 2.0 license

## Integration

Designed as an OpenClaw plugin first, standalone library second.
Hook point: tool execution pipeline (wraps existing calls, non-invasive).
