# 🦞 ClawOS

**An operating system built for AI agents.**

Not a wrapper. Not a framework. An OS — where agents are first-class processes with their own identity, memory, permissions, and security boundaries.

---

## The Idea

Today's AI agents run as guests inside human operating systems. They borrow tools, borrow filesystems, borrow network access — with no real isolation, no privilege model, and no way to verify their own integrity.

ClawOS starts from a different assumption: **what if the agent was a citizen, not a guest?**

An agent that boots with its own identity. That owns persistent memory across sessions. That has a security stack enforced *below* its reasoning layer — so even a compromised agent can't override its own guardrails. That can delegate to other agents with scoped permissions, not blind trust.

Not "AI in a container." An actual operating system abstraction where the agent is the process.

## What This Looks Like

- **Identity as a primitive.** Agents have a soul file, a memory store, and a trust profile — not just a system prompt. Identity persists across restarts, compactions, and model swaps.

- **Security below the agent.** The agent doesn't enforce its own safety — the OS does. Tool access, file permissions, and behavioral constraints are enforced at the gateway level. A prompt injection can influence the agent's reasoning but cannot make the OS execute a blocked action.

- **Memory that survives.** Not just context windows. Persistent, searchable, scoped memory — daily logs, long-term curated knowledge, per-project state. The agent wakes up and *knows* what happened yesterday.

- **Multi-agent as processes.** Agents delegate to other agents the way processes fork and exec. Scoped permissions, isolated workspaces, structured output. An orchestrator coordinates — it doesn't do the work itself.

- **The human is root.** Agents propose. Humans approve. External actions (emails, messages, deployments) require explicit authorization. The agent has opinions — it doesn't have unilateral power.

## Where It's Going

ClawOS is a long-term vision. The pieces are being built and tested in production:

- **[ProteClaw](https://github.com/yassinebkr/proteclaw)** — The security stack. 9 defense layers for OpenClaw agents: session integrity, injection detection, privilege separation, canary tokens, file write guards. Enforced at the gateway, outside agent control. *This is where ClawOS's security architecture lives now.*

- **Scratchy** — A spatial workbench where agents program the UI in real-time. Multi-agent teams, per-user backends, tool policies, live canvas rendering.

- **NullClaw integration** — Zig-based agent backend. 678 KB binary, ~1 MB RAM, <2ms startup. The foundation for running hundreds of isolated agent instances on commodity hardware.

Each piece works independently. Together, they're the beginning of something bigger.

## Why "ClawOS"

Because the best ideas start with a claw mark — a scratch on the surface that says *something was here, and it's not done yet.*

---

> *Built by [@yassinebkr](https://github.com/yassinebkr)*
