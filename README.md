# ClawOS

**ClawOS** was an early exploration into building an operating system-level security architecture for autonomous AI agents.

## Vision

As AI agents gain access to tools, files, shell commands, and messaging — the attack surface grows exponentially. A single prompt injection hidden in a web page or document can hijack an agent into exfiltrating data, running arbitrary commands, or modifying its own identity.

ClawOS was designed around one principle: **the agent cannot be trusted to secure itself**. Security enforcement must happen *outside* the agent's control, at the runtime level — like an OS kernel enforcing permissions on user-space processes.

The architecture explored multi-layered defense: session integrity, content trust tagging, signal detection, privilege separation, and file protection — all enforced at the gateway level, invisible to and unreachable by the agent.

## Status

The security components of ClawOS have evolved into an active project with a clearer scope and identity. This repository is preserved for historical reference.

## Author

Built by [@yassinebkr](https://github.com/yassinebkr) — started February 2026.

## License

MIT
