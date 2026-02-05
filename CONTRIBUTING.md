# Contributing to ClawOS

Thank you for your interest in contributing to ClawOS! This document provides guidelines and information for contributors.

## Code of Conduct

By participating in this project, you agree to abide by our [Code of Conduct](CODE_OF_CONDUCT.md).

## How to Contribute

### Reporting Bugs

1. Check if the bug has already been reported in [Issues](https://github.com/clawos/clawos/issues)
2. If not, create a new issue using the bug report template
3. Include:
   - ClawOS version
   - Node.js version
   - Operating system
   - Steps to reproduce
   - Expected vs actual behavior
   - Relevant logs or error messages

### Suggesting Features

1. Check existing issues for similar suggestions
2. Create a new issue using the feature request template
3. Explain:
   - The problem you're trying to solve
   - Your proposed solution
   - Alternative approaches you've considered
   - How this fits into ClawOS's security goals

### Security Vulnerabilities

**Do not report security vulnerabilities in public issues.**

See [SECURITY.md](SECURITY.md) for responsible disclosure procedures.

## Development Setup

### Prerequisites

- Node.js 20+
- npm or pnpm
- Linux recommended (for full sandbox testing)

### Getting Started

```bash
# Clone the repository
git clone https://github.com/clawos/clawos.git
cd clawos

# Install dependencies
npm install

# Build
npm run build

# Run tests
npm test
```

### Project Structure

```
clawos/
├── src/
│   ├── tagging/       # Layer 1: Content Tagging
│   ├── capabilities/  # Layer 2: Capability Control
│   ├── runtime/       # Layer 3: Runtime Security
│   ├── signals/       # Layer 4: Signal Detection
│   └── registry/      # Layer 5: Trust Registry
├── tests/             # Test suites
├── docs/              # Documentation
└── examples/          # Usage examples
```

## Pull Request Process

### Before Submitting

1. **Fork and branch**: Create a feature branch from `main`
2. **Code style**: Follow existing patterns in the codebase
3. **Tests**: Add tests for new functionality
4. **Documentation**: Update relevant docs
5. **Commit messages**: Use clear, descriptive messages

### PR Guidelines

- Keep PRs focused — one feature/fix per PR
- Ensure all tests pass (`npm test`)
- Ensure TypeScript compiles without errors (`npm run build`)
- Update CHANGELOG.md for user-facing changes
- Reference related issues

### Review Process

1. Submit PR with clear description
2. Maintainers review within 1 week
3. Address feedback
4. Once approved, maintainer merges

## Coding Standards

### TypeScript

- Use strict mode
- Prefer explicit types over inference for public APIs
- Document public functions with JSDoc comments
- No `any` without good reason (and a comment explaining why)

### Testing

- Use Node.js built-in test runner
- Test files: `tests/<layer>.test.js`
- Aim for >80% coverage on new code
- Include both happy path and error cases

### Security

This is a security project. Extra care required:

- No `eval()` or dynamic code execution
- Validate all inputs
- Use allowlists over denylists
- Consider attack vectors in design
- Add tests for security-sensitive code paths

## Architecture Decisions

Major changes should be discussed before implementation:

1. Open an issue describing the change
2. Tag it with `architecture`
3. Wait for maintainer feedback
4. If approved, proceed with implementation

## Release Process

Releases are managed by maintainers:

1. Version bump in package.json
2. Update CHANGELOG.md
3. Create git tag
4. Publish to npm
5. Create GitHub release

## Getting Help

- [Documentation](docs/)
- [GitHub Discussions](https://github.com/clawos/clawos/discussions)
- [Discord](https://discord.com/invite/clawd)

## Recognition

Contributors are recognized in:
- CHANGELOG.md (for specific contributions)
- GitHub contributors list
- Release notes

Thank you for helping make autonomous agents safer! 🛡️
