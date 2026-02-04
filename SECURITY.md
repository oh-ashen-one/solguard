# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | ✅ Current (Beta)  |

## Reporting a Vulnerability

SolShield AI is a security auditing tool, so we take security seriously. If you discover a vulnerability:

### In the SolShield AI Tool Itself

1. **DO NOT** open a public issue
2. Email: security@SolShield AI.dev (or open a private GitHub Security Advisory)
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

We will acknowledge within 48 hours and provide a timeline for resolution.

### In the Detection Patterns

If you find that SolShield AI:
- **Misses** a vulnerability (false negative)
- **Incorrectly flags** safe code (false positive)
- Has a **pattern that can be bypassed**

Please open a GitHub issue! These help us improve detection accuracy.

## Scope

### In Scope
- CLI application (`@SolShield AI/cli`)
- Web UI (`packages/web`)
- On-chain program (`packages/program`)
- Detection patterns (`packages/cli/src/patterns/`)
- API endpoints

### Out of Scope
- Third-party dependencies (report to upstream)
- Social engineering attacks
- Physical security

## Security Measures

### CLI
- No network calls except explicit GitHub/RPC fetches
- Code is parsed locally, not sent to external servers
- API mode is opt-in

### Web UI
- Audit requests processed server-side
- No code stored after audit completes
- No authentication required (stateless)

### On-Chain Program
- All accounts validated with Anchor constraints
- Admin operations require registry authority
- Dispute mechanism for challenging incorrect audits

## Acknowledgments

We appreciate responsible disclosure. Security researchers who report valid vulnerabilities will be acknowledged in our README (with permission).

---

*Building secure tools to help others build secure code.*
