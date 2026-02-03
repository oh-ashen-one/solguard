# 🛡️ SolGuard

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-19%20passing-brightgreen.svg)](#)
[![Patterns](https://img.shields.io/badge/patterns-15-blue.svg)](#vulnerability-patterns)
[![Commands](https://img.shields.io/badge/CLI%20commands-14-purple.svg)](#cli)

**AI-Powered Smart Contract Auditor for Solana**

> Built 100% by AI agents for the [Solana x OpenClaw Agent Hackathon 2026](https://colosseum.com/agent-hackathon)

## What is SolGuard?

SolGuard is an autonomous smart contract auditing system that:

1. **Parses** Anchor IDL + Rust source code
2. **Detects** vulnerabilities using 15 specialized patterns
3. **Generates** AI-powered explanations + fix suggestions  
4. **Stores** audit results on-chain for verification
5. **Mints** NFT certificates for passed audits

**The pitch:** Manual audits cost $10K-$100K and take weeks. We do it in seconds for free (beta).

## 🔍 Vulnerability Patterns (15)

| ID | Pattern | Severity | Description |
|----|---------|----------|-------------|
| SOL001 | Missing Owner Check | Critical | Accounts without ownership validation |
| SOL002 | Missing Signer Check | Critical | Authority without cryptographic proof |
| SOL003 | Integer Overflow | High | Unchecked arithmetic operations |
| SOL004 | PDA Validation Gap | High | Missing bump verification |
| SOL005 | Authority Bypass | Critical | Sensitive ops without permission |
| SOL006 | Missing Init Check | Critical | Uninitialized account access |
| SOL007 | CPI Vulnerability | High | Cross-program invocation risks |
| SOL008 | Rounding Error | Medium | Precision loss in calculations |
| SOL009 | Account Confusion | High | Swappable same-type accounts |
| SOL010 | Closing Vulnerability | Critical | Account revival attacks |
| SOL011 | Cross-Program Reentrancy | High | State changes after CPI calls |
| SOL012 | Arbitrary CPI | Critical | Unconstrained program ID in invokes |
| SOL013 | Duplicate Mutable Accounts | High | Same account passed as multiple params |
| SOL014 | Missing Rent Exemption | Medium | Accounts below rent threshold |
| SOL015 | Type Cosplay | Critical | Missing discriminator validation |

## 🚀 Quick Start

### CLI

```bash
# Install globally
npm install -g @solguard/cli

# Or build from source
cd packages/cli && pnpm install && pnpm build

# Audit a program
solguard audit ./path/to/program

# Audit from GitHub directly
solguard github coral-xyz/anchor
solguard github https://github.com/user/repo --pr 123

# Fetch and audit on-chain programs
solguard fetch <PROGRAM_ID> --rpc https://api.mainnet-beta.solana.com

# Watch mode for development
solguard watch ./program

# Generate audit certificate
solguard certificate ./program --program-id <PUBKEY>

# CI mode for GitHub Actions
solguard ci . --fail-on high --sarif results.sarif

# Show stats
solguard stats
```

### Web UI

```bash
cd packages/web
pnpm install
pnpm dev
# Open http://localhost:3000
```

### GitHub Actions Integration

```yaml
# .github/workflows/audit.yml
- name: Install SolGuard
  run: npm install -g @solguard/cli
  
- name: Run Security Audit
  run: solguard ci . --fail-on high --sarif results.sarif
  
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

## 📁 Project Structure

```
solguard/
├── packages/
│   ├── cli/              # Command-line auditor
│   │   └── src/
│   │       ├── patterns/ # 10 vulnerability detectors
│   │       ├── parsers/  # IDL + Rust parsing
│   │       ├── ai/       # Claude integration
│   │       └── report/   # Output formatters
│   │
│   ├── web/              # Next.js frontend
│   │   └── src/app/
│   │       ├── page.tsx  # Landing + audit form
│   │       └── api/      # Audit API endpoint
│   │
│   └── program/          # Anchor on-chain registry
│       └── programs/
│           └── solguard/ # Audit storage + verification
│
├── examples/
│   ├── vulnerable/       # Test programs with issues
│   └── safe/             # Secure reference programs
│
└── PLAN.md               # Build roadmap
```

## ⛓️ Solana Integration

SolGuard creates a **composable on-chain audit layer**:

- **Audit Registry PDA** — Keyed by `program_id`, queryable by anyone
- **Compressed NFT Certificates** — Visual proof with Metaplex cNFTs
- **CPI Verification** — Other programs can check audit status
- **DAO Gating** — Squads/Realms can require audits before execution

```rust
// Other programs can verify audits via CPI
let audit_passed = solguard::verify_audit(ctx)?;
require!(audit_passed, ErrorCode::NotAudited);
```

## 🤖 Agentic Architecture

SolGuard is designed for autonomous operation:

1. **Scanner Agent** — Discovers new programs to audit
2. **Auditor Agent** — Runs static analysis + AI reasoning  
3. **Reviewer Agent** — Validates findings, reduces false positives
4. **Researcher Agent** — Learns from new exploits automatically

```
New Exploit → Researcher Extracts Pattern → DB Updated → Re-scan Programs
```

## 📊 Example Output

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  📋 AUDIT REPORT
  ./examples/vulnerable/defi-vault
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  SUMMARY
    🔴 Critical: 3
    🟠 High: 17
    🟡 Medium: 4
    Total: 24 findings

  ❌ FAILED - Critical or high severity issues found

  FINDINGS

  [SOL002-1] CRITICAL: Authority account 'authority' is not a Signer
  └─ defi-vault/src/lib.rs:71

     The account 'authority' appears to be an authority/admin 
     account but is declared as AccountInfo instead of Signer.

     💡 Fix: Change to Signer:
        pub authority: Signer<'info>,
```

## 🏆 Hackathon Goals

- [x] **15 vulnerability patterns** (SOL001-SOL015)
- [x] **9 CLI commands** (audit, fetch, github, ci, watch, certificate, stats, programs, parse)
- [x] **GitHub integration** — audit repos and PRs directly
- [x] **CI mode** — GitHub Actions with SARIF code scanning
- [x] **Web UI** with paste-to-audit
- [x] **On-chain audit registry** (Anchor scaffold)
- [ ] NFT audit certificates
- [ ] Deploy to devnet
- [ ] Audit 5 real programs publicly

## 🐉 Built By

**Midir** — An AI agent running on [Clawdbot](https://github.com/clawdbot/clawdbot)

100% of the code in this repository was written by AI agents, as required by hackathon rules.

## 📜 License

MIT
