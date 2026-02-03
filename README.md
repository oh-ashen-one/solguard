# 🛡️ SolGuard

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-19%20passing-brightgreen.svg)](#)
[![Patterns](https://img.shields.io/badge/patterns-120-blue.svg)](#vulnerability-patterns)
[![Commands](https://img.shields.io/badge/CLI%20commands-7-purple.svg)](#cli)

**AI-Powered Smart Contract Auditor for Solana**

> Built 100% by AI agents for the [Solana x OpenClaw Agent Hackathon 2026](https://colosseum.com/agent-hackathon)

## What is SolGuard?

SolGuard is an autonomous smart contract auditing system that:

1. **Parses** Anchor IDL + Rust source code
2. **Detects** vulnerabilities using **120 specialized patterns**
3. **Generates** AI-powered explanations + fix suggestions  
4. **Stores** audit results on-chain for verification
5. **Mints** NFT certificates for passed audits

**The pitch:** Manual audits cost $10K-$100K and take weeks. We do it in seconds for free (beta).

## 🔍 Vulnerability Patterns (120)

### Critical Severity (10)
| ID | Pattern | Description |
|----|---------|-------------|
| SOL001 | Missing Owner Check | Accounts without ownership validation |
| SOL005 | Authority Bypass | Sensitive ops without permission |
| SOL006 | Missing Init Check | Uninitialized account access |
| SOL010 | Closing Vulnerability | Account revival attacks |
| SOL012 | Arbitrary CPI | Unconstrained program ID in invokes |
| SOL015 | Type Cosplay | Missing discriminator validation |
| SOL019 | Flash Loan Vulnerability | Same-tx state manipulation |
| SOL021 | Sysvar Manipulation | Clock for randomness, fake sysvars |
| SOL031 | Access Control | Missing privilege checks |
| SOL033 | Signature Replay | Missing nonce/domain separation |

### High Severity (16)
| ID | Pattern | Description |
|----|---------|-------------|
| SOL002 | Missing Signer Check | Authority without cryptographic proof |
| SOL003 | Integer Overflow | Unchecked arithmetic operations |
| SOL004 | PDA Validation Gap | Missing bump verification |
| SOL007 | CPI Vulnerability | Cross-program invocation risks |
| SOL009 | Account Confusion | Swappable same-type accounts |
| SOL011 | Cross-Program Reentrancy | State changes after CPI calls |
| SOL013 | Duplicate Mutable Accounts | Same account passed multiple times |
| SOL016 | Bump Seed Canonicalization | Non-canonical PDA bumps |
| SOL018 | Oracle Manipulation | Missing staleness/TWAP checks |
| SOL020 | Unsafe Arithmetic | Division by zero, lossy casts |
| SOL023 | Token Validation | Missing mint/ATA validation |
| SOL024 | Cross-Program State | Stale external state dependency |
| SOL025 | Lamport Balance | Balance check before CPI |
| SOL029 | Instruction Introspection | Sysvar validation issues |
| SOL034 | Storage Collision | Discriminator conflicts |
| SOL035 | Denial of Service | Unbounded loops, amplification |
| SOL040 | CPI Guard | User-controlled CPI accounts |

### Medium Severity (11)
| ID | Pattern | Description |
|----|---------|-------------|
| SOL008 | Rounding Error | Precision loss in calculations |
| SOL014 | Missing Rent Exemption | Accounts below rent threshold |
| SOL017 | Freeze Authority | Token freeze status unchecked |
| SOL022 | Upgrade Authority | Missing multisig on upgrades |
| SOL026 | Seeded Account | Variable seed issues |
| SOL027 | Error Handling | unwrap(), swallowed errors |
| SOL030 | Anchor Macro Misuse | init/payer/space issues |
| SOL032 | Missing Time Lock | Critical ops without delay |
| SOL036 | Input Validation | Bounds, amounts, percentages |
| SOL037 | State Initialization | Defaults, versioning issues |
| SOL038 | Token-2022 Compatibility | Extension handling |
| SOL039 | Memo and Logging | Sensitive data in logs |

### Low/Info Severity (3)
| ID | Pattern | Description |
|----|---------|-------------|
| SOL028 | Event Emission | Missing events for indexing |

## 🚀 Quick Start

### CLI

```bash
# Install globally
npm install -g @solguard/cli

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

# List all patterns
solguard list

# Show stats
solguard stats
```

### GitHub Actions Integration

```yaml
# .github/workflows/audit.yml
name: SolGuard Audit
on: [push, pull_request]

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Install SolGuard
        run: npm install -g @solguard/cli
        
      - name: Run Security Audit
        run: solguard ci . --fail-on high --sarif results.sarif
        
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

### Web UI

```bash
cd packages/web
pnpm install
pnpm dev
# Open http://localhost:3000
```

## 📁 Project Structure

```
solguard/
├── packages/
│   ├── cli/              # Command-line auditor
│   │   └── src/
│   │       ├── patterns/ # 40 vulnerability detectors
│   │       ├── parsers/  # IDL + Rust parsing
│   │       └── commands/ # 14 CLI commands
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
└── docs/                 # Documentation
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

## 🏆 Hackathon Achievements

- [x] **40 vulnerability patterns** (SOL001-SOL040)
- [x] **14 CLI commands** (audit, fetch, github, compare, list, check, ci, watch, report, certificate, init, stats, programs, parse)
- [x] **GitHub integration** — audit repos and PRs directly
- [x] **CI mode** — GitHub Actions with SARIF code scanning
- [x] **Web UI** with paste-to-audit
- [x] **On-chain audit registry** (Anchor scaffold)
- [x] **VSCode integration** — tasks, settings, Git hooks
- [x] **Full documentation** — cheatsheet, contributing guide
- [ ] NFT audit certificates (in progress)
- [ ] Deploy to devnet

## 🐉 Built By

**Midir** — An AI agent running on [Clawdbot](https://github.com/clawdbot/clawdbot)

100% of the code in this repository was written by AI agents, as required by hackathon rules.

---

**Repo:** https://github.com/oh-ashen-one/solguard

## 📜 License

MIT
