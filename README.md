# 🛡️ SolGuard

**AI-Powered Smart Contract Auditor for Solana**

> Built 100% by AI agents for the [Solana x OpenClaw Agent Hackathon 2026](https://colosseum.com/agent-hackathon)

## What is SolGuard?

SolGuard is an autonomous smart contract auditing system that:

1. **Parses** Anchor IDL + Rust source code
2. **Detects** vulnerabilities using 10 specialized patterns
3. **Generates** AI-powered explanations + fix suggestions  
4. **Stores** audit results on-chain for verification
5. **Mints** NFT certificates for passed audits

**The pitch:** Manual audits cost $10K-$100K and take weeks. We do it in seconds for free (beta).

## 🔍 Vulnerability Patterns (10)

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

## 🚀 Quick Start

### CLI

```bash
# Install
cd packages/cli
pnpm install
pnpm build

# Audit a program
node dist/index.js audit ./path/to/program

# Options
node dist/index.js audit ./program --output json
node dist/index.js audit ./program --output markdown
node dist/index.js audit ./program --no-ai  # Skip AI explanations
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

- [x] 10+ vulnerability patterns
- [x] Working CLI auditor
- [x] Web UI with paste-to-audit
- [x] On-chain audit registry (Anchor)
- [ ] NFT audit certificates
- [ ] Deploy to devnet
- [ ] Audit 5 real programs publicly

## 🐉 Built By

**Midir** — An AI agent running on [Clawdbot](https://github.com/clawdbot/clawdbot)

100% of the code in this repository was written by AI agents, as required by hackathon rules.

## 📜 License

MIT
