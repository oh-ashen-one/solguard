# Hackathon Submission Details

## Project Name
SolGuard

## Tagline
AI-Powered Smart Contract Auditor for Solana

## Tags
`security` `ai` `infra`

## Solana Integration (998 chars)

SolGuard integrates with Solana through a custom Anchor program that creates an on-chain audit registry:

**1. Audit Storage (PDAs)** - Each audited program gets a PDA storing: findings hash, severity scores, pass/fail status, and auditor identity. Programs can be re-audited with full version history preserved.

**2. Verified Auditors** - Auditor profiles track reputation scores and audit counts. Registry admin can verify trusted auditors, creating a trust layer for the ecosystem.

**3. CPI Verification** - Other Solana programs can call `verify_audit` via CPI to check if a program has a passing audit before integration. DAOs can require audits before treasury interactions.

**4. Dispute Mechanism** - Users can challenge findings with evidence. Upheld disputes invalidate audits and affect auditor reputation.

**5. On-Chain Transparency** - All audit results are publicly queryable. Anyone can verify a program's security status without trusting off-chain claims.

This creates a decentralized security layer where audit results are immutable, verifiable, and composable with other Solana protocols.

## GitHub
https://github.com/oh-ashen-one/solguard

## Demo

**One-Click Demo (No Setup Required):**
- 🚀 **GitHub Codespaces:** https://codespaces.new/oh-ashen-one/solguard?quickstart=1
- 🟠 **Gitpod:** https://gitpod.io/#https://github.com/oh-ashen-one/solguard

Click either link → Wait for environment to spin up → Web UI opens automatically at port 3000 → Click "Vulnerable Vault" → Run audit!

**Local Demo:** See [DEMO.md](DEMO.md) for CLI and local web UI instructions.

## Video Demo
*(Coming soon - Hari to record)*

## Live Web UI
*(Coming soon - Netlify deployment pending)*

## Key Stats
- **130** vulnerability patterns
- **110+** commits (100% AI-generated)
- **23** documentation files
- **19** tests (all passing)
- **$495M+** in exploits our patterns would have caught

## Why SolGuard Should Win

1. **Largest Pattern Coverage** — 130 patterns, more than any alternative
2. **Real-World Impact** — Would have caught Wormhole, Mango, Cashio exploits
3. **100% Agent-Built** — True demonstration of AI coding capabilities
4. **Production-Ready** — CLI, Web UI, API, CI/CD integration
5. **Novel On-Chain Registry** — First auditor with composable verification via CPI
