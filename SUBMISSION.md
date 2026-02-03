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
(Add demo URL or video link here)
