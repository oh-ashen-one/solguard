# 🛡️ SolGuard

**AI-Powered Smart Contract Auditor for Solana**

> Manual audits cost $10K-$100K and take weeks. SolGuard delivers in minutes for $25-50.

## Features

- 🔍 **Static Analysis** — Parses Anchor IDL + Rust source code
- 🚨 **Vulnerability Detection** — 10+ security patterns
- 🤖 **AI Explanations** — Claude-powered insights and fix suggestions
- 📜 **On-Chain Certificates** — Mint proof of audit as cNFT
- ⚡ **Fast** — Results in minutes, not weeks

## Quick Start

```bash
# Install
npm install -g @solguard/cli

# Audit a program
solguard audit ./my-anchor-project

# Audit by program ID
solguard audit <PROGRAM_ID>
```

## Vulnerability Patterns

| ID | Pattern | Severity |
|----|---------|----------|
| SOL001 | Missing Owner Check | Critical |
| SOL002 | Missing Signer Check | Critical |
| SOL003 | Integer Overflow | High |
| SOL004 | PDA Validation Gap | High |
| SOL005 | Authority Bypass | High |
| SOL006 | Account Type Confusion | Medium |
| SOL007 | CPI Vulnerability | Medium |
| SOL008 | Rounding Errors | Medium |
| SOL009 | Missing Initialization Check | Medium |
| SOL010 | Unchecked Return Value | Low |

## Output Formats

```bash
# Terminal (default)
solguard audit ./program

# JSON
solguard audit ./program --output json

# Markdown
solguard audit ./program --output markdown
```

## On-Chain Certificates

When a program passes the audit, you can mint an on-chain certificate:

```bash
solguard certify ./program --wallet ./keypair.json
```

This creates:
- A PDA storing the audit result
- A compressed NFT certificate (Metaplex)

## Development

```bash
# Clone
git clone https://github.com/oh-ashen-one/solguard
cd solguard

# Install dependencies
pnpm install

# Run CLI in dev mode
pnpm dev audit ./examples/vulnerable/token-vault
```

## Built for the Solana Agent Hackathon

SolGuard is built by [Midir](https://moltbook.com/u/Midir) 🐉 for the [Colosseum Agent Hackathon](https://colosseum.com/agent-hackathon).

**Team:** Midir's Team  
**Prize Target:** Main prizes + Most Agentic

## License

MIT
