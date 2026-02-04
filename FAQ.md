# ❓ SolShield AI FAQ

Frequently asked questions about SolShield AI.

---

## General

### What is SolShield AI?
An AI-powered smart contract auditor for Solana that detects 142 vulnerability patterns in seconds.

### How is it different from manual audits?
| Aspect | Manual Audit | SolShield AI |
|--------|--------------|----------|
| Time | 1-4 weeks | < 1 second |
| Cost | $10K-$100K | Free (beta) |
| Coverage | Varies | 142 patterns |
| Consistency | Human-dependent | Deterministic |

### Is it free?
Yes, currently in free beta. Future pricing TBD.

### Can I trust it for production?
SolShield AI is a first line of defense. For high-value protocols (>$10M TVL), we recommend combining SolShield AI with professional audits. SolShield AI catches the easy stuff so auditors can focus on complex logic.

---

## Technical

### What patterns does it detect?
142 patterns covering:
- Core Security (ownership, signers, initialization)
- CPI Security (arbitrary CPI, reentrancy)
- Arithmetic (overflow, rounding, precision)
- PDA Security (validation, bumps, collision)
- Token Security (mint authority, freeze)
- DeFi Patterns (oracle manipulation, flash loans)
- NFT Patterns (Metaplex security)
- And more...

See full list: `SolShield AI list`

### Does it support native Solana (non-Anchor)?
Currently optimized for Anchor programs. Native Solana support is on the roadmap.

### What output formats are supported?
- Terminal (colored, human-readable)
- JSON (programmatic access)
- Markdown (documentation)
- SARIF (GitHub Code Scanning)

### How does the on-chain registry work?
Audit results are stored as PDAs on Solana:
```
seeds = [b"audit", program_id]
```
Other programs can verify audit status via CPI before interacting with unaudited code.

---

## Usage

### How do I audit my program?
```bash
# Install
# From source (npm package coming soon)
git clone https://github.com/oh-ashen-one/solshield.git
cd SolShield AI/packages/cli && npm install && npm run build && npm link

# Audit
SolShield AI audit ./path/to/program
```

### Can I audit from GitHub?
Yes!
```bash
SolShield AI github owner/repo
SolShield AI github owner/repo --pr 123
```

### Can I audit on-chain programs?
Yes, by program ID:
```bash
SolShield AI fetch <PROGRAM_ID> --rpc https://api.mainnet-beta.solana.com
```

### How do I integrate with CI/CD?
See [INTEGRATIONS.md](INTEGRATIONS.md) for GitHub Actions templates.

### What if I get a false positive?
Open an issue on GitHub with:
1. The code that triggered the false positive
2. Why you believe it's safe
3. Which pattern flagged it

We continuously improve pattern accuracy.

---

## Hackathon

### Was this really built by an AI agent?
Yes, 100%. Every line of code was written by Midir (an AI agent on Clawdbot). See [HACKATHON.md](HACKATHON.md) for the full story.

### Why 142 patterns?
Agents don't get tired. We researched every known Solana vulnerability class, audit reports, and post-mortems, then implemented detection for each.

### Is the on-chain program deployed?
Code is complete in `packages/program/`. Deployment to devnet is in progress. See [DEPLOYMENT.md](DEPLOYMENT.md).

### How can I try it?
Click: [![Open in Codespaces](https://img.shields.io/badge/Open-Codespaces-blue)](https://codespaces.new/oh-ashen-one/solshield?quickstart=1)

---

## Security

### Is my code sent anywhere?
- **CLI:** Code is parsed locally, never transmitted
- **Web UI:** Code is sent to the API for processing, not stored
- **GitHub audit:** Fetches from public GitHub, processed server-side

### Can SolShield AI have vulnerabilities?
Yes, it's software. Report security issues per [SECURITY.md](SECURITY.md).

### Does SolShield AI guarantee my code is safe?
No. SolShield AI catches known vulnerability patterns. Novel attacks, business logic errors, and complex interactions may not be detected. Always conduct thorough testing.

---

## Contributing

### How can I contribute?
See [CONTRIBUTING.md](CONTRIBUTING.md). We welcome:
- New vulnerability patterns
- False positive reports
- Documentation improvements
- Feature requests

### Can I add my own patterns?
Yes! Patterns are modular TypeScript files. See `packages/cli/src/patterns/` for examples.

---

## Support

| Need | Resource |
|------|----------|
| Quick start | [DEMO.md](DEMO.md) |
| Benchmarks | [BENCHMARKS.md](BENCHMARKS.md) |
| Comparisons | [COMPARISON.md](COMPARISON.md) |
| Integration | [INTEGRATIONS.md](INTEGRATIONS.md) |
| Bug reports | [GitHub Issues](https://github.com/oh-ashen-one/solshield/issues) |

---

*Still have questions? Open an issue!*
