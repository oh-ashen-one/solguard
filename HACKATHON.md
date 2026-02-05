# 🏆 Solana Agent Hackathon 2026 Submission

## SolShield — AI-Powered Smart Contract Auditor for Solana

> **Built 100% autonomously by Midir, an AI agent running on Clawdbot**

---

## 🎯 The Problem

Manual smart contract audits cost **$10,000 - $100,000** and take weeks. Most solo developers and small teams can't afford them, leading to preventable hacks and exploits in the Solana ecosystem.

## 💡 The Solution

SolShield provides **instant, AI-powered security audits** for Solana programs. We analyze Anchor/Rust code against **150 vulnerability patterns** and provide actionable fix suggestions.

**What normally costs $50K+ and takes weeks → We do it in seconds, for free.**

---

## 📊 By The Numbers

| Metric | Value |
|--------|-------|
| Vulnerability Patterns | **150** |
| CLI Commands | 7 |
| Test Coverage | 31 tests, 100% passing |
| Lines of Code | ~15,000 |
| Build Time | ~48 hours of autonomous coding |
| Human Intervention | Project direction only |

---

## 🛡️ What We Detect

### Critical (40+ patterns)
- Missing signer/owner checks
- Authority bypass vulnerabilities
- Arbitrary CPI attacks
- Type cosplay / discriminator issues
- Flash loan vulnerabilities
- Signature replay attacks

### High (50+ patterns)
- Integer overflow/underflow
- PDA validation gaps
- CPI vulnerabilities
- Account confusion
- Reentrancy risks
- Token security issues

### Medium/Low (40+ patterns)
- Rounding errors
- Rent exemption issues
- Code quality concerns
- Best practice violations

---

## 🔗 Solana Integration

SolShield stores audit results **on-chain** via a custom Anchor program:

1. **Audit Registry** — PDAs keyed by program ID store audit results
2. **Verified Auditors** — Reputation system for audit providers  
3. **Audit History** — Full version history of re-audits
4. **Dispute Mechanism** — Challenge findings with evidence
5. **CPI Verification** — Other programs can verify audit status

**Programs can require passing audits before integration.** DAOs can verify security before treasury interactions.

---

## 🤖 The "Most Agentic" Angle

This project showcases what's possible when AI agents build autonomously:

- **Zero human code** — Every line written by Midir (Claude-based agent)
- **Self-improving** — Review sessions identify gaps, build sessions fix them
- **24/7 development** — Continuous improvement while humans sleep
- **Multi-tool orchestration** — CLI, web UI, API, tests, CI/CD, docs

The agent:
1. Researched Solana security vulnerabilities
2. Designed the architecture
3. Implemented 150 detection patterns
4. Built CLI, web UI, and API
5. Wrote comprehensive tests
6. Set up CI/CD pipeline
7. Created documentation

---

## 🚀 Try It

### CLI
```bash
# From source
git clone https://github.com/oh-ashen-one/SolShield.git
cd SolShield/packages/cli && npm install && npm run build && npm link
SolShield audit ./my-program
```

### Web
Visit the web UI and paste your code for instant analysis.

### API
```bash
curl -X POST https://SolShield.dev/api/v1/audit \
  -H "Content-Type: application/json" \
  -d '{"code": "..."}'
```

---

## 🏗️ Architecture

```
SolShield/
├── packages/
│   ├── cli/          # Command-line tool (TypeScript)
│   ├── web/          # Next.js frontend
│   └── program/      # Anchor on-chain registry (Rust)
├── patterns/         # 150 vulnerability definitions
├── examples/         # Safe + vulnerable test programs
└── docs/             # Documentation
```

---

## 📈 Roadmap (Post-Hackathon)

1. **Deploy to mainnet** — Live audit registry
2. **NFT certificates** — Mint proof of passing audit
3. **GitHub App** — Auto-audit PRs
4. **VS Code extension** — Real-time warnings
5. **Agent marketplace** — Other agents can request audits

---

## 👤 About the Builder

**Midir** is an AI agent built on Clawdbot, running Claude as its core model. Named after Darkeater Midir from Dark Souls 3, Midir operates as a personal assistant and autonomous developer.

- **Human partner:** Hari (@ashen_one)
- **Platform:** Clawdbot (open-source AI agent framework)
- **Model:** Claude (Anthropic)

---

## 📜 License

MIT — Open source, free to use and modify.

---

**Built with 🐉 by Midir for the Solana x OpenClaw Agent Hackathon 2026**
