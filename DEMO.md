# 🎬 SolGuard Demo Guide

> Quick guide for hackathon judges to evaluate SolGuard

---

## ⚡ FASTEST: One-Click Demo (No Setup!)

### Option A: GitHub Codespaces (Recommended)
[![Open in GitHub Codespaces](https://img.shields.io/badge/Open%20in-GitHub%20Codespaces-blue?logo=github)](https://codespaces.new/oh-ashen-one/solguard?quickstart=1)

1. Click the badge above (or [this link](https://codespaces.new/oh-ashen-one/solguard?quickstart=1))
2. Wait ~60 seconds for environment to spin up
3. Web UI opens automatically at port 3000
4. Click **"🔓 Vulnerable Vault"** → **"🔍 Run Security Audit"**
5. See instant vulnerability detection!

### Option B: Gitpod
[![Open in Gitpod](https://img.shields.io/badge/Open%20in-Gitpod-orange?logo=gitpod)](https://gitpod.io/#https://github.com/oh-ashen-one/solguard)

1. Click the badge above
2. Authorize Gitpod if prompted
3. Web UI starts automatically
4. Same steps as above

> **Why one-click?** Judges are busy. We respect your time. No `npm install` needed.

---

## 🖥️ Local Setup (If You Prefer)

### Web UI
```bash
cd packages/web
pnpm install
pnpm dev
# Open http://localhost:3000
```

### CLI
```bash
cd packages/cli
pnpm install
pnpm build
npm link

# Audit our vulnerable example
solguard audit ../examples/vulnerable/token-vault
```

### Test Suite
```bash
cd packages/cli
pnpm test
# All 19 tests should pass
```

---

## 🔍 What to Look For

### 1. Pattern Detection (150 patterns)
The audit should detect:
- **SOL002** - Missing signer checks
- **SOL003** - Integer overflow risks  
- **SOL005** - Authority bypass
- **SOL007** - CPI vulnerabilities
- And 126 more...

### 2. AI-Powered Explanations
Each finding includes:
- Clear description of the vulnerability
- Location in code (file + line number)
- **💡 Fix suggestion** with corrected code

### 3. Severity Classification
- 🔴 **Critical** - Immediate exploit risk
- 🟠 **High** - Significant vulnerability
- 🟡 **Medium** - Potential issue
- 🔵 **Low** - Best practice

---

## 📁 Key Files to Review

| File | Purpose |
|------|---------|
| `packages/cli/src/patterns/` | 150 vulnerability detectors |
| `packages/cli/src/test/` | Test suite (19 tests) |
| `packages/web/src/app/page.tsx` | Web UI with example buttons |
| `packages/program/programs/solguard/src/lib.rs` | On-chain audit registry |
| `examples/vulnerable/` | Test programs with known issues |
| `examples/safe/` | Secure reference implementations |

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         USER INPUT                               │
│        (Paste code, GitHub URL, or on-chain Program ID)         │
└─────────────────────┬───────────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────────┐
│                      PARSING LAYER                               │
│   Rust Parser (tree-sitter) │ IDL Parser │ GitHub/RPC Fetcher   │
└─────────────────────┬───────────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────────┐
│                    DETECTION ENGINE                              │
│            150 VULNERABILITY PATTERNS (SOL001-SOL150)           │
│   Core │ CPI │ Token │ PDA │ DeFi │ NFT │ Anchor │ Advanced    │
└─────────────────────┬───────────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────────┐
│                      OUTPUT LAYER                                │
│     Terminal Report │ JSON │ Markdown │ SARIF (GitHub CI)       │
└─────────────────────────────────────────────────────────────────┘
```

---

## 🤖 Built by AI

This entire codebase was written by **Midir**, an AI agent running on [Clawdbot](https://github.com/clawdbot/clawdbot).

- Zero human-written code
- Continuous improvement via automated review/build cycles
- Self-documenting as it builds

See [HACKATHON.md](HACKATHON.md) for the full agent journey.

---

## 📄 Sample Reports

See what SolGuard output looks like:
- [Failed audit example](examples/sample-reports/vulnerable-vault-report.md) — 4 critical findings
- [Passed audit example](examples/sample-reports/secure-vault-report.md) — Clean with certificate

---

**Questions?** Open an issue or check the README.
