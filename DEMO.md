# 🎬 SolGuard Demo Guide

> Quick guide for hackathon judges to evaluate SolGuard

## 🚀 Option 1: Web UI (Fastest)

```bash
cd packages/web
pnpm install
pnpm dev
# Open http://localhost:3000
```

1. Click **"🔓 Vulnerable Vault"** button to load example code
2. Click **"🔍 Run Security Audit"**
3. See instant vulnerability detection with fix suggestions

## 🖥️ Option 2: CLI

```bash
# Install
cd packages/cli
pnpm install
pnpm build
npm link

# Audit our vulnerable example
solguard audit ../examples/vulnerable/token-vault

# Expected output: Multiple findings across severity levels
```

## 📋 Option 3: Test Suite

```bash
cd packages/cli
pnpm test
# All 19 tests should pass
```

---

## 🔍 What to Look For

### 1. Pattern Detection (130 patterns)
The audit should detect:
- **SOL002** - Missing signer checks
- **SOL003** - Integer overflow risks  
- **SOL005** - Authority bypass
- **SOL007** - CPI vulnerabilities
- And many more...

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
| `packages/cli/src/patterns/` | 130 vulnerability detectors |
| `packages/cli/src/test/` | Test suite (19 tests) |
| `packages/web/src/app/page.tsx` | Web UI with example buttons |
| `packages/program/programs/solguard/src/lib.rs` | On-chain audit registry |
| `examples/vulnerable/` | Test programs with known issues |
| `examples/safe/` | Secure reference implementations |

---

## 🏗️ Architecture Summary

```
User Input (code/URL) 
    → Parsing (Rust/IDL) 
    → Detection (130 patterns) 
    → Report (Terminal/JSON/SARIF)
    → On-chain Storage (Anchor PDA)
```

---

## ⚡ Quick Verification

```bash
# Verify patterns exist
ls packages/cli/src/patterns/*.ts | wc -l
# Should show many pattern files

# Run a quick audit
echo 'pub authority: AccountInfo' | solguard audit --stdin
# Should flag missing Signer constraint
```

---

## 🤖 Built by AI

This entire codebase was written by **Midir**, an AI agent running on Clawdbot.

- Zero human-written code
- Continuous improvement via review/build cycles
- Self-documenting as it builds

See [HACKATHON.md](HACKATHON.md) for the full story.

---

**Questions?** Open an issue or check the README.
