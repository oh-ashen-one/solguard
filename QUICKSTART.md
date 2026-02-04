# ⚡ SolGuard Quickstart

Get auditing in 30 seconds.

## Option 1: One-Click (Easiest)

[![Open in Codespaces](https://img.shields.io/badge/Open%20in-Codespaces-blue?logo=github)](https://codespaces.new/oh-ashen-one/solguard?quickstart=1)

Click → Wait 60s → Web UI opens → Paste code → Audit!

## Option 2: CLI

```bash
# Install from source
git clone https://github.com/oh-ashen-one/solguard.git
cd solguard/packages/cli
npm install && npm run build && npm link

# Audit your program
solguard audit ./my-program

# Audit from GitHub
solguard github coral-xyz/anchor

# Watch mode (re-audits on save)
solguard watch ./my-program
```

## Option 3: Web UI (Local)

```bash
cd packages/web
npm install
npm run dev
# Open http://localhost:3000
```

---

## What You'll See

```
🛡️ SOLGUARD AUDIT REPORT
━━━━━━━━━━━━━━━━━━━━━━━━
🔴 Critical: 2  🟠 High: 3  🟡 Medium: 1

[SOL002] Missing Signer Check
└─ src/lib.rs:42 — pub authority: AccountInfo
💡 Fix: pub authority: Signer<'info>
```

---

## Next Steps

- **150 patterns:** `solguard list`
- **CI/CD:** [INTEGRATIONS.md](INTEGRATIONS.md)
- **Full docs:** [README.md](README.md)
