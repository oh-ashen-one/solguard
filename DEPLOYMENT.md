# 🚀 SolGuard Deployment Guide

This guide covers deploying both the **Web UI** and the **On-chain Program**.

---

## Web UI Deployment

### Option 1: Netlify (Recommended)

```bash
# Install Netlify CLI
npm install -g netlify-cli

# Navigate to web package
cd packages/web

# Login to Netlify
netlify login

# Deploy (follow prompts)
netlify deploy --prod
```

The `netlify.toml` is already configured.

### Option 2: Cloudflare Pages

```bash
# Install Wrangler
npm install -g wrangler

# Login
wrangler login

# Deploy
cd packages/web
npm run build
wrangler pages deploy .next
```

### Option 3: Railway

1. Connect GitHub repo at [railway.app](https://railway.app)
2. Set root directory to `packages/web`
3. Deploy automatically on push

---

## On-chain Program Deployment

This section explains how to deploy the SolGuard Anchor program to Solana devnet/mainnet.

---

## Prerequisites

- [Rust](https://rustup.rs/) installed
- [Solana CLI](https://docs.solana.com/cli/install-solana-cli-tools) installed
- [Anchor CLI](https://www.anchor-lang.com/docs/installation) installed
- SOL for deployment (~2-5 SOL for devnet)

```bash
# Verify installations
rustc --version
solana --version
anchor --version
```

---

## Option 1: Deploy via Anchor CLI (Recommended)

### 1. Configure Solana CLI

```bash
# Set to devnet for testing
solana config set --url devnet

# Create a new keypair (or use existing)
solana-keygen new -o ~/.config/solana/devnet.json

# Airdrop some SOL for deployment
solana airdrop 5
```

### 2. Build the Program

```bash
cd packages/program

# Install dependencies
yarn install

# Build with Anchor
anchor build
```

### 3. Get Program ID

```bash
# Get the program keypair address
solana address -k target/deploy/solguard-keypair.json
```

Update `declare_id!()` in `programs/solguard/src/lib.rs` with this address.

### 4. Deploy

```bash
anchor deploy --provider.cluster devnet
```

### 5. Verify Deployment

```bash
# Check program exists
solana program show <PROGRAM_ID>
```

---

## Option 2: Deploy via Solana Playground (No Local Setup)

1. Visit [Solana Playground](https://beta.solpg.io/)
2. Create new project → Select "Anchor"
3. Copy contents of `packages/program/programs/solguard/src/lib.rs`
4. Click "Build" → "Deploy"
5. Copy the deployed Program ID

---

## Option 3: Deploy via GitHub Codespaces

```bash
# In Codespaces terminal:

# Install Solana CLI
sh -c "$(curl -sSfL https://release.solana.com/stable/install)"
export PATH="$HOME/.local/share/solana/install/active_release/bin:$PATH"

# Install Anchor
cargo install --git https://github.com/coral-xyz/anchor avm --locked
avm install latest
avm use latest

# Configure for devnet
solana config set --url devnet
solana-keygen new

# Airdrop
solana airdrop 5

# Build and deploy
cd packages/program
anchor build
anchor deploy
```

---

## After Deployment

### 1. Update Program ID

Update these files with your deployed Program ID:
- `packages/program/programs/solguard/src/lib.rs` (declare_id!)
- `packages/program/Anchor.toml` (programs.devnet)
- `packages/cli/src/config.ts` (if applicable)

### 2. Initialize Registry

```typescript
// Using Anchor client
const tx = await program.methods
  .initializeRegistry()
  .accounts({
    registry: registryPDA,
    authority: wallet.publicKey,
    systemProgram: SystemProgram.programId,
  })
  .rpc();
```

### 3. Test CPI Verification

Other programs can verify audits via CPI:

```rust
// In another Anchor program
let cpi_accounts = VerifyAudit {
    audit: audit_account.to_account_info(),
    verifier: verifier.to_account_info(),
};
let cpi_ctx = CpiContext::new(solguard_program.to_account_info(), cpi_accounts);
let is_audited = solguard::cpi::verify_audit(cpi_ctx)?;
```

---

## Current Status

| Network | Status | Program ID |
|---------|--------|------------|
| Devnet | ⏳ Pending | TBD |
| Mainnet | ⏳ Pending | TBD |

---

## Troubleshooting

### "Insufficient funds"
```bash
solana airdrop 5  # Get more devnet SOL
```

### "Program too large"
```bash
# Extend program size
solana program extend <PROGRAM_ID> 50000
```

### "Account already exists"
The program was already deployed. Use `anchor upgrade` instead:
```bash
anchor upgrade target/deploy/solguard.so --program-id <PROGRAM_ID>
```

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    SolGuard Program                          │
├─────────────────────────────────────────────────────────────┤
│  create_audit()     → Store audit as PDA                    │
│  verify_audit()     → CPI-callable verification             │
│  update_audit()     → Re-audit with version history         │
│  register_auditor() → Create auditor profile                │
│  verify_auditor()   → Admin marks auditor as verified       │
│  create_dispute()   → Challenge audit findings              │
│  resolve_dispute()  → Admin resolves dispute                │
└─────────────────────────────────────────────────────────────┘

PDAs:
- [b"audit", program_id] → AuditReport
- [b"registry"] → AuditRegistry
- [b"auditor", authority] → AuditorProfile
- [b"history", audit, version] → AuditHistory
- [b"dispute", audit, disputer] → Dispute
```

---

*Need help? Open an issue on GitHub.*
