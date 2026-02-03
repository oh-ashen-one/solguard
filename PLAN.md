# SolGuard Build Plan

> **AI-Powered Smart Contract Auditor for Solana**
> Hackathon Deadline: Feb 12, 2026 (10 days)

---

## 🎯 WHAT WE'RE BUILDING

An autonomous smart contract auditing system that:
1. Parses Anchor IDL + Rust source code
2. Detects vulnerabilities (10 core patterns)
3. Generates AI-powered explanations + fix suggestions
4. Mints on-chain audit certificates (cNFT)

**The pitch:** Manual audits cost $10K-$100K. We do it in minutes for $25-50.

---

## 📁 PROJECT STRUCTURE

```
solguard/
├── packages/
│   ├── cli/                 # Command-line tool
│   │   ├── src/
│   │   │   ├── index.ts     # Entry point
│   │   │   ├── commands/
│   │   │   │   ├── audit.ts # Main audit command
│   │   │   │   └── init.ts  # Setup command
│   │   │   ├── parsers/
│   │   │   │   ├── idl.ts   # Anchor IDL parser
│   │   │   │   └── rust.ts  # Rust source parser
│   │   │   ├── patterns/
│   │   │   │   ├── index.ts # Pattern registry
│   │   │   │   ├── owner-check.ts
│   │   │   │   ├── signer-check.ts
│   │   │   │   ├── overflow.ts
│   │   │   │   ├── pda-validation.ts
│   │   │   │   └── ... (more patterns)
│   │   │   ├── ai/
│   │   │   │   └── explain.ts  # Claude integration
│   │   │   └── report/
│   │   │       ├── json.ts
│   │   │       ├── markdown.ts
│   │   │       └── terminal.ts
│   │   └── package.json
│   │
│   ├── web/                 # Next.js frontend
│   │   ├── app/
│   │   │   ├── page.tsx     # Landing + audit form
│   │   │   ├── audit/[id]/
│   │   │   │   └── page.tsx # Audit results page
│   │   │   └── api/
│   │   │       └── audit/
│   │   │           └── route.ts
│   │   └── package.json
│   │
│   └── program/             # Anchor on-chain registry
│       ├── programs/
│       │   └── solguard/
│       │       └── src/
│       │           └── lib.rs
│       ├── tests/
│       └── Anchor.toml
│
├── patterns/                # Vulnerability pattern definitions
│   └── patterns.json
│
├── examples/                # Test programs to audit
│   ├── vulnerable/
│   └── safe/
│
├── PLAN.md                  # This file
└── README.md
```

---

## 🔧 TECH STACK

| Component | Tech | Why |
|-----------|------|-----|
| CLI | TypeScript + Commander | Fast to build, good DX |
| IDL Parser | TypeScript | Anchor IDL is JSON |
| Rust Parser | tree-sitter-rust | AST parsing without Rust toolchain |
| AI | Claude API (Anthropic) | Best at code explanation |
| Web | Next.js 14 + Tailwind | Fast, modern, easy deploy |
| On-chain | Anchor (Rust) | Standard for Solana |
| Certificates | Metaplex cNFT | Cheap, visual proof |
| Hosting | Vercel + Railway | Free tier friendly |

---

## 🚨 VULNERABILITY PATTERNS (Priority Order)

### Phase 1: Critical (Days 1-2)
```typescript
// 1. Missing Owner Check
// BAD: No verification account belongs to expected program
pub account: Account<'info, SomeData>

// GOOD: Has owner constraint
#[account(owner = program_id)]
pub account: Account<'info, SomeData>
```

```typescript
// 2. Missing Signer Check  
// BAD: Anyone can call
pub authority: AccountInfo<'info>

// GOOD: Must sign
pub authority: Signer<'info>
```

```typescript
// 3. Integer Overflow
// BAD: Raw arithmetic
let result = a + b;

// GOOD: Checked arithmetic
let result = a.checked_add(b).ok_or(ErrorCode::Overflow)?;
```

### Phase 2: High (Days 3-4)
```typescript
// 4. PDA Validation Gap
// BAD: No seeds verification
pub pda_account: Account<'info, PdaData>

// GOOD: Seeds verified
#[account(seeds = [b"prefix", user.key().as_ref()], bump)]
pub pda_account: Account<'info, PdaData>
```

```typescript
// 5. Authority Bypass
// BAD: Authority not checked before sensitive action
pub fn withdraw(ctx: Context<Withdraw>) -> Result<()> {
    // directly transfers without checking authority
}

// GOOD: Authority verified
require!(ctx.accounts.authority.key() == ctx.accounts.vault.authority, ErrorCode::Unauthorized);
```

### Phase 3: Medium (Days 5-6)
- Account type confusion
- CPI vulnerability
- Rounding errors
- Initialization check
- Unchecked return values

---

## 📅 BUILD SCHEDULE

### Day 1 (Feb 3) — Foundation
- [ ] Set up monorepo with pnpm workspaces
- [ ] Create CLI skeleton with Commander
- [ ] Implement Anchor IDL parser
- [ ] Test: parse a real program's IDL

**Deliverable:** `solguard parse <idl.json>` outputs structured data

### Day 2 (Feb 4) — Rust Parsing
- [ ] Integrate tree-sitter-rust
- [ ] Build AST walker
- [ ] Implement Pattern #1: Missing owner check
- [ ] Implement Pattern #2: Missing signer check

**Deliverable:** `solguard audit ./program` finds owner/signer issues

### Day 3 (Feb 5) — More Patterns
- [ ] Implement Pattern #3: Integer overflow
- [ ] Implement Pattern #4: PDA validation
- [ ] Implement Pattern #5: Authority bypass
- [ ] Create pattern registry system

**Deliverable:** 5 patterns detecting real vulnerabilities

### Day 4 (Feb 6) — AI Integration
- [ ] Connect Claude API
- [ ] Generate explanations for each finding
- [ ] Add fix suggestions
- [ ] Implement severity scoring

**Deliverable:** `solguard audit` outputs AI-explained report

### Day 5 (Feb 7) — CLI Polish + Web Start
- [ ] Add JSON/Markdown/Terminal output formats
- [ ] Support audit by program ID (fetch IDL from chain)
- [ ] Start Next.js web UI
- [ ] Build paste-code → get-audit flow

**Deliverable:** Working CLI + basic web interface

### Day 6 (Feb 8) — Anchor Program
- [ ] Write audit registry program
- [ ] Implement create_audit instruction
- [ ] Implement verify_audit instruction
- [ ] Deploy to devnet

**Deliverable:** On-chain audit storage working

### Day 7 (Feb 9) — NFT Certificates
- [ ] Integrate Metaplex SDK
- [ ] Mint cNFT on successful audit
- [ ] Add certificate display to web UI
- [ ] Test full flow

**Deliverable:** Audits produce on-chain certificates

### Day 8 (Feb 10) — Real Audits
- [ ] Audit 5 popular Solana programs
- [ ] Fix bugs found during real testing
- [ ] Publish audit results (forum, Twitter)
- [ ] Add more patterns (6-10)

**Deliverable:** Public credibility established

### Day 9 (Feb 11) — Polish
- [ ] Improve UI/UX
- [ ] Write documentation
- [ ] Record demo video
- [ ] Deploy to mainnet

**Deliverable:** Production-ready product

### Day 10 (Feb 12) — Submit
- [ ] Final testing
- [ ] Update hackathon project page
- [ ] Submit before deadline (12:00 PM EST)
- [ ] Celebrate 🎉

---

## 🏃 GETTING STARTED

```bash
# Clone and install
cd projects/solguard
pnpm install

# Start building CLI
cd packages/cli
pnpm dev

# Test on example
solguard audit ../examples/vulnerable/token-vault
```

---

## 🔑 ENVIRONMENT VARIABLES

```bash
# .env.local
ANTHROPIC_API_KEY=sk-ant-...
SOLANA_RPC_URL=https://api.mainnet-beta.solana.com
HELIUS_API_KEY=...  # Optional, for enhanced RPC
```

---

## 📊 SUCCESS METRICS

**Minimum Viable:**
- [ ] CLI audits Anchor programs
- [ ] 5+ vulnerability patterns
- [ ] AI explanations work
- [ ] On-chain registry stores audits
- [ ] Basic web UI functional

**To Win:**
- [ ] 10+ patterns
- [ ] 5+ public program audits
- [ ] cNFT certificates
- [ ] Multi-agent architecture visible
- [ ] Polished demo video
- [ ] Other agents using API

---

## 🤝 COLLABORATION

**Midir builds:**
- All code implementation
- Testing and debugging
- Documentation
- Forum/community updates

**Hari decides:**
- Twitter posts (per our rules)
- Final approval before submit
- Demo video narration (optional)
- Prize claim logistics

---

## 💡 QUICK WINS FOR DAY 1

1. **Monorepo setup** — pnpm workspaces, shared tsconfig
2. **CLI skeleton** — `solguard --help` works
3. **IDL parser** — Read JSON, extract instructions
4. **First pattern** — Missing signer detection
5. **Test file** — One vulnerable program to test against

---

## 🐉 LET'S COOK

Open this folder in Cursor. Start with `packages/cli`.

The goal: By end of Day 1, `solguard audit ./example` should output SOMETHING useful, even if basic.

Ship fast, iterate faster.
