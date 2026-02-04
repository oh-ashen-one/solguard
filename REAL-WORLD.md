# 🔒 Real-World Exploits SolShield AI Would Catch

This document shows how SolShield AI's **142 patterns** map to real Solana exploits. These are based on public post-mortems and security analyses.

**Total preventable losses documented: $557M+**

---

## Summary Table

| Exploit | Date | Loss | SolShield AI Patterns | Status |
|---------|------|------|----------------------|--------|
| Wormhole Bridge | Feb 2022 | $326M | SOL002, SOL029, SOL142 | ✅ Covered |
| Mango Markets | Oct 2022 | $114M | SOL018 | ✅ Covered |
| Cashio | Mar 2022 | $52M | SOL001, SOL015, SOL134 | ✅ Covered |
| DEXX | Nov 2024 | $30M | SOL137, SOL039 | ✅ Covered |
| Crema Finance | Jul 2022 | $8.8M | SOL019, SOL131, SOL140 | ✅ Covered |
| Slope Wallet | Aug 2022 | $8M | SOL137, SOL039 | ✅ Covered |
| Audius | Jul 2022 | $6.1M | SOL132, SOL041 | ✅ Covered |
| Loopscale | Apr 2025 | $5.8M | SOL045, SOL139 | ✅ Covered |
| Raydium | Dec 2022 | $4.4M | SOL140, SOL138 | ✅ Covered |
| Nirvana Finance | Jul 2022 | $3.5M | SOL019, SOL133 | ✅ Covered |
| Pump.fun | May 2024 | $1.9M | SOL138 | ✅ Covered |
| Banana Gun | Sep 2024 | $1.4M | SOL141 | ✅ Covered |
| Cypher Protocol | Aug 2023 | $1M | SOL031, SOL138 | ✅ Covered |
| Thunder Terminal | Dec 2023 | $240K | SOL136, SOL138 | ✅ Covered |
| Web3.js Supply Chain | Dec 2024 | $160K | SOL136 | ✅ Covered |
| Solend Auth Bypass | Aug 2021 | $16K at risk | SOL135, SOL031 | ✅ Covered |

---

## 1. Wormhole Bridge Exploit ($326M, Feb 2022)

**What happened:** Attacker bypassed signature verification by exploiting a deprecated system program, forging valid Guardian signatures.

**SolShield AI Patterns:** `SOL002 - Missing Signer Check`, `SOL029 - Instruction Introspection`, `SOL142 - Signature Verification Bypass`

```rust
// ❌ VULNERABLE: Trusts sysvar without verification
pub fn verify_signatures(ctx: Context<VerifySignatures>) -> Result<()> {
    let instruction_sysvar = &ctx.accounts.instruction_sysvar;
    // Attacker can pass fake sysvar account
}
```

```rust
// ✅ FIXED: Proper verification
pub fn verify_signatures(ctx: Context<VerifySignatures>) -> Result<()> {
    require_keys_eq!(
        ctx.accounts.instruction_sysvar.key(),
        sysvar::instructions::ID,
        ErrorCode::InvalidSysvar
    );
}
```

**SolShield AI Output:**
```
[SOL142] Signature Verification Bypass
└─ lib.rs:42 — Sysvar used without ID verification
💡 Fix: require_keys_eq!(sysvar_account.key(), sysvar::instructions::ID)
```

---

## 2. Mango Markets Exploit ($114M, Oct 2022)

**What happened:** Attacker manipulated oracle price to artificially inflate collateral, then borrowed against it.

**SolShield AI Pattern:** `SOL018 - Oracle Manipulation Risk`

```rust
// ❌ VULNERABLE: Uses spot price without checks
pub fn calculate_collateral(ctx: Context<CalcCollateral>) -> Result<u64> {
    let price = ctx.accounts.oracle.price; // No staleness check!
    let collateral = user_tokens * price;
    Ok(collateral)
}
```

**SolShield AI Output:**
```
[SOL018] Oracle Manipulation Risk
└─ lib.rs:28 — Price feed used without staleness or TWAP check
💡 Fix: Verify oracle timestamp and use TWAP for large positions
```

---

## 3. Cashio Exploit ($52M, Mar 2022)

**What happened:** Missing validation allowed attacker to mint tokens by creating fake "collateral" accounts with worthless tokens.

**SolShield AI Patterns:** `SOL001 - Missing Owner Check`, `SOL015 - Type Cosplay`, `SOL134 - Infinite Mint Vulnerability`

```rust
// ❌ VULNERABLE: No validation on collateral account
#[derive(Accounts)]
pub struct MintTokens<'info> {
    pub collateral: AccountInfo<'info>,  // Not validated!
}
```

**SolShield AI Output:**
```
[SOL134] Infinite Mint Vulnerability
└─ lib.rs:15 — Token minting uses collateral but does not verify the root/source
💡 Fix: Verify collateral back to a trusted root: validate collateral.mint

[SOL001] Missing Owner Check
└─ lib.rs:15 — collateral: AccountInfo without owner validation
💡 Fix: Use Account<'info, T> or add owner constraint
```

---

## 4. DEXX Exploit ($30M, Nov 2024)

**What happened:** Private keys were exposed through improper key management, allowing attacker to drain user wallets.

**SolShield AI Pattern:** `SOL137 - Private Key Exposure`, `SOL039 - Memo and Logging`

**SolShield AI Output:**
```
[SOL137] Private Key Exposure Risk
└─ wallet.rs:42 — Code references private keys or keypairs
💡 Fix: Use PDAs for program-owned accounts. Never store or process private keys.
```

---

## 5. Crema Finance Exploit ($8.8M, Jul 2022)

**What happened:** Attacker created a fake tick account to manipulate transaction fee data, claiming excessive fees from liquidity pools.

**SolShield AI Patterns:** `SOL019 - Flash Loan Vulnerability`, `SOL131 - Tick Account Spoofing`, `SOL140 - CLMM Exploit`

```rust
// ❌ VULNERABLE: Tick account passed without owner verification
pub fn claim_fees(ctx: Context<ClaimFees>) -> Result<()> {
    let tick = &ctx.accounts.tick_account; // No owner check!
    let fees = calculate_fees_from_tick(tick)?;
    transfer_fees(fees)?;
}
```

**SolShield AI Output:**
```
[SOL131] Tick Account Spoofing
└─ lib.rs:56 — Tick account without owner verification
💡 Fix: Add owner constraint: #[account(owner = expected_program::ID)]

[SOL140] CLMM Exploit Vector
└─ lib.rs:58 — Fee calculation without proper checkpointing
💡 Fix: Store fee growth snapshot per position
```

---

## 6. Slope Wallet Drain ($8M, Aug 2022)

**What happened:** Private keys were accidentally logged and sent to a third-party analytics service.

**SolShield AI Pattern:** `SOL137 - Private Key Exposure`, `SOL039 - Memo and Logging`

**SolShield AI Output:**
```
[SOL137] Private Key Exposure Risk
└─ lib.rs:10 — Logging statement may expose sensitive key material
💡 Fix: Never log keys, secrets, or full account data
```

---

## 7. Audius Governance Exploit ($6.1M, Jul 2022)

**What happened:** Attacker submitted and executed malicious governance proposals, bypassing proper validation to transfer treasury funds.

**SolShield AI Patterns:** `SOL132 - Governance Proposal Injection`, `SOL041 - Governance Vulnerability`

```rust
// ❌ VULNERABLE: Proposal execution without proper checks
pub fn execute_proposal(ctx: Context<Execute>) -> Result<()> {
    // No quorum check, no timelock
    execute_treasury_transfer(ctx.accounts.proposal.amount)?;
}
```

**SolShield AI Output:**
```
[SOL132] Governance Proposal Injection
└─ lib.rs:45 — Proposal execution without quorum/threshold check
💡 Fix: require!(proposal.votes >= config.quorum && proposal.end_time < clock.unix_timestamp)

[SOL132] Governance Proposal Injection
└─ lib.rs:48 — Treasury operation without timelock
💡 Fix: Add timelock: require!(clock.unix_timestamp >= proposal.execute_after)
```

---

## 8. Nirvana Finance Exploit ($3.5M, Jul 2022)

**What happened:** Attacker used flash loans to manipulate the bonding curve, minting tokens at inflated rates.

**SolShield AI Patterns:** `SOL019 - Flash Loan Vulnerability`, `SOL133 - Bonding Curve Manipulation`

**SolShield AI Output:**
```
[SOL133] Bonding Curve Manipulation
└─ lib.rs:89 — Bonding curve without flash loan protection
💡 Fix: Add flash loan protection: check slot difference, implement cooldowns, or use TWAP

[SOL133] Bonding Curve Manipulation
└─ lib.rs:95 — Price derived from spot reserves without averaging
💡 Fix: Use time-weighted average price (TWAP) or external oracle
```

---

## 9. Pump.fun Employee Exploit ($1.9M, May 2024)

**What happened:** A former employee used retained access to drain protocol funds.

**SolShield AI Pattern:** `SOL138 - Insider Threat Vector`

**SolShield AI Output:**
```
[SOL138] Insider Threat Vector
└─ lib.rs:34 — Single authority with multiple critical powers
💡 Fix: Implement role separation: separate withdrawal, upgrade, and operational authorities

[SOL138] Insider Threat Vector
└─ lib.rs:67 — Admin can withdraw without multisig
💡 Fix: Require multisig (2-of-3 or 3-of-5) for any fund movements
```

---

## 10. Web3.js Supply Chain Attack ($160K, Dec 2024)

**What happened:** Malicious code was injected into the @solana/web3.js npm package, stealing private keys from applications.

**SolShield AI Pattern:** `SOL136 - Supply Chain Attack Vector`

**SolShield AI Output:**
```
[SOL136] Supply Chain Attack Vector
└─ Multiple files — Hardcoded external pubkey / Network calls detected
💡 Fix: Verify all dependencies, use lockfiles, audit external code
```

---

## 11. Solend Auth Bypass ($16K at risk, Aug 2021)

**What happened:** Attacker bypassed admin checks by creating a new lending market and passing it as an account they owned.

**SolShield AI Patterns:** `SOL135 - Liquidation Threshold Manipulation`, `SOL031 - Access Control`

**SolShield AI Output:**
```
[SOL135] Liquidation Threshold Manipulation
└─ lib.rs:112 — Reserve update without market ownership check
💡 Fix: Verify reserve belongs to the lending market: has_one = lending_market
```

---

## New Patterns Added (v2.0)

Based on our research of 2022-2025 exploits, we added 12 new patterns:

| ID | Pattern | Based On | Severity |
|----|---------|----------|----------|
| SOL131 | Tick Account Spoofing | Crema Finance | Critical |
| SOL132 | Governance Proposal Injection | Audius | Critical |
| SOL133 | Bonding Curve Manipulation | Nirvana Finance | Critical |
| SOL134 | Infinite Mint Vulnerability | Cashio | Critical |
| SOL135 | Liquidation Threshold Manipulation | Solend | Critical |
| SOL136 | Supply Chain Attack Vector | Web3.js | Critical |
| SOL137 | Private Key Exposure | Slope, DEXX | Critical |
| SOL138 | Insider Threat Vector | Pump.fun | High |
| SOL139 | Treasury Drain Attack | Multiple | Critical |
| SOL140 | CLMM/AMM Exploit | Crema, Raydium | Critical |
| SOL141 | Bot/Automation Compromise | Banana Gun | High |
| SOL142 | Signature Verification Bypass | Wormhole | Critical |

---

## Total Coverage

**142 vulnerability patterns** covering:
- Core Security (accounts, authority, signing)
- DeFi-specific (lending, AMM, oracles, flash loans)
- Governance and multisig
- Token operations and minting
- Cross-program interactions
- Supply chain and insider threats
- CLMM/concentrated liquidity

**$557M+ in documented exploits** that SolShield AI's patterns would have flagged.

---

## Disclaimer

These are simplified examples for illustration. Real-world vulnerabilities often involve complex interactions. SolShield AI is a detection tool, not a guarantee. Always conduct thorough manual review and professional audits for production code.

---

*"The best audit is the one that happens before deployment."*
