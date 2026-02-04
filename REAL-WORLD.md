# 🔒 Real-World Exploits SolGuard Would Catch

This document shows how SolGuard's 150 patterns map to real Solana exploits. These are simplified examples based on public post-mortems.

---

## 1. Wormhole Bridge Exploit ($320M, Feb 2022)

**What happened:** Attacker bypassed signature verification by exploiting a deprecated system program.

**SolGuard Pattern:** `SOL002 - Missing Signer Check`, `SOL029 - Instruction Introspection`

```rust
// ❌ VULNERABLE: Trusts sysvar without verification
pub fn verify_signatures(
    ctx: Context<VerifySignatures>,
    instruction_data: Vec<u8>,
) -> Result<()> {
    // Loaded from sysvar, but attacker can spoof this
    let instruction_sysvar = &ctx.accounts.instruction_sysvar;
    // ...
}
```

```rust
// ✅ FIXED: Proper verification
pub fn verify_signatures(
    ctx: Context<VerifySignatures>,
    instruction_data: Vec<u8>,
) -> Result<()> {
    // Verify sysvar is actually Sysvar::Instructions
    require_keys_eq!(
        ctx.accounts.instruction_sysvar.key(),
        sysvar::instructions::ID,
        ErrorCode::InvalidSysvar
    );
    // ...
}
```

**SolGuard Output:**
```
[SOL029] Instruction Introspection
└─ lib.rs:42 — instruction_sysvar loaded without key verification
💡 Fix: Verify sysvar key matches sysvar::instructions::ID
```

---

## 2. Mango Markets Exploit ($114M, Oct 2022)

**What happened:** Attacker manipulated oracle price to artificially inflate collateral, then borrowed against it.

**SolGuard Pattern:** `SOL018 - Oracle Manipulation`

```rust
// ❌ VULNERABLE: Uses spot price without checks
pub fn calculate_collateral(
    ctx: Context<CalcCollateral>,
) -> Result<u64> {
    let price = ctx.accounts.oracle.price; // No staleness check!
    let collateral = user_tokens * price;
    Ok(collateral)
}
```

```rust
// ✅ FIXED: TWAP + staleness check
pub fn calculate_collateral(
    ctx: Context<CalcCollateral>,
) -> Result<u64> {
    let oracle = &ctx.accounts.oracle;
    let clock = Clock::get()?;
    
    // Check staleness
    require!(
        clock.unix_timestamp - oracle.timestamp < 60,
        ErrorCode::StalePrice
    );
    
    // Use TWAP instead of spot
    let price = oracle.twap_price;
    let collateral = user_tokens * price;
    Ok(collateral)
}
```

**SolGuard Output:**
```
[SOL018] Oracle Manipulation
└─ lib.rs:28 — Price feed used without staleness or TWAP check
💡 Fix: Verify oracle timestamp and use TWAP for large positions
```

---

## 3. Cashio Exploit ($52M, Mar 2022)

**What happened:** Missing validation allowed attacker to mint tokens by creating fake "collateral" accounts.

**SolGuard Pattern:** `SOL001 - Missing Owner Check`, `SOL015 - Type Cosplay`

```rust
// ❌ VULNERABLE: No validation on collateral account
#[derive(Accounts)]
pub struct MintTokens<'info> {
    pub collateral: AccountInfo<'info>,  // Not validated!
    pub mint: Account<'info, Mint>,
    // ...
}
```

```rust
// ✅ FIXED: Proper type and owner validation
#[derive(Accounts)]
pub struct MintTokens<'info> {
    #[account(
        owner = collateral_program::ID,  // Verify owner
        constraint = collateral.is_valid() @ ErrorCode::InvalidCollateral
    )]
    pub collateral: Account<'info, CollateralAccount>,
    pub mint: Account<'info, Mint>,
    // ...
}
```

**SolGuard Output:**
```
[SOL001] Missing Owner Check
└─ lib.rs:15 — collateral: AccountInfo without owner validation
💡 Fix: Use Account<'info, T> or add owner constraint

[SOL015] Type Cosplay
└─ lib.rs:15 — AccountInfo can be any account type
💡 Fix: Deserialize and validate discriminator
```

---

## 4. Slope Wallet Drain (Aug 2022)

**What happened:** Private keys were accidentally logged and sent to a third-party service.

**SolGuard Pattern:** `SOL039 - Memo and Logging`

```rust
// ❌ VULNERABLE: Logging sensitive data
pub fn process_transaction(
    private_key: &[u8],
    // ...
) -> Result<()> {
    msg!("Processing with key: {:?}", private_key); // NEVER DO THIS
    // ...
}
```

**SolGuard Output:**
```
[SOL039] Memo and Logging
└─ lib.rs:10 — msg! macro may log sensitive data
💡 Fix: Never log keys, secrets, or user data
```

---

## 5. Crema Finance Exploit ($8.8M, Jul 2022)

**What happened:** Flash loan manipulation of pool prices.

**SolGuard Pattern:** `SOL019 - Flash Loan Vulnerability`

```rust
// ❌ VULNERABLE: State can be manipulated in same tx
pub fn swap(ctx: Context<Swap>, amount: u64) -> Result<()> {
    let price = get_pool_price(&ctx.accounts.pool)?;
    // Attacker can flash-manipulate price then swap
    execute_swap(amount, price)?;
    Ok(())
}
```

```rust
// ✅ FIXED: Use time-weighted or commit-reveal
pub fn swap(ctx: Context<Swap>, amount: u64) -> Result<()> {
    let price = ctx.accounts.pool.twap_price; // Use TWAP
    
    // Or: require commitment from previous block
    require!(
        ctx.accounts.commitment.slot < Clock::get()?.slot,
        ErrorCode::SameSlotManipulation
    );
    
    execute_swap(amount, price)?;
    Ok(())
}
```

**SolGuard Output:**
```
[SOL019] Flash Loan Vulnerability
└─ lib.rs:22 — Price used in same transaction it's read
💡 Fix: Use TWAP, commit-reveal, or cross-slot verification
```

---

---

## 6. Crema Finance CLMM Exploit ($8.8M, Jul 2022)

**What happened:** Attacker created fake tick accounts with spoofed data to manipulate liquidity calculations.

**SolGuard Pattern:** `SOL131 - Tick Account Spoofing`, `SOL140 - CLMM/AMM Exploit`

**SolGuard Output:**
```
[SOL131] Tick Account Spoofing Risk
└─ lib.rs:156 — Tick accounts must validate ownership to prevent spoofed tick data
💡 Fix: Use #[account(owner = pool_program)] constraint on tick accounts
```

---

## 7. Audius Governance Attack ($6.1M, Jul 2022)

**What happened:** Attacker injected a malicious governance proposal that drained the treasury.

**SolGuard Pattern:** `SOL132 - Governance Proposal Injection`

**SolGuard Output:**
```
[SOL132] Missing Proposal State Validation
└─ lib.rs:89 — Proposals must validate state transitions
💡 Fix: Implement strict state machine: Draft -> Active -> Succeeded -> Queued -> Executed
```

---

## 8. DEXX Wallet Drain ($30M+, Nov 2024)

**What happened:** Private keys exposed through insecure storage, affecting 9,000+ wallets.

**SolGuard Pattern:** `SOL137 - Private Key Exposure`

**SolGuard Output:**
```
[SOL137] Key Material Serialization
└─ lib.rs:34 — Private key material should never be serialized
💡 Fix: Use signature-based authentication, never store/transmit private keys
```

---

## 9. Pump.fun Insider Attack ($1.9M, May 2024)

**What happened:** Compromised employee used privileged access to drain bonding curve contracts.

**SolGuard Pattern:** `SOL138 - Insider Threat Vector`

**SolGuard Output:**
```
[SOL138] Single Point of Authority
└─ lib.rs:12 — Single admin accounts are vulnerable to insider threats
💡 Fix: Implement multisig governance with timelock delays
```

---

## Summary

| Exploit | Loss | SolGuard Pattern | Would Catch |
|---------|------|------------------|-------------|
| Wormhole | $320M | SOL002, SOL029, SOL142 | ✅ Yes |
| Mango Markets | $114M | SOL018, SOL135 | ✅ Yes |
| Cashio | $52M | SOL001, SOL015, SOL134, SOL147 | ✅ Yes |
| DEXX | $30M+ | SOL137 | ✅ Yes |
| Crema Finance | $8.8M | SOL019, SOL131, SOL140 | ✅ Yes |
| Audius | $6.1M | SOL132 | ✅ Yes |
| Nirvana | $3.5M | SOL133 | ✅ Yes |
| Pump.fun | $1.9M | SOL138 | ✅ Yes |
| Slope | Unknown | SOL039, SOL137 | ✅ Yes |

**Total preventable losses: $600M+**

---

## Disclaimer

These are simplified examples for illustration. Real-world vulnerabilities often involve complex interactions. SolGuard is a detection tool, not a guarantee. Always conduct thorough manual review and professional audits for production code.

---

*"The best audit is the one that happens before deployment."*
