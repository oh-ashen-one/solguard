# 🔒 Real-World Exploits SolShield AI Would Catch

This document shows how SolShield AI's 130 patterns map to real Solana exploits. These are simplified examples based on public post-mortems.

---

## 1. Wormhole Bridge Exploit ($320M, Feb 2022)

**What happened:** Attacker bypassed signature verification by exploiting a deprecated system program.

**SolShield AI Pattern:** `SOL002 - Missing Signer Check`, `SOL029 - Instruction Introspection`

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

**SolShield AI Output:**
```
[SOL029] Instruction Introspection
└─ lib.rs:42 — instruction_sysvar loaded without key verification
💡 Fix: Verify sysvar key matches sysvar::instructions::ID
```

---

## 2. Mango Markets Exploit ($114M, Oct 2022)

**What happened:** Attacker manipulated oracle price to artificially inflate collateral, then borrowed against it.

**SolShield AI Pattern:** `SOL018 - Oracle Manipulation`

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

**SolShield AI Output:**
```
[SOL018] Oracle Manipulation
└─ lib.rs:28 — Price feed used without staleness or TWAP check
💡 Fix: Verify oracle timestamp and use TWAP for large positions
```

---

## 3. Cashio Exploit ($52M, Mar 2022)

**What happened:** Missing validation allowed attacker to mint tokens by creating fake "collateral" accounts.

**SolShield AI Pattern:** `SOL001 - Missing Owner Check`, `SOL015 - Type Cosplay`

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

**SolShield AI Output:**
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

**SolShield AI Pattern:** `SOL039 - Memo and Logging`

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

**SolShield AI Output:**
```
[SOL039] Memo and Logging
└─ lib.rs:10 — msg! macro may log sensitive data
💡 Fix: Never log keys, secrets, or user data
```

---

## 5. Crema Finance Exploit ($8.8M, Jul 2022)

**What happened:** Flash loan manipulation of pool prices.

**SolShield AI Pattern:** `SOL019 - Flash Loan Vulnerability`

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

**SolShield AI Output:**
```
[SOL019] Flash Loan Vulnerability
└─ lib.rs:22 — Price used in same transaction it's read
💡 Fix: Use TWAP, commit-reveal, or cross-slot verification
```

---

## Summary

| Exploit | Loss | SolShield AI Pattern | Would Catch |
|---------|------|------------------|-------------|
| Wormhole | $320M | SOL002, SOL029 | ✅ Yes |
| Mango Markets | $114M | SOL018 | ✅ Yes |
| Cashio | $52M | SOL001, SOL015 | ✅ Yes |
| Slope | Unknown | SOL039 | ✅ Yes |
| Crema | $8.8M | SOL019 | ✅ Yes |

**Total preventable losses: $495M+**

---

## Disclaimer

These are simplified examples for illustration. Real-world vulnerabilities often involve complex interactions. SolShield AI is a detection tool, not a guarantee. Always conduct thorough manual review and professional audits for production code.

---

*"The best audit is the one that happens before deployment."*
