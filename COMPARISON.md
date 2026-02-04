# 🔍 SolGuard vs Alternatives

How does SolGuard compare to other Solana security tools?

## Feature Matrix

| Feature | SolGuard | Soteria | Sec3 | Manual Audit |
|---------|----------|---------|------|--------------|
| **Patterns** | 150 | ~20 | ~30 | Varies |
| **Speed** | < 1 sec | Minutes | N/A | Weeks |
| **Cost** | Free (beta) | Paid | Paid | $10K-$100K |
| **CLI** | ✅ | ✅ | ❌ | N/A |
| **Web UI** | ✅ | ❌ | ✅ | N/A |
| **GitHub CI** | ✅ SARIF | ❌ | ❌ | N/A |
| **On-chain registry** | ✅ | ❌ | ❌ | ❌ |
| **CPI verification** | ✅ | ❌ | ❌ | ❌ |
| **Audit by GitHub URL** | ✅ | ❌ | ✅ | N/A |
| **Watch mode** | ✅ | ❌ | ❌ | N/A |
| **AI explanations** | ✅ | ❌ | ❌ | ✅ |
| **Fix suggestions** | ✅ | ❌ | ❌ | ✅ |

## Unique to SolGuard

### 1. On-Chain Audit Registry
```rust
// Other programs can verify audits via CPI
let passed = solguard::cpi::verify_audit(ctx)?;
require!(passed, ErrorCode::NotAudited);
```

No other tool stores audit results on-chain for composable verification.

### 2. 150 Patterns (Largest Coverage)
- Core Security (SOL001-SOL015)
- CPI Security (SOL040-SOL055)
- DeFi Patterns (SOL056-SOL075)
- Token Security (SOL076-SOL090)
- NFT Patterns (SOL091-SOL100)
- Advanced (SOL101-SOL130)

### 3. Watch Mode for Development
```bash
solguard watch ./program
# Re-audits on every file change
# Real-time security feedback while coding
```

### 4. GitHub Integration
```bash
# Audit any public repo
solguard github coral-xyz/anchor

# Audit a specific PR
solguard github solana-labs/solana --pr 1234

# Fetch and audit on-chain programs
solguard fetch <PROGRAM_ID>
```

### 5. Built by AI, for AI Era
SolGuard was 100% coded by an AI agent, demonstrating what's possible when agents build security tools. The patterns are comprehensive because an AI can process vast amounts of vulnerability research without fatigue.

## When to Use What

| Scenario | Best Choice |
|----------|-------------|
| Quick check during development | **SolGuard** |
| CI/CD security gate | **SolGuard** |
| Pre-deployment audit | **SolGuard** + Manual |
| High-value protocol (>$10M TVL) | **SolGuard** + Professional audit |
| Learning about vulnerabilities | **SolGuard** (free, educational) |

## Limitations

**SolGuard is NOT a replacement for professional audits when:**
- Protocol handles significant value (>$10M)
- Novel mechanisms that may have unknown attack vectors
- Regulatory or compliance requirements
- Insurance/liability considerations

**SolGuard excels at:**
- Catching common vulnerabilities early
- Continuous security during development
- Educational feedback for developers
- First line of defense before professional review

## Cost Analysis

### Without SolGuard (Traditional)
```
Development: 2 months
Wait for audit slot: 1-2 months
Audit: $50,000
Fixes + re-audit: $10,000
Total: 3-4 months, $60,000
```

### With SolGuard (Hybrid)
```
Development + continuous SolGuard: 2 months
Pre-audit fixes from SolGuard: $0
Professional audit (cleaner code): $30,000
Fewer issues = faster audit
Total: 2-3 months, $30,000
```

**Savings: 50% cost, 25% time**

---

## Summary

SolGuard isn't trying to replace professional auditors — it's trying to make security accessible to everyone, catch issues early, and ensure even small teams can ship secure code.

| Tool | Best For |
|------|----------|
| **SolGuard** | Speed, cost, coverage, CI/CD, development |
| **Soteria** | Specific deep checks |
| **Sec3** | Enterprise workflows |
| **Manual Audit** | High-stakes deployments |

---

*The best security strategy uses multiple tools. SolGuard is the fast, free first line.*
