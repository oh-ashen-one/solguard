# SolGuard Cheat Sheet

## Quick Commands

```bash
# Audit local program
solguard audit ./my-program

# Audit from GitHub
solguard github coral-xyz/anchor
solguard github user/repo --pr 123

# Watch mode for development
solguard watch ./program

# CI mode with SARIF
solguard ci . --fail-on high --sarif results.sarif

# List all 150 patterns
solguard list

# Show audit stats
solguard stats
```

## Output Formats

```bash
solguard audit . --output terminal  # Default (colored)
solguard audit . --output json      # Machine-readable
solguard audit . --output markdown  # Documentation
```

## 150 Vulnerability Patterns

### By Category

| Category | Count | Examples |
|----------|-------|----------|
| Core Security | 15 | Owner/signer checks, access control |
| Account Safety | 20 | Closing, revival, confusion, init |
| CPI Security | 10 | Reentrancy, arbitrary CPI, return data |
| PDA Security | 12 | Bump validation, seeds, collision |
| Token Security | 18 | Mint/burn, freeze, decimals, ATA |
| DeFi | 15 | Flash loans, oracles, AMM, vaults |
| Anchor | 10 | Constraints, init, zero-copy |
| Math | 8 | Overflow, precision, rounding |
| Operations | 12 | Time locks, compute, pause |
| Other | 10 | NFT, governance, code quality |

### Critical Patterns (Must Fix)

| ID | Pattern | Description |
|----|---------|-------------|
| SOL001 | Missing Owner Check | Account ownership not verified |
| SOL002 | Missing Signer Check | Authority without signature |
| SOL005 | Authority Bypass | Sensitive ops unprotected |
| SOL010 | Closing Vulnerability | Account revival attacks |
| SOL012 | Arbitrary CPI | Unconstrained program ID |
| SOL015 | Type Cosplay | Missing discriminator |
| SOL019 | Flash Loan | Same-tx manipulation |

### High Severity Patterns

| ID | Pattern | Description |
|----|---------|-------------|
| SOL003 | Integer Overflow | Unchecked arithmetic |
| SOL004 | PDA Validation Gap | Missing bump check |
| SOL007 | CPI Vulnerability | Unsafe cross-program calls |
| SOL011 | Reentrancy | State change after CPI |
| SOL016 | Bump Seed | Non-canonical PDAs |
| SOL018 | Oracle Manipulation | Stale price data |

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Pass — No critical/high issues |
| 1 | Fail — Issues found |
| 2 | Error — Invalid input |

## Git Hooks

```bash
# Pre-commit: audit before commit
cp examples/hooks/pre-commit .git/hooks/
chmod +x .git/hooks/pre-commit

# Pre-push: block if critical issues
cp examples/hooks/pre-push .git/hooks/
chmod +x .git/hooks/pre-push
```

## GitHub Actions

```yaml
name: SolGuard Audit
on: [push, pull_request]

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm install -g @solguard/cli
      - run: solguard ci . --fail-on high --sarif results.sarif
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

## REST API

```bash
# Health check
curl https://solguard.dev/api/v1/audit

# Audit code
curl -X POST https://solguard.dev/api/v1/audit \
  -H "Content-Type: application/json" \
  -d '{"code": "use anchor_lang::prelude::*; ..."}'
```

## Links

- **GitHub:** https://github.com/oh-ashen-one/solguard
- **Patterns:** See web UI for full searchable list
- **API Docs:** /api page in web UI
