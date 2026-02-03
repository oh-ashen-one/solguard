# 🔍 SolGuard Pattern Reference

Complete list of all **130 vulnerability patterns** detected by SolGuard.

---

## Overview

| Category | Count | Severity Range |
|----------|-------|----------------|
| Core Security | 15 | Critical - Medium |
| CPI Security | 12 | Critical - High |
| Arithmetic | 8 | High - Medium |
| PDA Security | 10 | Critical - High |
| Token Security | 15 | Critical - Medium |
| DeFi Patterns | 12 | Critical - High |
| NFT Security | 5 | High - Medium |
| Account Management | 18 | Critical - Low |
| Anchor-Specific | 10 | High - Medium |
| Advanced | 25 | Critical - Low |

---

## Core Security (SOL001-SOL015)

| ID | Name | Severity | Description |
|----|------|----------|-------------|
| SOL001 | Missing Owner Check | 🔴 Critical | Accounts without ownership validation |
| SOL002 | Missing Signer Check | 🔴 Critical | Authority without cryptographic proof |
| SOL003 | Integer Overflow | 🟠 High | Unchecked arithmetic operations |
| SOL004 | PDA Validation Gap | 🟠 High | Missing bump verification |
| SOL005 | Authority Bypass | 🔴 Critical | Sensitive ops without permission |
| SOL006 | Missing Init Check | 🔴 Critical | Uninitialized account access |
| SOL007 | CPI Vulnerability | 🟠 High | Cross-program invocation risks |
| SOL008 | Rounding Error | 🟡 Medium | Precision loss in calculations |
| SOL009 | Account Confusion | 🟠 High | Swappable same-type accounts |
| SOL010 | Closing Vulnerability | 🔴 Critical | Account revival attacks |
| SOL011 | Reentrancy Risk | 🟠 High | State changes after CPI |
| SOL012 | Arbitrary CPI | 🔴 Critical | Unconstrained program ID |
| SOL013 | Duplicate Mutable | 🟠 High | Same account multiple times |
| SOL014 | Rent Exemption | 🟡 Medium | Below rent threshold |
| SOL015 | Type Cosplay | 🔴 Critical | Missing discriminator |

---

## CPI Security (SOL040-SOL055)

| ID | Name | Severity | Description |
|----|------|----------|-------------|
| SOL040 | CPI Guard | 🟠 High | User-controlled CPI accounts |
| SOL041 | CPI Return Data | 🟠 High | Unchecked return values |
| SOL042 | CPI Depth | 🟠 High | Exceeding call stack limits |
| SOL043 | Anchor CPI Safety | 🟠 High | Anchor-specific CPI issues |
| SOL044 | Cross-Instance | 🟠 High | Instance confusion in CPI |
| SOL045 | Associated Program | 🟡 Medium | ATA program validation |
| SOL046 | System Program Abuse | 🟠 High | System program misuse |
| SOL047 | Cross-Program State | 🟠 High | Stale external state |
| SOL048 | Program ID Check | 🔴 Critical | Missing program verification |
| SOL049 | Cross-Chain | 🔴 Critical | Bridge vulnerabilities |
| SOL050 | Lookup Table | 🟠 High | ALT manipulation |
| SOL051 | Program Cache | 🟡 Medium | Cached program issues |

---

## Arithmetic (SOL020-SOL028)

| ID | Name | Severity | Description |
|----|------|----------|-------------|
| SOL020 | Unsafe Math | 🟠 High | Division by zero, lossy casts |
| SOL021 | Sysvar Manipulation | 🔴 Critical | Clock for randomness |
| SOL022 | Upgrade Authority | 🟡 Medium | Missing multisig |
| SOL023 | Token Validation | 🟠 High | Missing mint/ATA validation |
| SOL024 | Cross-Program State | 🟠 High | Stale external state |
| SOL025 | Lamport Balance | 🟠 High | Balance check before CPI |
| SOL026 | Seeded Account | 🟡 Medium | Variable seed issues |
| SOL027 | Error Handling | 🟡 Medium | unwrap(), swallowed errors |
| SOL028 | Arithmetic Precision | 🟠 High | Precision loss |

---

## PDA Security (SOL016-SOL019, SOL070-SOL079)

| ID | Name | Severity | Description |
|----|------|----------|-------------|
| SOL016 | Bump Seed | 🟠 High | Non-canonical bumps |
| SOL017 | Freeze Authority | 🟡 Medium | Token freeze unchecked |
| SOL018 | Oracle Manipulation | 🟠 High | Missing staleness/TWAP |
| SOL019 | Flash Loan | 🔴 Critical | Same-tx manipulation |
| SOL070 | PDA Collision | 🔴 Critical | Seed collision attacks |
| SOL071 | PDA Signer Seeds | 🟠 High | Invalid signer seeds |
| SOL072 | Account Key Derivation | 🟠 High | Derivation errors |
| SOL073 | Account Seed Length | 🟠 High | Seed too long |
| SOL074 | PDA Bump Storage | 🟠 High | Bump not stored |
| SOL075 | Program Derived | 🟠 High | PDA validation |

---

## Token Security (SOL076-SOL090)

| ID | Name | Severity | Description |
|----|------|----------|-------------|
| SOL076 | Mint Authority | 🔴 Critical | Unauthorized minting |
| SOL077 | Token Ownership | 🟠 High | Owner validation |
| SOL078 | Token Approval | 🟡 Medium | Delegate issues |
| SOL079 | Token Burn Safety | 🟠 High | Burn authorization |
| SOL080 | Token Freeze | 🟡 Medium | Freeze status |
| SOL081 | Token Account Closure | 🟠 High | Closure attacks |
| SOL082 | Token Decimal Handling | 🟡 Medium | Decimal precision |
| SOL083 | ATA Security | 🟠 High | Associated token issues |
| SOL084 | Wrapped SOL | 🟡 Medium | wSOL handling |
| SOL085 | Token-2022 | 🟡 Medium | Extension compatibility |
| SOL086 | Token Extensions | 🟠 High | Extension vulnerabilities |
| SOL087 | Supply Manipulation | 🔴 Critical | Supply attacks |

---

## DeFi Patterns (SOL056-SOL069)

| ID | Name | Severity | Description |
|----|------|----------|-------------|
| SOL056 | AMM | 🟠 High | AMM vulnerabilities |
| SOL057 | Lending | 🟠 High | Lending protocol issues |
| SOL058 | Staking | 🟠 High | Staking vulnerabilities |
| SOL059 | Vault | 🟠 High | Vault security |
| SOL060 | Bridge | 🔴 Critical | Cross-chain bridge |
| SOL061 | Governance | 🟠 High | DAO vulnerabilities |
| SOL062 | Sandwich Attack | 🟠 High | MEV exploitation |
| SOL063 | Fee Handling | 🟡 Medium | Fee calculation |
| SOL064 | Withdraw Pattern | 🟠 High | Withdrawal logic |
| SOL065 | Initialization Frontrun | 🔴 Critical | Init frontrunning |
| SOL066 | Priority Fee | 🟡 Medium | Priority fee issues |
| SOL067 | Slot Manipulation | 🟠 High | Slot-based attacks |

---

## NFT Security (SOL091-SOL100)

| ID | Name | Severity | Description |
|----|------|----------|-------------|
| SOL091 | Metaplex Security | 🟠 High | Metaplex vulnerabilities |
| SOL092 | NFT Metadata | 🟡 Medium | Metadata validation |
| SOL093 | Merkle | 🟠 High | Merkle tree issues |
| SOL094 | Compression | 🟠 High | cNFT vulnerabilities |
| SOL095 | Royalty Enforcement | 🟡 Medium | Royalty bypass |

---

## Account Management (SOL029-SOL039)

| ID | Name | Severity | Description |
|----|------|----------|-------------|
| SOL029 | Instruction Introspection | 🟠 High | Sysvar validation |
| SOL030 | Anchor Macros | 🟡 Medium | Macro misuse |
| SOL031 | Access Control | 🔴 Critical | Permission checks |
| SOL032 | Time Lock | 🟡 Medium | Missing delays |
| SOL033 | Signature Replay | 🔴 Critical | Nonce/domain |
| SOL034 | Storage Collision | 🔴 Critical | Discriminator conflicts |
| SOL035 | Denial of Service | 🟠 High | Unbounded loops |
| SOL036 | Input Validation | 🟡 Medium | Bounds checking |
| SOL037 | State Initialization | 🟡 Medium | Defaults, versioning |
| SOL038 | Account Size | 🟡 Medium | Size validation |
| SOL039 | Memo Logging | 🟡 Medium | Sensitive data in logs |

---

## Anchor-Specific (SOL101-SOL110)

| ID | Name | Severity | Description |
|----|------|----------|-------------|
| SOL101 | Anchor Account Init | 🟠 High | Init patterns |
| SOL102 | Constraint Order | 🟡 Medium | Constraint ordering |
| SOL103 | Constraint Validation | 🟠 High | Missing constraints |
| SOL104 | Constraint Combo | 🟠 High | Conflicting constraints |
| SOL105 | Account Reallocation | 🟠 High | Realloc issues |
| SOL106 | Account Discriminator Check | 🟠 High | Discriminator validation |
| SOL107 | Account Close Destination | 🟠 High | Close dest validation |
| SOL108 | Account Data Init | 🟡 Medium | Data initialization |
| SOL109 | Account Data Match | 🟡 Medium | Data matching |
| SOL110 | Zero Copy Account | 🟡 Medium | Zero-copy issues |

---

## Advanced (SOL111-SOL130)

| ID | Name | Severity | Description |
|----|------|----------|-------------|
| SOL111 | Privilege Escalation | 🔴 Critical | Privilege attacks |
| SOL112 | Account Borrowing | 🟠 High | Borrow checker |
| SOL113 | Remaining Accounts | 🟠 High | Extra accounts |
| SOL114 | Rent Drain | 🟠 High | Rent theft |
| SOL115 | Account Revival | 🔴 Critical | Revival attacks |
| SOL116 | Program Data Authority | 🔴 Critical | Upgrade authority |
| SOL117 | Discriminator | 🟠 High | Type identification |
| SOL118 | Timestamp Manipulation | 🟠 High | Time-based attacks |
| SOL119 | Account Lifetime | 🟠 High | Lifetime issues |
| SOL120 | Event Ordering | 🟡 Medium | Event sequence |
| SOL121 | Account Type Safety | 🟠 High | Type confusion |
| SOL122 | Syscall Security | 🟠 High | Syscall vulnerabilities |
| SOL123 | SPL Governance | 🟠 High | SPL Gov issues |
| SOL124 | Multisig | 🟠 High | Multisig vulnerabilities |
| SOL125 | Versioning | 🟡 Medium | Version mismatches |
| SOL126 | Atomic Operations | 🟠 High | Atomicity issues |
| SOL127 | Initialization Order | 🟠 High | Init ordering |
| SOL128 | Instruction Data | 🟡 Medium | Instruction parsing |
| SOL129 | Authority Scope | 🟡 Medium | Authority boundaries |
| SOL130 | Error Propagation | 🟡 Medium | Error handling |

---

## Usage

```bash
# List all patterns
solguard list

# Filter by severity
solguard list --severity critical

# Run specific patterns
solguard audit . --patterns SOL001,SOL002,SOL003

# Exclude patterns
solguard audit . --exclude SOL028
```

---

## Severity Legend

| Icon | Level | Meaning |
|------|-------|---------|
| 🔴 | Critical | Immediate exploit risk, must fix |
| 🟠 | High | Significant vulnerability |
| 🟡 | Medium | Potential issue |
| 🔵 | Low | Best practice |
| ⚪ | Info | Informational |

---

*Run `solguard list` for the most up-to-date pattern list.*
