# 📋 SolGuard CLI Cheatsheet

Quick reference for all commands and options.

---

## Installation

```bash
# From source (npm package coming soon)
git clone https://github.com/oh-ashen-one/solguard.git
cd solguard/packages/cli
npm install && npm run build && npm link
```

---

## Commands

### `audit` — Analyze code for vulnerabilities

```bash
# Basic usage
solguard audit ./path/to/program

# Current directory
solguard audit .

# Multiple paths
solguard audit ./program1 ./program2

# Options
solguard audit . --verbose          # Detailed output
solguard audit . --format json      # JSON output
solguard audit . --format markdown  # Markdown report
solguard audit . --min-severity high # Only high+ findings
solguard audit . --patterns SOL001,SOL002  # Specific patterns
solguard audit . --exclude SOL028   # Skip patterns
```

### `github` — Audit from GitHub

```bash
# Audit a repo
solguard github owner/repo

# Specific branch
solguard github owner/repo --branch develop

# Specific PR
solguard github owner/repo --pr 123

# Subdirectory
solguard github owner/repo --path programs/my-program
```

### `fetch` — Audit on-chain programs

```bash
# Mainnet
solguard fetch <PROGRAM_ID>

# Devnet
solguard fetch <PROGRAM_ID> --rpc https://api.devnet.solana.com

# Custom RPC
solguard fetch <PROGRAM_ID> --rpc https://my-rpc.com
```

### `watch` — Continuous monitoring

```bash
# Watch directory
solguard watch ./program

# Watch with options
solguard watch . --min-severity critical
```

### `ci` — CI/CD mode

```bash
# Fail on critical
solguard ci . --fail-on critical

# Fail on high or above
solguard ci . --fail-on high

# Generate SARIF for GitHub
solguard ci . --sarif results.sarif

# Combined
solguard ci . --fail-on high --sarif results.sarif
```

### `list` — Show all patterns

```bash
# All patterns
solguard list

# Filter by severity
solguard list --severity critical
solguard list --severity high

# Filter by category
solguard list --category cpi
```

### `stats` — Show statistics

```bash
solguard stats
```

---

## Output Formats

| Format | Use Case |
|--------|----------|
| `--format terminal` | Human-readable (default) |
| `--format json` | Programmatic access |
| `--format markdown` | Documentation |
| `--sarif file.sarif` | GitHub Code Scanning |

---

## Severity Levels

| Level | Flag | Meaning |
|-------|------|---------|
| 🔴 Critical | `--min-severity critical` | Immediate exploit risk |
| 🟠 High | `--min-severity high` | Significant vulnerability |
| 🟡 Medium | `--min-severity medium` | Potential issue |
| 🔵 Low | `--min-severity low` | Best practice |

---

## Common Patterns

| ID | Name | Quick Check |
|----|------|-------------|
| SOL001 | Missing Owner | `owner = program::ID` |
| SOL002 | Missing Signer | `Signer<'info>` |
| SOL003 | Overflow | `checked_add/sub/mul` |
| SOL005 | Authority Bypass | `has_one = authority` |
| SOL012 | Arbitrary CPI | Hardcode program IDs |
| SOL018 | Oracle | Check staleness + TWAP |

---

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No issues (or below threshold) |
| 1 | Issues found above threshold |
| 2 | Error (parse failure, etc.) |

---

## Environment Variables

```bash
# Custom RPC
SOLANA_RPC_URL=https://my-rpc.com solguard fetch <ID>

# Verbose by default
SOLGUARD_VERBOSE=1 solguard audit .
```

---

## Examples

```bash
# Quick audit before commit
solguard audit . --min-severity high

# Full audit with report
solguard audit . --format markdown > audit-report.md

# CI pipeline
solguard ci . --fail-on critical --sarif results.sarif

# Audit competitor's code
solguard github coral-xyz/anchor --path programs/
```

---

*Full docs: [README.md](README.md) | Patterns: [PATTERNS.md](PATTERNS.md)*
