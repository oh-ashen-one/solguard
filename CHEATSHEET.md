# 📋 SolShield AI CLI Cheatsheet

Quick reference for all commands and options.

---

## Installation

```bash
# From source (npm package coming soon)
git clone https://github.com/oh-ashen-one/solshield.git
cd SolShield AI/packages/cli
npm install && npm run build && npm link
```

---

## Commands

### `demo` — Quick showcase

```bash
# Run interactive demo with included vulnerable example
SolShield AI demo

# Shows: audit results, severity breakdown, fix suggestions
# Great for first-time users or demos
```

### `audit` — Analyze code for vulnerabilities

```bash
# Basic usage
SolShield AI audit ./path/to/program

# Current directory
SolShield AI audit .

# Multiple paths
SolShield AI audit ./program1 ./program2

# Options
SolShield AI audit . --verbose          # Detailed output
SolShield AI audit . --format json      # JSON output
SolShield AI audit . --format markdown  # Markdown report
SolShield AI audit . --min-severity high # Only high+ findings
SolShield AI audit . --patterns SOL001,SOL002  # Specific patterns
SolShield AI audit . --exclude SOL028   # Skip patterns
```

### `github` — Audit from GitHub

```bash
# Audit a repo
SolShield AI github owner/repo

# Specific branch
SolShield AI github owner/repo --branch develop

# Specific PR
SolShield AI github owner/repo --pr 123

# Subdirectory
SolShield AI github owner/repo --path programs/my-program
```

### `fetch` — Audit on-chain programs

```bash
# Mainnet
SolShield AI fetch <PROGRAM_ID>

# Devnet
SolShield AI fetch <PROGRAM_ID> --rpc https://api.devnet.solana.com

# Custom RPC
SolShield AI fetch <PROGRAM_ID> --rpc https://my-rpc.com
```

### `watch` — Continuous monitoring

```bash
# Watch directory
SolShield AI watch ./program

# Watch with options
SolShield AI watch . --min-severity critical
```

### `ci` — CI/CD mode

```bash
# Fail on critical
SolShield AI ci . --fail-on critical

# Fail on high or above
SolShield AI ci . --fail-on high

# Generate SARIF for GitHub
SolShield AI ci . --sarif results.sarif

# Combined
SolShield AI ci . --fail-on high --sarif results.sarif
```

### `list` — Show all patterns

```bash
# All patterns
SolShield AI list

# Filter by severity
SolShield AI list --severity critical
SolShield AI list --severity high

# Filter by category
SolShield AI list --category cpi
```

### `stats` — Show statistics

```bash
SolShield AI stats
```

### `score` — Get security grade (A-F)

```bash
# Get a letter grade for your program
SolShield AI score ./path/to/program

# JSON output
SolShield AI score . --output json

# Example output:
#     ╔═══════════════════════════════════╗
#     ║       🏆  GRADE: A+              ║
#     ║          SCORE: 100/100          ║
#     ╚═══════════════════════════════════╝
```

**Grading Scale:**
| Grade | Score | Meaning |
|-------|-------|---------|
| A+ | 95-100 | Production ready |
| A/A- | 85-94 | Excellent security |
| B+/B/B- | 70-84 | Good, minor issues |
| C+/C/C- | 55-69 | Needs attention |
| D+/D/D- | 30-54 | Significant issues |
| F | 0-29 | Critical vulnerabilities |

### `badge` — Generate README badges

```bash
# Generate shields.io badge markdown
SolShield AI badge ./path/to/program

# Different badge styles
SolShield AI badge . --style flat-square
SolShield AI badge . --style for-the-badge

# Save to file
SolShield AI badge . --output BADGES.md

# JSON output (for CI/automation)
SolShield AI badge . --format json
```

**Example Output:**
```markdown
[![SolShield AI](https://img.shields.io/badge/SolShield AI-secure-brightgreen?style=flat)](https://github.com/oh-ashen-one/solshield)
[![Security Grade](https://img.shields.io/badge/Security%20Grade-A+-brightgreen?style=flat)](https://github.com/oh-ashen-one/solshield)
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
SOLANA_RPC_URL=https://my-rpc.com SolShield AI fetch <ID>

# Verbose by default
SolShield AI_VERBOSE=1 SolShield AI audit .
```

---

## Examples

```bash
# Quick audit before commit
SolShield AI audit . --min-severity high

# Full audit with report
SolShield AI audit . --format markdown > audit-report.md

# CI pipeline
SolShield AI ci . --fail-on critical --sarif results.sarif

# Audit competitor's code
SolShield AI github coral-xyz/anchor --path programs/
```

---

*Full docs: [README.md](README.md) | Patterns: [PATTERNS.md](PATTERNS.md)*
