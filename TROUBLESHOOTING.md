# 🔧 SolShield AI Troubleshooting

Solutions for common issues.

---

## Installation

### "command not found: SolShield AI"

**Fix:** Add npm global bin to PATH:
```bash
# Find where npm installs globals
npm config get prefix

# Add to PATH (adjust for your shell)
export PATH="$(npm config get prefix)/bin:$PATH"
```

### "Permission denied" during install

**Fix:** Use a Node version manager:
```bash
# Install nvm (Node Version Manager)
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.0/install.sh | bash

# Install and use Node 20
nvm install 20
nvm use 20

# Now install without sudo
# From source (npm package coming soon)
git clone https://github.com/oh-ashen-one/solshield.git
cd SolShield AI/packages/cli && npm install && npm run build && npm link
```

---

## Auditing

### "No files found"

**Cause:** No `.rs` files in the path

**Fix:** 
```bash
# Specify the correct path
SolShield AI audit ./programs/my-program

# Or audit current directory
cd programs/my-program
SolShield AI audit .
```

### "Parse error" on valid Rust code

**Cause:** Tree-sitter limitations with very new syntax

**Fix:** 
1. Open an issue with the code sample
2. As workaround, simplify the problematic code section

### Empty results (no findings)

**Cause:** Code is secure OR patterns don't match

**Check:** Run with verbose mode:
```bash
SolShield AI audit . --verbose
```

---

## Web UI

### "localhost:3000 not loading"

**Fix:**
```bash
cd packages/web
pnpm install  # or npm install
pnpm dev
```

### "API error" when auditing

**Cause:** Backend not running or code too large

**Fix:**
1. Check terminal for errors
2. Try smaller code samples
3. Restart: `pnpm dev`

---

## GitHub Integration

### "Repository not found"

**Cause:** Private repo or typo

**Fix:**
```bash
# Public repos only
SolShield AI github owner/repo

# For private repos (coming soon)
# Will need GitHub token
```

### "PR not found"

**Fix:** Ensure PR exists and repo is correct:
```bash
SolShield AI github owner/repo --pr 123
```

---

## CI/CD

### "SARIF upload fails"

**Fix:** Ensure workflow permissions:
```yaml
permissions:
  security-events: write
```

### "CI takes too long"

**Fix:** Audit only changed files:
```yaml
- name: Get changed files
  id: changed
  uses: tj-actions/changed-files@v41
  with:
    files: '**/*.rs'

- name: Audit changed files
  if: steps.changed.outputs.any_changed == 'true'
  run: SolShield AI audit ${{ steps.changed.outputs.all_changed_files }}
```

---

## On-Chain Fetching

### "Failed to fetch program"

**Cause:** Invalid program ID or RPC issues

**Fix:**
```bash
# Verify program exists
solana program show <PROGRAM_ID>

# Use different RPC
SolShield AI fetch <PROGRAM_ID> --rpc https://api.mainnet-beta.solana.com
```

### "Program is not an Anchor program"

**Cause:** SolShield AI currently optimized for Anchor

**Workaround:** Fetch the source from GitHub instead:
```bash
SolShield AI github owner/repo
```

---

## False Positives

### "Flagging safe code"

**Steps:**
1. Check if it's actually a vulnerability
2. If false positive, open an issue with:
   - The code
   - Which pattern flagged it
   - Why you believe it's safe

### "Too many warnings"

**Fix:** Filter by severity:
```bash
# Only critical and high
SolShield AI audit . --min-severity high

# Or exclude specific patterns
SolShield AI audit . --exclude SOL028,SOL039
```

---

## Performance

### "Audit taking too long"

**Cause:** Very large codebase or many files

**Fix:**
```bash
# Audit specific directory
SolShield AI audit ./programs/specific-program

# Skip test files
SolShield AI audit . --ignore '**/test/**'
```

### "Out of memory"

**Fix:** Increase Node.js memory:
```bash
NODE_OPTIONS="--max-old-space-size=4096" SolShield AI audit .
```

---

## Codespaces/Gitpod

### "Port 3000 not opening"

**Fix:**
1. Check "Ports" tab in VS Code
2. Click "Open in Browser" on port 3000
3. Or manually forward: `http://localhost:3000`

### "pnpm not found"

**Fix:**
```bash
npm install -g pnpm
```

---

## Still Stuck?

1. **Check logs:** Run with `--verbose`
2. **Search issues:** [GitHub Issues](https://github.com/oh-ashen-one/solshield/issues)
3. **Open new issue:** Include error message, steps to reproduce, and environment info

---

*Most issues have simple fixes. When in doubt, restart and retry.*
