# 🔌 SolGuard Integrations

Ready-to-use templates for integrating SolGuard into your workflow.

## Quick Links

| Integration | Template | Description |
|-------------|----------|-------------|
| [GitHub Actions](#github-actions) | [Template](examples/ci-templates/github-actions.yml) | CI/CD with SARIF + PR comments |
| [Pre-commit Hook](#pre-commit-hook) | [Template](examples/ci-templates/pre-commit-hook.sh) | Block commits with critical issues |
| [VS Code](#vs-code) | [Template](examples/ci-templates/vscode-tasks.json) | Run audits from editor |
| [Badge](#badge) | [Docs](BADGE.md) | Show audit status in README |

---

## GitHub Actions

Automatically audit every PR and push.

### Basic Setup

```yaml
# .github/workflows/solguard.yml
name: SolGuard
on: [push, pull_request]

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: |
          git clone https://github.com/oh-ashen-one/solguard.git /tmp/solguard
          cd /tmp/solguard/packages/cli && npm install && npm run build && npm link
      - run: solguard ci . --fail-on high --sarif results.sarif
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

### Features
- ✅ Fails CI on critical/high issues
- ✅ SARIF integration shows findings inline in GitHub
- ✅ PR comments with full report (see [full template](examples/ci-templates/github-actions.yml))

---

## Pre-commit Hook

Catch issues before they're committed.

### Setup

```bash
# Download hook
curl -o .git/hooks/pre-commit \
  https://raw.githubusercontent.com/oh-ashen-one/solguard/main/examples/ci-templates/pre-commit-hook.sh

# Make executable
chmod +x .git/hooks/pre-commit
```

### Behavior
- 🔴 **Critical issues** → Blocks commit
- 🟠 **High issues** → Warning, allows commit
- 🟢 **No issues** → Passes silently
- ⚡ **Bypass** → `git commit --no-verify`

---

## VS Code

Run audits from your editor.

### Setup

1. Copy [vscode-tasks.json](examples/ci-templates/vscode-tasks.json) to `.vscode/tasks.json`
2. Open Command Palette (`Ctrl/Cmd + Shift + P`)
3. Type "Run Task"
4. Select a SolGuard task

### Available Tasks
- **Audit Current File** — Check the active file
- **Audit Workspace** — Check entire project
- **Watch Mode** — Continuous monitoring
- **List Patterns** — Show all 130 patterns
- **Show Stats** — Audit statistics

---

## Badge

Show your audit status to visitors.

```markdown
[![Audited by SolGuard](https://img.shields.io/badge/Audited%20by-SolGuard%20🛡️-brightgreen)](https://github.com/oh-ashen-one/solguard)
```

[![Audited by SolGuard](https://img.shields.io/badge/Audited%20by-SolGuard%20🛡️-brightgreen)](https://github.com/oh-ashen-one/solguard)

See [BADGE.md](BADGE.md) for more badge options.

---

## Programmatic API

Use SolGuard in your own tools:

```typescript
// Coming soon: @solguard/core package
import { audit } from '@solguard/core';

const results = await audit({
  path: './programs',
  patterns: ['SOL001', 'SOL002', 'SOL003'], // or 'all'
  severity: 'high', // minimum severity to report
});

console.log(results.findings);
```

---

## REST API

For web integrations:

```bash
# Local (when running web UI)
curl -X POST http://localhost:3000/api/audit \
  -H "Content-Type: application/json" \
  -d '{"code": "pub fn withdraw(...) { ... }"}'
```

Response:
```json
{
  "findings": [...],
  "summary": {
    "critical": 2,
    "high": 5,
    "medium": 3,
    "low": 1
  },
  "passed": false
}
```

---

## IDE Extensions (Roadmap)

- [ ] VS Code Extension — Real-time squiggles
- [ ] IntelliJ/Rust Plugin — Integrated analysis
- [ ] Neovim Plugin — LSP integration

---

## Need Help?

- 📖 [DEMO.md](DEMO.md) — Quick start guide
- 📊 [BENCHMARKS.md](BENCHMARKS.md) — Performance info
- 🔒 [SECURITY.md](SECURITY.md) — Security policy
- 🐛 [Issues](https://github.com/oh-ashen-one/solguard/issues) — Bug reports

---

*Integrate once, audit forever.*
