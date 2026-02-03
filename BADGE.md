# 🛡️ SolGuard Audit Badge

Show that your Solana program has been audited by SolGuard!

## Usage

Add this badge to your README:

### Markdown

```markdown
[![Audited by SolGuard](https://img.shields.io/badge/Audited%20by-SolGuard%20🛡️-brightgreen)](https://github.com/oh-ashen-one/solguard)
```

**Result:** [![Audited by SolGuard](https://img.shields.io/badge/Audited%20by-SolGuard%20🛡️-brightgreen)](https://github.com/oh-ashen-one/solguard)

### With Status

```markdown
<!-- Passed audit -->
[![SolGuard: Passed](https://img.shields.io/badge/SolGuard-Passed%20✓-brightgreen)](https://github.com/oh-ashen-one/solguard)

<!-- Has warnings -->
[![SolGuard: Warnings](https://img.shields.io/badge/SolGuard-Warnings%20⚠️-yellow)](https://github.com/oh-ashen-one/solguard)

<!-- Critical issues -->
[![SolGuard: Critical](https://img.shields.io/badge/SolGuard-Critical%20🔴-red)](https://github.com/oh-ashen-one/solguard)
```

**Results:**
- [![SolGuard: Passed](https://img.shields.io/badge/SolGuard-Passed%20✓-brightgreen)](https://github.com/oh-ashen-one/solguard)
- [![SolGuard: Warnings](https://img.shields.io/badge/SolGuard-Warnings%20⚠️-yellow)](https://github.com/oh-ashen-one/solguard)
- [![SolGuard: Critical](https://img.shields.io/badge/SolGuard-Critical%20🔴-red)](https://github.com/oh-ashen-one/solguard)

### With Pattern Count

```markdown
[![SolGuard: 130 Patterns](https://img.shields.io/badge/SolGuard-130%20Patterns%20Checked-blue)](https://github.com/oh-ashen-one/solguard)
```

**Result:** [![SolGuard: 130 Patterns](https://img.shields.io/badge/SolGuard-130%20Patterns%20Checked-blue)](https://github.com/oh-ashen-one/solguard)

## Dynamic Badge (Future)

Once on-chain audit registry is deployed, badges will be dynamic:

```markdown
![SolGuard Status](https://solguard.dev/badge/<PROGRAM_ID>)
```

This will query the on-chain registry and show real-time audit status.

## CI Badge

For GitHub Actions integration:

```yaml
# In your workflow
- name: Run SolGuard
  run: solguard ci . --fail-on critical

# Badge shows CI status
[![SolGuard CI](https://github.com/YOUR_ORG/YOUR_REPO/actions/workflows/solguard.yml/badge.svg)](https://github.com/YOUR_ORG/YOUR_REPO/actions/workflows/solguard.yml)
```

## Why Use a Badge?

1. **Trust Signal** — Shows you care about security
2. **Transparency** — Visitors know the code was checked
3. **Best Practice** — Encourages security-first culture
4. **Community** — Supports open-source security tooling

---

*Get audited: [github.com/oh-ashen-one/solguard](https://github.com/oh-ashen-one/solguard)*
