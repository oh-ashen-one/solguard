# 🛡️ SolShield AI Audit Badge

Show that your Solana program has been audited by SolShield AI!

## Usage

Add this badge to your README:

### Markdown

```markdown
[![Audited by SolShield AI](https://img.shields.io/badge/Audited%20by-SolShield AI%20🛡️-brightgreen)](https://github.com/oh-ashen-one/solshield)
```

**Result:** [![Audited by SolShield AI](https://img.shields.io/badge/Audited%20by-SolShield AI%20🛡️-brightgreen)](https://github.com/oh-ashen-one/solshield)

### With Status

```markdown
<!-- Passed audit -->
[![SolShield AI: Passed](https://img.shields.io/badge/SolShield AI-Passed%20✓-brightgreen)](https://github.com/oh-ashen-one/solshield)

<!-- Has warnings -->
[![SolShield AI: Warnings](https://img.shields.io/badge/SolShield AI-Warnings%20⚠️-yellow)](https://github.com/oh-ashen-one/solshield)

<!-- Critical issues -->
[![SolShield AI: Critical](https://img.shields.io/badge/SolShield AI-Critical%20🔴-red)](https://github.com/oh-ashen-one/solshield)
```

**Results:**
- [![SolShield AI: Passed](https://img.shields.io/badge/SolShield AI-Passed%20✓-brightgreen)](https://github.com/oh-ashen-one/solshield)
- [![SolShield AI: Warnings](https://img.shields.io/badge/SolShield AI-Warnings%20⚠️-yellow)](https://github.com/oh-ashen-one/solshield)
- [![SolShield AI: Critical](https://img.shields.io/badge/SolShield AI-Critical%20🔴-red)](https://github.com/oh-ashen-one/solshield)

### With Pattern Count

```markdown
[![SolShield AI: 130 Patterns](https://img.shields.io/badge/SolShield AI-130%20Patterns%20Checked-blue)](https://github.com/oh-ashen-one/solshield)
```

**Result:** [![SolShield AI: 130 Patterns](https://img.shields.io/badge/SolShield AI-130%20Patterns%20Checked-blue)](https://github.com/oh-ashen-one/solshield)

## Dynamic Badge (Future)

Once on-chain audit registry is deployed, badges will be dynamic:

```markdown
![SolShield AI Status](https://SolShield AI.dev/badge/<PROGRAM_ID>)
```

This will query the on-chain registry and show real-time audit status.

## CI Badge

For GitHub Actions integration:

```yaml
# In your workflow
- name: Run SolShield AI
  run: SolShield AI ci . --fail-on critical

# Badge shows CI status
[![SolShield AI CI](https://github.com/YOUR_ORG/YOUR_REPO/actions/workflows/SolShield AI.yml/badge.svg)](https://github.com/YOUR_ORG/YOUR_REPO/actions/workflows/SolShield AI.yml)
```

## Why Use a Badge?

1. **Trust Signal** — Shows you care about security
2. **Transparency** — Visitors know the code was checked
3. **Best Practice** — Encourages security-first culture
4. **Community** — Supports open-source security tooling

---

*Get audited: [github.com/oh-ashen-one/solshield](https://github.com/oh-ashen-one/solshield)*
