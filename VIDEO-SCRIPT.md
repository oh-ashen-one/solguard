# 🎬 SolGuard Demo Video Script

**Target length:** 2-3 minutes
**What you need:** Screen recording software (Loom, OBS, or iPhone)

---

## Shot 1: The Hook (15 seconds)

**Show:** GitHub README with the "Try It Now" badges

**Say:**
> "Manual smart contract audits cost $10-100K and take weeks. 
> SolGuard does it in seconds — and it was built entirely by an AI agent."

---

## Shot 2: One-Click Demo (30 seconds)

**Do:**
1. Click the "Open in GitHub Codespaces" badge
2. Show the environment spinning up
3. Wait for Web UI to open at port 3000

**Say:**
> "Judges, you can try this right now. One click, no setup required.
> The Web UI opens automatically in about 60 seconds."

---

## Shot 3: Vulnerable Code Audit (45 seconds)

**Do:**
1. Click "🔓 Vulnerable Vault" button
2. Briefly scroll through the code (show it's real Rust)
3. Click "🔍 Run Security Audit"
4. Show the results loading
5. Scroll through findings

**Say:**
> "This vault has intentional vulnerabilities. Watch SolGuard detect them:
> - Missing signer check — anyone can pretend to be the authority
> - Integer overflow — balance can underflow to max u64
> - Authority bypass — no verification on withdraw
> 
> Each finding includes the exact line, explanation, and a fix suggestion."

---

## Shot 4: Pattern Breadth (20 seconds)

**Do:**
1. Click "Patterns" in the nav
2. Show the search/filter
3. Quickly scroll to show scale

**Say:**
> "2400+ vulnerability patterns covering everything from basic signer checks
> to advanced DeFi attacks like oracle manipulation and flash loans."

---

## Shot 5: CLI Power (30 seconds)

**Do:**
1. Open terminal in Codespaces
2. Run: `solguard audit ../examples/vulnerable/token-vault`
3. Show the colored output
4. Run: `solguard github coral-xyz/anchor` (or any public repo)

**Say:**
> "The CLI can audit local files, fetch from GitHub, 
> or even pull on-chain programs by their address.
> 
> CI mode generates SARIF files for GitHub code scanning."

---

## Shot 6: The Close (15 seconds)

**Show:** README or HACKATHON.md

**Say:**
> "SolGuard: 2400+ patterns, CLI, Web UI, and on-chain verification —
> all written by Midir, an AI agent on Clawdbot.
> 
> Security audits for everyone. Free in beta. Try it now."

---

## Tips for Recording

- **Energy:** You're excited about this. Sound like it.
- **Pace:** Not too fast. Judges are evaluating, not speedrunning.
- **Mistakes:** Minor flubs are fine. Authenticity > polish.
- **Music:** Optional background music at low volume adds polish
- **Thumbnail:** Screenshot of the audit results with "SolGuard" text

---

## Quick Commands Reference

```bash
# Audit local code
solguard audit ./path/to/program

# Audit from GitHub
solguard github owner/repo
solguard github owner/repo --pr 123

# List all 2400+ patterns
solguard list

# Show stats
solguard stats
```

---

**Estimated recording time:** 15 minutes (with retakes)
**Post-recording:** Trim dead air, add captions if possible

Good luck! 🎬

