/**
 * SolGuard Security Patterns - Batch 76
 * 
 * Feb 2026 Final Comprehensive Batch
 * SOL3676-SOL3750 (75 patterns)
 * 
 * Sources:
 * - DEV.to "15 Critical Solana Vulnerabilities" (Jan 2026)
 * - Helius "Complete History of Solana Hacks" (Updated Feb 2026)
 * - CertiK January 2026 Report ($400M lost industry-wide)
 * - Step Finance $40M Hack Analysis (Jan 31, 2025)
 * - Owner Permission Phishing Campaign (Dec 2025-Feb 2026)
 * - Solana Security Ecosystem Report 2025
 */

import type { PatternInput, Finding } from './index.js';

// Helper to find line number from character index
function findLineNumber(content: string, charIndex: number): number {
  const lines = content.substring(0, charIndex).split('\n');
  return lines.length;
}

// Helper to get code snippet around a line
function getCodeSnippet(content: string, lineNum: number, context: number = 2): string {
  const lines = content.split('\n');
  const start = Math.max(0, lineNum - context - 1);
  const end = Math.min(lines.length, lineNum + context);
  return lines.slice(start, end).join('\n').substring(0, 200);
}

/**
 * Batch 76: Feb 2026 Final Comprehensive Patterns (SOL3676-SOL3750)
 */
export function checkBatch76Patterns(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';
  const fileName = input.path || 'unknown';
  
  if (!content) return findings;
  
  // ===========================================
  // DEV.TO 15 CRITICAL VULNERABILITIES (Enhanced)
  // ===========================================
  
  // SOL3676: Account Reinitialization Attack
  // From DEV.to - allows attacker to reset account state
  const reinitPatterns = [
    /init\s*(?!.*constraint.*is_initialized)/gi,
    /initialize.*pub\s+fn.*(?!.*require.*!.*initialized)/gis,
  ];
  reinitPatterns.forEach(pattern => {
    const matches = content.matchAll(pattern);
    for (const match of matches) {
      const lineNum = findLineNumber(content, match.index || 0);
      findings.push({
        id: 'SOL3676',
        title: 'Account Reinitialization Vulnerability',
        severity: 'critical',
        description: 'Account can be reinitialized, allowing attacker to reset state and potentially steal funds. The Solend 2021 attack exploited similar missing init checks.',
        location: { file: fileName, line: lineNum },
        recommendation: 'Add is_initialized check: require!(!account.is_initialized, ErrorCode::AlreadyInitialized)',
        code: getCodeSnippet(content, lineNum),
      });
    }
  });
  
  // SOL3677: Arbitrary CPI Target
  // Attacker can specify which program to call
  const arbitraryCpiPattern = /invoke(?:_signed)?\s*\(\s*&\s*\w+\s*,/gi;
  const matches3677 = content.matchAll(arbitraryCpiPattern);
  for (const match of matches3677) {
    const context = content.substring(Math.max(0, (match.index || 0) - 100), (match.index || 0) + 200);
    if (!context.includes('program_id ==') && !context.includes('require!') && !context.includes('TOKEN_PROGRAM_ID')) {
      const lineNum = findLineNumber(content, match.index || 0);
      findings.push({
        id: 'SOL3677',
        title: 'Arbitrary CPI Target Vulnerability',
        severity: 'critical',
        description: 'CPI call without validating target program. Attacker could redirect call to malicious program.',
        location: { file: fileName, line: lineNum },
        recommendation: 'Hardcode expected program IDs or validate against allowlist before CPI',
        code: getCodeSnippet(content, lineNum),
      });
    }
  }
  
  // SOL3678: Missing Instruction Sysvar Validation
  // Step Finance hack vector - instruction introspection bypass
  const sysvarPattern = /sysvar::instructions|Instructions::load/gi;
  const matches3678 = content.matchAll(sysvarPattern);
  for (const match of matches3678) {
    const context = content.substring((match.index || 0), (match.index || 0) + 300);
    if (!context.includes('verify') && !context.includes('check') && !context.includes('validate')) {
      const lineNum = findLineNumber(content, match.index || 0);
      findings.push({
        id: 'SOL3678',
        title: 'Unvalidated Instruction Sysvar Access',
        severity: 'high',
        description: 'Instructions sysvar accessed without validation. Step Finance $40M hack exploited instruction introspection.',
        location: { file: fileName, line: lineNum },
        recommendation: 'Validate instruction sysvar data and verify expected instruction sequence',
        code: getCodeSnippet(content, lineNum),
      });
    }
  }
  
  // SOL3679: Duplicate Account in Instruction
  // Passing same account twice to bypass checks
  const accountsPattern = /#\[derive\(Accounts\)\][\s\S]*?pub\s+struct\s+\w+[\s\S]*?\{[\s\S]*?\}/g;
  const matches3679 = content.matchAll(accountsPattern);
  for (const match of matches3679) {
    const accountsContent = match[0];
    const accountNames = accountsContent.match(/pub\s+(\w+)\s*:/g) || [];
    if (accountNames.length > 2 && !accountsContent.includes('constraint') && !accountsContent.includes('key()')) {
      const lineNum = findLineNumber(content, match.index || 0);
      findings.push({
        id: 'SOL3679',
        title: 'Potential Duplicate Account Vulnerability',
        severity: 'medium',
        description: 'Multiple accounts without uniqueness constraints. Attacker could pass same account twice.',
        location: { file: fileName, line: lineNum },
        recommendation: 'Add constraints: constraint = account1.key() != account2.key()',
        code: getCodeSnippet(content, lineNum),
      });
    }
  }
  
  // SOL3680: Bump Seed Not Stored
  // DEV.to vulnerability #5 - PDA canonicalization
  const pdaInitPattern = /seeds\s*=\s*\[[\s\S]*?\]\s*,\s*bump(?!\s*=)/gi;
  const matches3680 = content.matchAll(pdaInitPattern);
  for (const match of matches3680) {
    const lineNum = findLineNumber(content, match.index || 0);
    findings.push({
      id: 'SOL3680',
      title: 'PDA Bump Seed Not Stored',
      severity: 'high',
      description: 'PDA created without storing bump seed. Non-canonical bumps could create shadow PDAs.',
      location: { file: fileName, line: lineNum },
      recommendation: 'Store bump in account: bump = vault.bump, and verify on subsequent access',
      code: getCodeSnippet(content, lineNum),
    });
  }
  
  // ===========================================
  // OWNER PERMISSION PHISHING (Dec 2025 - Feb 2026)
  // ===========================================
  
  // SOL3681: SetAuthority Without Timelock
  // Owner permission phishing campaign
  const setAuthPattern = /set_authority|SetAuthority|transfer_authority/gi;
  const matches3681 = content.matchAll(setAuthPattern);
  for (const match of matches3681) {
    const context = content.substring(Math.max(0, (match.index || 0) - 100), (match.index || 0) + 200);
    if (!context.includes('timelock') && !context.includes('delay') && !context.includes('multisig')) {
      const lineNum = findLineNumber(content, match.index || 0);
      findings.push({
        id: 'SOL3681',
        title: 'Authority Transfer Without Timelock',
        severity: 'critical',
        description: 'Authority transfer without timelock. Owner phishing attacks in Dec 2025-Feb 2026 exploited instant authority transfers.',
        location: { file: fileName, line: lineNum },
        recommendation: 'Add timelock: require!(current_time > pending_authority_time + TIMELOCK_PERIOD)',
        code: getCodeSnippet(content, lineNum),
      });
    }
  }
  
  // SOL3682: Approval Without Scope Limits
  const approvePattern = /approve|Approve|delegate/gi;
  const matches3682 = content.matchAll(approvePattern);
  for (const match of matches3682) {
    const context = content.substring((match.index || 0), (match.index || 0) + 200);
    if (!context.includes('amount') || context.includes('u64::MAX') || context.includes('unlimited')) {
      const lineNum = findLineNumber(content, match.index || 0);
      findings.push({
        id: 'SOL3682',
        title: 'Unlimited Token Approval',
        severity: 'high',
        description: 'Token approval without amount limits. Phishing attacks trick users into unlimited approvals.',
        location: { file: fileName, line: lineNum },
        recommendation: 'Always specify exact approval amounts, never use unlimited approvals',
        code: getCodeSnippet(content, lineNum),
      });
    }
  }
  
  // SOL3683: Owner Change Without Two-Step
  const ownerChangePattern = /owner\s*=|set_owner|change_owner|new_owner/gi;
  const matches3683 = content.matchAll(ownerChangePattern);
  for (const match of matches3683) {
    const context = content.substring(Math.max(0, (match.index || 0) - 150), (match.index || 0) + 150);
    if (!context.includes('pending') && !context.includes('accept') && !context.includes('confirm')) {
      const lineNum = findLineNumber(content, match.index || 0);
      findings.push({
        id: 'SOL3683',
        title: 'Single-Step Owner Change',
        severity: 'high',
        description: 'Ownership transfer in single transaction. Should require two-step (propose + accept) pattern.',
        location: { file: fileName, line: lineNum },
        recommendation: 'Implement two-step ownership: set_pending_owner() then accept_ownership()',
        code: getCodeSnippet(content, lineNum),
      });
    }
  }
  
  // ===========================================
  // STEP FINANCE $40M HACK PATTERNS (Jan 31, 2025)
  // ===========================================
  
  // SOL3684: Executive Key Compromise Vector
  const adminKeyPattern = /admin_key|executive|master_key|root_authority/gi;
  const matches3684 = content.matchAll(adminKeyPattern);
  for (const match of matches3684) {
    const context = content.substring(Math.max(0, (match.index || 0) - 100), (match.index || 0) + 200);
    if (!context.includes('multisig') && !context.includes('threshold') && !context.includes('timelock')) {
      const lineNum = findLineNumber(content, match.index || 0);
      findings.push({
        id: 'SOL3684',
        title: 'Single Admin Key Without Multisig',
        severity: 'critical',
        description: 'Executive/admin key without multisig protection. Step Finance $40M hack targeted executive vulnerability.',
        location: { file: fileName, line: lineNum },
        recommendation: 'Use multisig (e.g., Squads) for all admin operations',
        code: getCodeSnippet(content, lineNum),
      });
    }
  }
  
  // SOL3685: Emergency Withdrawal Without Limits
  const emergencyPattern = /emergency|rescue|recover|admin_withdraw/gi;
  const matches3685 = content.matchAll(emergencyPattern);
  for (const match of matches3685) {
    const context = content.substring((match.index || 0), (match.index || 0) + 300);
    if (!context.includes('limit') && !context.includes('cap') && !context.includes('timelock')) {
      const lineNum = findLineNumber(content, match.index || 0);
      findings.push({
        id: 'SOL3685',
        title: 'Unlimited Emergency Withdrawal',
        severity: 'critical',
        description: 'Emergency withdrawal without limits. Compromised admin can drain entire protocol.',
        location: { file: fileName, line: lineNum },
        recommendation: 'Add withdrawal limits and timelock: require!(amount <= EMERGENCY_LIMIT)',
        code: getCodeSnippet(content, lineNum),
      });
    }
  }
  
  // SOL3686: Missing Circuit Breaker
  const largeTransferPattern = /transfer|withdraw|drain/gi;
  const matches3686 = content.matchAll(largeTransferPattern);
  for (const match of matches3686) {
    const context = content.substring(Math.max(0, (match.index || 0) - 200), (match.index || 0) + 200);
    if (!context.includes('circuit') && !context.includes('pause') && !context.includes('halt') && !context.includes('limit')) {
      const lineNum = findLineNumber(content, match.index || 0);
      // Only flag if in a function that looks like it handles large amounts
      if (context.includes('vault') || context.includes('pool') || context.includes('treasury')) {
        findings.push({
          id: 'SOL3686',
          title: 'Missing Circuit Breaker',
          severity: 'high',
          description: 'Large fund movements without circuit breaker. Step Finance needed manual intervention.',
          location: { file: fileName, line: lineNum },
          recommendation: 'Implement circuit breaker: auto-pause when withdrawal > X% of TVL in Y time',
          code: getCodeSnippet(content, lineNum),
        });
      }
    }
  }
  
  // ===========================================
  // DEXX $30M PRIVATE KEY LEAK (Nov 2024)
  // ===========================================
  
  // SOL3687: Centralized Key Storage Pattern
  const keyStoragePattern = /private_key|secret_key|keypair|seed_phrase|mnemonic/gi;
  const matches3687 = content.matchAll(keyStoragePattern);
  for (const match of matches3687) {
    const lineNum = findLineNumber(content, match.index || 0);
    findings.push({
      id: 'SOL3687',
      title: 'Private Key in Code',
      severity: 'critical',
      description: 'Private key reference detected. DEXX $30M hack was caused by centralized key management.',
      location: { file: fileName, line: lineNum },
      recommendation: 'Never store private keys in code. Use HSM, MPC, or hardware wallets.',
      code: getCodeSnippet(content, lineNum),
    });
  }
  
  // SOL3688: User Wallet Custody
  const custodyPattern = /user_keypair|custod|hold_key|store_key/gi;
  const matches3688 = content.matchAll(custodyPattern);
  for (const match of matches3688) {
    const lineNum = findLineNumber(content, match.index || 0);
    findings.push({
      id: 'SOL3688',
      title: 'User Key Custody Risk',
      severity: 'critical',
      description: 'Pattern suggests custodial key storage. DEXX attack compromised 9,000+ wallets.',
      location: { file: fileName, line: lineNum },
      recommendation: 'Never hold user private keys. Use non-custodial design with user-controlled wallets.',
      code: getCodeSnippet(content, lineNum),
    });
  }
  
  // ===========================================
  // WEB3.JS SUPPLY CHAIN ATTACK (Dec 2024)
  // ===========================================
  
  // SOL3689: Dependency Version Pinning
  const importPattern = /use\s+solana_|extern\s+crate\s+solana/gi;
  const matches3689 = content.matchAll(importPattern);
  for (const match of matches3689) {
    const lineNum = findLineNumber(content, match.index || 0);
    findings.push({
      id: 'SOL3689',
      title: 'Solana Dependency Without Version Pin',
      severity: 'medium',
      description: 'Solana crate import detected. Web3.js supply chain attack (Dec 2024) shows risk of unpinned deps.',
      location: { file: fileName, line: lineNum },
      recommendation: 'Pin exact versions in Cargo.toml: solana-program = "=1.18.0"',
      code: getCodeSnippet(content, lineNum),
    });
  }
  
  // ===========================================
  // NOONES $8M BRIDGE EXPLOIT (Jan 2025)
  // ===========================================
  
  // SOL3690: Cross-Chain Message Without Finality
  const bridgePattern = /bridge|cross_chain|wormhole|layerzero/gi;
  const matches3690 = content.matchAll(bridgePattern);
  for (const match of matches3690) {
    const context = content.substring((match.index || 0), (match.index || 0) + 300);
    if (!context.includes('finality') && !context.includes('confirmation') && !context.includes('slot_confirmed')) {
      const lineNum = findLineNumber(content, match.index || 0);
      findings.push({
        id: 'SOL3690',
        title: 'Bridge Without Finality Check',
        severity: 'critical',
        description: 'Cross-chain bridge without finality verification. NoOnes $8M exploit across multiple chains.',
        location: { file: fileName, line: lineNum },
        recommendation: 'Wait for sufficient confirmations: require!(slot_confirmed >= 32)',
        code: getCodeSnippet(content, lineNum),
      });
    }
  }
  
  // ===========================================
  // LOOPSCALE $5.8M RATEX EXPLOIT (2025)
  // ===========================================
  
  // SOL3691: Exchange Rate Manipulation
  const ratePattern = /exchange_rate|rate_x|conversion_rate|price_ratio/gi;
  const matches3691 = content.matchAll(ratePattern);
  for (const match of matches3691) {
    const context = content.substring(Math.max(0, (match.index || 0) - 100), (match.index || 0) + 200);
    if (!context.includes('twap') && !context.includes('oracle') && !context.includes('time_weighted')) {
      const lineNum = findLineNumber(content, match.index || 0);
      findings.push({
        id: 'SOL3691',
        title: 'Exchange Rate Without TWAP',
        severity: 'critical',
        description: 'Exchange rate without time-weighted average. Loopscale $5.8M RateX exploit.',
        location: { file: fileName, line: lineNum },
        recommendation: 'Use TWAP oracle: require!(rate_age < MAX_STALENESS && use_twap())',
        code: getCodeSnippet(content, lineNum),
      });
    }
  }
  
  // SOL3692: Share Price Manipulation
  const sharePattern = /share_price|shares_per|price_per_share|vault_share/gi;
  const matches3692 = content.matchAll(sharePattern);
  for (const match of matches3692) {
    const context = content.substring((match.index || 0), (match.index || 0) + 200);
    if (!context.includes('virtual') && !context.includes('dead_shares') && !context.includes('minimum')) {
      const lineNum = findLineNumber(content, match.index || 0);
      findings.push({
        id: 'SOL3692',
        title: 'Share Price Inflation Risk',
        severity: 'high',
        description: 'Share calculation without inflation protection. First depositor attack vector.',
        location: { file: fileName, line: lineNum },
        recommendation: 'Add virtual shares: total_shares = actual_shares + VIRTUAL_SHARES',
        code: getCodeSnippet(content, lineNum),
      });
    }
  }
  
  // ===========================================
  // MANGO MARKETS $116M ORACLE MANIPULATION
  // ===========================================
  
  // SOL3693: Single Oracle Source
  const oraclePattern = /oracle|price_feed|pyth|switchboard/gi;
  const matches3693 = content.matchAll(oraclePattern);
  for (const match of matches3693) {
    const context = content.substring(Math.max(0, (match.index || 0) - 150), (match.index || 0) + 250);
    if (context.split(/oracle|price/gi).length <= 2 && !context.includes('aggregate') && !context.includes('multiple')) {
      const lineNum = findLineNumber(content, match.index || 0);
      findings.push({
        id: 'SOL3693',
        title: 'Single Oracle Dependency',
        severity: 'high',
        description: 'Single oracle source detected. Mango Markets $116M used single-source price manipulation.',
        location: { file: fileName, line: lineNum },
        recommendation: 'Aggregate multiple oracles: price = median(pyth, switchboard, chainlink)',
        code: getCodeSnippet(content, lineNum),
      });
    }
  }
  
  // SOL3694: Missing Confidence Interval Check
  const pricePattern = /\.price|get_price|fetch_price|price_data/gi;
  const matches3694 = content.matchAll(pricePattern);
  for (const match of matches3694) {
    const context = content.substring((match.index || 0), (match.index || 0) + 200);
    if (!context.includes('confidence') && !context.includes('conf') && !context.includes('deviation')) {
      const lineNum = findLineNumber(content, match.index || 0);
      findings.push({
        id: 'SOL3694',
        title: 'Oracle Without Confidence Check',
        severity: 'high',
        description: 'Price fetched without confidence interval validation.',
        location: { file: fileName, line: lineNum },
        recommendation: 'Check confidence: require!(price.conf < price.price * MAX_CONF_PCT)',
        code: getCodeSnippet(content, lineNum),
      });
    }
  }
  
  // ===========================================
  // CREMA FINANCE $8.8M TICK SPOOFING
  // ===========================================
  
  // SOL3695: CLMM Tick Account Validation
  const tickPattern = /tick|position.*liquidity|concentrated/gi;
  const matches3695 = content.matchAll(tickPattern);
  for (const match of matches3695) {
    const context = content.substring(Math.max(0, (match.index || 0) - 100), (match.index || 0) + 200);
    if (!context.includes('owner') && !context.includes('verify') && !context.includes('program_id')) {
      const lineNum = findLineNumber(content, match.index || 0);
      findings.push({
        id: 'SOL3695',
        title: 'CLMM Tick Without Owner Verification',
        severity: 'critical',
        description: 'Tick account without ownership check. Crema Finance $8.8M used fake tick accounts.',
        location: { file: fileName, line: lineNum },
        recommendation: 'Verify tick ownership: require!(tick_account.owner == &PROGRAM_ID)',
        code: getCodeSnippet(content, lineNum),
      });
    }
  }
  
  // ===========================================
  // CASHIO $52M INFINITE MINT
  // ===========================================
  
  // SOL3696: Collateral Mint Validation
  const collateralPattern = /collateral|backing|reserve.*mint/gi;
  const matches3696 = content.matchAll(collateralPattern);
  for (const match of matches3696) {
    const context = content.substring((match.index || 0), (match.index || 0) + 250);
    if (!context.includes('whitelist') && !context.includes('allowed_mint') && !context.includes('verify_mint')) {
      const lineNum = findLineNumber(content, match.index || 0);
      findings.push({
        id: 'SOL3696',
        title: 'Collateral Without Mint Whitelist',
        severity: 'critical',
        description: 'Collateral accepted without mint validation. Cashio $52M used fake collateral.',
        location: { file: fileName, line: lineNum },
        recommendation: 'Whitelist collateral mints: require!(ALLOWED_MINTS.contains(&mint.key()))',
        code: getCodeSnippet(content, lineNum),
      });
    }
  }
  
  // SOL3697: Root of Trust Validation
  const trustPattern = /root.*trust|trust.*root|anchor.*mint/gi;
  const matches3697 = content.matchAll(trustPattern);
  for (const match of matches3697) {
    const lineNum = findLineNumber(content, match.index || 0);
    findings.push({
      id: 'SOL3697',
      title: 'Missing Root of Trust Chain',
      severity: 'critical',
      description: 'Root of trust pattern detected but may be incomplete. Cashio missing validation chain.',
      location: { file: fileName, line: lineNum },
      recommendation: 'Validate complete chain: collateral -> pool -> bank -> root',
      code: getCodeSnippet(content, lineNum),
    });
  }
  
  // ===========================================
  // WORMHOLE $326M SIGNATURE BYPASS
  // ===========================================
  
  // SOL3698: Guardian Signature Verification
  const guardianPattern = /guardian|verify_signature|signature.*check/gi;
  const matches3698 = content.matchAll(guardianPattern);
  for (const match of matches3698) {
    const context = content.substring((match.index || 0), (match.index || 0) + 200);
    if (!context.includes('quorum') && !context.includes('threshold') && !context.includes('count')) {
      const lineNum = findLineNumber(content, match.index || 0);
      findings.push({
        id: 'SOL3698',
        title: 'Guardian Without Quorum Check',
        severity: 'critical',
        description: 'Guardian/signature verification without quorum. Wormhole $326M bypass.',
        location: { file: fileName, line: lineNum },
        recommendation: 'Require quorum: require!(valid_sigs >= (guardians * 2 / 3) + 1)',
        code: getCodeSnippet(content, lineNum),
      });
    }
  }
  
  // SOL3699: Secp256k1 Instruction Validation
  const secpPattern = /secp256k1|ed25519.*verify|verify.*signature/gi;
  const matches3699 = content.matchAll(secpPattern);
  for (const match of matches3699) {
    const context = content.substring((match.index || 0), (match.index || 0) + 200);
    if (!context.includes('instruction_sysvar') && !context.includes('check_ed25519')) {
      const lineNum = findLineNumber(content, match.index || 0);
      findings.push({
        id: 'SOL3699',
        title: 'Signature Verify Without Instruction Check',
        severity: 'critical',
        description: 'Signature verification without validating instruction sysvar.',
        location: { file: fileName, line: lineNum },
        recommendation: 'Validate via instruction sysvar, not just return value',
        code: getCodeSnippet(content, lineNum),
      });
    }
  }
  
  // ===========================================
  // ADVANCED DEFI PATTERNS
  // ===========================================
  
  // SOL3700: Flash Loan Reentrancy
  const flashLoanPattern = /flash.*loan|instant.*borrow|same.*transaction.*repay/gi;
  const matches3700 = content.matchAll(flashLoanPattern);
  for (const match of matches3700) {
    const context = content.substring((match.index || 0), (match.index || 0) + 300);
    if (!context.includes('reentrant') && !context.includes('lock') && !context.includes('guard')) {
      const lineNum = findLineNumber(content, match.index || 0);
      findings.push({
        id: 'SOL3700',
        title: 'Flash Loan Without Reentrancy Guard',
        severity: 'critical',
        description: 'Flash loan implementation without reentrancy protection.',
        location: { file: fileName, line: lineNum },
        recommendation: 'Add reentrancy guard: set_locked(true) before callback',
        code: getCodeSnippet(content, lineNum),
      });
    }
  }
  
  // SOL3701: Liquidation Threshold Manipulation
  const liquidationPattern = /liquidation|health.*factor|collateral.*ratio/gi;
  const matches3701 = content.matchAll(liquidationPattern);
  for (const match of matches3701) {
    const context = content.substring(Math.max(0, (match.index || 0) - 100), (match.index || 0) + 200);
    if (!context.includes('minimum') && !context.includes('floor') && !context.includes('bound')) {
      const lineNum = findLineNumber(content, match.index || 0);
      findings.push({
        id: 'SOL3701',
        title: 'Liquidation Without Minimum Bounds',
        severity: 'high',
        description: 'Liquidation parameters without minimum bounds. Solend attack set threshold to 1%.',
        location: { file: fileName, line: lineNum },
        recommendation: 'Set bounds: require!(liquidation_threshold >= MIN_THRESHOLD)',
        code: getCodeSnippet(content, lineNum),
      });
    }
  }
  
  // SOL3702-SOL3710: Token-2022 Extension Patterns
  const token2022Patterns = [
    { id: 'SOL3702', pattern: /transfer.*hook|TransferHook/gi, name: 'Transfer Hook Validation', desc: 'Transfer hook without validation' },
    { id: 'SOL3703', pattern: /confidential.*transfer|ConfidentialTransfer/gi, name: 'Confidential Transfer Security', desc: 'Confidential transfer without proper encryption handling' },
    { id: 'SOL3704', pattern: /permanent.*delegate|PermanentDelegate/gi, name: 'Permanent Delegate Risk', desc: 'Permanent delegate can drain tokens anytime' },
    { id: 'SOL3705', pattern: /non.*transferable|NonTransferable/gi, name: 'Non-Transferable Token Bypass', desc: 'Non-transferable token could be bypassed via wrapping' },
    { id: 'SOL3706', pattern: /interest.*bearing|InterestBearing/gi, name: 'Interest Rate Manipulation', desc: 'Interest-bearing token rate manipulation' },
    { id: 'SOL3707', pattern: /default.*account.*state/gi, name: 'Default Account State Risk', desc: 'Default frozen state could lock user funds' },
    { id: 'SOL3708', pattern: /memo.*required|MemoTransfer/gi, name: 'Memo Requirement Bypass', desc: 'Memo requirement without enforcement' },
    { id: 'SOL3709', pattern: /cpi.*guard|CpiGuard/gi, name: 'CPI Guard Misconfiguration', desc: 'CPI guard not properly configured' },
    { id: 'SOL3710', pattern: /transfer.*fee.*config|TransferFeeConfig/gi, name: 'Transfer Fee Exploitation', desc: 'Transfer fee config without max bounds' },
  ];
  
  for (const p of token2022Patterns) {
    const matches = content.matchAll(p.pattern);
    for (const match of matches) {
      const lineNum = findLineNumber(content, match.index || 0);
      findings.push({
        id: p.id,
        title: p.name,
        severity: 'high',
        description: p.desc + '. Token-2022 extensions require careful validation.',
        location: { file: fileName, line: lineNum },
        recommendation: 'Review Token-2022 extension security implications',
        code: getCodeSnippet(content, lineNum),
      });
    }
  }
  
  // SOL3711-SOL3720: Compressed NFT Patterns
  const cnftPatterns = [
    { id: 'SOL3711', pattern: /merkle.*proof|verify.*proof/gi, name: 'cNFT Proof Validation', desc: 'Merkle proof without proper verification' },
    { id: 'SOL3712', pattern: /concurrent.*merkle|ConcurrentMerkle/gi, name: 'Concurrent Merkle Race', desc: 'Race condition in concurrent merkle updates' },
    { id: 'SOL3713', pattern: /canopy.*depth|tree.*depth/gi, name: 'Tree Depth Mismatch', desc: 'Tree depth/canopy mismatch could cause failures' },
    { id: 'SOL3714', pattern: /leaf.*schema|LeafSchema/gi, name: 'Leaf Schema Validation', desc: 'Leaf schema version not validated' },
    { id: 'SOL3715', pattern: /creator.*verification|verify.*creator/gi, name: 'Creator Verification Skip', desc: 'Creator verification can be bypassed' },
    { id: 'SOL3716', pattern: /collection.*verification/gi, name: 'Collection Verification', desc: 'Collection verification without authority check' },
    { id: 'SOL3717', pattern: /delegate.*burn|burn.*delegate/gi, name: 'Delegate Burn Authority', desc: 'Delegate with burn authority risk' },
    { id: 'SOL3718', pattern: /tree.*authority|authority.*tree/gi, name: 'Tree Authority Validation', desc: 'Tree authority not validated' },
    { id: 'SOL3719', pattern: /update.*metadata.*tree/gi, name: 'Metadata Update Security', desc: 'Metadata update without authorization' },
    { id: 'SOL3720', pattern: /decompress|decompression/gi, name: 'Decompression Validation', desc: 'Decompression without proper asset verification' },
  ];
  
  for (const p of cnftPatterns) {
    const matches = content.matchAll(p.pattern);
    for (const match of matches) {
      const lineNum = findLineNumber(content, match.index || 0);
      findings.push({
        id: p.id,
        title: p.name,
        severity: 'high',
        description: p.desc + '. Bubblegum/cNFT security pattern.',
        location: { file: fileName, line: lineNum },
        recommendation: 'Follow Metaplex cNFT security best practices',
        code: getCodeSnippet(content, lineNum),
      });
    }
  }
  
  // SOL3721-SOL3730: MEV and Jito Patterns
  const mevPatterns = [
    { id: 'SOL3721', pattern: /bundle|jito.*tip|tip.*account/gi, name: 'Bundle Tip Validation', desc: 'Jito bundle tip without validation' },
    { id: 'SOL3722', pattern: /priority.*fee|compute.*price/gi, name: 'Priority Fee Griefing', desc: 'Priority fee allows economic griefing' },
    { id: 'SOL3723', pattern: /backrun|frontrun|sandwich/gi, name: 'MEV Exposure', desc: 'Transaction vulnerable to MEV extraction' },
    { id: 'SOL3724', pattern: /slot.*leader|leader.*schedule/gi, name: 'Leader Schedule Exploitation', desc: 'Leader schedule exposure for MEV' },
    { id: 'SOL3725', pattern: /transaction.*ordering/gi, name: 'Ordering Dependency', desc: 'Transaction ordering creates MEV opportunity' },
    { id: 'SOL3726', pattern: /slippage.*tolerance/gi, name: 'Slippage Tolerance', desc: 'Wide slippage allows sandwich attacks' },
    { id: 'SOL3727', pattern: /batch.*auction|sealed.*bid/gi, name: 'Batch Auction Security', desc: 'Batch auction front-running prevention' },
    { id: 'SOL3728', pattern: /commit.*reveal/gi, name: 'Commit-Reveal Timing', desc: 'Commit-reveal scheme timing vulnerability' },
    { id: 'SOL3729', pattern: /fair.*ordering|time.*priority/gi, name: 'Fair Ordering', desc: 'Fair ordering not enforced' },
    { id: 'SOL3730', pattern: /atomic.*arb|arbitrage/gi, name: 'Atomic Arbitrage', desc: 'Atomic arbitrage extraction vector' },
  ];
  
  for (const p of mevPatterns) {
    const matches = content.matchAll(p.pattern);
    for (const match of matches) {
      const lineNum = findLineNumber(content, match.index || 0);
      findings.push({
        id: p.id,
        title: p.name,
        severity: 'medium',
        description: p.desc + '. MEV protection pattern.',
        location: { file: fileName, line: lineNum },
        recommendation: 'Implement MEV-resistant design patterns',
        code: getCodeSnippet(content, lineNum),
      });
    }
  }
  
  // SOL3731-SOL3740: Governance and DAO Security
  const govPatterns = [
    { id: 'SOL3731', pattern: /governance.*token|voting.*power/gi, name: 'Governance Token Snapshot', desc: 'Voting power without snapshot mechanism' },
    { id: 'SOL3732', pattern: /proposal.*threshold/gi, name: 'Proposal Threshold', desc: 'Low proposal threshold allows spam' },
    { id: 'SOL3733', pattern: /quorum.*requirement/gi, name: 'Quorum Manipulation', desc: 'Quorum can be manipulated with flash loans' },
    { id: 'SOL3734', pattern: /execution.*delay|timelock.*delay/gi, name: 'Execution Delay Bypass', desc: 'Execution delay could be bypassed' },
    { id: 'SOL3735', pattern: /veto.*power|guardian.*veto/gi, name: 'Veto Power Centralization', desc: 'Centralized veto creates single point of failure' },
    { id: 'SOL3736', pattern: /delegate.*vote|voting.*delegate/gi, name: 'Vote Delegation Security', desc: 'Vote delegation without proper controls' },
    { id: 'SOL3737', pattern: /vote.*weight.*calculation/gi, name: 'Vote Weight Calculation', desc: 'Vote weight calculation manipulation' },
    { id: 'SOL3738', pattern: /proposal.*cancel|cancel.*proposal/gi, name: 'Proposal Cancellation', desc: 'Proposal cancellation authority abuse' },
    { id: 'SOL3739', pattern: /treasury.*execution/gi, name: 'Treasury Execution Risk', desc: 'Treasury can execute arbitrary transactions' },
    { id: 'SOL3740', pattern: /realm|spl.*governance/gi, name: 'SPL Governance Config', desc: 'SPL Governance misconfiguration' },
  ];
  
  for (const p of govPatterns) {
    const matches = content.matchAll(p.pattern);
    for (const match of matches) {
      const lineNum = findLineNumber(content, match.index || 0);
      findings.push({
        id: p.id,
        title: p.name,
        severity: 'high',
        description: p.desc + '. DAO governance security pattern.',
        location: { file: fileName, line: lineNum },
        recommendation: 'Review governance security best practices',
        code: getCodeSnippet(content, lineNum),
      });
    }
  }
  
  // SOL3741-SOL3750: Infrastructure and Operational Security
  const infraPatterns = [
    { id: 'SOL3741', pattern: /rpc.*endpoint|cluster.*url/gi, name: 'RPC Endpoint Exposure', desc: 'RPC endpoint hardcoded or exposed' },
    { id: 'SOL3742', pattern: /rate.*limit|request.*throttle/gi, name: 'Rate Limiting', desc: 'Missing rate limiting for expensive operations' },
    { id: 'SOL3743', pattern: /transaction.*simulation|simulate/gi, name: 'Simulation Bypass', desc: 'Simulation can be bypassed for actual execution' },
    { id: 'SOL3744', pattern: /recent.*blockhash|blockhash.*cache/gi, name: 'Blockhash Management', desc: 'Blockhash management vulnerability' },
    { id: 'SOL3745', pattern: /durable.*nonce/gi, name: 'Durable Nonce Security', desc: 'Durable nonce account security' },
    { id: 'SOL3746', pattern: /lookup.*table|address.*lookup/gi, name: 'Lookup Table Poisoning', desc: 'Address lookup table could be poisoned' },
    { id: 'SOL3747', pattern: /versioned.*transaction|v0.*transaction/gi, name: 'Versioned Transaction', desc: 'Versioned transaction handling' },
    { id: 'SOL3748', pattern: /compute.*budget|request.*units/gi, name: 'Compute Budget Attack', desc: 'Compute budget can be exhausted by attacker' },
    { id: 'SOL3749', pattern: /program.*upgrade|bpf.*upgrade/gi, name: 'Program Upgrade Authority', desc: 'Program upgrade authority centralization' },
    { id: 'SOL3750', pattern: /idl.*publish|anchor.*idl/gi, name: 'IDL Exposure', desc: 'IDL publication exposes program interface' },
  ];
  
  for (const p of infraPatterns) {
    const matches = content.matchAll(p.pattern);
    for (const match of matches) {
      const lineNum = findLineNumber(content, match.index || 0);
      findings.push({
        id: p.id,
        title: p.name,
        severity: 'medium',
        description: p.desc + '. Infrastructure security pattern.',
        location: { file: fileName, line: lineNum },
        recommendation: 'Follow Solana operational security guidelines',
        code: getCodeSnippet(content, lineNum),
      });
    }
  }
  
  return findings;
}
