/**
 * SolGuard Batch 101 Patterns
 * 
 * Feb 6, 2026 10:00 AM - Solsec Deep Dive + Armani Sealevel + Neodyme PoC Framework + Cope Roulette + Port Finance
 * Sources: github.com/sannykim/solsec, Armani's Sealevel Attacks, OtterSec, Neodyme workshops
 * Patterns: SOL6301-SOL6400
 */

import type { Finding, PatternInput } from './index.js';

// ====== ARMANI SEALEVEL ATTACKS (Official Solana Foundation Security Patterns) ======

// SOL6301: Sealevel Attack - Missing Signer Check (Armani #1)
function checkSealevelMissingSignerCheck(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  const content = input.rust.content;

  // Pattern: Using AccountInfo without checking is_signer
  const accountInfoWithoutSigner = /let\s+(\w+)\s*=\s*&ctx\.accounts\.(\w+)[\s\S]{0,200}(?!is_signer|Signer<)/;
  if (accountInfoWithoutSigner.test(content) && 
      !content.includes('#[account(signer)]') &&
      content.includes('AccountInfo')) {
    findings.push({
      id: 'SOL6301',
      title: 'Sealevel Attack: Missing Signer Check',
      severity: 'critical',
      description: 'Armani Sealevel Attack #1: Account is used without verifying is_signer. Attacker can pass any account as authority.',
      location: { file: input.path },
      recommendation: 'Use Anchor\'s Signer<\'info> type or add #[account(signer)] constraint. Never trust AccountInfo without signer verification.',
      code: 'https://github.com/project-serum/sealevel-attacks'
    });
  }
  return findings;
}

// SOL6302: Sealevel Attack - Missing Owner Check (Armani #2)
function checkSealevelMissingOwnerCheck(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  const content = input.rust.content;

  // Pattern: Deserializing account data without checking owner
  const deserializeWithoutOwner = /try_from_slice|Account::unpack|borsh::BorshDeserialize[\s\S]{0,300}(?!\.owner\s*==|has_one|owner\s*=)/;
  if (deserializeWithoutOwner.test(content) && 
      !content.includes('constraint = ') &&
      content.includes('AccountInfo')) {
    findings.push({
      id: 'SOL6302',
      title: 'Sealevel Attack: Missing Owner Check',
      severity: 'critical',
      description: 'Armani Sealevel Attack #2: Account data is deserialized without verifying owner. Attacker can pass malicious account with crafted data.',
      location: { file: input.path },
      recommendation: 'Always verify account.owner == expected_program_id before deserializing. Use Anchor\'s Account<T> which checks owner automatically.',
      code: 'require!(account.owner == &crate::ID, ErrorCode::InvalidOwner);'
    });
  }
  return findings;
}

// SOL6303: Sealevel Attack - Missing Key Check (Armani #3)
function checkSealevelMissingKeyCheck(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  const content = input.rust.content;

  // Pattern: Using account without verifying its pubkey matches expected
  const missingKeyCheck = /ctx\.accounts\.(\w+)[\s\S]{0,200}(?!\.key\(\)\s*==|\.key\s*==|address\s*=)/;
  if (missingKeyCheck.test(content) && 
      content.includes('invoke_signed') &&
      !content.includes('has_one')) {
    findings.push({
      id: 'SOL6303',
      title: 'Sealevel Attack: Missing Key Check',
      severity: 'high',
      description: 'Armani Sealevel Attack #3: Account pubkey not verified before use in CPI. Attacker can pass different account than expected.',
      location: { file: input.path },
      recommendation: 'Use has_one constraint or verify account.key() == expected_key. Anchor\'s address constraint also helps.',
      code: '#[account(address = expected_pubkey)]'
    });
  }
  return findings;
}

// SOL6304: Sealevel Attack - Arithmetic Overflow/Underflow (Armani #4)
function checkSealevelArithmeticOverflow(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  const content = input.rust.content;

  // Pattern: Using +, -, *, / without checked_ or saturating_
  const uncheckedMath = /(?<!checked_|saturating_)(\+|\-|\*|\/)\s*(?!0\b)/;
  if (uncheckedMath.test(content) && 
      !content.includes('#![deny(clippy::integer_arithmetic)]') &&
      (content.includes('amount') || content.includes('balance') || content.includes('supply'))) {
    findings.push({
      id: 'SOL6304',
      title: 'Sealevel Attack: Arithmetic Overflow/Underflow Risk',
      severity: 'high',
      description: 'Armani Sealevel Attack #4: Unchecked arithmetic operations can overflow/underflow. Attackers can manipulate token amounts.',
      location: { file: input.path },
      recommendation: 'Use checked_add(), checked_sub(), checked_mul(), checked_div() or saturating_ variants. Add #![deny(clippy::integer_arithmetic)].',
      code: 'amount.checked_add(fee).ok_or(ErrorCode::Overflow)?'
    });
  }
  return findings;
}

// SOL6305: Sealevel Attack - Type Cosplay (Armani #5)
function checkSealevelTypeCosplay(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  const content = input.rust.content;

  // Pattern: Deserializing without discriminator check
  const typeCosplay = /BorshDeserialize[\s\S]{0,100}(?!discriminator|DISCRIMINATOR)/;
  if (typeCosplay.test(content) && 
      !content.includes('#[account(discriminator') &&
      content.includes('struct')) {
    findings.push({
      id: 'SOL6305',
      title: 'Sealevel Attack: Type Cosplay Vulnerability',
      severity: 'critical',
      description: 'Armani Sealevel Attack #5: Account can masquerade as different type without discriminator check. Attacker passes wrong account type.',
      location: { file: input.path },
      recommendation: 'Use Anchor\'s #[account] macro which adds automatic 8-byte discriminator. For native Solana, manually check discriminator bytes.',
      code: 'require!(data[0..8] == EXPECTED_DISCRIMINATOR, ErrorCode::InvalidAccountType);'
    });
  }
  return findings;
}

// SOL6306: Sealevel Attack - Duplicate Mutable Accounts (Armani #6)
function checkSealevelDuplicateMutable(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  const content = input.rust.content;

  // Pattern: Multiple mutable accounts without checking they're different
  const duplicateMutable = /#\[account\(mut\)\][\s\S]*?#\[account\(mut\)\]/;
  if (duplicateMutable.test(content) && 
      !content.includes('constraint = ') &&
      !content.includes('.key() != ')) {
    findings.push({
      id: 'SOL6306',
      title: 'Sealevel Attack: Duplicate Mutable Accounts',
      severity: 'high',
      description: 'Armani Sealevel Attack #6: Same account can be passed for multiple mutable parameters, causing double-spend or state corruption.',
      location: { file: input.path },
      recommendation: 'Add constraint to ensure accounts are different: constraint = account_a.key() != account_b.key()',
      code: '#[account(mut, constraint = from.key() != to.key() @ ErrorCode::DuplicateAccounts)]'
    });
  }
  return findings;
}

// SOL6307: Sealevel Attack - Bump Seed Canonicalization (Armani #7)
function checkSealevelBumpCanon(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  const content = input.rust.content;

  // Pattern: Using find_program_address but not storing/verifying canonical bump
  const bumpIssue = /find_program_address[\s\S]{0,200}(?!bump\s*=|bump_seed|canonical_bump)/;
  if (bumpIssue.test(content) && 
      content.includes('Pubkey::find_program_address') &&
      !content.includes('bump = ')) {
    findings.push({
      id: 'SOL6307',
      title: 'Sealevel Attack: Bump Seed Canonicalization',
      severity: 'medium',
      description: 'Armani Sealevel Attack #7: PDA created without storing canonical bump. Attacker may use different bump to create collision.',
      location: { file: input.path },
      recommendation: 'Always store the canonical bump returned by find_program_address and verify it on subsequent calls.',
      code: '#[account(seeds = [b"vault"], bump = vault.bump)]'
    });
  }
  return findings;
}

// SOL6308: Sealevel Attack - PDA Sharing (Armani #8)
function checkSealevelPDASharing(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  const content = input.rust.content;

  // Pattern: PDA seeds don't include user-specific data
  const pdaSharing = /seeds\s*=\s*\[\s*b"[\w]+"\s*\](?!\s*,\s*[\w]+\.key)/;
  if (pdaSharing.test(content) && 
      content.includes('init') &&
      !content.includes('user.key()')) {
    findings.push({
      id: 'SOL6308',
      title: 'Sealevel Attack: PDA Sharing Vulnerability',
      severity: 'high',
      description: 'Armani Sealevel Attack #8: PDA seeds don\'t include user-specific data. Different users may share the same PDA.',
      location: { file: input.path },
      recommendation: 'Include user pubkey or other unique identifier in PDA seeds to prevent account sharing.',
      code: 'seeds = [b"user_vault", user.key().as_ref()]'
    });
  }
  return findings;
}

// SOL6309: Sealevel Attack - Closing Accounts (Armani #9)
function checkSealevelClosingAccounts(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  const content = input.rust.content;

  // Pattern: Closing account without zeroing data or checking rent
  const closeIssue = /close\s*=|\.close\([\s\S]{0,200}(?!\.assign|memset|data\.fill\(0\))/;
  if (closeIssue.test(content) && 
      !content.includes('realloc') &&
      content.includes('lamports')) {
    findings.push({
      id: 'SOL6309',
      title: 'Sealevel Attack: Improper Account Closing',
      severity: 'high',
      description: 'Armani Sealevel Attack #9: Account closed without zeroing data. Account may be revived with stale data in same transaction.',
      location: { file: input.path },
      recommendation: 'Use Anchor\'s close constraint which properly zeros data and transfers lamports. For native, zero data before transferring lamports.',
      code: '#[account(mut, close = recipient)]'
    });
  }
  return findings;
}

// ====== NEODYME COMMON PITFALLS ======

// SOL6310: Neodyme - Unverified Invoke Signed Seeds
function checkNeodymeInvokeSigned(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  const content = input.rust.content;

  // Pattern: invoke_signed with potentially incorrect seeds
  const invokeSignedIssue = /invoke_signed\s*\([\s\S]{0,500}(?!assert!|require!|verify)/;
  if (invokeSignedIssue.test(content) && 
      content.includes('invoke_signed') &&
      !content.includes('seeds_check')) {
    findings.push({
      id: 'SOL6310',
      title: 'Neodyme: Unverified Invoke Signed Seeds',
      severity: 'high',
      description: 'Neodyme Common Pitfall: invoke_signed called without verifying seeds match expected PDA. Attacker can pass incorrect seeds.',
      location: { file: input.path },
      recommendation: 'Verify PDA address matches expected before invoke_signed. Use create_program_address to validate.',
      code: 'assert_eq!(Pubkey::create_program_address(&seeds, program_id)?, expected_pda);'
    });
  }
  return findings;
}

// SOL6311: Neodyme - Account Confusion Attack
function checkNeodymeAccountConfusion(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  const content = input.rust.content;

  // Pattern: Multiple accounts of same type without differentiation
  const accountConfusion = /AccountInfo[\s\S]*?AccountInfo[\s\S]*?AccountInfo/;
  if (accountConfusion.test(content) && 
      !content.includes('discriminator') &&
      !content.includes('#[account(')) {
    findings.push({
      id: 'SOL6311',
      title: 'Neodyme: Account Confusion Attack',
      severity: 'critical',
      description: 'Neodyme Common Pitfall: Multiple AccountInfo without type differentiation. Anchor\'s 8-byte discriminator prevents this.',
      location: { file: input.path },
      recommendation: 'Use Anchor with #[account] macro which automatically adds type discriminators. For native, add manual discriminator checks.',
      code: '#[account] // Anchor adds 8-byte discriminator automatically'
    });
  }
  return findings;
}

// ====== COPE ROULETTE EXPLOIT PATTERNS ======

// SOL6312: Cope Roulette - Reverting Transaction Exploit
function checkCopeRouletteRevert(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  const content = input.rust.content;

  // Pattern: Random/lottery without revert protection
  const revertExploit = /(random|lottery|roulette|chance|probability)[\s\S]{0,500}(?!revert_check|simulation_check|recent_blockhash)/i;
  if (revertExploit.test(content) && 
      (content.includes('transfer') || content.includes('payout'))) {
    findings.push({
      id: 'SOL6312',
      title: 'Cope Roulette: Reverting Transaction Exploit',
      severity: 'critical',
      description: 'Arrowana Cope Roulette: Randomness games vulnerable to revert attacks. Attacker submits TX, reverts if loses, keeps if wins.',
      location: { file: input.path },
      recommendation: 'Use commit-reveal scheme or VRF (Switchboard). Delay payout to separate transaction. Check for simulation detection.',
      code: 'require!(!is_simulating(), ErrorCode::SimulationDetected);'
    });
  }
  return findings;
}

// SOL6313: Simulation Detection Bypass
function checkSimulationDetectionBypass(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  const content = input.rust.content;

  // Pattern: Simulation detection that can be bypassed
  const simBypass = /Clock::get\(\)[\s\S]{0,200}(random|lottery|game)/i;
  if (simBypass.test(content) && 
      !content.includes('commit') &&
      !content.includes('reveal')) {
    findings.push({
      id: 'SOL6313',
      title: 'Simulation Detection Bypass',
      severity: 'high',
      description: 'Using Clock for simulation detection can be bypassed. Bank module allows sophisticated simulation attacks.',
      location: { file: input.path },
      recommendation: 'Use commit-reveal pattern with time delay. Check Instructions sysvar for preflight detection.',
      code: 'let ixs = Instructions::load(instructions_sysvar)?; // Check for simulation'
    });
  }
  return findings;
}

// ====== PORT FINANCE MAX WITHDRAW BUG ======

// SOL6314: Port Finance - Max Withdraw Calculation Bug
function checkPortFinanceMaxWithdraw(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  const content = input.rust.content;

  // Pattern: Withdraw calculation without proper bounds
  const maxWithdrawBug = /(max_withdraw|withdraw_amount|available_liquidity)[\s\S]{0,200}(?!min\(|cmp::min|\.min\()/;
  if (maxWithdrawBug.test(content) && 
      content.includes('withdraw') &&
      (content.includes('liquidity') || content.includes('reserve'))) {
    findings.push({
      id: 'SOL6314',
      title: 'Port Finance: Max Withdraw Calculation Bug',
      severity: 'high',
      description: 'nojob Port Finance bug: Withdraw calculation doesn\'t properly bound by available liquidity. Can drain more than available.',
      location: { file: input.path },
      recommendation: 'Always use min(requested_amount, available_liquidity) for withdrawals. Add explicit bounds checking.',
      code: 'let withdraw_amount = amount.min(reserve.liquidity.available_amount);'
    });
  }
  return findings;
}

// ====== JET PROTOCOL BREAK BUG ======

// SOL6315: Jet Protocol - Break Logic Bug
function checkJetBreakBug(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  const content = input.rust.content;

  // Pattern: break statement in loop with financial logic
  const breakBug = /for[\s\S]{0,200}break[\s\S]{0,100}(balance|amount|transfer|deposit)/i;
  if (breakBug.test(content)) {
    findings.push({
      id: 'SOL6315',
      title: 'Jet Protocol: Break Logic Bug',
      severity: 'high',
      description: 'Jayne Jet Protocol bug: Unintended use of break in loop causes early termination, skipping required validation.',
      location: { file: input.path },
      recommendation: 'Review all break statements in loops handling financial logic. Ensure all iterations complete or use continue instead.',
      code: '// Avoid: break; // Use: continue; or complete all iterations'
    });
  }
  return findings;
}

// ====== NEODYME $2.6B SPL-LENDING ROUNDING ======

// SOL6316: Neodyme - SPL-Lending Rounding Exploit
function checkNeodymeSPLRounding(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  const content = input.rust.content;

  // Pattern: Division/rounding in lending without direction control
  const roundingExploit = /(collateral|borrow|repay|liquidat)[\s\S]{0,200}(\/|div|checked_div)[\s\S]{0,100}(?!ceil|floor|round_up|round_down)/i;
  if (roundingExploit.test(content) && 
      content.includes('exchange_rate')) {
    findings.push({
      id: 'SOL6316',
      title: 'Neodyme: SPL-Lending Rounding Exploit ($2.6B at risk)',
      severity: 'critical',
      description: 'Neodyme 2021: Innocent rounding errors in SPL-Lending put $2.6B at risk. Attacker accumulates dust across many small operations.',
      location: { file: input.path },
      recommendation: 'Always round in favor of the protocol: ceil when user receives, floor when user deposits. Use explicit direction.',
      code: 'let collateral = deposit.checked_ceil_div(exchange_rate)?; // Round UP against user'
    });
  }
  return findings;
}

// ====== SOLENS INCINERATOR ATTACK ======

// SOL6317: Solens - Incinerator SPL Token Attack
function checkSolensIncineratorAttack(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  const content = input.rust.content;

  // Pattern: Token burning without proper validation
  const incineratorAttack = /(burn|incinerator|destroy)[\s\S]{0,200}(?!owner_check|authority_check)/i;
  if (incineratorAttack.test(content) && 
      content.includes('spl_token') &&
      content.includes('mint')) {
    findings.push({
      id: 'SOL6317',
      title: 'Solens: Incinerator SPL Token Attack',
      severity: 'high',
      description: 'Solens Royal Flush Attack: Chaining small exploits in token incinerator programs. Watch samczsun\'s exploit chaining talk.',
      location: { file: input.path },
      recommendation: 'Verify all accounts in burn/transfer operations. Don\'t trust user-provided token accounts without validation.',
      code: 'require!(burn_account.owner == authority.key(), ErrorCode::InvalidOwner);'
    });
  }
  return findings;
}

// ====== SOLENS CANDY MACHINE EXPLOIT ======

// SOL6318: Solens - Candy Machine UncheckedAccount
function checkSolensCandyMachine(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  const content = input.rust.content;

  // Pattern: UncheckedAccount without proper documentation
  const candyMachineExploit = /UncheckedAccount[\s\S]{0,100}(?!\/\/\/ CHECK|#\[doc)/;
  if (candyMachineExploit.test(content)) {
    findings.push({
      id: 'SOL6318',
      title: 'Solens: Candy Machine UncheckedAccount Exploit',
      severity: 'critical',
      description: 'Solens 2022: Candy Machine exploit via UncheckedAccount. Anchor PR #1452 now requires /// CHECK documentation.',
      location: { file: input.path },
      recommendation: 'All UncheckedAccount must have /// CHECK comment explaining why it\'s safe. Better yet, use typed accounts.',
      code: '/// CHECK: This account is verified in the instruction handler\npub unchecked: UncheckedAccount<\'info>,'
    });
  }
  return findings;
}

// ====== SEC3 STAKE POOL SEMANTIC INCONSISTENCY ======

// SOL6319: Sec3 - Stake Pool Semantic Inconsistency
function checkSec3StakePoolInconsistency(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  const content = input.rust.content;

  // Pattern: Stake operations with potential semantic issues
  const semanticInconsistency = /(stake|unstake|withdraw_stake)[\s\S]{0,300}(update|set|modify)[\s\S]{0,100}(?!verify|validate|check)/i;
  if (semanticInconsistency.test(content) && 
      content.includes('pool')) {
    findings.push({
      id: 'SOL6319',
      title: 'Sec3: Stake Pool Semantic Inconsistency',
      severity: 'high',
      description: 'Sec3 X-Ray detection: Semantic inconsistency between stake pool operations. Even audited code (3 auditors) had this bug.',
      location: { file: input.path },
      recommendation: 'Ensure semantic consistency between related operations. Use invariant checks after state modifications.',
      code: '// Add invariant: total_stake == sum(all_validator_stakes)'
    });
  }
  return findings;
}

// ====== ROOTER SOLEND MALICIOUS LENDING MARKET ======

// SOL6320: Rooter - Malicious Lending Market
function checkRooterMaliciousLendingMarket(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  const content = input.rust.content;

  // Pattern: Lending market creation without proper validation
  const maliciousMarket = /(create_market|init_market|lending_market)[\s\S]{0,300}(?!whitelist|verified|trusted)/i;
  if (maliciousMarket.test(content) && 
      content.includes('lending') &&
      !content.includes('admin_only')) {
    findings.push({
      id: 'SOL6320',
      title: 'Rooter: Malicious Lending Market Attack',
      severity: 'critical',
      description: 'Rooter 2022: Attacker creates malicious lending market to bypass security checks. Read Kudelski\'s Solana Program Security blog.',
      location: { file: input.path },
      recommendation: 'Use whitelist for trusted lending markets. Verify market ownership and configuration before interacting.',
      code: 'require!(TRUSTED_MARKETS.contains(&market.key()), ErrorCode::UntrustedMarket);'
    });
  }
  return findings;
}

// ====== HANA TOKEN APPROVE REVOCATION ======

// SOL6321: Hana - Token Approval Revocation Trick
function checkHanaApprovalRevocation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  const content = input.rust.content;

  // Pattern: Token approvals without revocation mechanism
  const approvalTrick = /(approve|delegate|set_authority)[\s\S]{0,200}(?!revoke|revoken|zero_approval)/i;
  if (approvalTrick.test(content) && 
      content.includes('spl_token')) {
    findings.push({
      id: 'SOL6321',
      title: 'Hana: Token Approval Revocation Trick',
      severity: 'medium',
      description: 'Hana 2501babe: Sneaky ways to revoke Solana token approvals. Users may have lingering approvals they\'re not aware of.',
      location: { file: input.path },
      recommendation: 'Always provide clear revocation mechanism. Consider using close_account to fully revoke. Check revoken tool.',
      code: 'spl_token::instruction::revoke(&spl_token::ID, &token_account, &owner, &[])?'
    });
  }
  return findings;
}

// ====== OTTERSEC LP TOKEN ORACLE MANIPULATION ======

// SOL6322: OtterSec - LP Token Oracle Manipulation ($200M)
function checkOtterSecLPOracle(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  const content = input.rust.content;

  // Pattern: LP token pricing without fair value calculation
  const lpOracleManip = /(lp_token|pool_token|liquidity_token)[\s\S]{0,300}(price|value|oracle)[\s\S]{0,100}(?!fair_price|twap|geometric_mean)/i;
  if (lpOracleManip.test(content)) {
    findings.push({
      id: 'SOL6322',
      title: 'OtterSec: LP Token Oracle Manipulation ($200M at risk)',
      severity: 'critical',
      description: 'OtterSec 2022: $200M bluff via LP token oracle manipulation. Move AMM price to manipulate oracle, exploit lending protocol.',
      location: { file: input.path },
      recommendation: 'Use fair pricing for LP tokens (geometric mean of reserves). Use TWAPs. See Drift oracle guardrails for examples.',
      code: 'let fair_price = (reserve_a * reserve_b).sqrt() * 2 / total_supply;'
    });
  }
  return findings;
}

// ====== DRIFT ORACLE GUARDRAILS ======

// SOL6323: Drift - Missing Oracle Guardrails
function checkDriftOracleGuardrails(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  const content = input.rust.content;

  // Pattern: Oracle usage without guardrails
  const oracleGuardrails = /(oracle|price_feed|pyth|switchboard)[\s\S]{0,300}(?!confidence|deviation|stale|guardrail|max_divergence)/i;
  if (oracleGuardrails.test(content) && 
      content.includes('get_price')) {
    findings.push({
      id: 'SOL6323',
      title: 'Drift: Missing Oracle Guardrails',
      severity: 'high',
      description: 'Drift Protocol implements oracle guardrails to prevent manipulation. Missing guardrails allow flash loan attacks.',
      location: { file: input.path },
      recommendation: 'Implement oracle guardrails: confidence intervals, staleness checks, max divergence from TWAP, circuit breakers.',
      code: 'require!(oracle.confidence < MAX_CONFIDENCE && oracle.timestamp > min_timestamp);'
    });
  }
  return findings;
}

// ====== WORMHOLE SIGNATURE SET SPOOFING ======

// SOL6324: Wormhole - Signature Set Spoofing
function checkWormholeSignatureSpoofing(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  const content = input.rust.content;

  // Pattern: Guardian/signature verification delegation
  const signatureSpoofing = /(guardian|signature|verify_signatures|validator_set)[\s\S]{0,300}(delegate|chain|forward)/i;
  if (signatureSpoofing.test(content) && 
      !content.includes('direct_verify')) {
    findings.push({
      id: 'SOL6324',
      title: 'Wormhole: Signature Set Spoofing',
      severity: 'critical',
      description: 'Wormhole 2022: $326M hack via signature verification bypass. When chaining delegation of signature verification, ensure it leads to proper verification.',
      location: { file: input.path },
      recommendation: 'Validate unmodified, reference-only accounts per Solana docs. Never trust delegated signature verification without direct validation.',
      code: '// Verify signature directly, don\'t trust delegated verification'
    });
  }
  return findings;
}

// ====== CASHIO ROOT OF TRUST ======

// SOL6325: Cashio - Missing Root of Trust
function checkCashioRootOfTrust(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  const content = input.rust.content;

  // Pattern: Collateral validation without root of trust
  const rootOfTrust = /(collateral|backing|mint|deposit)[\s\S]{0,300}(?!root_of_trust|trusted_mint|verified_token)/i;
  if (rootOfTrust.test(content) && 
      content.includes('validate') &&
      (content.includes('saber') || content.includes('lp') || content.includes('collateral'))) {
    findings.push({
      id: 'SOL6325',
      title: 'Cashio: Missing Root of Trust',
      severity: 'critical',
      description: 'Cashio 2022: $52.8M infinite mint glitch. Missing validation of mint field in collateral account. Establish root of trust!',
      location: { file: input.path },
      recommendation: 'samczsun: Establish a root of trust! Verify all input accounts chain back to trusted, hardcoded values.',
      code: 'require!(collateral.mint == TRUSTED_MINT, ErrorCode::InvalidCollateralMint);'
    });
  }
  return findings;
}

// ====== ADDITIONAL AUDIT FIRM PATTERNS ======

// SOL6326: Kudelski - Data Validation Basics
function checkKudelskiDataValidation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  const content = input.rust.content;

  // Pattern: Account data used without validation
  const dataValidation = /data\.(borrow|borrow_mut|as_ref)[\s\S]{0,200}(?!validate|check|verify)/;
  if (dataValidation.test(content) && 
      !content.includes('try_borrow')) {
    findings.push({
      id: 'SOL6326',
      title: 'Kudelski: Missing Data Validation',
      severity: 'high',
      description: 'Kudelski 2021: High-level overview emphasizes ownership and data validation as critical security requirements.',
      location: { file: input.path },
      recommendation: 'Always validate account data before use. Check length, discriminator, and expected values.',
      code: 'let data = account.try_borrow_data()?; require!(data.len() >= EXPECTED_SIZE);'
    });
  }
  return findings;
}

// SOL6327: Certik - Francium Style Exploits
function checkCertikFranciumStyle(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  const content = input.rust.content;

  // Pattern: Yield farming without proper accounting
  const yieldFarming = /(farm|harvest|compound|yield)[\s\S]{0,300}(reward|emission|apr)/i;
  if (yieldFarming.test(content) && 
      !content.includes('last_update') &&
      !content.includes('reward_per_share')) {
    findings.push({
      id: 'SOL6327',
      title: 'Certik: Yield Farming Accounting',
      severity: 'medium',
      description: 'Certik Francium audit: Yield farming protocols require precise reward accounting to prevent drain attacks.',
      location: { file: input.path },
      recommendation: 'Track reward_per_share and last_update_time. Use accumulator pattern for fair distribution.',
      code: 'pending_reward = user_amount * (reward_per_share - user_reward_debt)'
    });
  }
  return findings;
}

// SOL6328: Halborn - Cropper AMM Patterns
function checkHalbornCropperAMM(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  const content = input.rust.content;

  // Pattern: AMM swap without slippage protection
  const ammSlippage = /(swap|exchange|trade)[\s\S]{0,300}(?!min_amount|slippage|minimum_out)/i;
  if (ammSlippage.test(content) && 
      content.includes('pool') &&
      content.includes('amount')) {
    findings.push({
      id: 'SOL6328',
      title: 'Halborn: AMM Slippage Protection',
      severity: 'high',
      description: 'Halborn Cropper AMM audit: All swaps must have slippage protection to prevent sandwich attacks.',
      location: { file: input.path },
      recommendation: 'Always require minimum_amount_out parameter. Revert if output is less than minimum.',
      code: 'require!(amount_out >= minimum_amount_out, ErrorCode::SlippageExceeded);'
    });
  }
  return findings;
}

// SOL6329: SlowMist - Larix Lending Patterns
function checkSlowMistLarix(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  const content = input.rust.content;

  // Pattern: Lending interest calculation issues
  const interestCalc = /(interest|borrow_rate|utilization)[\s\S]{0,300}(calculate|compute|update)/i;
  if (interestCalc.test(content) && 
      !content.includes('compound') &&
      content.includes('rate')) {
    findings.push({
      id: 'SOL6329',
      title: 'SlowMist: Lending Interest Calculation',
      severity: 'medium',
      description: 'SlowMist Larix audit: Interest calculations must compound correctly to prevent accumulation errors over time.',
      location: { file: input.path },
      recommendation: 'Use compound interest formula. Update interest on every interaction. Handle accrued interest precisely.',
      code: 'let compound_interest = principal * (1 + rate).pow(periods) - principal;'
    });
  }
  return findings;
}

// SOL6330: Bramah - Saber/Crema Patterns
function checkBramahSaberCrema(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  const content = input.rust.content;

  // Pattern: Stableswap curve implementation
  const stableswap = /(stable|curve|amplification|amp_factor)/i;
  if (stableswap.test(content) && 
      content.includes('swap') &&
      !content.includes('invariant_check')) {
    findings.push({
      id: 'SOL6330',
      title: 'Bramah: Stableswap Curve Security',
      severity: 'medium',
      description: 'Bramah Saber/Crema audits: Stableswap curves require invariant checks and proper amplification handling.',
      location: { file: input.path },
      recommendation: 'Verify curve invariant before and after operations. Handle amplification factor changes safely.',
      code: 'require!(compute_d(balances) == D, ErrorCode::InvariantViolated);'
    });
  }
  return findings;
}

// ====== 2026 EMERGING PATTERNS ======

// SOL6331: 2026 - AI Agent Wallet Security
function checkAIAgentWalletSecurity(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  const content = input.rust.content;

  // Pattern: Automated/agent wallet operations
  const aiAgent = /(agent|automated|bot|script)[\s\S]{0,300}(wallet|keypair|sign)/i;
  if (aiAgent.test(content) && 
      !content.includes('spending_limit') &&
      !content.includes('rate_limit')) {
    findings.push({
      id: 'SOL6331',
      title: '2026: AI Agent Wallet Security',
      severity: 'high',
      description: 'Emerging 2026: AI agents with wallet access need spending limits and rate limiting to prevent runaway transactions.',
      location: { file: input.path },
      recommendation: 'Implement per-transaction and daily spending limits. Add rate limiting. Use session keys with limited scope.',
      code: 'require!(daily_spent + amount <= daily_limit, ErrorCode::SpendingLimitExceeded);'
    });
  }
  return findings;
}

// SOL6332: 2026 - Intent-Based Architecture Security
function checkIntentBasedSecurity(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  const content = input.rust.content;

  // Pattern: Intent/solver architecture
  const intentBased = /(intent|solver|fulfillment|order_flow)/i;
  if (intentBased.test(content) && 
      !content.includes('deadline') &&
      !content.includes('expiry')) {
    findings.push({
      id: 'SOL6332',
      title: '2026: Intent-Based Architecture Security',
      severity: 'medium',
      description: 'Emerging 2026: Intent-based systems need deadline enforcement to prevent stale intent execution.',
      location: { file: input.path },
      recommendation: 'Add expiry timestamps to all intents. Verify solver reputation. Implement fallback mechanisms.',
      code: 'require!(Clock::get()?.unix_timestamp < intent.expiry, ErrorCode::IntentExpired);'
    });
  }
  return findings;
}

// SOL6333: Sec3 2025 - Business Logic 38.5%
function checkSec3BusinessLogic2025(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  const content = input.rust.content;

  // Pattern: Complex business logic without invariant checks
  const businessLogic = /(deposit|withdraw|swap|liquidate|claim)[\s\S]{0,500}(?!invariant|assert_state|verify_state)/i;
  if (businessLogic.test(content) && 
      content.includes('mut') &&
      content.includes('state')) {
    findings.push({
      id: 'SOL6333',
      title: 'Sec3 2025: Business Logic Vulnerability (38.5% of all bugs)',
      severity: 'high',
      description: 'Sec3 2025 Report: Business logic flaws account for 38.5% of all vulnerabilities in 163 audits. Top category for high/critical.',
      location: { file: input.path },
      recommendation: 'Add invariant checks after every state mutation. Document expected state transitions. Use state machine patterns.',
      code: 'fn verify_invariants(&self) -> Result<()> { /* check all invariants */ }'
    });
  }
  return findings;
}

// SOL6334: Sec3 2025 - Input Validation 25%
function checkSec3InputValidation2025(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  const content = input.rust.content;

  // Pattern: Function parameters without validation
  const inputValidation = /pub fn \w+[\s\S]{0,100}(amount|value|index|count):\s*(u64|u128|usize)[\s\S]{0,200}(?!require!|assert!|check)/;
  if (inputValidation.test(content)) {
    findings.push({
      id: 'SOL6334',
      title: 'Sec3 2025: Input Validation (25% of all bugs)',
      severity: 'high',
      description: 'Sec3 2025 Report: Input validation issues account for 25% of all vulnerabilities. Second highest category.',
      location: { file: input.path },
      recommendation: 'Validate all inputs at function entry. Check bounds, ranges, and expected values. Fail fast.',
      code: 'require!(amount > 0 && amount <= MAX_AMOUNT, ErrorCode::InvalidAmount);'
    });
  }
  return findings;
}

// SOL6335: Sec3 2025 - Access Control 19%
function checkSec3AccessControl2025(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  const content = input.rust.content;

  // Pattern: Admin/privileged functions without proper access control
  const accessControl = /(admin|owner|authority|governance)[\s\S]{0,300}(set|update|change|modify)[\s\S]{0,100}(?!has_one|constraint|signer)/i;
  if (accessControl.test(content)) {
    findings.push({
      id: 'SOL6335',
      title: 'Sec3 2025: Access Control (19% of all bugs)',
      severity: 'critical',
      description: 'Sec3 2025 Report: Access control failures account for 19% of all vulnerabilities. Third highest category.',
      location: { file: input.path },
      recommendation: 'Use has_one constraint for authority checks. Implement role-based access control. Add timelocks for sensitive operations.',
      code: '#[account(has_one = authority @ ErrorCode::Unauthorized)]'
    });
  }
  return findings;
}

// Combined scanner for Batch 101
export function checkBatch101Patterns(input: PatternInput): Finding[] {
  return [
    // Armani Sealevel Attacks
    ...checkSealevelMissingSignerCheck(input),
    ...checkSealevelMissingOwnerCheck(input),
    ...checkSealevelMissingKeyCheck(input),
    ...checkSealevelArithmeticOverflow(input),
    ...checkSealevelTypeCosplay(input),
    ...checkSealevelDuplicateMutable(input),
    ...checkSealevelBumpCanon(input),
    ...checkSealevelPDASharing(input),
    ...checkSealevelClosingAccounts(input),
    // Neodyme Common Pitfalls
    ...checkNeodymeInvokeSigned(input),
    ...checkNeodymeAccountConfusion(input),
    // Cope Roulette
    ...checkCopeRouletteRevert(input),
    ...checkSimulationDetectionBypass(input),
    // Port Finance
    ...checkPortFinanceMaxWithdraw(input),
    // Jet Protocol
    ...checkJetBreakBug(input),
    // Neodyme $2.6B
    ...checkNeodymeSPLRounding(input),
    // Solens
    ...checkSolensIncineratorAttack(input),
    ...checkSolensCandyMachine(input),
    // Sec3
    ...checkSec3StakePoolInconsistency(input),
    // Rooter
    ...checkRooterMaliciousLendingMarket(input),
    // Hana
    ...checkHanaApprovalRevocation(input),
    // OtterSec
    ...checkOtterSecLPOracle(input),
    // Drift
    ...checkDriftOracleGuardrails(input),
    // Wormhole
    ...checkWormholeSignatureSpoofing(input),
    // Cashio
    ...checkCashioRootOfTrust(input),
    // Audit Firms
    ...checkKudelskiDataValidation(input),
    ...checkCertikFranciumStyle(input),
    ...checkHalbornCropperAMM(input),
    ...checkSlowMistLarix(input),
    ...checkBramahSaberCrema(input),
    // 2026 Emerging
    ...checkAIAgentWalletSecurity(input),
    ...checkIntentBasedSecurity(input),
    // Sec3 2025 Report
    ...checkSec3BusinessLogic2025(input),
    ...checkSec3InputValidation2025(input),
    ...checkSec3AccessControl2025(input),
  ];
}

// Export all patterns
export const batch101Patterns = {
  checkSealevelMissingSignerCheck,
  checkSealevelMissingOwnerCheck,
  checkSealevelMissingKeyCheck,
  checkSealevelArithmeticOverflow,
  checkSealevelTypeCosplay,
  checkSealevelDuplicateMutable,
  checkSealevelBumpCanon,
  checkSealevelPDASharing,
  checkSealevelClosingAccounts,
  checkNeodymeInvokeSigned,
  checkNeodymeAccountConfusion,
  checkCopeRouletteRevert,
  checkSimulationDetectionBypass,
  checkPortFinanceMaxWithdraw,
  checkJetBreakBug,
  checkNeodymeSPLRounding,
  checkSolensIncineratorAttack,
  checkSolensCandyMachine,
  checkSec3StakePoolInconsistency,
  checkRooterMaliciousLendingMarket,
  checkHanaApprovalRevocation,
  checkOtterSecLPOracle,
  checkDriftOracleGuardrails,
  checkWormholeSignatureSpoofing,
  checkCashioRootOfTrust,
  checkKudelskiDataValidation,
  checkCertikFranciumStyle,
  checkHalbornCropperAMM,
  checkSlowMistLarix,
  checkBramahSaberCrema,
  checkAIAgentWalletSecurity,
  checkIntentBasedSecurity,
  checkSec3BusinessLogic2025,
  checkSec3InputValidation2025,
  checkSec3AccessControl2025,
};
