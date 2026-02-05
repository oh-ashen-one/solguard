/**
 * Batch 34: February 2026 Latest Exploits & Security Patterns
 * 
 * Based on:
 * - Signature Phishing Attack (Jan 7, 2026) - Owner permission manipulation
 * - Step Finance Hack (Feb 1, 2026) - $40M wallet compromise
 * - NoOnes Exploit (Jan 2025) - $8.5M withdrawal bypass
 * - Recent phishing/social engineering vectors
 */

import type { PatternInput } from './index.js';
import type { Finding } from '../commands/audit.js';

// SOL885: Signature Phishing via Owner Permission Field
export function checkOwnerPermissionPhishing(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rust = input.rust;
  if (!rust?.content) return findings;

  // Check for patterns vulnerable to owner permission manipulation
  const ownerPatterns = [
    /set_authority.*owner/gi,
    /authority.*assignment/gi,
    /transfer.*ownership/gi,
    /owner\s*=\s*ctx\.accounts/gi,
    /update_authority/gi,
  ];

  // Check if there's proper verification before owner changes
  const hasSignerCheck = /is_signer|Signer<|#\[account\(.*signer.*\)\]/i.test(rust.content);
  const hasConfirmation = /pending_owner|confirm_transfer|two_step/i.test(rust.content);

  for (const pattern of ownerPatterns) {
    if (pattern.test(rust.content) && !hasConfirmation) {
      findings.push({
        id: 'SOL885',
        severity: 'critical',
        title: 'Owner Permission Phishing Attack Vector',
        message: 'Account ownership transfer without two-step confirmation enables signature phishing attacks. Attackers can trick users into signing transactions that silently transfer account control. Implement pending owner confirmation mechanism.',
        file: input.path,
        line: 0,
        recommendation: 'Use two-step ownership transfer: (1) set_pending_owner, (2) accept_ownership. Require explicit confirmation from new owner.',
      });
      break;
    }
  }

  return findings;
}

// SOL886: Wallet Key Exposure via Centralized Storage
export function checkCentralizedWalletStorage(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rust = input.rust;
  if (!rust?.content) return findings;

  // Patterns indicating centralized key management
  const centralizedPatterns = [
    /hot_wallet|hotWallet/gi,
    /central.*key/gi,
    /admin.*private/gi,
    /master.*wallet/gi,
    /treasury.*single/gi,
    /withdraw.*authority.*single/gi,
  ];

  // Check for multisig protection
  const hasMultisig = /multisig|multi_sig|threshold|m_of_n|squads/i.test(rust.content);
  const hasTimelock = /timelock|time_lock|delay|cooldown/i.test(rust.content);

  for (const pattern of centralizedPatterns) {
    if (pattern.test(rust.content) && !hasMultisig) {
      findings.push({
        id: 'SOL886',
        severity: 'critical',
        title: 'Centralized Wallet Key Exposure Risk (Step Finance Style)',
        message: 'Single-key treasury/withdrawal authority without multisig creates catastrophic loss risk. The Step Finance hack ($40M) exploited compromised admin keys with no multisig protection.',
        file: input.path,
        line: 0,
        recommendation: 'Implement multisig for all treasury operations. Use hardware wallets. Add timelocks for large withdrawals.',
      });
      break;
    }
  }

  return findings;
}

// SOL887: Transaction Simulation Bypass Detection
export function checkSimulationBypassRisk(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rust = input.rust;
  if (!rust?.content) return findings;

  // Patterns that behave differently in simulation vs execution
  const simulationSensitive = [
    /get_stack_height|sol_get_stack_height/gi,
    /Clock::get\(\).*\?/gi,
    /slot\(\)|current_slot/gi,
    /block_time|unix_timestamp/gi,
  ];

  // Check for different behavior based on context
  const hasBranchingLogic = /if.*slot|if.*timestamp|if.*block/i.test(rust.content);

  for (const pattern of simulationSensitive) {
    if (pattern.test(rust.content) && hasBranchingLogic) {
      findings.push({
        id: 'SOL887',
        severity: 'high',
        title: 'Transaction Simulation Bypass Risk',
        message: 'Logic that varies based on slot/timestamp can behave differently in simulation vs execution. Phishing attacks exploit this to show safe simulation results while executing malicious transfers.',
        file: input.path,
        line: 0,
        recommendation: 'Avoid time-sensitive branching that could differ between simulation and execution. Use deterministic logic paths.',
      });
      break;
    }
  }

  return findings;
}

// SOL888: Hidden Authority Transfer in Transaction
export function checkHiddenAuthorityTransfer(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rust = input.rust;
  if (!rust?.content) return findings;

  // Check for authority changes bundled with other operations
  const bundledAuth = [
    /transfer.*set_authority/gi,
    /swap.*update.*owner/gi,
    /claim.*authority/gi,
    /deposit.*set.*admin/gi,
  ];

  for (const pattern of bundledAuth) {
    if (pattern.test(rust.content)) {
      findings.push({
        id: 'SOL888',
        severity: 'critical',
        title: 'Hidden Authority Transfer Attack Vector',
        message: 'Authority changes bundled with other operations can be hidden in complex transactions. Users may sign thinking they are just swapping tokens while losing account ownership.',
        file: input.path,
        line: 0,
        recommendation: 'Separate authority change instructions. Emit clear events on any authority modification. Require explicit user consent for ownership changes.',
      });
      break;
    }
  }

  return findings;
}

// SOL889: NoOnes-Style Withdrawal Verification Missing
export function checkWithdrawalVerificationMissing(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rust = input.rust;
  if (!rust?.content) return findings;

  // Check for withdrawal without proper verification
  const hasWithdraw = /withdraw|claim|redeem|transfer_out/i.test(rust.content);
  const hasBalanceCheck = /balance.*check|require.*balance|assert.*balance/i.test(rust.content);
  const hasSignatureVerify = /verify.*signature|ed25519_verify|signature.*valid/i.test(rust.content);

  if (hasWithdraw && !hasBalanceCheck && !hasSignatureVerify) {
    findings.push({
      id: 'SOL889',
      severity: 'critical',
      title: 'Withdrawal Verification Missing (NoOnes Style)',
      message: 'Withdrawal function lacks proper balance and signature verification. The NoOnes exploit ($8.5M) bypassed verification checks to drain funds across chains.',
      file: input.path,
      line: 0,
      recommendation: 'Implement strict balance checks, signature verification, and rate limiting on all withdrawal operations.',
    });
  }

  return findings;
}

// SOL890: Social Engineering Attack Surface
export function checkSocialEngineeringAttackSurface(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rust = input.rust;
  if (!rust?.content) return findings;

  // Patterns that could be exploited via social engineering
  const socialEngPatterns = [
    /emergency.*withdraw/gi,
    /admin.*override/gi,
    /bypass.*check/gi,
    /manual.*transfer/gi,
    /recover.*funds/gi,
  ];

  const hasAdequateLogging = /emit!|msg!.*admin|event.*log/i.test(rust.content);

  for (const pattern of socialEngPatterns) {
    if (pattern.test(rust.content) && !hasAdequateLogging) {
      findings.push({
        id: 'SOL890',
        severity: 'high',
        title: 'Social Engineering Attack Surface',
        message: 'Admin/emergency functions without proper logging create social engineering attack vectors. Compromised team members or impersonators could abuse these functions.',
        file: input.path,
        line: 0,
        recommendation: 'Add comprehensive event logging for all admin actions. Implement time delays and notification systems for emergency functions.',
      });
      break;
    }
  }

  return findings;
}

// SOL891: DEV.to 11 Vulns - Missing Signer Check Pattern
export function checkMissingSignerPattern(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rust = input.rust;
  if (!rust?.content) return findings;

  // Pattern: checking key equality without signer verification
  const keyCheckWithoutSigner = /\.key\(\)\s*==.*authority|authority.*==.*\.key\(\)/gi;
  const hasSignerCheck = /is_signer|Signer<'info>/i.test(rust.content);

  if (keyCheckWithoutSigner.test(rust.content) && !hasSignerCheck) {
    findings.push({
      id: 'SOL891',
      severity: 'critical',
      title: 'Key Equality Check Without Signer Verification',
      message: 'Checking if a public key matches authority without verifying the key holder signed the transaction. Attackers can pass any public key without owning it.',
      file: input.path,
      line: 0,
      recommendation: 'Always use Signer<\'info> type or explicitly check is_signer before trusting authority matches.',
    });
  }

  return findings;
}

// SOL892: Missing Account Data Matching
export function checkMissingAccountDataMatching(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rust = input.rust;
  if (!rust?.content) return findings;

  // Check for accepting accounts without validating relationships
  const hasTokenAccount = /TokenAccount|token_account|token::Token/i.test(rust.content);
  const hasConstraint = /constraint\s*=.*mint\s*==|#\[account\(.*has_one/i.test(rust.content);

  if (hasTokenAccount && !hasConstraint) {
    findings.push({
      id: 'SOL892',
      severity: 'high',
      title: 'Missing Account Data Relationship Validation',
      message: 'Token accounts accepted without validating mint/owner relationships. Attackers can substitute their own accounts that pass type checks but have different mints.',
      file: input.path,
      line: 0,
      recommendation: 'Use Anchor constraints to validate account relationships: constraint = user_token.mint == pool.mint',
    });
  }

  return findings;
}

// SOL893: Non-Canonical PDA Bump
export function checkNonCanonicalBump(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rust = input.rust;
  if (!rust?.content) return findings;

  // Check for PDA creation without storing bump
  const hasPdaCreation = /find_program_address|create_program_address|Pubkey::find_program_address/i.test(rust.content);
  const storesBump = /bump\s*:|bump\s*=|canonical_bump|store.*bump/i.test(rust.content);

  if (hasPdaCreation && !storesBump) {
    findings.push({
      id: 'SOL893',
      severity: 'high',
      title: 'Non-Canonical PDA Bump Risk',
      message: 'PDA created without storing/verifying canonical bump. Multiple valid PDAs can exist for same logical seeds with different bumps, enabling shadow account attacks.',
      file: input.path,
      line: 0,
      recommendation: 'Store the canonical bump in account data and verify it on subsequent operations.',
    });
  }

  return findings;
}

// SOL894: Missing Discriminator Check
export function checkMissingDiscriminatorCheck(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rust = input.rust;
  if (!rust?.content) return findings;

  // Check for raw account deserialization without discriminator
  const rawDeserialize = /try_from_slice|deserialize.*AccountInfo|from_account_info.*unsafe/i.test(rust.content);
  const hasDiscriminator = /discriminator|DISCRIMINATOR|account_discriminator/i.test(rust.content);
  const usesAnchorAccount = /Account<'info,|#\[account\]/i.test(rust.content);

  if (rawDeserialize && !hasDiscriminator && !usesAnchorAccount) {
    findings.push({
      id: 'SOL894',
      severity: 'critical',
      title: 'Type Cosplay via Missing Discriminator',
      message: 'Account deserialized without discriminator check. Different account types with similar layouts can be substituted, causing misinterpretation of fields.',
      file: input.path,
      line: 0,
      recommendation: 'Add unique 8-byte discriminator to each account type. Verify discriminator before deserializing.',
    });
  }

  return findings;
}

// SOL895: Arithmetic Without Overflow Check
export function checkArithmeticOverflowRisk(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rust = input.rust;
  if (!rust?.content) return findings;

  // Check for unchecked arithmetic in critical paths
  const uncheckedMath = /\+\s*=|\-\s*=|\*\s*=|\/\s*=/g;
  const hasCheckedMath = /checked_add|checked_sub|checked_mul|checked_div|saturating_|overflow-checks\s*=\s*true/i.test(rust.content);

  const uncheckedCount = (rust.content.match(uncheckedMath) || []).length;

  if (uncheckedCount > 3 && !hasCheckedMath) {
    findings.push({
      id: 'SOL895',
      severity: 'high',
      title: 'Arithmetic Overflow Risk',
      message: `Found ${uncheckedCount} unchecked arithmetic operations without using checked_* methods. Integer overflow in Solana can lead to funds loss.`,
      file: input.path,
      line: 0,
      recommendation: 'Use checked_add(), checked_sub(), checked_mul(), checked_div() for all arithmetic. Enable overflow-checks in Cargo.toml for release builds.',
    });
  }

  return findings;
}

// SOL896: Rent Exemption Not Verified
export function checkRentExemptionNotVerified(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rust = input.rust;
  if (!rust?.content) return findings;

  // Check for account creation without rent exemption
  const createsAccount = /create_account|init\s*,|space\s*=/i.test(rust.content);
  const checksRent = /rent.*exempt|is_exempt|minimum_balance|Rent::get/i.test(rust.content);

  if (createsAccount && !checksRent) {
    findings.push({
      id: 'SOL896',
      severity: 'medium',
      title: 'Rent Exemption Not Verified',
      message: 'Account created without verifying rent exemption. Non-rent-exempt accounts can be garbage collected, potentially losing user funds.',
      file: input.path,
      line: 0,
      recommendation: 'Always verify account meets rent exemption threshold or use Anchor\'s space calculation.',
    });
  }

  return findings;
}

// SOL897: Closing Account to Wrong Destination
export function checkClosingAccountDestination(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rust = input.rust;
  if (!rust?.content) return findings;

  // Check for close without verifying destination
  const hasClose = /close\s*=|close_account|account_info.*lamports/i.test(rust.content);
  const verifyDestination = /destination.*==|close.*authority|rent_recipient.*verify/i.test(rust.content);

  if (hasClose && !verifyDestination) {
    findings.push({
      id: 'SOL897',
      severity: 'high',
      title: 'Closing Account Lamports to Unverified Destination',
      message: 'Account close operation without verifying lamport destination. Attackers could redirect rent reclaim to their own accounts.',
      file: input.path,
      line: 0,
      recommendation: 'Verify close destination matches expected recipient. Use Anchor close constraint with explicit destination.',
    });
  }

  return findings;
}

// SOL898: CPI Without Program ID Verification
export function checkCpiProgramIdVerification(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rust = input.rust;
  if (!rust?.content) return findings;

  // Check for CPI without verifying called program
  const hasCpi = /invoke|invoke_signed|CpiContext/i.test(rust.content);
  const verifiesProgram = /program\.key\(\)\s*==|program_id.*check|token_program\.key\(\)/i.test(rust.content);
  const usesAnchorProgram = /Program<'info,|token_program:\s*Program/i.test(rust.content);

  if (hasCpi && !verifiesProgram && !usesAnchorProgram) {
    findings.push({
      id: 'SOL898',
      severity: 'critical',
      title: 'Arbitrary CPI - Missing Program ID Verification',
      message: 'Cross-program invocation without verifying the target program ID. Attackers can substitute malicious programs that mimic expected interfaces.',
      file: input.path,
      line: 0,
      recommendation: 'Always verify program ID before CPI. Use Anchor\'s Program<\'info, T> type which enforces verification.',
    });
  }

  return findings;
}

// SOL899: Account Revival Attack Vector
export function checkAccountRevivalVector(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rust = input.rust;
  if (!rust?.content) return findings;

  // Check for close without zeroing data
  const hasClose = /close|close_account/i.test(rust.content);
  const zerosData = /data\.fill\(0\)|zero.*data|clear.*account/i.test(rust.content);

  if (hasClose && !zerosData) {
    findings.push({
      id: 'SOL899',
      severity: 'high',
      title: 'Account Revival Attack Vector',
      message: 'Account closed without zeroing data. Attackers can re-create the account at same address with old data, potentially gaining unauthorized access.',
      file: input.path,
      line: 0,
      recommendation: 'Zero account data before closing. Set discriminator to invalid value. Consider using unique PDAs for each lifecycle.',
    });
  }

  return findings;
}

// SOL900: Flash Loan Oracle Manipulation
export function checkFlashLoanOracleManipulation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rust = input.rust;
  if (!rust?.content) return findings;

  // Check for oracle usage without flash loan protection
  const hasOracle = /oracle|price_feed|get_price|pyth|switchboard/i.test(rust.content);
  const hasFlashProtection = /flash.*loan.*check|same.*slot.*block|twap|time.*weighted/i.test(rust.content);

  if (hasOracle && !hasFlashProtection) {
    findings.push({
      id: 'SOL900',
      severity: 'critical',
      title: 'Flash Loan Oracle Manipulation Risk',
      message: 'Oracle price used without flash loan manipulation protection. Mango Markets lost $116M to oracle manipulation via flash loans.',
      file: input.path,
      line: 0,
      recommendation: 'Use TWAP oracles. Check price staleness. Implement same-slot manipulation detection. Add liquidation delays.',
    });
  }

  return findings;
}

// SOL901: Monero Conversion Pattern (Fund Obfuscation Risk)
export function checkFundObfuscationPattern(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rust = input.rust;
  if (!rust?.content) return findings;

  // Check for patterns that could enable fund obfuscation
  const obfuscationPatterns = [
    /withdrawal.*limit.*bypass/gi,
    /no.*rate.*limit/gi,
    /unlimited.*withdraw/gi,
    /single.*transaction.*drain/gi,
  ];

  for (const pattern of obfuscationPatterns) {
    if (pattern.test(rust.content)) {
      findings.push({
        id: 'SOL901',
        severity: 'high',
        title: 'Fund Obfuscation Risk (No Rate Limiting)',
        message: 'Large withdrawals without rate limiting enable rapid fund extraction and conversion to privacy coins (like in Step Finance attack where funds went to Monero).',
        file: input.path,
        line: 0,
        recommendation: 'Implement daily withdrawal limits. Add timelocks for large amounts. Use multisig for treasury operations.',
      });
      break;
    }
  }

  return findings;
}

// SOL902: Missing Emergency Pause Mechanism
export function checkMissingEmergencyPause(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rust = input.rust;
  if (!rust?.content) return findings;

  // Check if protocol has pause mechanism
  const hasWithdraw = /withdraw|transfer_out|redeem|claim/i.test(rust.content);
  const hasPause = /pause|paused|frozen|emergency.*stop|circuit.*breaker/i.test(rust.content);

  if (hasWithdraw && !hasPause) {
    findings.push({
      id: 'SOL902',
      severity: 'medium',
      title: 'Missing Emergency Pause Mechanism',
      message: 'Protocol lacks emergency pause functionality. When exploits are detected, inability to pause operations allows continued fund drainage.',
      file: input.path,
      line: 0,
      recommendation: 'Implement pausable pattern with guardian multisig. Add circuit breakers for unusual activity detection.',
    });
  }

  return findings;
}

// SOL903: Insufficient Event Logging for Forensics
export function checkInsufficientEventLogging(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rust = input.rust;
  if (!rust?.content) return findings;

  // Check for critical operations without event emission
  const criticalOps = /withdraw|deposit|transfer|set_authority|close/gi;
  const hasEvents = /emit!|log_instruction|msg!|program_log/i.test(rust.content);

  const criticalCount = (rust.content.match(criticalOps) || []).length;

  if (criticalCount > 2 && !hasEvents) {
    findings.push({
      id: 'SOL903',
      severity: 'low',
      title: 'Insufficient Event Logging for Post-Incident Forensics',
      message: 'Critical operations lack event emission. Proper logging is essential for detecting exploits and post-incident forensics.',
      file: input.path,
      line: 0,
      recommendation: 'Emit events for all state-changing operations. Include relevant account addresses and amounts in event data.',
    });
  }

  return findings;
}

// SOL904: Reentrancy via CPI State
export function checkReentrancyViaCpi(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rust = input.rust;
  if (!rust?.content) return findings;

  // Check for CPI before state update (classic reentrancy)
  const cpiBeforeUpdate = /invoke.*\.try_borrow_mut|CpiContext.*account\..*=|transfer.*amount.*save/i.test(rust.content);
  const hasReentrancyGuard = /reentrancy.*guard|is_locked|lock.*flag|mutex/i.test(rust.content);

  if (cpiBeforeUpdate && !hasReentrancyGuard) {
    findings.push({
      id: 'SOL904',
      severity: 'critical',
      title: 'Cross-Program Reentrancy Risk',
      message: 'CPI call appears before state updates, enabling reentrancy attacks. Malicious programs called via CPI can call back before state is finalized.',
      file: input.path,
      line: 0,
      recommendation: 'Follow checks-effects-interactions pattern. Update state before making CPI calls. Consider reentrancy guards for complex operations.',
    });
  }

  return findings;
}

// Export all patterns
export const batchedPatterns34 = {
  checkOwnerPermissionPhishing,
  checkCentralizedWalletStorage,
  checkSimulationBypassRisk,
  checkHiddenAuthorityTransfer,
  checkWithdrawalVerificationMissing,
  checkSocialEngineeringAttackSurface,
  checkMissingSignerPattern,
  checkMissingAccountDataMatching,
  checkNonCanonicalBump,
  checkMissingDiscriminatorCheck,
  checkArithmeticOverflowRisk,
  checkRentExemptionNotVerified,
  checkClosingAccountDestination,
  checkCpiProgramIdVerification,
  checkAccountRevivalVector,
  checkFlashLoanOracleManipulation,
  checkFundObfuscationPattern,
  checkMissingEmergencyPause,
  checkInsufficientEventLogging,
  checkReentrancyViaCpi,
};
