import type { Finding } from '../commands/audit.js';
import type { ParsedIdl } from '../parsers/idl.js';
import type { ParsedRust } from '../parsers/rust.js';

type PatternInput = { idl: ParsedIdl | null; rust: ParsedRust | null };

/**
 * SOL541-SOL560: Infrastructure & Operational Security Patterns
 * Patterns based on operational incidents and infrastructure attacks.
 */

// SOL541: Unprotected Admin Functions
export function checkUnprotectedAdminFunctions(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (input.rust?.sourceCode) {
    const code = input.rust.sourceCode;
    if (/pub fn admin|pub fn set_|pub fn update_/.test(code) && !/admin_only|require_admin|authority_check/.test(code)) {
      findings.push({
        id: 'SOL541',
        severity: 'critical',
        title: 'Unprotected Admin Functions',
        description: 'Administrative functions lack proper access control.',
        location: 'Admin functions',
        recommendation: 'Add explicit admin/authority checks to all privileged functions.',
      });
    }
  }
  return findings;
}

// SOL542: Missing Input Length Validation
export function checkMissingInputLengthValidation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (input.rust?.sourceCode) {
    const code = input.rust.sourceCode;
    if (/Vec<|String|&\[u8\]/.test(code) && !/max_len|len\(\)\s*<|len\(\)\s*<=/.test(code)) {
      findings.push({
        id: 'SOL542',
        severity: 'medium',
        title: 'Missing Input Length Validation',
        description: 'Variable-length inputs not bounded, risking compute exhaustion.',
        location: 'Input parameters',
        recommendation: 'Add maximum length validation for all variable-length inputs.',
      });
    }
  }
  return findings;
}

// SOL543: Account Data Size Mismatch
export function checkAccountDataSizeMismatch(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (input.rust?.sourceCode) {
    const code = input.rust.sourceCode;
    if (/data_len\(\)|data\.len\(\)/.test(code) && !/==\s*std::mem::size_of|ACCOUNT_SIZE/.test(code)) {
      findings.push({
        id: 'SOL543',
        severity: 'high',
        title: 'Account Data Size Mismatch',
        description: 'Account data size not properly validated against expected size.',
        location: 'Account deserialization',
        recommendation: 'Validate account data size matches expected struct size.',
      });
    }
  }
  return findings;
}

// SOL544: Deprecated Solana API Usage
export function checkDeprecatedSolanaApiUsage(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (input.rust?.sourceCode) {
    const code = input.rust.sourceCode;
    if (/solana_sdk::clock|system_instruction::create_account\s*\(/.test(code)) {
      findings.push({
        id: 'SOL544',
        severity: 'low',
        title: 'Deprecated Solana API Usage',
        description: 'Using deprecated Solana SDK patterns.',
        location: 'SDK usage',
        recommendation: 'Update to latest Solana SDK patterns and anchor macros.',
      });
    }
  }
  return findings;
}

// SOL545: Missing Program Deployment Check
export function checkMissingProgramDeploymentCheck(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (input.rust?.sourceCode) {
    const code = input.rust.sourceCode;
    if (/invoke|invoke_signed/.test(code) && !/executable|program_id/.test(code)) {
      findings.push({
        id: 'SOL545',
        severity: 'high',
        title: 'Missing Program Deployment Check',
        description: 'CPI target program not verified as executable.',
        location: 'CPI calls',
        recommendation: 'Verify target program is deployed and executable before CPI.',
      });
    }
  }
  return findings;
}

// SOL546: Unsafe Type Casting
export function checkUnsafeTypeCasting(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (input.rust?.sourceCode) {
    const code = input.rust.sourceCode;
    if (/as\s+u64|as\s+u128|as\s+i64/.test(code) && !/try_into|checked_|saturating_/.test(code)) {
      findings.push({
        id: 'SOL546',
        severity: 'high',
        title: 'Unsafe Type Casting',
        description: 'Unchecked type casting may cause overflow/underflow.',
        location: 'Type conversions',
        recommendation: 'Use try_into() with proper error handling for type conversions.',
      });
    }
  }
  return findings;
}

// SOL547: Missing Account Ownership Validation
export function checkMissingAccountOwnershipValidation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (input.rust?.sourceCode) {
    const code = input.rust.sourceCode;
    if (/AccountInfo|next_account_info/.test(code) && !/owner\s*==|check_owner/.test(code)) {
      findings.push({
        id: 'SOL547',
        severity: 'critical',
        title: 'Missing Account Ownership Validation',
        description: 'Account ownership not verified, allowing fake account injection.',
        location: 'Account validation',
        recommendation: 'Always verify account owner matches expected program.',
      });
    }
  }
  return findings;
}

// SOL548: Improper Bump Seed Validation
export function checkImproperBumpSeedValidation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (input.rust?.sourceCode) {
    const code = input.rust.sourceCode;
    if (/find_program_address|Pubkey::create_program_address/.test(code) && !/canonical_bump|bump\s*==/.test(code)) {
      findings.push({
        id: 'SOL548',
        severity: 'high',
        title: 'Improper Bump Seed Validation',
        description: 'Non-canonical bump seed usage may allow PDA collision.',
        location: 'PDA derivation',
        recommendation: 'Always use canonical bump seed from find_program_address.',
      });
    }
  }
  return findings;
}

// SOL549: Insufficient Entropy in Seeds
export function checkInsufficientEntropyInSeeds(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (input.rust?.sourceCode) {
    const code = input.rust.sourceCode;
    if (/seeds\s*=\s*\[|&\[.*\.as_ref\(\)/.test(code) && !/user|authority|nonce|timestamp/.test(code)) {
      findings.push({
        id: 'SOL549',
        severity: 'medium',
        title: 'Insufficient Entropy in PDA Seeds',
        description: 'PDA seeds may be predictable without user-specific components.',
        location: 'PDA seed construction',
        recommendation: 'Include user pubkey or other unique identifier in PDA seeds.',
      });
    }
  }
  return findings;
}

// SOL550: Missing Close Account Cleanup
export function checkMissingCloseAccountCleanup(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (input.rust?.sourceCode) {
    const code = input.rust.sourceCode;
    if (/close\s*=|close_account/.test(code) && !/zero_data|memset|clear/.test(code)) {
      findings.push({
        id: 'SOL550',
        severity: 'medium',
        title: 'Missing Close Account Data Cleanup',
        description: 'Closed accounts may retain sensitive data in memory.',
        location: 'Account closure',
        recommendation: 'Zero account data before closing to prevent data leakage.',
      });
    }
  }
  return findings;
}

// SOL551: Vulnerable to Compute Budget Exhaustion
export function checkComputeBudgetExhaustion(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (input.rust?.sourceCode) {
    const code = input.rust.sourceCode;
    if (/for.*in|while|loop/.test(code) && !/sol_remaining_compute_units|compute_budget/.test(code)) {
      findings.push({
        id: 'SOL551',
        severity: 'medium',
        title: 'Vulnerable to Compute Budget Exhaustion',
        description: 'Loops without compute unit checks may exhaust budget.',
        location: 'Loop constructs',
        recommendation: 'Check remaining compute units in long-running operations.',
      });
    }
  }
  return findings;
}

// SOL552: Unsafe Arithmetic in Token Calculations
export function checkUnsafeArithmeticTokenCalc(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (input.rust?.sourceCode) {
    const code = input.rust.sourceCode;
    if (/amount\s*\*|amount\s*\/|\.mul\(|\.div\(/.test(code) && !/checked_|saturating_|overflow/.test(code)) {
      findings.push({
        id: 'SOL552',
        severity: 'high',
        title: 'Unsafe Arithmetic in Token Calculations',
        description: 'Token amount calculations without overflow protection.',
        location: 'Token math',
        recommendation: 'Use checked_mul, checked_div for all token calculations.',
      });
    }
  }
  return findings;
}

// SOL553: Missing Account Discriminator
export function checkMissingAccountDiscriminator(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (input.rust?.sourceCode) {
    const code = input.rust.sourceCode;
    if (/struct\s+\w+Account|pub struct.*\{/.test(code) && !/discriminator|DISCRIMINATOR|#\[account\]/.test(code)) {
      findings.push({
        id: 'SOL553',
        severity: 'high',
        title: 'Missing Account Discriminator',
        description: 'Account struct lacks discriminator for type identification.',
        location: 'Account struct definition',
        recommendation: 'Use Anchor #[account] or manually add 8-byte discriminator.',
      });
    }
  }
  return findings;
}

// SOL554: Improper Error Handling in CPI
export function checkImproperErrorHandlingCpi(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (input.rust?.sourceCode) {
    const code = input.rust.sourceCode;
    if (/invoke|invoke_signed/.test(code) && !/\?|unwrap_or|match.*Err/.test(code)) {
      findings.push({
        id: 'SOL554',
        severity: 'high',
        title: 'Improper Error Handling in CPI',
        description: 'CPI results not properly handled, may silently fail.',
        location: 'CPI calls',
        recommendation: 'Properly propagate CPI errors with descriptive messages.',
      });
    }
  }
  return findings;
}

// SOL555: Reentrancy Through CPI Callback
export function checkReentrancyThroughCallback(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (input.rust?.sourceCode) {
    const code = input.rust.sourceCode;
    if (/callback|on_complete|after_action/.test(code) && !/reentrancy|lock|mutex/.test(code)) {
      findings.push({
        id: 'SOL555',
        severity: 'critical',
        title: 'Reentrancy Through CPI Callback',
        description: 'Callback mechanism may enable reentrancy attacks.',
        location: 'Callback handling',
        recommendation: 'Implement reentrancy guards for callback patterns.',
      });
    }
  }
  return findings;
}

// SOL556: Missing Rent Exemption Check
export function checkMissingRentExemptionCheck(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (input.rust?.sourceCode) {
    const code = input.rust.sourceCode;
    if (/create_account|allocate/.test(code) && !/rent_exempt|minimum_balance/.test(code)) {
      findings.push({
        id: 'SOL556',
        severity: 'medium',
        title: 'Missing Rent Exemption Check',
        description: 'Account creation without verifying rent exemption.',
        location: 'Account creation',
        recommendation: 'Always ensure accounts are rent-exempt or handle rent properly.',
      });
    }
  }
  return findings;
}

// SOL557: Unsafe Deserialization Pattern
export function checkUnsafeDeserializationPattern(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (input.rust?.sourceCode) {
    const code = input.rust.sourceCode;
    if (/deserialize|try_from_slice|unpack/.test(code) && !/len\(\)\s*>=|data_len\(\)\s*>=/.test(code)) {
      findings.push({
        id: 'SOL557',
        severity: 'high',
        title: 'Unsafe Deserialization Pattern',
        description: 'Deserialization without verifying minimum data length.',
        location: 'Data deserialization',
        recommendation: 'Verify data length before deserialization.',
      });
    }
  }
  return findings;
}

// SOL558: Missing Token Account Freeze Check
export function checkMissingTokenAccountFreezeCheck(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (input.rust?.sourceCode) {
    const code = input.rust.sourceCode;
    if (/token.*transfer|transfer.*token/.test(code) && !/is_frozen|freeze_authority/.test(code)) {
      findings.push({
        id: 'SOL558',
        severity: 'medium',
        title: 'Missing Token Account Freeze Check',
        description: 'Token operations without checking freeze status.',
        location: 'Token transfers',
        recommendation: 'Check if token account is frozen before operations.',
      });
    }
  }
  return findings;
}

// SOL559: Improper Authority Delegation
export function checkImproperAuthorityDelegation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (input.rust?.sourceCode) {
    const code = input.rust.sourceCode;
    if (/delegate|set_authority|approve/.test(code) && !/revoke|expiration|max_amount/.test(code)) {
      findings.push({
        id: 'SOL559',
        severity: 'high',
        title: 'Improper Authority Delegation',
        description: 'Delegations without limits or expiration.',
        location: 'Delegation logic',
        recommendation: 'Add amount limits and expiration to all delegations.',
      });
    }
  }
  return findings;
}

// SOL560: Missing State Machine Validation
export function checkMissingStateMachineValidation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (input.rust?.sourceCode) {
    const code = input.rust.sourceCode;
    if (/state|status|phase/.test(code) && !/valid_transition|allowed_state|require_state/.test(code)) {
      findings.push({
        id: 'SOL560',
        severity: 'high',
        title: 'Missing State Machine Validation',
        description: 'State transitions not properly validated.',
        location: 'State management',
        recommendation: 'Implement proper state machine with validated transitions.',
      });
    }
  }
  return findings;
}

// Functions are exported inline
