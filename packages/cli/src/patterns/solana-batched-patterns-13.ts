import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

// SOL351-SOL370: Advanced vulnerability patterns from security research and CTFs

/**
 * SOL351: Anchor init_if_needed Race Condition
 * Race condition in Anchor's init_if_needed constraint
 */
export function checkAnchorInitIfNeeded(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rustCode = input.rust?.content || '';
  
  if (/init_if_needed/.test(rustCode)) {
    findings.push({
      id: 'SOL351',
      title: 'Anchor init_if_needed Race Condition',
      severity: 'high',
      description: 'init_if_needed can have race conditions where multiple transactions compete to initialize the same account.',
      location: input.path,
      recommendation: 'Use init constraint for first initialization. Use separate check for subsequent access. Consider PDA seeds for uniqueness.'
    });
  }
  
  return findings;
}

/**
 * SOL352: Account Close Lamport Dust
 * Accounts closed with dust lamports can be revived
 */
export function checkAccountCloseLamportDust(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rustCode = input.rust?.content || '';
  
  if (/close\s*=|close_account/.test(rustCode)) {
    if (!/lamports\s*=\s*0|transfer_all_lamports/.test(rustCode)) {
      findings.push({
        id: 'SOL352',
        title: 'Account Close Lamport Dust',
        severity: 'medium',
        description: 'Account closure may leave dust lamports, allowing account revival. Transfer ALL lamports when closing.',
        location: input.path,
        recommendation: 'Use **ctx.accounts.target.close(ctx.accounts.destination.to_account_info()) which handles this properly.'
      });
    }
  }
  
  return findings;
}

/**
 * SOL353: Program Derived Address Collision
 * Different seed combinations producing same PDA
 */
export function checkPdaSeedCollision(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rustCode = input.rust?.content || '';
  
  if (/find_program_address|create_program_address/.test(rustCode)) {
    // Check for variable-length seeds that could collide
    if (/seeds.*\[.*\.\.\.|as_bytes\(\).*,.*as_bytes\(\)/.test(rustCode)) {
      if (!/seeds.*=.*\[.*b"|len.*check/.test(rustCode)) {
        findings.push({
          id: 'SOL353',
          title: 'PDA Seed Collision Risk',
          severity: 'high',
          description: 'Variable-length PDA seeds can collide. "ab" + "c" = "a" + "bc" when concatenated.',
          location: input.path,
          recommendation: 'Use fixed-length separators or encode lengths in seeds. Example: [b"prefix", &[seed_len], seed.as_bytes()]'
        });
      }
    }
  }
  
  return findings;
}

/**
 * SOL354: Borsh Deserialization DoS
 * Malformed data causing expensive deserialization
 */
export function checkBorshDeserializationDoS(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rustCode = input.rust?.content || '';
  
  if (/try_from_slice|deserialize|BorshDeserialize/.test(rustCode)) {
    if (/Vec<|String|HashMap|BTreeMap/.test(rustCode)) {
      if (!/max_len|bounded|capacity_limit/.test(rustCode)) {
        findings.push({
          id: 'SOL354',
          title: 'Borsh Deserialization DoS',
          severity: 'medium',
          description: 'Unbounded deserialization of Vec/String/HashMap can exhaust compute units with malicious data.',
          location: input.path,
          recommendation: 'Set maximum bounds on collection sizes. Use bounded types or validate length before deserializing.'
        });
      }
    }
  }
  
  return findings;
}

/**
 * SOL355: Invoke Signed Seeds Mismatch
 * Signer seeds not matching actual PDA derivation
 */
export function checkInvokeSignedSeedsMismatch(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rustCode = input.rust?.content || '';
  
  if (/invoke_signed/.test(rustCode)) {
    const seedsMatch = rustCode.match(/signer_seeds.*?=.*?\[([^\]]+)\]/gs);
    const pdaMatch = rustCode.match(/find_program_address.*?\(&\[([^\]]+)\]/gs);
    
    if (seedsMatch && pdaMatch) {
      // Basic check - more sophisticated analysis would compare actual values
      findings.push({
        id: 'SOL355',
        title: 'Invoke Signed Seeds Validation',
        severity: 'info',
        description: 'Ensure invoke_signed signer_seeds exactly match the PDA derivation seeds (including bump).',
        location: input.path,
        recommendation: 'Double-check seeds order and values. The bump must be included in signer_seeds. Use canonical bump.'
      });
    }
  }
  
  return findings;
}

/**
 * SOL356: Token Account Authority Confusion
 * Confusing token account owner vs authority
 */
export function checkTokenAuthorityConfusion(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rustCode = input.rust?.content || '';
  
  if (/TokenAccount|token_account|token::/.test(rustCode)) {
    if (/\.owner|owner\s*=/.test(rustCode) && !/token_account\.owner|\.authority/.test(rustCode)) {
      findings.push({
        id: 'SOL356',
        title: 'Token Account Authority Confusion',
        severity: 'high',
        description: 'Token account.owner is the program (SPL Token). The actual owner/authority is account.authority.',
        location: input.path,
        recommendation: 'Use token_account.authority to get the actual owner. Do not confuse with AccountInfo.owner (program).'
      });
    }
  }
  
  return findings;
}

/**
 * SOL357: Writable Account Not Marked Mutable
 * Account written to but not marked mut in Anchor
 */
export function checkWritableNotMutable(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rustCode = input.rust?.content || '';
  
  // Look for assignments without mut constraint
  if (/ctx\.accounts\.(\w+)\.(\w+)\s*=/.test(rustCode)) {
    if (!/#\[account\(.*mut.*\)\]/.test(rustCode)) {
      findings.push({
        id: 'SOL357',
        title: 'Writable Account Not Marked Mutable',
        severity: 'high',
        description: 'Account is being written to but may not be marked as mutable. Changes will be silently discarded.',
        location: input.path,
        recommendation: 'Add #[account(mut)] constraint to accounts that are modified. Check all state changes persist.'
      });
    }
  }
  
  return findings;
}

/**
 * SOL358: Missing Account Rent Exemption on Creation
 * New accounts not funded with rent exemption
 */
export function checkAccountCreationRentExemption(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rustCode = input.rust?.content || '';
  
  if (/create_account|init\s*,/.test(rustCode)) {
    if (!/rent_exempt|Rent::get|minimum_balance/.test(rustCode)) {
      findings.push({
        id: 'SOL358',
        title: 'Account Creation Rent Exemption',
        severity: 'medium',
        description: 'Account created without ensuring rent exemption. Non-rent-exempt accounts can be garbage collected.',
        location: input.path,
        recommendation: 'Fund new accounts with Rent::get()?.minimum_balance(account_size). Anchor init handles this automatically.'
      });
    }
  }
  
  return findings;
}

/**
 * SOL359: Recursive CPI Depth Exhaustion
 * CPI chains exhausting the 4-level depth limit
 */
export function checkRecursiveCpiDepth(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rustCode = input.rust?.content || '';
  
  if (/invoke|invoke_signed|CpiContext/.test(rustCode)) {
    // Check for potential recursive calls
    if (/self_program_id|current_program/.test(rustCode)) {
      findings.push({
        id: 'SOL359',
        title: 'Recursive CPI Depth Exhaustion',
        severity: 'medium',
        description: 'Recursive CPI can exhaust the 4-level depth limit, causing transaction failure.',
        location: input.path,
        recommendation: 'Limit recursive CPI depth. Track depth in account state. Fail gracefully at max depth.'
      });
    }
  }
  
  return findings;
}

/**
 * SOL360: Solana Clock Sysvar Reliability
 * Clock sysvar values can be manipulated by validators
 */
export function checkClockSysvarReliability(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rustCode = input.rust?.content || '';
  
  if (/Clock::get|sysvar::clock|unix_timestamp/.test(rustCode)) {
    if (/deadline|expir|timeout|lock_until/.test(rustCode)) {
      findings.push({
        id: 'SOL360',
        title: 'Clock Sysvar Time Manipulation',
        severity: 'medium',
        description: 'Clock sysvar unix_timestamp can be off by seconds. Validators have some flexibility in block timestamps.',
        location: input.path,
        recommendation: 'Allow timestamp tolerance in time-sensitive checks. Use slot number for more reliable ordering. Do not use for sub-minute precision.'
      });
    }
  }
  
  return findings;
}

/**
 * SOL361: Program Log Size Limit
 * Excessive logging consuming compute units
 */
export function checkProgramLogSizeLimit(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rustCode = input.rust?.content || '';
  
  if (/msg!|sol_log|emit!|log_data/.test(rustCode)) {
    const logCount = (rustCode.match(/msg!|sol_log|emit!/g) || []).length;
    if (logCount > 20) {
      findings.push({
        id: 'SOL361',
        title: 'Excessive Program Logging',
        severity: 'low',
        description: `Found ${logCount} log statements. Excessive logging wastes compute units (10K CU limit for logs).`,
        location: input.path,
        recommendation: 'Reduce logging in production. Use conditional logging based on feature flags. Reserve logs for errors.'
      });
    }
  }
  
  return findings;
}

/**
 * SOL362: Heap Memory Exhaustion
 * Programs exceeding 32KB heap limit
 */
export function checkHeapMemoryExhaustion(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rustCode = input.rust?.content || '';
  
  // Check for large allocations
  if (/Vec::with_capacity|Box::new|vec!\[.*;\s*\d{4,}/.test(rustCode)) {
    findings.push({
      id: 'SOL362',
      title: 'Heap Memory Exhaustion Risk',
      severity: 'medium',
      description: 'Large heap allocations can exhaust the 32KB heap limit, causing program failure.',
      location: input.path,
      recommendation: 'Minimize heap allocations. Use stack where possible. Process data in chunks. Consider zero-copy patterns.'
    });
  }
  
  return findings;
}

/**
 * SOL363: Account Data Size Change After Init
 * Reallocation required for growing account data
 */
export function checkAccountDataSizeChange(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rustCode = input.rust?.content || '';
  
  if (/Vec<|String|push|extend|append/.test(rustCode) && /Account|ProgramAccount/.test(rustCode)) {
    if (!/realloc|AccountInfo::realloc/.test(rustCode)) {
      findings.push({
        id: 'SOL363',
        title: 'Account Data Size Increase Without Realloc',
        severity: 'high',
        description: 'Growing collections in accounts require reallocation. Account data size is fixed at creation.',
        location: input.path,
        recommendation: 'Use AccountInfo::realloc() to resize. Or pre-allocate maximum expected size at creation.'
      });
    }
  }
  
  return findings;
}

/**
 * SOL364: Cross-Program Account Ordering Dependency
 * CPI expecting specific account ordering
 */
export function checkCpiAccountOrdering(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rustCode = input.rust?.content || '';
  
  if (/invoke|CpiContext/.test(rustCode) && /accounts\[|remaining_accounts/.test(rustCode)) {
    findings.push({
      id: 'SOL364',
      title: 'CPI Account Ordering Dependency',
      severity: 'info',
      description: 'CPI with specific account ordering can break if target program changes its account layout.',
      location: input.path,
      recommendation: 'Use named accounts where possible. Document expected account order. Version check target programs.'
    });
  }
  
  return findings;
}

/**
 * SOL365: Program ID Hardcoding
 * Hardcoded program IDs that may change
 */
export function checkProgramIdHardcoding(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rustCode = input.rust?.content || '';
  
  // Look for hardcoded Pubkey strings (base58)
  const base58Pattern = /Pubkey::from_str\s*\(\s*"[1-9A-HJ-NP-Za-km-z]{32,44}"\s*\)/g;
  const matches = rustCode.match(base58Pattern);
  
  if (matches && matches.length > 0) {
    findings.push({
      id: 'SOL365',
      title: 'Hardcoded Program IDs',
      severity: 'medium',
      description: `Found ${matches.length} hardcoded program ID(s). These may become outdated if programs upgrade.`,
      location: input.path,
      recommendation: 'Use declare_id! for own program ID. Use constants from official SDKs for well-known programs. Consider upgradeable ID storage.'
    });
  }
  
  return findings;
}

/**
 * SOL366: Solana Sysvar Account Deprecation
 * Using deprecated sysvar accounts instead of inline access
 */
export function checkSysvarDeprecation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rustCode = input.rust?.content || '';
  
  if (/Sysvar<.*>|sysvar::/.test(rustCode)) {
    if (/rent_sysvar|clock_sysvar|epoch_schedule_sysvar/.test(rustCode)) {
      findings.push({
        id: 'SOL366',
        title: 'Deprecated Sysvar Account Usage',
        severity: 'low',
        description: 'Using sysvar accounts instead of inline access. Inline is more efficient and saves an account.',
        location: input.path,
        recommendation: 'Use Clock::get()?, Rent::get()?, etc. instead of passing sysvar accounts. Anchor: #[account(address = ...)]'
      });
    }
  }
  
  return findings;
}

/**
 * SOL367: Token Amount Truncation
 * Integer division truncating token amounts
 */
export function checkTokenAmountTruncation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rustCode = input.rust?.content || '';
  
  if (/amount\s*\/|\.div\(|checked_div/.test(rustCode)) {
    if (/token|spl|mint|transfer/.test(rustCode)) {
      findings.push({
        id: 'SOL367',
        title: 'Token Amount Truncation',
        severity: 'medium',
        description: 'Integer division truncates token amounts. With many small operations, this accumulates losses.',
        location: input.path,
        recommendation: 'Multiply before dividing. Use higher precision internally. Account for dust in protocol design.'
      });
    }
  }
  
  return findings;
}

/**
 * SOL368: Native SOL vs Wrapped SOL Confusion
 * Confusing native SOL handling with WSOL
 */
export function checkNativeSolWrappedConfusion(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rustCode = input.rust?.content || '';
  
  if (/native_mint|NATIVE_MINT|So11111111111111111111111111111111111111112/.test(rustCode)) {
    if (!/sync_native|close_account|create_token_account/.test(rustCode)) {
      findings.push({
        id: 'SOL368',
        title: 'Native SOL / Wrapped SOL Handling',
        severity: 'medium',
        description: 'WSOL requires special handling: sync_native() after SOL deposits, and close_account to unwrap.',
        location: input.path,
        recommendation: 'Use spl_token::instruction::sync_native after depositing SOL. Close token account to unwrap to native SOL.'
      });
    }
  }
  
  return findings;
}

/**
 * SOL369: Missing Transfer Hook for Token-2022
 * Token-2022 transfer hooks not being invoked
 */
export function checkToken2022TransferHook(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rustCode = input.rust?.content || '';
  
  if (/transfer_checked|token_2022|Token2022/.test(rustCode)) {
    if (!/transfer_hook|invoke_transfer_hook/.test(rustCode)) {
      findings.push({
        id: 'SOL369',
        title: 'Token-2022 Transfer Hook Missing',
        severity: 'high',
        description: 'Token-2022 tokens may have transfer hooks. Not invoking them can cause failed transfers or break functionality.',
        location: input.path,
        recommendation: 'Use TransferChecked instruction which handles hooks. Or invoke transfer hooks explicitly via spl-transfer-hook-interface.'
      });
    }
  }
  
  return findings;
}

/**
 * SOL370: Metadata URI Validation
 * NFT/token metadata URI not validated
 */
export function checkMetadataUriValidation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rustCode = input.rust?.content || '';
  
  if (/metadata|uri|json_uri|token_uri/.test(rustCode)) {
    if (!/validate_uri|starts_with|https?:\/\/|ipfs:\/\/|arweave/.test(rustCode)) {
      findings.push({
        id: 'SOL370',
        title: 'Metadata URI Validation Missing',
        severity: 'low',
        description: 'Metadata URIs should be validated to prevent malicious or invalid content.',
        location: input.path,
        recommendation: 'Validate URI format and protocol (https, ipfs, arweave). Set maximum URI length. Consider allowlisting domains.'
      });
    }
  }
  
  return findings;
}
