/**
 * SolShield Security Patterns - Batch 10 (SOL291-SOL310)
 * Additional advanced patterns from security research
 */

import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

// SOL291: JIT Cache Bug (Solana Core 2023)
export function checkJitCacheVulnerability(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  // Check for BPF/SBF program patterns
  if (/solana.*program|anchor|bpf|sbf/gi.test(content)) {
    // Warn about JIT-related optimizations
    if (/inline|optimize|hot.*path|cache/gi.test(content)) {
      findings.push({
        id: 'SOL291',
        severity: 'info',
        title: 'JIT/Cache Optimization Patterns',
        description: 'Code uses patterns that interact with Solana JIT compiler. The 2023 JIT cache bug caused a 5-hour network outage. Ensure tested on latest validator.',
        location: input.path,
        recommendation: 'Test programs on latest Solana validator version. Be aware of JIT compilation edge cases.',
      });
    }
  }
  
  return findings;
}

// SOL292: Durable Nonce Misuse
export function checkDurableNonceMisuse(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  // Check for durable nonce usage
  if (/durable.*nonce|nonce.*account|advance.*nonce/gi.test(content)) {
    // Check for proper nonce validation
    if (!/verify.*nonce|check.*nonce.*authority|validate.*nonce/gi.test(content)) {
      findings.push({
        id: 'SOL292',
        severity: 'high',
        title: 'Durable Nonce Validation Missing',
        description: 'Durable nonce used without proper validation. The 2022 durable nonce bug allowed transaction replay under certain conditions.',
        location: input.path,
        recommendation: 'Always verify nonce authority. Validate nonce account state. Follow Solana nonce best practices.',
      });
    }
  }
  
  return findings;
}

// SOL293: Duplicate Block Check Pattern
export function checkDuplicateBlockPattern(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  // Check for validator/leader patterns
  if (/validator|leader|block.*production|consensus/gi.test(content)) {
    // Check for duplicate handling
    if (!/duplicate.*check|block.*hash.*verify|unique.*block/gi.test(content)) {
      findings.push({
        id: 'SOL293',
        severity: 'high',
        title: 'Duplicate Block Handling',
        description: 'Block/transaction handling may not account for duplicates. The 2023 duplicate block bug exploited validator edge cases.',
        location: input.path,
        recommendation: 'Implement idempotent transaction processing. Handle duplicate detection at application layer.',
      });
    }
  }
  
  return findings;
}

// SOL294: Turbine Propagation Security
export function checkTurbinePropagation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  // Check for data propagation patterns (relevant for custom validators/relayers)
  if (/propagat|broadcast|shred|turbine/gi.test(content)) {
    // Check for merkle verification
    if (!/merkle|hash.*tree|verify.*shred/gi.test(content)) {
      findings.push({
        id: 'SOL294',
        severity: 'high',
        title: 'Data Propagation Without Merkle Verification',
        description: 'Data propagation without cryptographic verification. The 2023 Turbine failure was caused by unverified data propagation.',
        location: input.path,
        recommendation: 'Always verify propagated data with Merkle proofs or equivalent cryptographic verification.',
      });
    }
  }
  
  return findings;
}

// SOL295: ELF Address Alignment Vulnerability
export function checkElfAlignment(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  // Check for low-level memory patterns
  if (/unsafe|ptr|align|memory.*layout/gi.test(content)) {
    // Check for alignment issues
    if (/cast|transmute|from_raw_parts/gi.test(content)) {
      if (!/align.*check|alignment|aligned/gi.test(content)) {
        findings.push({
          id: 'SOL295',
          severity: 'medium',
          title: 'Potential Alignment Issue',
          description: 'Unsafe memory operations without explicit alignment checks. The 2024 ELF address alignment vulnerability affected program loading.',
          location: input.path,
          recommendation: 'Ensure all memory operations respect alignment requirements. Use #[repr(C)] or #[repr(packed)] explicitly.',
        });
      }
    }
  }
  
  return findings;
}

// SOL296: Checked Math Enforcement
export function checkCheckedMathEnforcement(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  // Check for arithmetic operations
  if (/\+\s*=|\-\s*=|\*\s*=|\/\s*=/g.test(content)) {
    // Check for checked math usage
    if (!/checked_|saturating_|overflowing_/gi.test(content)) {
      // Check if overflow-checks is enabled
      if (!/overflow.checks.*=.*true/gi.test(content)) {
        findings.push({
          id: 'SOL296',
          severity: 'high',
          title: 'Unchecked Arithmetic Operations',
          description: 'Arithmetic operations without checked math. Solana programs should use checked_add, checked_sub, etc. to prevent overflow.',
          location: input.path,
          recommendation: 'Use checked_* methods for all arithmetic. Enable overflow-checks in Cargo.toml for release builds.',
        });
      }
    }
  }
  
  return findings;
}

// SOL297: Seed Derivation Predictability
export function checkSeedPredictability(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  // Check for PDA seed derivation
  if (/find_program_address|create_program_address|seeds/gi.test(content)) {
    // Check for predictable seeds
    if (/seeds.*=.*\[.*b".*"\s*\]/gi.test(content)) {
      // Check if seed is just a static string without unique components
      if (!/seeds.*=.*\[.*\.key\(\)|\.as_ref\(\)|to_le_bytes/gi.test(content)) {
        findings.push({
          id: 'SOL297',
          severity: 'high',
          title: 'Predictable PDA Seeds',
          description: 'PDA seeds may be predictable (only static strings). Attackers can derive the same PDA and potentially front-run or manipulate.',
          location: input.path,
          recommendation: 'Include unique identifiers in PDA seeds (user pubkey, unique IDs, timestamps).',
        });
      }
    }
  }
  
  return findings;
}

// SOL298: Cross-Program Return Data Injection
export function checkCpiReturnInjection(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  // Check for CPI return data usage
  if (/get_return_data|set_return_data|return_data/gi.test(content)) {
    // Check for program ID verification
    if (!/verify.*program.*id|check.*program|expected.*program/gi.test(content)) {
      findings.push({
        id: 'SOL298',
        severity: 'critical',
        title: 'CPI Return Data Without Program Verification',
        description: 'Return data from CPI used without verifying originating program. Malicious programs can inject false return data.',
        location: input.path,
        recommendation: 'Always verify the program ID that set the return data matches expected program.',
      });
    }
  }
  
  return findings;
}

// SOL299: Account Info Lifetime Issues
export function checkAccountLifetime(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  // Check for account data references
  if (/data\.borrow|try_borrow_data|data_as_mut_slice/gi.test(content)) {
    // Check for holding references across CPIs
    if (/invoke|invoke_signed/gi.test(content)) {
      if (/let.*=.*borrow.*\n.*invoke/gis.test(content)) {
        findings.push({
          id: 'SOL299',
          severity: 'high',
          title: 'Account Data Reference Across CPI',
          description: 'Holding account data reference while making CPI. Account data may be modified by CPI, invalidating the reference.',
          location: input.path,
          recommendation: 'Drop account data borrows before CPI. Re-borrow data after CPI returns.',
        });
      }
    }
  }
  
  return findings;
}

// SOL300: Anchor Constraint Ordering Bug
export function checkAnchorConstraintOrdering(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  // Check for Anchor constraint patterns
  if (/#\[account\s*\(/gi.test(content)) {
    // Check for constraint ordering issues
    const accountBlocks = content.match(/#\[account\s*\([^\]]+\]\s*pub\s+\w+/gi) || [];
    for (const block of accountBlocks) {
      // init should come before seeds
      if (/seeds.*init/gi.test(block)) {
        findings.push({
          id: 'SOL300',
          severity: 'medium',
          title: 'Anchor Constraint Order Issue',
          description: 'Anchor constraints may be in suboptimal order. "init" should come before "seeds" for clarity and to avoid edge cases.',
          location: input.path,
          recommendation: 'Order Anchor constraints as: init, seeds, bump, constraint, has_one, etc.',
        });
        break;
      }
    }
  }
  
  return findings;
}

// SOL301: Missing Account Rent Check
export function checkMissingRentCheck(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  // Check for account creation
  if (/create_account|init|Initialize/gi.test(content)) {
    // Check for rent exemption verification
    if (!/rent.*exempt|minimum.*balance|Rent::get/gi.test(content)) {
      findings.push({
        id: 'SOL301',
        severity: 'medium',
        title: 'Missing Rent Exemption Check',
        description: 'Account creation without rent exemption verification. Accounts may be garbage collected if not rent-exempt.',
        location: input.path,
        recommendation: 'Always verify accounts are rent-exempt. Use Rent::get()?.minimum_balance(data_len) for size calculation.',
      });
    }
  }
  
  return findings;
}

// SOL302: System Program Invocation Without Verification
export function checkSystemProgramInvocation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  // Check for system program usage
  if (/system_instruction|create_account|transfer.*system/gi.test(content)) {
    // Check for system program verification
    if (!/system_program.*key|is_system_program|system_program::check/gi.test(content)) {
      findings.push({
        id: 'SOL302',
        severity: 'high',
        title: 'System Program Not Verified',
        description: 'System program invocation without verifying system program account. Attacker could pass fake system program.',
        location: input.path,
        recommendation: 'Always verify system_program.key() == system_program::ID before invoking.',
      });
    }
  }
  
  return findings;
}

// SOL303: Token Program Version Mismatch
export function checkTokenProgramVersion(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  // Check for token operations
  if (/spl_token|token_program|mint_to|transfer.*token/gi.test(content)) {
    // Check for Token-2022 compatibility
    if (/token_2022|token_extensions/gi.test(content)) {
      if (!/check.*program.*id|is_token_program|verify.*token.*program/gi.test(content)) {
        findings.push({
          id: 'SOL303',
          severity: 'high',
          title: 'Token Program Version Not Verified',
          description: 'Token operations without verifying token program version. Mixing Token and Token-2022 programs can cause issues.',
          location: input.path,
          recommendation: 'Explicitly check token program ID. Handle both Token and Token-2022 appropriately.',
        });
      }
    }
  }
  
  return findings;
}

// SOL304: Lookup Table Poisoning
export function checkLookupTablePoisoning(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  // Check for address lookup table usage
  if (/lookup.*table|address.*table|alt/gi.test(content)) {
    // Check for authority verification
    if (!/verify.*authority|table.*authority|owner.*check/gi.test(content)) {
      findings.push({
        id: 'SOL304',
        severity: 'high',
        title: 'Lookup Table Authority Not Verified',
        description: 'Address lookup table used without verifying authority. Malicious tables could resolve to wrong addresses.',
        location: input.path,
        recommendation: 'Verify lookup table authority. Only use tables from trusted sources. Validate resolved addresses.',
      });
    }
  }
  
  return findings;
}

// SOL305: Compute Unit Exhaustion Attack
export function checkComputeExhaustion(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  // Check for loops or iterations
  if (/for\s+\w+\s+in|while|loop|iter\(\)|into_iter/gi.test(content)) {
    // Check for unbounded loops
    if (/\.len\(\)|remaining_accounts|accounts\.iter/gi.test(content)) {
      if (!/max.*iteration|limit.*loop|bound.*check/gi.test(content)) {
        findings.push({
          id: 'SOL305',
          severity: 'high',
          title: 'Potential Compute Unit Exhaustion',
          description: 'Unbounded iteration over accounts or data. Attackers can pass many accounts to exhaust compute units.',
          location: input.path,
          recommendation: 'Add maximum iteration limits. Verify account counts before processing. Request appropriate compute budget.',
        });
      }
    }
  }
  
  return findings;
}

// SOL306: Priority Fee Manipulation
export function checkPriorityFeeManipulation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  // Check for fee-related patterns
  if (/priority.*fee|compute.*unit.*price|fee.*market/gi.test(content)) {
    // Check for manipulation protection
    if (!/max.*fee|fee.*cap|reasonable.*fee/gi.test(content)) {
      findings.push({
        id: 'SOL306',
        severity: 'medium',
        title: 'Priority Fee Not Capped',
        description: 'Priority fees without caps. Users could be manipulated into paying excessive fees.',
        location: input.path,
        recommendation: 'Implement reasonable fee caps. Warn users about high fees. Use fee estimation algorithms.',
      });
    }
  }
  
  return findings;
}

// SOL307: Versioned Transaction Handling
export function checkVersionedTransactionHandling(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  // Check for transaction handling
  if (/Transaction|versioned|v0/gi.test(content)) {
    // Check for version handling
    if (/transaction/gi.test(content)) {
      if (!/version.*check|legacy|VersionedTransaction/gi.test(content)) {
        findings.push({
          id: 'SOL307',
          severity: 'low',
          title: 'Transaction Version Handling',
          description: 'Transaction handling may not account for different versions. Ensure compatibility with legacy and versioned transactions.',
          location: input.path,
          recommendation: 'Handle both legacy and versioned (v0) transactions appropriately.',
        });
      }
    }
  }
  
  return findings;
}

// SOL308: Missing Signer Seed Validation
export function checkSignerSeedValidationComplete(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  // Check for PDA signing
  if (/invoke_signed|signer_seeds|seeds/gi.test(content)) {
    // Check for complete seed validation
    if (!/bump.*=|canonical.*bump|find_program_address.*\.\s*1/gi.test(content)) {
      findings.push({
        id: 'SOL308',
        severity: 'high',
        title: 'Signer Seed Bump Not Validated',
        description: 'PDA signing without validating canonical bump. Non-canonical bumps can cause address collisions.',
        location: input.path,
        recommendation: 'Always use the canonical bump from find_program_address. Store and verify bump values.',
      });
    }
  }
  
  return findings;
}

// SOL309: Account Lamport Drain
export function checkAccountLamportDrain(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  // Check for lamport transfers
  if (/lamports|sub_lamports|transfer.*lamport/gi.test(content)) {
    // Check for balance verification
    if (!/check.*balance|sufficient.*lamport|lamports\s*>=|lamports\s*>/gi.test(content)) {
      findings.push({
        id: 'SOL309',
        severity: 'high',
        title: 'Lamport Transfer Without Balance Check',
        description: 'Lamport transfer without verifying sufficient balance. Can cause account to become non-rent-exempt.',
        location: input.path,
        recommendation: 'Always verify account has sufficient lamports after transfer. Maintain rent-exempt minimum.',
      });
    }
  }
  
  return findings;
}

// SOL310: Instruction Sysvar Spoofing
export function checkInstructionSysvarSpoofing(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  // Check for instruction sysvar usage
  if (/instructions.*sysvar|get_instruction|sysvar.*instructions/gi.test(content)) {
    // Check for proper verification
    if (!/sysvar::instructions::id|check.*sysvar|verify.*sysvar/gi.test(content)) {
      findings.push({
        id: 'SOL310',
        severity: 'critical',
        title: 'Instruction Sysvar Not Verified',
        description: 'Using instruction sysvar without verifying the account is the real sysvar. Attacker could pass fake instruction data.',
        location: input.path,
        recommendation: 'Always verify account key == sysvar::instructions::ID before reading instruction data.',
      });
    }
  }
  
  return findings;
}
