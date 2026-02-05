/**
 * Solana Batched Patterns 20 - Data Integrity & DoS Vulnerabilities
 * Based on Sec3 2025 Report: Data Integrity (8.9%) + DoS (8.5%)
 * 20 patterns targeting data handling and availability issues
 */

import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

// SOL633: Unchecked Division Remainder
export function checkUncheckedDivisionRemainder(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';

  // Division without handling remainder
  if (/\/\s*\d+|checked_div|\.div\(/.test(content) &&
      !/remainder|%|modulo/.test(content)) {
    findings.push({
      id: 'SOL633',
      title: 'Unchecked Division Remainder',
      severity: 'medium',
      category: 'data-integrity',
      description: 'Division remainder not handled can lead to accumulating dust',
      location: input.path,
      recommendation: 'Handle division remainders explicitly or use ceiling division'
    });
  }

  return findings;
}

// SOL634: Missing Data Version Check
export function checkMissingDataVersionCheck(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';

  // Account data without version
  if (/deserialize|try_from_slice|unpack/i.test(content) &&
      !/version|schema.*version|data.*version/.test(content)) {
    findings.push({
      id: 'SOL634',
      title: 'Missing Data Version Check',
      severity: 'medium',
      category: 'data-integrity',
      description: 'Account data without version tracking breaks upgradability',
      location: input.path,
      recommendation: 'Include version field in account data for migration support'
    });
  }

  return findings;
}

// SOL635: Inconsistent Serialization Format
export function checkInconsistentSerialization(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';

  // Multiple serialization methods
  const hasBorsh = /borsh::|BorshSerialize|BorshDeserialize/.test(content);
  const hasBytemuck = /bytemuck|Pod|Zeroable/.test(content);
  const hasManual = /to_le_bytes|from_le_bytes/.test(content);
  
  const methodCount = [hasBorsh, hasBytemuck, hasManual].filter(Boolean).length;
  if (methodCount > 1) {
    findings.push({
      id: 'SOL635',
      title: 'Inconsistent Serialization Format',
      severity: 'medium',
      category: 'data-integrity',
      description: 'Multiple serialization formats can lead to data corruption',
      location: input.path,
      recommendation: 'Use consistent serialization format throughout the program'
    });
  }

  return findings;
}

// SOL636: Missing Checksum Validation
export function checkMissingChecksumValidation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';

  // Data transfer/storage without checksum
  if (/message|payload|data.*transfer/i.test(content) &&
      /hash|verify/i.test(content) &&
      !/checksum|crc|digest.*verify/.test(content)) {
    findings.push({
      id: 'SOL636',
      title: 'Missing Checksum Validation',
      severity: 'medium',
      category: 'data-integrity',
      description: 'Cross-chain or off-chain data should include checksum validation',
      location: input.path,
      recommendation: 'Include and verify checksums for critical data transfers'
    });
  }

  return findings;
}

// SOL637: Race Condition in Parallel Updates
export function checkRaceConditionParallelUpdates(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';

  // Concurrent access patterns
  if (/try_borrow_mut|borrow_mut/i.test(content) &&
      !/lock|mutex|atomic/.test(content)) {
    const mutBorrows = content.match(/try_borrow_mut|borrow_mut/g);
    if (mutBorrows && mutBorrows.length > 2) {
      findings.push({
        id: 'SOL637',
        title: 'Race Condition in Parallel Updates',
        severity: 'high',
        category: 'data-integrity',
        description: 'Multiple mutable borrows may indicate race condition risk',
        location: input.path,
        recommendation: 'Ensure exclusive access patterns for shared state'
      });
    }
  }

  return findings;
}

// SOL638: Missing Atomic Update Guarantee
export function checkMissingAtomicUpdate(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';

  // Multiple related updates that should be atomic
  if (/balance.*=|amount.*=|supply.*=/i.test(content)) {
    const updates = content.match(/\.\w+\s*=\s*[^=]/g);
    if (updates && updates.length > 3) {
      if (!/transaction|atomic|batch/.test(content)) {
        findings.push({
          id: 'SOL638',
          title: 'Missing Atomic Update Guarantee',
          severity: 'high',
          category: 'data-integrity',
          description: 'Related state updates must be atomic to maintain consistency',
          location: input.path,
          recommendation: 'Ensure all related updates complete together or not at all'
        });
      }
    }
  }

  return findings;
}

// SOL639: Incorrect Bit Manipulation
export function checkIncorrectBitManipulation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';

  // Bit operations that might overflow
  if (/<<|>>|&|\\||\^/.test(content) && /flags|bitmap|mask/.test(content)) {
    if (!/checked_shl|checked_shr|wrapping/.test(content)) {
      findings.push({
        id: 'SOL639',
        title: 'Incorrect Bit Manipulation',
        severity: 'medium',
        category: 'data-integrity',
        description: 'Bit shift operations can overflow without checked variants',
        location: input.path,
        recommendation: 'Use checked bit operations to prevent overflow'
      });
    }
  }

  return findings;
}

// SOL640: Missing Data Migration Path
export function checkMissingDataMigration(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';

  // Upgradeable program without migration
  if (/upgradeable|migration/i.test(content) || input.path.includes('upgrade')) {
    if (!/migrate|v1.*v2|old.*new|legacy/.test(content)) {
      findings.push({
        id: 'SOL640',
        title: 'Missing Data Migration Path',
        severity: 'medium',
        category: 'data-integrity',
        description: 'Upgradeable programs need clear data migration strategy',
        location: input.path,
        recommendation: 'Implement data migration functions for program upgrades'
      });
    }
  }

  return findings;
}

// SOL641: Compute Unit Exhaustion
export function checkComputeUnitExhaustion(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';

  // Unbounded loops
  if (/for\s+\w+\s+in|while\s+/.test(content) &&
      !/\.len\(\)|limit|max_iter|bounded/.test(content)) {
    findings.push({
      id: 'SOL641',
      title: 'Compute Unit Exhaustion',
      severity: 'high',
      category: 'dos',
      description: 'Unbounded iteration can exhaust compute units causing DoS',
      location: input.path,
      recommendation: 'Limit iteration counts to prevent compute exhaustion'
    });
  }

  return findings;
}

// SOL642: Account Creation DoS
export function checkAccountCreationDos(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';

  // Account creation without rate limit
  if (/init|create.*account|system_instruction::create/i.test(content) &&
      !/rate.*limit|cooldown|max.*per/.test(content)) {
    findings.push({
      id: 'SOL642',
      title: 'Account Creation DoS',
      severity: 'medium',
      category: 'dos',
      description: 'Unrestricted account creation can be used for DoS attacks',
      location: input.path,
      recommendation: 'Implement rate limiting or cost for account creation'
    });
  }

  return findings;
}

// SOL643: Log Spam Attack
export function checkLogSpamAttack(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';

  // Excessive logging in loops
  if (/for\s+.*\{[\s\S]*msg!|while\s+.*\{[\s\S]*msg!/i.test(content)) {
    findings.push({
      id: 'SOL643',
      title: 'Log Spam Attack',
      severity: 'low',
      category: 'dos',
      description: 'Logging in loops consumes compute and can be exploited',
      location: input.path,
      recommendation: 'Minimize logging inside loops or aggregate log messages'
    });
  }

  return findings;
}

// SOL644: Memory Allocation DoS
export function checkMemoryAllocationDos(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';

  // Vector allocation from user input
  if (/Vec::with_capacity|vec!\s*\[.*;\s*\w+\]/.test(content) &&
      /size|length|count/i.test(content)) {
    if (!/MAX|limit|\.min\(/.test(content)) {
      findings.push({
        id: 'SOL644',
        title: 'Memory Allocation DoS',
        severity: 'high',
        category: 'dos',
        description: 'Unbounded memory allocation from user input can crash programs',
        location: input.path,
        recommendation: 'Cap memory allocations with maximum size limits'
      });
    }
  }

  return findings;
}

// SOL645: Stack Overflow via Recursion
export function checkStackOverflowRecursion(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';

  // Recursive function calls
  const fnMatch = content.match(/fn\s+(\w+)[^{]*\{[\s\S]*\1\s*\(/g);
  if (fnMatch) {
    findings.push({
      id: 'SOL645',
      title: 'Stack Overflow via Recursion',
      severity: 'high',
      category: 'dos',
      description: 'Recursive calls can exhaust stack space causing crash',
      location: input.path,
      recommendation: 'Use iterative approach or limit recursion depth'
    });
  }

  return findings;
}

// SOL646: Blocking Operation in Critical Path
export function checkBlockingOperationCriticalPath(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';

  // External calls that might block
  if (/invoke.*program|CpiContext/i.test(content) &&
      /loop|for\s+|while\s+/.test(content)) {
    findings.push({
      id: 'SOL646',
      title: 'Blocking Operation in Critical Path',
      severity: 'medium',
      category: 'dos',
      description: 'CPI calls in loops can create performance bottlenecks',
      location: input.path,
      recommendation: 'Batch external calls or move outside critical paths'
    });
  }

  return findings;
}

// SOL647: Queue Griefing Attack
export function checkQueueGriefingAttack(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';

  // Queue operations without cost
  if (/queue|pending|buffer/i.test(content) &&
      /push|enqueue|add/i.test(content) &&
      !/fee|cost|deposit|stake/.test(content)) {
    findings.push({
      id: 'SOL647',
      title: 'Queue Griefing Attack',
      severity: 'medium',
      category: 'dos',
      description: 'Free queue operations can be griefed to block legitimate users',
      location: input.path,
      recommendation: 'Require deposit or fee for queue operations'
    });
  }

  return findings;
}

// SOL648: Oracle Liveness Dependency
export function checkOracleLivenessDependency(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';

  // Oracle dependency without fallback
  if (/oracle|price.*feed|pyth|switchboard/i.test(content) &&
      !/fallback|backup|stale.*check|timeout/.test(content)) {
    findings.push({
      id: 'SOL648',
      title: 'Oracle Liveness Dependency',
      severity: 'high',
      category: 'dos',
      description: 'Single oracle dependency can halt protocol if oracle fails',
      location: input.path,
      recommendation: 'Implement fallback oracles and stale data handling'
    });
  }

  return findings;
}

// SOL649: Insufficient Gas Reserve
export function checkInsufficientGasReserve(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';

  // Complex operations without compute buffer
  if (/invoke_signed|CpiContext/i.test(content) &&
      !/sol_remaining_compute_units|compute.*budget/.test(content)) {
    const cpiCount = (content.match(/invoke|CpiContext/gi) || []).length;
    if (cpiCount > 2) {
      findings.push({
        id: 'SOL649',
        title: 'Insufficient Gas Reserve',
        severity: 'medium',
        category: 'dos',
        description: 'Multiple CPIs without compute budget checks may run out of compute',
        location: input.path,
        recommendation: 'Check remaining compute units before complex operations'
      });
    }
  }

  return findings;
}

// SOL650: Signature Verification DoS
export function checkSignatureVerificationDos(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';

  // Multiple signature verifications
  if (/verify.*signature|ed25519.*verify|secp256k1.*recover/i.test(content)) {
    if (/for\s+|loop|iterator/i.test(content)) {
      findings.push({
        id: 'SOL650',
        title: 'Signature Verification DoS',
        severity: 'high',
        category: 'dos',
        description: 'Multiple signature verifications are computationally expensive',
        location: input.path,
        recommendation: 'Limit number of signatures or use aggregate signatures'
      });
    }
  }

  return findings;
}

// SOL651: Integer Underflow on Unsigned
export function checkIntegerUnderflowUnsigned(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';

  // Subtraction on unsigned without checks
  if (/u64|u128|usize/i.test(content) &&
      /\s*-\s*(?!\s*1\s*[;,\)])/.test(content) &&
      !/checked_sub|saturating_sub|wrapping_sub/.test(content)) {
    findings.push({
      id: 'SOL651',
      title: 'Integer Underflow on Unsigned',
      severity: 'critical',
      category: 'data-integrity',
      description: 'Subtraction on unsigned integers can underflow in debug mode or wrap in release',
      location: input.path,
      recommendation: 'Use checked_sub or saturating_sub for unsigned subtraction'
    });
  }

  return findings;
}

// SOL652: Hash Collision Risk
export function checkHashCollisionRisk(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';

  // Short hash usage
  if (/hash|digest/i.test(content) && /\[u8;\s*[48]\]|\.as_ref\(\)\[\.\.8\]/.test(content)) {
    findings.push({
      id: 'SOL652',
      title: 'Hash Collision Risk',
      severity: 'medium',
      category: 'data-integrity',
      description: 'Truncated hashes increase collision probability',
      location: input.path,
      recommendation: 'Use full hash length for security-critical identifiers'
    });
  }

  return findings;
}
