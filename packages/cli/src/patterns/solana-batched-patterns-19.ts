/**
 * Solana Batched Patterns 19 - Access Control & Input Validation Vulnerabilities
 * Based on Sec3 2025 Report: Access Control (19%) + Input Validation (25%)
 * 20 patterns targeting authorization and input handling flaws
 */

import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

// SOL613: Missing Role-Based Access Control
export function checkMissingRBAC(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';

  // Admin functions without role checks
  if (/admin|owner|authority/i.test(content) &&
      /pub\s+fn\s+\w+/i.test(content) &&
      !/role|permission|access.*level|#\[access_control/.test(content)) {
    findings.push({
      id: 'SOL613',
      title: 'Missing Role-Based Access Control',
      severity: 'high',
      category: 'access-control',
      description: 'Administrative functions without proper role-based access control',
      location: input.path,
      recommendation: 'Implement RBAC with clearly defined roles and permissions'
    });
  }

  return findings;
}

// SOL614: Hardcoded Authority Address
export function checkHardcodedAuthorityAddress(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';

  // Pubkey literals that might be authorities
  const pubkeyMatches = content.match(/Pubkey::new_from_array\s*\(\s*\[[\d\s,]+\]\s*\)/g);
  if (pubkeyMatches && pubkeyMatches.length > 0) {
    findings.push({
      id: 'SOL614',
      title: 'Hardcoded Authority Address',
      severity: 'medium',
      category: 'access-control',
      description: 'Hardcoded authority addresses cannot be rotated if compromised',
      location: input.path,
      recommendation: 'Store authority in account state with rotation mechanism'
    });
  }

  return findings;
}

// SOL615: Missing Multi-Signature Requirement
export function checkMissingMultisigRequirement(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';

  // Critical operations with single signer
  if (/emergency|upgrade|pause|mint.*authority/i.test(content) &&
      !/multisig|multi.*sig|threshold|m.*of.*n/.test(content)) {
    findings.push({
      id: 'SOL615',
      title: 'Missing Multi-Signature Requirement',
      severity: 'high',
      category: 'access-control',
      description: 'Critical operations should require multiple signatures',
      location: input.path,
      recommendation: 'Implement multisig for emergency and administrative functions'
    });
  }

  return findings;
}

// SOL616: Unrestricted Delegate Authority
export function checkUnrestrictedDelegateAuthority(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';

  // Delegation without restrictions
  if (/delegate|delegated/i.test(content) &&
      !/max.*delegate|delegate.*limit|restricted/.test(content)) {
    findings.push({
      id: 'SOL616',
      title: 'Unrestricted Delegate Authority',
      severity: 'medium',
      category: 'access-control',
      description: 'Delegation without restrictions can lead to authority abuse',
      location: input.path,
      recommendation: 'Implement caps and expiry on delegated authority'
    });
  }

  return findings;
}

// SOL617: Missing Authority Separation
export function checkMissingAuthoritySeparation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';

  // Single authority controlling multiple functions
  if (/admin|authority/i.test(content)) {
    const adminFunctions = content.match(/pub\s+fn\s+\w*(admin|owner|authority)\w*/gi);
    if (adminFunctions && adminFunctions.length > 3) {
      findings.push({
        id: 'SOL617',
        title: 'Missing Authority Separation',
        severity: 'medium',
        category: 'access-control',
        description: 'Single authority controls too many functions - separation of duties needed',
        location: input.path,
        recommendation: 'Separate authorities for different protocol functions'
      });
    }
  }

  return findings;
}

// SOL618: Insufficient Input Length Validation
export function checkInsufficientInputLengthValidation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';

  // Data/instruction parsing without length checks
  if (/instruction_data|&data\[|\.data\(\)/i.test(content) &&
      !/\.len\(\)|data\.len|size_of|MIN_LEN/.test(content)) {
    findings.push({
      id: 'SOL618',
      title: 'Insufficient Input Length Validation',
      severity: 'high',
      category: 'input-validation',
      description: 'Instruction data parsed without length validation can cause panics',
      location: input.path,
      recommendation: 'Validate input data length before parsing'
    });
  }

  return findings;
}

// SOL619: Missing Numeric Bounds Validation
export function checkMissingNumericBounds(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';

  // Numeric inputs without bounds
  if (/amount|quantity|size|count/i.test(content) &&
      /u64|u128|i64|i128/i.test(content) &&
      !/require!?\s*\(|assert|>=|<=|MAX|MIN/.test(content)) {
    findings.push({
      id: 'SOL619',
      title: 'Missing Numeric Bounds Validation',
      severity: 'medium',
      category: 'input-validation',
      description: 'Numeric inputs without bounds checking can cause unexpected behavior',
      location: input.path,
      recommendation: 'Validate all numeric inputs against acceptable bounds'
    });
  }

  return findings;
}

// SOL620: Unvalidated String Input
export function checkUnvalidatedStringInput(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';

  // String handling without validation
  if (/String|str|&\[u8\]/i.test(content) &&
      /name|symbol|uri|metadata/i.test(content) &&
      !/max.*len|\.len\(\)\s*[<>]|\.truncate/.test(content)) {
    findings.push({
      id: 'SOL620',
      title: 'Unvalidated String Input',
      severity: 'medium',
      category: 'input-validation',
      description: 'String inputs without length validation can exceed storage limits',
      location: input.path,
      recommendation: 'Enforce maximum length on all string inputs'
    });
  }

  return findings;
}

// SOL621: Missing Zero Address Check
export function checkMissingZeroAddressCheck(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';

  // Address assignments without zero check
  if (/authority\s*=|owner\s*=|recipient\s*=/i.test(content) &&
      !/Pubkey::default|system_program::ID|zero|empty/.test(content)) {
    findings.push({
      id: 'SOL621',
      title: 'Missing Zero Address Check',
      severity: 'high',
      category: 'input-validation',
      description: 'Setting authority or recipient to zero address can lock funds',
      location: input.path,
      recommendation: 'Validate addresses are not Pubkey::default() or system program'
    });
  }

  return findings;
}

// SOL622: Insufficient Array Index Validation
export function checkInsufficientArrayIndexValidation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';

  // Array access with user input
  if (/\[\s*\w+\s*\]/.test(content) && /index|idx|i\s*\]|position/.test(content)) {
    if (!/\.get\(|\.get_mut\(|bounds|\.len\(\)/.test(content)) {
      findings.push({
        id: 'SOL622',
        title: 'Insufficient Array Index Validation',
        severity: 'high',
        category: 'input-validation',
        description: 'Array access with unchecked indices can cause panic',
        location: input.path,
        recommendation: 'Use .get() or validate indices against array length'
      });
    }
  }

  return findings;
}

// SOL623: Missing Timestamp Future Validation
export function checkMissingTimestampFutureValidation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';

  // Timestamp inputs (expiry, unlock, etc)
  if (/expir|unlock.*time|deadline|timestamp/i.test(content) &&
      !/>\s*clock|>\s*now|future|after/.test(content)) {
    findings.push({
      id: 'SOL623',
      title: 'Missing Timestamp Future Validation',
      severity: 'medium',
      category: 'input-validation',
      description: 'Time-based inputs should be validated against current time',
      location: input.path,
      recommendation: 'Ensure future timestamps are actually in the future'
    });
  }

  return findings;
}

// SOL624: Unvalidated Percentage Input
export function checkUnvalidatedPercentageInput(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';

  // Percentage/basis points without bounds
  if (/percent|bps|basis.*point|rate/i.test(content) &&
      /u16|u32|u64/i.test(content) &&
      !/<=\s*100|<=\s*10000|MAX_BPS|MAX_PERCENT/.test(content)) {
    findings.push({
      id: 'SOL624',
      title: 'Unvalidated Percentage Input',
      severity: 'medium',
      category: 'input-validation',
      description: 'Percentage inputs without 0-100% bounds can break calculations',
      location: input.path,
      recommendation: 'Validate percentages are within 0-100% (or 0-10000 bps)'
    });
  }

  return findings;
}

// SOL625: Missing Pubkey Format Validation
export function checkMissingPubkeyValidation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';

  // Pubkey from bytes without validation
  if (/Pubkey::new\(|Pubkey::try_from/i.test(content) &&
      !/on_curve|valid|verify/.test(content)) {
    findings.push({
      id: 'SOL625',
      title: 'Missing Pubkey Format Validation',
      severity: 'medium',
      category: 'input-validation',
      description: 'Pubkey constructed from bytes may not be valid ed25519 point',
      location: input.path,
      recommendation: 'Validate pubkey is on curve if used for signature verification'
    });
  }

  return findings;
}

// SOL626: Timelock Bypass via Parameter
export function checkTimelockBypassParameter(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';

  // Timelock with configurable delay
  if (/timelock|delay/i.test(content) &&
      /set.*delay|configure.*time|update.*lock/i.test(content)) {
    if (!/MIN_DELAY|minimum.*delay|>=\s*\d+/.test(content)) {
      findings.push({
        id: 'SOL626',
        title: 'Timelock Bypass via Parameter',
        severity: 'critical',
        category: 'access-control',
        description: 'Configurable timelock without minimum can be set to zero',
        location: input.path,
        recommendation: 'Enforce minimum timelock delay that cannot be bypassed'
      });
    }
  }

  return findings;
}

// SOL627: Missing Reentrancy Guard on State Changes
export function checkMissingReentrancyGuardStateChange(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';

  // External calls before state updates
  if (/invoke|CpiContext|transfer/i.test(content)) {
    const invokePos = content.search(/invoke|CpiContext|transfer/i);
    const stateUpdatePos = content.search(/\.\w+\s*=\s*[^=]/);
    
    if (invokePos > 0 && stateUpdatePos > 0 && invokePos < stateUpdatePos) {
      findings.push({
        id: 'SOL627',
        title: 'Missing Reentrancy Guard on State Changes',
        severity: 'high',
        category: 'access-control',
        description: 'External call before state update creates reentrancy risk',
        location: input.path,
        recommendation: 'Update state before external calls (checks-effects-interactions)'
      });
    }
  }

  return findings;
}

// SOL628: Insufficient Merkle Proof Validation
export function checkInsufficientMerkleProofValidation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';

  // Merkle proof verification
  if (/merkle|proof/i.test(content)) {
    if (!/hash.*leaf|leaf.*hash|double.*hash/.test(content)) {
      findings.push({
        id: 'SOL628',
        title: 'Insufficient Merkle Proof Validation',
        severity: 'high',
        category: 'input-validation',
        description: 'Merkle proofs without proper leaf hashing are vulnerable to second preimage attacks',
        location: input.path,
        recommendation: 'Hash leaf data before merkle proof verification'
      });
    }
  }

  return findings;
}

// SOL629: Missing Enum Variant Exhaustiveness
export function checkMissingEnumExhaustiveness(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';

  // Match on instruction/action enums with underscore catch-all
  if (/match\s+\w+\s*\{[\s\S]*_\s*=>/.test(content) &&
      /instruction|action|command/i.test(content)) {
    findings.push({
      id: 'SOL629',
      title: 'Missing Enum Variant Exhaustiveness',
      severity: 'medium',
      category: 'input-validation',
      description: 'Catch-all pattern in instruction matching may hide new variants',
      location: input.path,
      recommendation: 'Explicitly handle all enum variants without catch-all'
    });
  }

  return findings;
}

// SOL630: Missing Program ID Validation in CPIs
export function checkMissingProgramIdValidationCpi(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';

  // CPI without program ID check
  if (/invoke|invoke_signed|CpiContext/i.test(content) &&
      /remaining_accounts|ctx\.remaining/i.test(content) &&
      !/\.key\(\)\s*==|program.*id|key.*==.*program/.test(content)) {
    findings.push({
      id: 'SOL630',
      title: 'Missing Program ID Validation in CPIs',
      severity: 'critical',
      category: 'access-control',
      description: 'CPI targets from remaining accounts must validate program ID',
      location: input.path,
      recommendation: 'Verify target program ID before CPI invocation'
    });
  }

  return findings;
}

// SOL631: Missing Authority Expiry Check
export function checkMissingAuthorityExpiry(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';

  // Temporary/delegated authority without expiry
  if (/temporary|delegat|session/i.test(content) &&
      /authority|signer/i.test(content) &&
      !/expir|valid.*until|ttl/.test(content)) {
    findings.push({
      id: 'SOL631',
      title: 'Missing Authority Expiry Check',
      severity: 'medium',
      category: 'access-control',
      description: 'Temporary authorities without expiry can be used indefinitely',
      location: input.path,
      recommendation: 'Implement expiry timestamps for temporary authorities'
    });
  }

  return findings;
}

// SOL632: Unsafe Type Conversion
export function checkUnsafeTypeConversion(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';

  // Unsafe as casts on user input
  if (/as\s+u\d+|as\s+i\d+/.test(content) && 
      /amount|size|count|index/i.test(content)) {
    if (!/try_into|try_from|checked/.test(content)) {
      findings.push({
        id: 'SOL632',
        title: 'Unsafe Type Conversion',
        severity: 'high',
        category: 'input-validation',
        description: 'Unsafe type casts on user input can cause truncation or overflow',
        location: input.path,
        recommendation: 'Use try_into() or checked conversion for user inputs'
      });
    }
  }

  return findings;
}
