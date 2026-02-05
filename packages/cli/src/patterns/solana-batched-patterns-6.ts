import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/** SOL276: Unsafe Signer Seeds */
export function checkUnsafeSignerSeeds(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const { rust, path } = input;
  if (!rust) return findings;
  if (rust.content.includes('signer_seeds') && !rust.content.includes('&[&[')) {
    findings.push({ id: 'SOL276', severity: 'high', title: 'Unsafe Signer Seeds', description: 'Signer seeds format may be incorrect.', location: { file: path, line: 1 }, recommendation: 'Use proper nested slice format.' });
  }
  return findings;
}

/** SOL277: Missing Account Validation Combo */
export function checkMissingValidationCombo(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const { rust, path } = input;
  if (!rust) return findings;
  if (rust.content.includes('AccountInfo') && !rust.content.includes('is_signer') && !rust.content.includes('owner ==')) {
    findings.push({ id: 'SOL277', severity: 'critical', title: 'Missing Account Validation', description: 'Raw AccountInfo without validation.', location: { file: path, line: 1 }, recommendation: 'Validate owner, signer, and data.' });
  }
  return findings;
}

/** SOL278: Unsafe Lamport Math */
export function checkUnsafeLamportMath(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const { rust, path } = input;
  if (!rust) return findings;
  const lines = rust.content.split('\n');
  for (let i = 0; i < lines.length; i++) {
    if (/lamports.*[-+]/.test(lines[i]) && !lines[i].includes('checked') && !lines[i].includes('saturating')) {
      findings.push({ id: 'SOL278', severity: 'high', title: 'Unsafe Lamport Math', description: 'Lamport arithmetic without overflow check.', location: { file: path, line: i + 1 }, recommendation: 'Use checked arithmetic for lamports.' });
    }
  }
  return findings;
}

/** SOL279: Missing Key Derivation Salt */
export function checkMissingKeyDerivationSalt(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const { rust, path } = input;
  if (!rust) return findings;
  if (rust.content.includes('find_program_address') && !rust.content.includes('b"') && !rust.content.includes('as_bytes')) {
    findings.push({ id: 'SOL279', severity: 'medium', title: 'Missing PDA Salt', description: 'PDA derivation without seed bytes.', location: { file: path, line: 1 }, recommendation: 'Add descriptive seed prefixes.' });
  }
  return findings;
}

/** SOL280: Implicit Trust */
export function checkImplicitTrust(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const { rust, path } = input;
  if (!rust) return findings;
  const lines = rust.content.split('\n');
  for (let i = 0; i < lines.length; i++) {
    if (/assume.*safe|trusted.*account|skip.*check/i.test(lines[i])) {
      findings.push({ id: 'SOL280', severity: 'critical', title: 'Implicit Trust', description: 'Assumption of safety without verification.', location: { file: path, line: i + 1 }, recommendation: 'Never assume - always verify.' });
    }
  }
  return findings;
}

/** SOL281: Missing Instruction Data Validation */
export function checkMissingInstructionDataValidation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const { rust, path } = input;
  if (!rust) return findings;
  if (rust.content.includes('instruction_data') && !rust.content.includes('try_from_slice') && !rust.content.includes('deserialize')) {
    findings.push({ id: 'SOL281', severity: 'high', title: 'Raw Instruction Data', description: 'Instruction data without deserialization.', location: { file: path, line: 1 }, recommendation: 'Properly deserialize instruction data.' });
  }
  return findings;
}

/** SOL282: Missing Account Length Check */
export function checkMissingAccountLengthCheck(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const { rust, path } = input;
  if (!rust) return findings;
  if (rust.content.includes('data.borrow()') && !rust.content.includes('data_len') && !rust.content.includes('.len()')) {
    findings.push({ id: 'SOL282', severity: 'high', title: 'Missing Data Length Check', description: 'Account data access without length validation.', location: { file: path, line: 1 }, recommendation: 'Validate account data length.' });
  }
  return findings;
}

/** SOL283: Unsafe Casting From Bytes */
export function checkUnsafeCastingFromBytes(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const { rust, path } = input;
  if (!rust) return findings;
  const lines = rust.content.split('\n');
  for (let i = 0; i < lines.length; i++) {
    if (/from_le_bytes|from_be_bytes/.test(lines[i]) && !lines.slice(i-3, i).join('').includes('try_into')) {
      findings.push({ id: 'SOL283', severity: 'medium', title: 'Unsafe Byte Conversion', description: 'Byte conversion may fail.', location: { file: path, line: i + 1 }, recommendation: 'Use try_into for safe conversion.' });
    }
  }
  return findings;
}

/** SOL284: Missing CPI Program Check */
export function checkMissingCpiProgramCheck(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const { rust, path } = input;
  if (!rust) return findings;
  if (rust.content.includes('invoke_signed') && !rust.content.includes('key() ==') && !rust.content.includes('program_id ==')) {
    findings.push({ id: 'SOL284', severity: 'critical', title: 'CPI Without Program Check', description: 'invoke_signed without verifying target.', location: { file: path, line: 1 }, recommendation: 'Verify CPI target program ID.' });
  }
  return findings;
}

/** SOL285: Missing Account Writable Check */
export function checkMissingWritableCheck(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const { rust, path } = input;
  if (!rust) return findings;
  if (rust.content.includes('try_borrow_mut') && !rust.content.includes('is_writable')) {
    findings.push({ id: 'SOL285', severity: 'high', title: 'Missing Writable Check', description: 'Mutable borrow without is_writable check.', location: { file: path, line: 1 }, recommendation: 'Verify account is writable.' });
  }
  return findings;
}
