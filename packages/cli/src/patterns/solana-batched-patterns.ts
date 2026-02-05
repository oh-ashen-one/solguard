import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/** SOL226: Unsafe Slice Access */
export function checkUnsafeSlice(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const { rust, path } = input;
  if (!rust) return findings;
  const lines = rust.content.split('\n');
  for (let i = 0; i < lines.length; i++) {
    if (/\[.*\.\..*\]/.test(lines[i]) && !lines.slice(Math.max(0, i-3), i).join('').includes('len()')) {
      findings.push({ id: 'SOL226', severity: 'medium', title: 'Unsafe Slice Access', description: 'Slice access without bounds check.', location: { file: path, line: i + 1 }, recommendation: 'Use get() or check length.' });
    }
  }
  return findings;
}

/** SOL227: Hardcoded Address */
export function checkHardcodedAddress(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const { rust, path } = input;
  if (!rust) return findings;
  const lines = rust.content.split('\n');
  for (let i = 0; i < lines.length; i++) {
    if (/Pubkey::new_from_array/.test(lines[i]) || /pubkey!\s*\(.*[A-HJ-NP-Za-km-z1-9]{32}/.test(lines[i])) {
      findings.push({ id: 'SOL227', severity: 'medium', title: 'Hardcoded Address', description: 'Hardcoded public key found.', location: { file: path, line: i + 1 }, recommendation: 'Use constants or environment config.' });
    }
  }
  return findings;
}

/** SOL228: Excessive Account Access */
export function checkExcessiveAccounts(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const { idl, path } = input;
  if (!idl) return findings;
  for (const ix of idl.instructions) {
    if ((ix.accounts?.length || 0) > 20) {
      findings.push({ id: 'SOL228', severity: 'medium', title: 'Excessive Accounts', description: `Instruction "${ix.name}" has ${ix.accounts?.length} accounts.`, location: { file: path, line: 1 }, recommendation: 'Reduce account count or split instruction.' });
    }
  }
  return findings;
}

/** SOL229: Deprecated Instruction */
export function checkDeprecatedInstruction(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const { rust, path } = input;
  if (!rust) return findings;
  const deprecated = ['system_instruction::create_account_with_seed', 'spl_token::instruction::approve_checked'];
  const lines = rust.content.split('\n');
  for (let i = 0; i < lines.length; i++) {
    for (const d of deprecated) {
      if (lines[i].includes(d)) {
        findings.push({ id: 'SOL229', severity: 'low', title: 'Deprecated Instruction', description: `Using deprecated: ${d}`, location: { file: path, line: i + 1 }, recommendation: 'Use modern alternatives.' });
      }
    }
  }
  return findings;
}

/** SOL230: Missing Account Close */
export function checkMissingClose(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const { rust, path } = input;
  if (!rust) return findings;
  if (rust.content.includes('init') && !rust.content.includes('close')) {
    findings.push({ id: 'SOL230', severity: 'low', title: 'Missing Close Handler', description: 'Account init without close instruction.', location: { file: path, line: 1 }, recommendation: 'Add close instruction for rent recovery.' });
  }
  return findings;
}

/** SOL231: Token Decimal Mismatch */
export function checkDecimalMismatch(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const { rust, path } = input;
  if (!rust) return findings;
  const lines = rust.content.split('\n');
  for (let i = 0; i < lines.length; i++) {
    if (/decimals.*!=/.test(lines[i]) || /\* 10\^/.test(lines[i]) || /\* 1e/.test(lines[i])) {
      findings.push({ id: 'SOL231', severity: 'high', title: 'Token Decimal Handling', description: 'Hardcoded decimal conversion.', location: { file: path, line: i + 1 }, recommendation: 'Use dynamic decimal handling.' });
    }
  }
  return findings;
}

/** SOL232: Missing Sysvar Clock */
export function checkMissingSysvarClock(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const { rust, path } = input;
  if (!rust) return findings;
  if (rust.content.includes('timestamp') || rust.content.includes('slot')) {
    if (!rust.content.includes('Clock') && !rust.content.includes('sysvar')) {
      findings.push({ id: 'SOL232', severity: 'high', title: 'Missing Clock Sysvar', description: 'Using time without Clock sysvar.', location: { file: path, line: 1 }, recommendation: 'Use Clock sysvar for time.' });
    }
  }
  return findings;
}

/** SOL233: Unbounded String */
export function checkUnboundedString(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const { rust, path } = input;
  if (!rust) return findings;
  const lines = rust.content.split('\n');
  for (let i = 0; i < lines.length; i++) {
    if (/String\s*,/.test(lines[i]) && !lines.slice(i, i+5).join('').includes('max_len')) {
      findings.push({ id: 'SOL233', severity: 'medium', title: 'Unbounded String', description: 'String field without max length.', location: { file: path, line: i + 1 }, recommendation: 'Use fixed-size arrays or bounded strings.' });
    }
  }
  return findings;
}

/** SOL234: Vec Without Capacity */
export function checkVecNoCapacity(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const { rust, path } = input;
  if (!rust) return findings;
  const lines = rust.content.split('\n');
  for (let i = 0; i < lines.length; i++) {
    if (/Vec::new\(\)/.test(lines[i]) && lines.slice(i, i+5).join('').includes('push')) {
      findings.push({ id: 'SOL234', severity: 'low', title: 'Vec Without Capacity', description: 'Vec created without capacity hint.', location: { file: path, line: i + 1 }, recommendation: 'Use with_capacity() for known sizes.' });
    }
  }
  return findings;
}

/** SOL235: Missing Rent Check */
export function checkMissingRentCheck(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const { rust, path } = input;
  if (!rust) return findings;
  if (rust.content.includes('create_account') && !rust.content.includes('rent') && !rust.content.includes('Rent')) {
    findings.push({ id: 'SOL235', severity: 'high', title: 'Missing Rent Check', description: 'Account creation without rent calculation.', location: { file: path, line: 1 }, recommendation: 'Calculate rent-exempt minimum.' });
  }
  return findings;
}
