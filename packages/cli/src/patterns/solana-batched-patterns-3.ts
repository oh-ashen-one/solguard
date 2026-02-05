import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/** SOL246: Missing Bump Validation */
export function checkMissingBumpValidation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const { rust, path } = input;
  if (!rust) return findings;
  if (rust.content.includes('find_program_address') && !rust.content.includes('bump')) {
    findings.push({ id: 'SOL246', severity: 'high', title: 'Missing Bump Validation', description: 'PDA derivation without bump check.', location: { file: path, line: 1 }, recommendation: 'Store and validate canonical bump.' });
  }
  return findings;
}

/** SOL247: Excessive Gas Usage */
export function checkExcessiveGas(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const { rust, path } = input;
  if (!rust) return findings;
  const lines = rust.content.split('\n');
  for (let i = 0; i < lines.length; i++) {
    if (/msg!\s*\(/.test(lines[i])) {
      findings.push({ id: 'SOL247', severity: 'low', title: 'Excessive Logging', description: 'msg! macro uses compute units.', location: { file: path, line: i + 1 }, recommendation: 'Minimize logging in production.' });
    }
  }
  return findings;
}

/** SOL248: Clone Instead of Copy */
export function checkCloneInsteadCopy(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const { rust, path } = input;
  if (!rust) return findings;
  const lines = rust.content.split('\n');
  for (let i = 0; i < lines.length; i++) {
    if (/\.clone\(\)/.test(lines[i])) {
      findings.push({ id: 'SOL248', severity: 'low', title: 'Unnecessary Clone', description: 'clone() may be inefficient.', location: { file: path, line: i + 1 }, recommendation: 'Consider using references or Copy types.' });
    }
  }
  return findings;
}

/** SOL249: Missing Authority Rotation */
export function checkMissingAuthorityRotation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const { idl, path } = input;
  if (!idl) return findings;
  const hasAuth = idl.instructions.some(ix => ix.name.toLowerCase().includes('authority'));
  const hasRotate = idl.instructions.some(ix => ix.name.toLowerCase().includes('rotate') || ix.name.toLowerCase().includes('transfer_authority'));
  if (hasAuth && !hasRotate) {
    findings.push({ id: 'SOL249', severity: 'medium', title: 'No Authority Rotation', description: 'Program has authority but no rotation.', location: { file: path, line: 1 }, recommendation: 'Add authority transfer function.' });
  }
  return findings;
}

/** SOL250: Unprotected Initialize */
export function checkUnprotectedInitialize(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const { idl, path } = input;
  if (!idl) return findings;
  const initIx = idl.instructions.find(ix => ix.name.toLowerCase() === 'initialize');
  if (initIx && !initIx.accounts?.some(a => a.isSigner && a.name.includes('auth'))) {
    findings.push({ id: 'SOL250', severity: 'critical', title: 'Unprotected Initialize', description: 'Initialize can be called by anyone.', location: { file: path, line: 1 }, recommendation: 'Add signer check or init_if_needed guard.' });
  }
  return findings;
}

/** SOL251: Missing Program ID Check */
export function checkMissingProgramIdCheck(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const { rust, path } = input;
  if (!rust) return findings;
  if (rust.content.includes('invoke') && !rust.content.includes('program_id') && !rust.content.includes('program::ID')) {
    findings.push({ id: 'SOL251', severity: 'critical', title: 'Missing Program ID Check', description: 'CPI without verifying target program.', location: { file: path, line: 1 }, recommendation: 'Verify program ID before CPI.' });
  }
  return findings;
}

/** SOL252: Unvalidated Account Data */
export function checkUnvalidatedAccountData(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const { rust, path } = input;
  if (!rust) return findings;
  const lines = rust.content.split('\n');
  for (let i = 0; i < lines.length; i++) {
    if (/try_borrow_data|data\.borrow/.test(lines[i])) {
      const context = lines.slice(i, Math.min(lines.length, i+10)).join('');
      if (!context.includes('deserialize') && !context.includes('unpack')) {
        findings.push({ id: 'SOL252', severity: 'high', title: 'Raw Account Data', description: 'Reading account data without deserialization.', location: { file: path, line: i + 1 }, recommendation: 'Deserialize and validate account data.' });
      }
    }
  }
  return findings;
}

/** SOL253: Timestamp Drift */
export function checkTimestampDrift(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const { rust, path } = input;
  if (!rust) return findings;
  const lines = rust.content.split('\n');
  for (let i = 0; i < lines.length; i++) {
    if (/unix_timestamp/.test(lines[i]) && !lines.slice(i, i+10).join('').includes('tolerance')) {
      findings.push({ id: 'SOL253', severity: 'medium', title: 'Timestamp Without Tolerance', description: 'Timestamp comparison without drift tolerance.', location: { file: path, line: i + 1 }, recommendation: 'Add buffer for clock drift.' });
    }
  }
  return findings;
}

/** SOL254: Missing Instruction Sysvar */
export function checkMissingInstructionSysvar(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const { rust, path } = input;
  if (!rust) return findings;
  if (rust.content.includes('signer_seeds') && !rust.content.includes('instructions_sysvar') && !rust.content.includes('Instructions')) {
    findings.push({ id: 'SOL254', severity: 'medium', title: 'Missing Instructions Sysvar', description: 'Consider instruction introspection for security.', location: { file: path, line: 1 }, recommendation: 'Add instructions sysvar for flash loan protection.' });
  }
  return findings;
}

/** SOL255: Excessive Nesting */
export function checkExcessiveNesting(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const { rust, path } = input;
  if (!rust) return findings;
  const lines = rust.content.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const depth = (lines[i].match(/\{/g) || []).length - (lines[i].match(/\}/g) || []).length;
    const leading = lines[i].search(/\S/);
    if (leading > 40) {
      findings.push({ id: 'SOL255', severity: 'low', title: 'Excessive Nesting', description: 'Deeply nested code is error-prone.', location: { file: path, line: i + 1 }, recommendation: 'Refactor into smaller functions.' });
    }
  }
  return findings;
}
