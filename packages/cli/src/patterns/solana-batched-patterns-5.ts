import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/** SOL266: Missing Balance Check */
export function checkMissingBalanceCheck(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const { rust, path } = input;
  if (!rust) return findings;
  if (rust.content.includes('transfer') && !rust.content.includes('balance') && !rust.content.includes('amount <=')) {
    findings.push({ id: 'SOL266', severity: 'high', title: 'Missing Balance Check', description: 'Transfer without balance validation.', location: { file: path, line: 1 }, recommendation: 'Verify sufficient balance before transfer.' });
  }
  return findings;
}

/** SOL267: Unsafe Token Burn */
export function checkUnsafeTokenBurn(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const { rust, path } = input;
  if (!rust) return findings;
  if (rust.content.includes('burn') && !rust.content.includes('authority')) {
    findings.push({ id: 'SOL267', severity: 'critical', title: 'Unsafe Token Burn', description: 'Burn without authority check.', location: { file: path, line: 1 }, recommendation: 'Verify burn authority.' });
  }
  return findings;
}

/** SOL268: Missing Anchor Error */
export function checkMissingAnchorError(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const { rust, path } = input;
  if (!rust) return findings;
  if (rust.content.includes('#[program]') && !rust.content.includes('#[error_code]')) {
    findings.push({ id: 'SOL268', severity: 'low', title: 'No Custom Errors', description: 'Anchor program without custom errors.', location: { file: path, line: 1 }, recommendation: 'Define custom error codes.' });
  }
  return findings;
}

/** SOL269: Missing Access List */
export function checkMissingAccessList(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const { idl, path } = input;
  if (!idl) return findings;
  const sensitiveOps = idl.instructions.filter(ix => 
    ix.name.includes('mint') || ix.name.includes('burn') || ix.name.includes('admin'));
  for (const ix of sensitiveOps) {
    if (!ix.accounts?.some(a => a.name.includes('whitelist') || a.name.includes('allowlist'))) {
      findings.push({ id: 'SOL269', severity: 'medium', title: 'No Access Control List', description: `${ix.name} lacks allowlist.`, location: { file: path, line: 1 }, recommendation: 'Consider access control lists.' });
    }
  }
  return findings;
}

/** SOL270: Uncapped Supply */
export function checkUncappedSupply(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const { rust, path } = input;
  if (!rust) return findings;
  if (rust.content.includes('mint_to') && !rust.content.includes('max_supply') && !rust.content.includes('cap')) {
    findings.push({ id: 'SOL270', severity: 'high', title: 'Uncapped Token Supply', description: 'Minting without supply cap.', location: { file: path, line: 1 }, recommendation: 'Add maximum supply check.' });
  }
  return findings;
}

/** SOL271: Missing Pause */
export function checkMissingPause(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const { idl, path } = input;
  if (!idl) return findings;
  const hasPause = idl.instructions.some(ix => ix.name.toLowerCase().includes('pause'));
  const hasTransfer = idl.instructions.some(ix => ix.name.toLowerCase().includes('transfer'));
  if (hasTransfer && !hasPause) {
    findings.push({ id: 'SOL271', severity: 'medium', title: 'No Pause Function', description: 'No emergency pause capability.', location: { file: path, line: 1 }, recommendation: 'Add pause mechanism for emergencies.' });
  }
  return findings;
}

/** SOL272: Missing Upgrade Guard */
export function checkMissingUpgradeGuard(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const { rust, path } = input;
  if (!rust) return findings;
  if (!rust.content.includes('upgradeable') && !rust.content.includes('bpf_upgradeable')) {
    // Program may be non-upgradeable which is actually good for security
  } else if (!rust.content.includes('upgrade_authority')) {
    findings.push({ id: 'SOL272', severity: 'medium', title: 'Upgrade Authority Unclear', description: 'Upgradeable program without clear authority.', location: { file: path, line: 1 }, recommendation: 'Document upgrade authority.' });
  }
  return findings;
}

/** SOL273: Missing Reentrancy Guard */
export function checkMissingReentrancyGuard(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const { rust, path } = input;
  if (!rust) return findings;
  if (rust.content.includes('invoke') && rust.content.includes('borrow_mut')) {
    if (!rust.content.includes('reentrancy') && !rust.content.includes('lock') && !rust.content.includes('processing')) {
      findings.push({ id: 'SOL273', severity: 'high', title: 'Missing Reentrancy Guard', description: 'CPI with mutable borrow without guard.', location: { file: path, line: 1 }, recommendation: 'Add reentrancy protection.' });
    }
  }
  return findings;
}

/** SOL274: Missing Decimal Normalization */
export function checkMissingDecimalNormalization(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const { rust, path } = input;
  if (!rust) return findings;
  if (rust.content.includes('decimals') && rust.content.includes('amount')) {
    if (!rust.content.includes('10.pow') && !rust.content.includes('10_u64.pow')) {
      findings.push({ id: 'SOL274', severity: 'high', title: 'No Decimal Normalization', description: 'Token amounts without decimal handling.', location: { file: path, line: 1 }, recommendation: 'Normalize token decimals in calculations.' });
    }
  }
  return findings;
}

/** SOL275: Exposed Internal Function */
export function checkExposedInternalFunction(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const { rust, path } = input;
  if (!rust) return findings;
  const lines = rust.content.split('\n');
  for (let i = 0; i < lines.length; i++) {
    if (/pub\s+fn\s+_/.test(lines[i]) || /pub\s+fn\s+internal_/.test(lines[i])) {
      findings.push({ id: 'SOL275', severity: 'medium', title: 'Exposed Internal Function', description: 'Internal function may be public.', location: { file: path, line: i + 1 }, recommendation: 'Use pub(crate) for internal functions.' });
    }
  }
  return findings;
}
