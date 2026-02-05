import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/** SOL256: Unvalidated Token Mint */
export function checkUnvalidatedTokenMint(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const { rust, path } = input;
  if (!rust) return findings;
  if (rust.content.includes('token_account') && !rust.content.includes('mint ==')) {
    findings.push({ id: 'SOL256', severity: 'critical', title: 'Unvalidated Token Mint', description: 'Token account without mint validation.', location: { file: path, line: 1 }, recommendation: 'Validate token mint matches expected.' });
  }
  return findings;
}

/** SOL257: Missing Delegate Check */
export function checkMissingDelegateCheck(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const { rust, path } = input;
  if (!rust) return findings;
  if (rust.content.includes('transfer') && rust.content.includes('delegate') && !rust.content.includes('delegate ==')) {
    findings.push({ id: 'SOL257', severity: 'high', title: 'Missing Delegate Check', description: 'Delegate transfer without validation.', location: { file: path, line: 1 }, recommendation: 'Verify delegate authority.' });
  }
  return findings;
}

/** SOL258: Stale Account Reference */
export function checkStaleAccountReference(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const { rust, path } = input;
  if (!rust) return findings;
  if (rust.content.includes('reload') || rust.content.includes('refresh')) {
    findings.push({ id: 'SOL258', severity: 'medium', title: 'Account Reload Pattern', description: 'Account reload may indicate stale data issues.', location: { file: path, line: 1 }, recommendation: 'Ensure fresh account data in operations.' });
  }
  return findings;
}

/** SOL259: Missing Close Authority */
export function checkMissingCloseAuthority(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const { rust, path } = input;
  if (!rust) return findings;
  if (rust.content.includes('close') && !rust.content.includes('close_authority')) {
    findings.push({ id: 'SOL259', severity: 'high', title: 'Missing Close Authority', description: 'Close without authority validation.', location: { file: path, line: 1 }, recommendation: 'Verify close authority matches expected.' });
  }
  return findings;
}

/** SOL260: Unguarded State Transition */
export function checkUnguardedStateTransition(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const { rust, path } = input;
  if (!rust) return findings;
  const lines = rust.content.split('\n');
  for (let i = 0; i < lines.length; i++) {
    if (/state\s*=\s*State::/.test(lines[i])) {
      const context = lines.slice(Math.max(0, i-5), i).join('');
      if (!context.includes('require') && !context.includes('assert') && !context.includes('match')) {
        findings.push({ id: 'SOL260', severity: 'high', title: 'Unguarded State Transition', description: 'State change without validation.', location: { file: path, line: i + 1 }, recommendation: 'Validate state transitions.' });
      }
    }
  }
  return findings;
}

/** SOL261: Missing Event Emission */
export function checkMissingEventEmission(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const { rust, idl, path } = input;
  if (idl && !idl.events?.length && idl.instructions.some(ix => ix.name.includes('transfer') || ix.name.includes('swap'))) {
    findings.push({ id: 'SOL261', severity: 'low', title: 'No Events Defined', description: 'Program has state-changing ops but no events.', location: { file: path, line: 1 }, recommendation: 'Add events for off-chain indexing.' });
  }
  return findings;
}

/** SOL262: Hardcoded Fee */
export function checkHardcodedFee(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const { rust, path } = input;
  if (!rust) return findings;
  const lines = rust.content.split('\n');
  for (let i = 0; i < lines.length; i++) {
    if (/fee\s*[:=]\s*\d+/.test(lines[i]) && !lines[i].includes('const')) {
      findings.push({ id: 'SOL262', severity: 'medium', title: 'Hardcoded Fee', description: 'Fee value is hardcoded.', location: { file: path, line: i + 1 }, recommendation: 'Make fees configurable.' });
    }
  }
  return findings;
}

/** SOL263: Missing Slippage Check */
export function checkMissingSlippage(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const { rust, path } = input;
  if (!rust) return findings;
  if (rust.content.includes('swap') && !rust.content.includes('slippage') && !rust.content.includes('min_out')) {
    findings.push({ id: 'SOL263', severity: 'critical', title: 'Missing Slippage Check', description: 'Swap without slippage protection.', location: { file: path, line: 1 }, recommendation: 'Add minimum output amount check.' });
  }
  return findings;
}

/** SOL264: Unvalidated Price Feed */
export function checkUnvalidatedPriceFeed(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const { rust, path } = input;
  if (!rust) return findings;
  if ((rust.content.includes('pyth') || rust.content.includes('switchboard')) && !rust.content.includes('confidence')) {
    findings.push({ id: 'SOL264', severity: 'high', title: 'Missing Price Confidence', description: 'Price feed without confidence check.', location: { file: path, line: 1 }, recommendation: 'Check oracle confidence interval.' });
  }
  return findings;
}

/** SOL265: Missing Price Staleness */
export function checkMissingPriceStaleness(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const { rust, path } = input;
  if (!rust) return findings;
  if ((rust.content.includes('price') || rust.content.includes('oracle')) && !rust.content.includes('last_update') && !rust.content.includes('stale')) {
    findings.push({ id: 'SOL265', severity: 'high', title: 'Missing Staleness Check', description: 'Price data without freshness validation.', location: { file: path, line: 1 }, recommendation: 'Validate price feed timestamp.' });
  }
  return findings;
}
