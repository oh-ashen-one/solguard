import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL059: Withdrawal Pattern Issues
 * Vulnerabilities in withdrawal/claim functionality.
 */
export function checkWithdrawPattern(input: PatternInput): Finding[] {
  const findings: Finding[] = [];

  if (!input.rust || !input.rust.files) return findings;

  for (const file of input.rust.files) {
    const lines = file.lines;

    lines.forEach((line, index) => {
      const lineNum = index + 1;

      // Pattern 1: Withdraw without balance update first (CEI violation)
      if (line.includes('withdraw') || line.includes('claim')) {
        const fnEnd = Math.min(lines.length, index + 30);
        const fnBody = lines.slice(index, fnEnd).join('\n');

        // Check order: should update state before transfer
        const transferIndex = fnBody.indexOf('transfer');
        const updateIndex = Math.max(
          fnBody.indexOf('balance ='),
          fnBody.indexOf('balance -='),
          fnBody.indexOf('amount ='),
          fnBody.indexOf('claimed')
        );

        if (transferIndex > 0 && updateIndex > transferIndex) {
          findings.push({
            id: `SOL059-${findings.length + 1}`,
            pattern: 'Withdrawal Pattern Issue',
            severity: 'critical',
            title: 'State update after transfer (CEI violation)',
            description: 'Balance updated after transfer. Vulnerable to reentrancy.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Update state before external calls (Checks-Effects-Interactions).',
          });
        }
      }

      // Pattern 2: Withdraw all without minimum check
      if (line.includes('withdraw') && !line.includes('amount')) {
        const fnEnd = Math.min(lines.length, index + 15);
        const fnBody = lines.slice(index, fnEnd).join('\n');

        if (fnBody.includes('balance') && !fnBody.includes('min') && !fnBody.includes('>=')) {
          findings.push({
            id: `SOL059-${findings.length + 1}`,
            pattern: 'Withdrawal Pattern Issue',
            severity: 'low',
            title: 'Withdraw without minimum balance check',
            description: 'Can withdraw entire balance including dust amounts.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Consider minimum withdrawal: require!(amount >= MIN_WITHDRAW)',
          });
        }
      }

      // Pattern 3: Multiple withdrawals possible (no single-use flag)
      if (line.includes('claim') && !line.includes('claimed')) {
        const fnEnd = Math.min(lines.length, index + 20);
        const fnBody = lines.slice(index, fnEnd).join('\n');

        if (!fnBody.includes('claimed') && !fnBody.includes('used') && !fnBody.includes('redeemed')) {
          findings.push({
            id: `SOL059-${findings.length + 1}`,
            pattern: 'Withdrawal Pattern Issue',
            severity: 'high',
            title: 'Claim without single-use tracking',
            description: 'No flag to prevent multiple claims.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Track claims: require!(!user.claimed); user.claimed = true;',
          });
        }
      }
    });
  }

  return findings;
}
