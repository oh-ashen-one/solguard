import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL057: Fee Handling Vulnerabilities
 * Issues with protocol fees and fee distribution.
 */
export function checkFeeHandling(input: PatternInput): Finding[] {
  const findings: Finding[] = [];

  if (!input.rust || !input.rust.files) return findings;

  for (const file of input.rust.files) {
    const lines = file.lines;

    lines.forEach((line, index) => {
      const lineNum = index + 1;

      // Pattern 1: Fee calculation before transfer
      if (line.includes('fee') && (line.includes('*') || line.includes('/'))) {
        const contextEnd = Math.min(lines.length, index + 15);
        const context = lines.slice(index, contextEnd).join('\n');

        if (context.includes('transfer') && !context.includes('-') && !context.includes('sub')) {
          findings.push({
            id: `SOL057-${findings.length + 1}`,
            pattern: 'Fee Handling Vulnerability',
            severity: 'high',
            title: 'Fee calculated but not deducted from transfer',
            description: 'Fee calculated but full amount may still be transferred.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Deduct fee: transfer_amount = amount - fee',
          });
        }
      }

      // Pattern 2: Fee recipient from user input
      if (line.includes('fee') && line.includes('recipient')) {
        if (line.includes('args.') || line.includes('params.')) {
          findings.push({
            id: `SOL057-${findings.length + 1}`,
            pattern: 'Fee Handling Vulnerability',
            severity: 'high',
            title: 'Fee recipient from user input',
            description: 'User can specify fee recipient. Could redirect fees to themselves.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Use hardcoded fee recipient or validate against config.',
          });
        }
      }

      // Pattern 3: No minimum fee enforcement
      if (line.includes('fee') && (line.includes('bps') || line.includes('basis'))) {
        const contextStart = Math.max(0, index - 5);
        const context = lines.slice(contextStart, index + 5).join('\n');

        if (!context.includes('min') && !context.includes('MIN') && 
            context.includes('set') || context.includes('=')) {
          findings.push({
            id: `SOL057-${findings.length + 1}`,
            pattern: 'Fee Handling Vulnerability',
            severity: 'low',
            title: 'No minimum fee enforcement',
            description: 'Fees can be set to zero, potentially enabling abuse.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Consider minimum fee: require!(fee_bps >= MIN_FEE_BPS)',
          });
        }
      }

      // Pattern 4: Fee overflow in calculation
      if (line.includes('fee') && line.includes('*') && !line.includes('checked')) {
        findings.push({
          id: `SOL057-${findings.length + 1}`,
          pattern: 'Fee Handling Vulnerability',
          severity: 'medium',
          title: 'Fee calculation may overflow',
          description: 'Fee multiplication without checked math.',
          location: { file: file.path, line: lineNum },
          suggestion: 'Use checked: amount.checked_mul(fee_bps)?.checked_div(10000)?',
        });
      }
    });
  }

  return findings;
}
