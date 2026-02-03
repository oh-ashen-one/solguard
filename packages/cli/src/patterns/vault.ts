import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL047: Vault/Treasury Vulnerabilities
 * Issues with fund management and vaults.
 */
export function checkVault(input: PatternInput): Finding[] {
  const findings: Finding[] = [];

  if (!input.rust || !input.rust.files) return findings;

  for (const file of input.rust.files) {
    const lines = file.lines;
    const content = file.content;

    if (!content.includes('vault') && !content.includes('treasury') && 
        !content.includes('Vault') && !content.includes('Treasury')) {
      continue;
    }

    lines.forEach((line, index) => {
      const lineNum = index + 1;

      // Pattern 1: Withdraw without limits
      if (line.includes('withdraw') || line.includes('drain')) {
        const fnEnd = Math.min(lines.length, index + 25);
        const fnBody = lines.slice(index, fnEnd).join('\n');

        if (!fnBody.includes('limit') && !fnBody.includes('max') && 
            !fnBody.includes('daily') && !fnBody.includes('cooldown')) {
          findings.push({
            id: `SOL047-${findings.length + 1}`,
            pattern: 'Vault Vulnerability',
            severity: 'high',
            title: 'Vault withdrawal without limits',
            description: 'No withdrawal limits. Compromised key could drain entire vault instantly.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Add daily withdrawal limits and/or timelocks for large amounts.',
          });
        }
      }

      // Pattern 2: Single signer for large withdrawals
      if (line.includes('signer') && content.includes('withdraw')) {
        const contextStart = Math.max(0, index - 10);
        const context = lines.slice(contextStart, index + 10).join('\n');

        if (!context.includes('multisig') && !context.includes('threshold') &&
            !context.includes('Squad')) {
          findings.push({
            id: `SOL047-${findings.length + 1}`,
            pattern: 'Vault Vulnerability',
            severity: 'medium',
            title: 'Vault with single signer',
            description: 'Single key can withdraw. Consider multisig for treasuries.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Use multisig (Squads) for treasury management.',
          });
        }
      }

      // Pattern 3: Emergency withdraw without safeguards
      if (line.includes('emergency') && line.includes('withdraw')) {
        const fnEnd = Math.min(lines.length, index + 20);
        const fnBody = lines.slice(index, fnEnd).join('\n');

        if (!fnBody.includes('pause') && !fnBody.includes('timelock') &&
            !fnBody.includes('delay')) {
          findings.push({
            id: `SOL047-${findings.length + 1}`,
            pattern: 'Vault Vulnerability',
            severity: 'high',
            title: 'Emergency withdraw without safeguards',
            description: 'Emergency function with no protections. Could be abused.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Add timelock or require pause before emergency actions.',
          });
        }
      }
    });
  }

  return findings;
}
