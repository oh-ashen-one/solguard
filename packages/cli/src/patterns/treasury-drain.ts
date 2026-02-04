import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL139: Treasury Drain Attack Patterns (Multiple exploits)
 * 
 * Detects vulnerabilities that could allow draining of protocol
 * treasuries or vaults through various attack vectors.
 */
export function checkTreasuryDrain(input: PatternInput): Finding[] {
  const findings: Finding[] = [];

  if (!input.rust || !input.rust.files) return findings;

  for (const file of input.rust.files) {
    const lines = file.lines;
    const content = file.content;

    lines.forEach((line, index) => {
      const lineNum = index + 1;
      const lineLower = line.toLowerCase();

      // Pattern 1: Treasury withdrawal without rate limiting
      if ((lineLower.includes('treasury') || lineLower.includes('vault') || lineLower.includes('pool')) &&
          (lineLower.includes('withdraw') || lineLower.includes('transfer'))) {
        const fileContent = content.toLowerCase();
        
        if (!fileContent.includes('rate_limit') && !fileContent.includes('daily_limit') &&
            !fileContent.includes('max_withdrawal') && !fileContent.includes('cooldown')) {
          findings.push({
            id: `SOL139-${findings.length + 1}`,
            pattern: 'Treasury Drain Attack',
            severity: 'high',
            title: 'Treasury withdrawal without rate limiting',
            description: 'No rate limit on treasury withdrawals. Exploit could drain entire treasury in one transaction.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Add rate limits: require!(daily_withdrawn + amount <= config.daily_limit)',
          });
        }
      }

      // Pattern 2: Missing balance check before transfer
      if (lineLower.includes('transfer') && !lineLower.includes('balance')) {
        const fnEnd = Math.min(lines.length, index + 10);
        const fnBody = lines.slice(index, fnEnd).join('\n').toLowerCase();
        
        if (!fnBody.includes('balance') && !fnBody.includes('amount <=') && !fnBody.includes('sufficient')) {
          findings.push({
            id: `SOL139-${findings.length + 1}`,
            pattern: 'Treasury Drain Attack',
            severity: 'medium',
            title: 'Transfer without explicit balance check',
            description: 'Transfer may not check if sufficient balance exists. Could cause unexpected behavior.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Always verify: require!(treasury.balance >= amount, InsufficientFunds)',
          });
        }
      }

      // Pattern 3: Fee collection to arbitrary address
      if (lineLower.includes('fee') && (lineLower.includes('collector') || lineLower.includes('recipient'))) {
        if (line.includes('AccountInfo') || line.includes('UncheckedAccount')) {
          findings.push({
            id: `SOL139-${findings.length + 1}`,
            pattern: 'Treasury Drain Attack',
            severity: 'high',
            title: 'Fee collection to unconstrained address',
            description: 'Fees can be sent to any address. Attacker could redirect fees to themselves.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Store fee recipient in config: has_one = fee_collector',
          });
        }
      }

      // Pattern 4: Reward distribution manipulation
      if ((lineLower.includes('reward') || lineLower.includes('yield') || lineLower.includes('earnings')) &&
          lineLower.includes('claim')) {
        const fnEnd = Math.min(lines.length, index + 25);
        const fnBody = lines.slice(index, fnEnd).join('\n').toLowerCase();
        
        if (!fnBody.includes('verified') && !fnBody.includes('merkle') && 
            !fnBody.includes('accumulated')) {
          findings.push({
            id: `SOL139-${findings.length + 1}`,
            pattern: 'Treasury Drain Attack',
            severity: 'high',
            title: 'Reward claim without proper verification',
            description: 'Reward claims may not properly verify entitlement. Could allow overclaiming.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Track claimed amounts: require!(!user.has_claimed_epoch(current_epoch))',
          });
        }
      }

      // Pattern 5: No minimum reserve requirement
      if (lineLower.includes('withdraw') || lineLower.includes('drain')) {
        const fileContent = content.toLowerCase();
        
        if (!fileContent.includes('reserve') && !fileContent.includes('minimum') &&
            !fileContent.includes('buffer') && !fileContent.includes('floor')) {
          findings.push({
            id: `SOL139-${findings.length + 1}`,
            pattern: 'Treasury Drain Attack',
            severity: 'medium',
            title: 'No minimum reserve requirement',
            description: 'Treasury can be completely drained. No minimum reserve for operations.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Maintain reserve: require!(treasury.balance - amount >= MIN_RESERVE)',
          });
        }
      }
    });
  }

  return findings;
}
