import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL148: SPL Lending Rounding
 * Detects rounding vulnerabilities in lending protocols
 * Real-world: Neodyme $2.6B at-risk disclosure in SPL lending
 */
export function checkSplLendingRounding(input: PatternInput): Finding[] {
  const findings: Finding[] = [];

  if (input.rust?.content) {
    const content = input.rust.content;
    const lines = content.split('\n');

    // Check for lending-related patterns
    const lendingPatterns = [
      /borrow|lend|deposit|withdraw/i,
      /interest_rate|apy|apr/i,
      /collateral_ratio|utilization/i,
      /liquidity_amount|reserve_amount/i,
    ];

    const hasLending = lendingPatterns.some(p => p.test(content));

    if (hasLending) {
      // Check for rounding direction
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];

        // Check for division without explicit rounding
        if (line.match(/\/\s*\d|\/\s*\w/) && !line.includes('//')) {
          if (!line.includes('checked_div') && !line.includes('saturating_div')) {
            findings.push({
              id: 'SOL148',
              title: 'Unchecked Division',
              severity: 'high',
              description: 'Division in lending must use checked operations and explicit rounding direction.',
              location: { file: input.path, line: i + 1 },
              suggestion: 'Use checked math: amount.checked_div(rate).ok_or(MathError)?',
              cwe: 'CWE-682',
            });
            break;
          }
        }

        // Check for round vs floor/ceil
        if (line.includes('.round()')) {
          findings.push({
            id: 'SOL148',
            title: 'Using Round Instead of Floor/Ceil',
            severity: 'critical',
            description: 'Lending protocols should use floor() for user withdrawals and ceil() for protocol fees.',
            location: { file: input.path, line: i + 1 },
            suggestion: 'Use directional rounding: floor() favors protocol, ceil() favors user. Choose based on context.',
            cwe: 'CWE-682',
          });
        }
      }

      // Check for dust amount handling
      if (!content.includes('MIN_') && !content.includes('dust') && !content.includes('minimum_amount')) {
        findings.push({
          id: 'SOL148',
          title: 'No Dust Amount Handling',
          severity: 'medium',
          description: 'Lending protocols should handle dust amounts to prevent rounding exploits.',
          location: { file: input.path, line: 1 },
          suggestion: 'Add minimum amounts: require!(amount >= MIN_DEPOSIT_AMOUNT, AmountTooSmall)',
          cwe: 'CWE-682',
        });
      }

      // Check for exchange rate manipulation
      if (content.includes('exchange_rate') || content.includes('share')) {
        if (!content.includes('virtual_') && !content.includes('offset')) {
          findings.push({
            id: 'SOL148',
            title: 'Exchange Rate Manipulation Risk',
            severity: 'high',
            description: 'Share/exchange rate calculations are vulnerable to first-depositor attacks without virtual offset.',
            location: { file: input.path, line: 1 },
            suggestion: 'Use virtual offset: shares = (deposit * (total_shares + VIRTUAL_SHARES)) / (total_assets + VIRTUAL_ASSETS)',
            cwe: 'CWE-682',
          });
        }
      }

      // Check for interest accrual precision
      if (content.includes('interest') && content.includes('compound')) {
        if (!content.includes('u128') && !content.includes('U256')) {
          findings.push({
            id: 'SOL148',
            title: 'Insufficient Precision for Interest',
            severity: 'high',
            description: 'Interest calculations need higher precision (u128/U256) to prevent rounding losses.',
            location: { file: input.path, line: 1 },
            suggestion: 'Use u128 for intermediate calculations: let interest_u128 = (principal as u128) * rate_u128 / SCALE',
            cwe: 'CWE-190',
          });
        }
      }
    }
  }

  return findings;
}
