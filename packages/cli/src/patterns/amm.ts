import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL044: AMM/DEX Vulnerabilities
 * Issues with automated market makers and swaps.
 */
export function checkAmm(input: PatternInput): Finding[] {
  const findings: Finding[] = [];

  if (!input.rust || !input.rust.files) return findings;

  for (const file of input.rust.files) {
    const lines = file.lines;
    const content = file.content;

    if (!content.includes('swap') && !content.includes('pool') && 
        !content.includes('liquidity') && !content.includes('amm')) {
      continue;
    }

    lines.forEach((line, index) => {
      const lineNum = index + 1;

      // Pattern 1: Swap without slippage protection
      if (line.includes('swap') || line.includes('exchange')) {
        const fnEnd = Math.min(lines.length, index + 30);
        const fnBody = lines.slice(index, fnEnd).join('\n');

        if (!fnBody.includes('slippage') && !fnBody.includes('min_out') && 
            !fnBody.includes('minimum') && !fnBody.includes('amount_out_min')) {
          findings.push({
            id: `SOL044-${findings.length + 1}`,
            pattern: 'AMM/DEX Vulnerability',
            severity: 'critical',
            title: 'Swap without slippage protection',
            description: 'Swap function without minimum output amount. Users vulnerable to sandwich attacks.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Add slippage param: require!(amount_out >= min_amount_out)',
          });
        }
      }

      // Pattern 2: LP token calculation issues
      if (line.includes('lp_token') || line.includes('mint_lp') || line.includes('shares')) {
        const contextStart = Math.max(0, index - 5);
        const context = lines.slice(contextStart, index + 10).join('\n');

        // Check for first depositor attack
        if (context.includes('total_supply') && context.includes('== 0')) {
          if (!context.includes('virtual') && !context.includes('MINIMUM')) {
            findings.push({
              id: `SOL044-${findings.length + 1}`,
              pattern: 'AMM/DEX Vulnerability',
              severity: 'critical',
              title: 'First depositor inflation attack possible',
              description: 'LP calculation on empty pool. Attacker can inflate shares and steal deposits.',
              location: { file: file.path, line: lineNum },
              suggestion: 'Use virtual reserves or lock minimum liquidity on first deposit.',
            });
          }
        }
      }

      // Pattern 3: Constant product without fee
      if (line.includes('* ') && line.includes('k') || line.includes('constant_product')) {
        const contextStart = Math.max(0, index - 10);
        const context = lines.slice(contextStart, index + 5).join('\n');

        if (!context.includes('fee') && !context.includes('FEE')) {
          findings.push({
            id: `SOL044-${findings.length + 1}`,
            pattern: 'AMM/DEX Vulnerability',
            severity: 'low',
            title: 'AMM without trading fees',
            description: 'No trading fee for LP incentives. May not attract liquidity.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Add swap fee (e.g., 0.3%) to incentivize LPs.',
          });
        }
      }

      // Pattern 4: Imbalanced add liquidity
      if (line.includes('add_liquidity') || line.includes('deposit')) {
        const fnEnd = Math.min(lines.length, index + 25);
        const fnBody = lines.slice(index, fnEnd).join('\n');

        if (!fnBody.includes('ratio') && !fnBody.includes('proportion') &&
            fnBody.includes('amount_a') && fnBody.includes('amount_b')) {
          findings.push({
            id: `SOL044-${findings.length + 1}`,
            pattern: 'AMM/DEX Vulnerability',
            severity: 'medium',
            title: 'Add liquidity without ratio enforcement',
            description: 'Liquidity can be added at wrong ratio, causing immediate arbitrage loss.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Enforce current pool ratio or return excess tokens.',
          });
        }
      }
    });
  }

  return findings;
}
