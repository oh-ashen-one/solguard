import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL305: LP Token Fair Pricing
 * Detects vulnerable LP token pricing that can be manipulated
 * Real-world: OtterSec $200M bluff - LP token oracle manipulation
 */
export function checkLpFairPricing(input: PatternInput): Finding[] {
  const findings: Finding[] = [];

  if (input.rust?.content) {
    const content = input.rust.content;
    const lines = content.split('\n');

    // Detect LP token / AMM patterns
    const isLpRelated = /lp_token|liquidity_pool|amm|pool_token|share_token/i.test(content);
    const hasOracle = /oracle|price_feed|get_price/i.test(content);

    if (isLpRelated) {
      // Check for naive LP pricing (reserve0 * price0 + reserve1 * price1) / totalSupply
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        const contextLines = lines.slice(Math.max(0, i - 5), Math.min(i + 5, lines.length)).join('\n');

        // Detect simple reserve-based pricing
        if ((line.includes('reserve') && line.includes('price')) || 
            (line.includes('token_a') && line.includes('token_b') && contextLines.includes('price'))) {
          if (!contextLines.includes('sqrt') && !contextLines.includes('fair') && !contextLines.includes('geometric')) {
            findings.push({
              id: 'SOL305',
              title: 'Manipulable LP Token Pricing',
              severity: 'critical',
              description: 'Simple reserve-based LP pricing can be manipulated via flash loans.',
              location: { file: input.path, line: i + 1 },
              suggestion: 'Use fair pricing formula: 2 * sqrt(reserve0 * reserve1) * sqrt(price0 * price1) / totalSupply',
              cwe: 'CWE-682',
            });
            break;
          }
        }
      }

      // Check for spot price usage in collateral valuation
      if (hasOracle && content.includes('collateral')) {
        if (!content.includes('twap') && !content.includes('time_weighted')) {
          findings.push({
            id: 'SOL305',
            title: 'Spot Price for LP Collateral',
            severity: 'critical',
            description: 'Using spot prices for LP collateral valuation enables oracle manipulation attacks.',
            location: { file: input.path, line: 1 },
            suggestion: 'Use TWAP: let price = oracle.get_twap(window_seconds)?;',
            cwe: 'CWE-346',
          });
        }
      }

      // Check for single-block price usage
      if (content.includes('get_price') || content.includes('fetch_price')) {
        for (let i = 0; i < lines.length; i++) {
          const line = lines[i];
          if (line.includes('price') && !content.includes('previous_') && !content.includes('last_')) {
            if (content.includes('borrow') || content.includes('liquidat')) {
              findings.push({
                id: 'SOL305',
                title: 'Single-Block Price Oracle',
                severity: 'high',
                description: 'Lending/liquidation using single-block prices is vulnerable to flash loan attacks.',
                location: { file: input.path, line: i + 1 },
                suggestion: 'Use multi-block validation: require!(current_price.within_tolerance(previous_price, MAX_DEVIATION))',
                cwe: 'CWE-346',
              });
              break;
            }
          }
        }
      }

      // Check for reserve ratio validation
      if (content.includes('reserve') && !content.includes('k_invariant') && !content.includes('constant_product')) {
        findings.push({
          id: 'SOL305',
          title: 'Missing Invariant Check',
          severity: 'high',
          description: 'AMM operations should validate the constant product invariant.',
          location: { file: input.path, line: 1 },
          suggestion: 'Check invariant: require!(new_reserve0 * new_reserve1 >= old_k, InvariantViolation)',
          cwe: 'CWE-682',
        });
      }

      // Check for virtual reserves
      if (content.includes('exchange_rate') || content.includes('share_price')) {
        if (!content.includes('virtual') && !content.includes('OFFSET') && !content.includes('BASE_')) {
          findings.push({
            id: 'SOL305',
            title: 'Missing Virtual Reserves',
            severity: 'high',
            description: 'LP share calculations without virtual reserves are vulnerable to first-depositor attacks.',
            location: { file: input.path, line: 1 },
            suggestion: 'Add virtual reserves: shares = deposit * (total_shares + VIRTUAL_SHARES) / (total_assets + VIRTUAL_ASSETS)',
            cwe: 'CWE-682',
          });
        }
      }

      // Check for price bounds
      if (hasOracle && !content.includes('max_price') && !content.includes('min_price') && !content.includes('bound')) {
        findings.push({
          id: 'SOL305',
          title: 'Unbounded Oracle Price',
          severity: 'medium',
          description: 'Oracle prices should have sanity bounds to prevent extreme manipulation.',
          location: { file: input.path, line: 1 },
          suggestion: 'Add bounds: require!(price >= MIN_PRICE && price <= MAX_PRICE, PriceOutOfBounds)',
          cwe: 'CWE-20',
        });
      }
    }
  }

  return findings;
}
