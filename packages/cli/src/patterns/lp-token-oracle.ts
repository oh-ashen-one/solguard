import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL143: LP Token Oracle Manipulation
 * Detects vulnerabilities in LP token pricing used by lending protocols
 * Real-world: OtterSec $200M potential exploit disclosure
 */
export function checkLpTokenOracle(input: PatternInput): Finding[] {
  const findings: Finding[] = [];

  if (input.rust?.content) {
    const content = input.rust.content;
    const lines = content.split('\n');

    // Check for LP token pricing patterns
    const lpPatterns = [
      /lp_token|liquidity_token/i,
      /pool_token.*price|price.*pool_token/i,
      /total_supply.*reserve|reserve.*total_supply/i,
      /get_lp_price|lp_value/i,
    ];

    const hasLpPricing = lpPatterns.some(p => p.test(content));

    if (hasLpPricing) {
      // Check for naive LP pricing (vulnerable to manipulation)
      if (content.includes('reserve') && content.includes('total_supply')) {
        if (!content.includes('fair_price') && !content.includes('sqrt')) {
          findings.push({
            id: 'SOL143',
            title: 'Naive LP Token Pricing',
            severity: 'critical',
            description: 'LP token pricing using reserve/supply is vulnerable to manipulation. Use fair LP pricing formulas.',
            location: { file: input.path, line: 1 },
            suggestion: 'Use fair pricing: fair_lp_price = 2 * sqrt(reserve0 * reserve1 * price0 * price1) / total_supply',
            cwe: 'CWE-682',
          });
        }
      }

      // Check for spot price usage
      if (content.includes('spot_price') || content.includes('current_price')) {
        if (!content.includes('twap') && !content.includes('vwap')) {
          findings.push({
            id: 'SOL143',
            title: 'Spot Price for LP Valuation',
            severity: 'critical',
            description: 'Using spot prices for LP valuation enables flash loan manipulation. Use TWAP/VWAP.',
            location: { file: input.path, line: 1 },
            suggestion: 'Use TWAP: let price = oracle.get_twap(asset, 30 * 60); // 30-minute TWAP',
            cwe: 'CWE-362',
          });
        }
      }

      // Check for single-block manipulation protection
      if (!content.includes('last_block') && !content.includes('slot_check')) {
        findings.push({
          id: 'SOL143',
          title: 'No Same-Block Protection',
          severity: 'high',
          description: 'LP token operations should prevent same-block manipulation attacks.',
          location: { file: input.path, line: 1 },
          suggestion: 'Add slot check: require!(current_slot > last_interaction_slot, SameSlotManipulation)',
          cwe: 'CWE-362',
        });
      }
    }

    // Check for collateral factor on LP tokens
    if (content.includes('collateral') && content.match(/lp|pool/i)) {
      if (!content.includes('collateral_factor') && !content.includes('ltv')) {
        findings.push({
          id: 'SOL143',
          title: 'Missing LP Collateral Factor',
          severity: 'high',
          description: 'LP tokens used as collateral need conservative collateral factors due to IL and manipulation risk.',
          location: { file: input.path, line: 1 },
          suggestion: 'Set conservative LTV: LP tokens should have lower collateral factors (e.g., 50-60%) than single assets.',
          cwe: 'CWE-20',
        });
      }
    }
  }

  return findings;
}
