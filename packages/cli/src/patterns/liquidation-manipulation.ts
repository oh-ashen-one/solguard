import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL135: Liquidation Threshold Manipulation
 * Detects vulnerabilities in lending protocol liquidation mechanisms
 * Real-world: Solend, Mango Markets attacks
 */
export function checkLiquidationManipulation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];

  if (input.rust?.content) {
    const content = input.rust.content;
    const lines = content.split('\n');

    // Check for liquidation-related code
    const liquidationPatterns = [
      /liquidat|liquidation/i,
      /health_factor|health_ratio/i,
      /collateral_ratio|ltv/i,
      /seize|repay_borrow/i,
    ];

    const hasLiquidation = liquidationPatterns.some(p => p.test(content));

    if (hasLiquidation) {
      // Check for oracle manipulation protection
      if (!content.includes('twap') && !content.includes('time_weighted')) {
        findings.push({
          id: 'SOL135',
          title: 'Liquidation Vulnerable to Price Manipulation',
          severity: 'critical',
          description: 'Liquidations using spot prices are vulnerable to oracle manipulation attacks.',
          location: { file: input.path, line: 1 },
          suggestion: 'Use TWAP (time-weighted average price) for liquidation price feeds: let price = oracle.get_twap(asset, window)',
          cwe: 'CWE-362',
        });
      }

      // Check for liquidation bonus bounds
      if (!content.includes('liquidation_bonus') && !content.includes('incentive')) {
        findings.push({
          id: 'SOL135',
          title: 'Missing Liquidation Incentive Bounds',
          severity: 'high',
          description: 'Liquidation incentives should be bounded to prevent excessive profit extraction.',
          location: { file: input.path, line: 1 },
          suggestion: 'Bound liquidation bonus: let bonus = std::cmp::min(calculated_bonus, MAX_LIQUIDATION_BONUS)',
          cwe: 'CWE-20',
        });
      }

      // Check for partial liquidation support
      if (!content.includes('close_factor') && !content.includes('partial')) {
        for (let i = 0; i < lines.length; i++) {
          if (lines[i].match(/liquidat/i)) {
            findings.push({
              id: 'SOL135',
              title: 'No Partial Liquidation Support',
              severity: 'medium',
              description: 'Allowing only full liquidations can cause unnecessary losses. Support partial liquidations.',
              location: { file: input.path, line: i + 1 },
              suggestion: 'Implement close factor: let max_repay = debt * CLOSE_FACTOR; // e.g., 50%',
              cwe: 'CWE-682',
            });
            break;
          }
        }
      }

      // Check for self-liquidation prevention
      if (!content.includes('liquidator') || !content.includes('borrower')) {
        findings.push({
          id: 'SOL135',
          title: 'Self-Liquidation Not Prevented',
          severity: 'high',
          description: 'Users should not be able to liquidate their own positions to extract protocol value.',
          location: { file: input.path, line: 1 },
          suggestion: 'Prevent self-liquidation: require!(liquidator.key() != borrower.key(), SelfLiquidation)',
          cwe: 'CWE-284',
        });
      }
    }
  }

  return findings;
}
