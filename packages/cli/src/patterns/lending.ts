import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL045: Lending Protocol Vulnerabilities
 * Issues with borrowing, lending, and collateral.
 */
export function checkLending(input: PatternInput): Finding[] {
  const findings: Finding[] = [];

  if (!input.rust || !input.rust.files) return findings;

  for (const file of input.rust.files) {
    const lines = file.lines;
    const content = file.content;

    if (!content.includes('borrow') && !content.includes('lend') && 
        !content.includes('collateral') && !content.includes('liquidat')) {
      continue;
    }

    lines.forEach((line, index) => {
      const lineNum = index + 1;

      // Pattern 1: Borrow without collateral check
      if (line.includes('borrow') || line.includes('take_loan')) {
        const fnEnd = Math.min(lines.length, index + 30);
        const fnBody = lines.slice(index, fnEnd).join('\n');

        if (!fnBody.includes('collateral') && !fnBody.includes('health') && 
            !fnBody.includes('ltv')) {
          findings.push({
            id: `SOL045-${findings.length + 1}`,
            pattern: 'Lending Protocol Vulnerability',
            severity: 'critical',
            title: 'Borrow without collateral validation',
            description: 'Loan issued without checking collateral or LTV ratio.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Validate: borrowed_value <= collateral_value * LTV_RATIO',
          });
        }
      }

      // Pattern 2: Liquidation without incentive
      if (line.includes('liquidate') || line.includes('Liquidation')) {
        const fnEnd = Math.min(lines.length, index + 25);
        const fnBody = lines.slice(index, fnEnd).join('\n');

        if (!fnBody.includes('bonus') && !fnBody.includes('discount') && 
            !fnBody.includes('incentive')) {
          findings.push({
            id: `SOL045-${findings.length + 1}`,
            pattern: 'Lending Protocol Vulnerability',
            severity: 'medium',
            title: 'Liquidation without liquidator incentive',
            description: 'No liquidation bonus. Liquidators may not be motivated to liquidate.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Add liquidation bonus (e.g., 5-10% discount on collateral).',
          });
        }
      }

      // Pattern 3: Interest rate without bounds
      if (line.includes('interest_rate') || line.includes('borrow_rate')) {
        const contextEnd = Math.min(lines.length, index + 10);
        const context = lines.slice(index, contextEnd).join('\n');

        if (!context.includes('max') && !context.includes('MAX') && 
            !context.includes('cap')) {
          findings.push({
            id: `SOL045-${findings.length + 1}`,
            pattern: 'Lending Protocol Vulnerability',
            severity: 'medium',
            title: 'Interest rate without maximum cap',
            description: 'Interest rate can grow unbounded in high utilization.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Cap interest rate: min(calculated_rate, MAX_RATE)',
          });
        }
      }

      // Pattern 4: Collateral factor per asset
      if (line.includes('collateral_factor') || line.includes('ltv')) {
        const contextStart = Math.max(0, index - 5);
        const context = lines.slice(contextStart, index + 5).join('\n');

        if (!context.includes('asset') && !context.includes('mint') && 
            !context.includes('token')) {
          findings.push({
            id: `SOL045-${findings.length + 1}`,
            pattern: 'Lending Protocol Vulnerability',
            severity: 'high',
            title: 'Collateral factor not asset-specific',
            description: 'Same LTV for all assets is risky. Volatile assets need lower LTV.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Set per-asset collateral factors based on volatility.',
          });
        }
      }

      // Pattern 5: Reserve refresh missing
      if (line.includes('reserve') && (line.includes('borrow') || line.includes('repay'))) {
        const contextStart = Math.max(0, index - 15);
        const context = lines.slice(contextStart, index + 1).join('\n');

        if (!context.includes('refresh') && !context.includes('accrue') && 
            !context.includes('update')) {
          findings.push({
            id: `SOL045-${findings.length + 1}`,
            pattern: 'Lending Protocol Vulnerability',
            severity: 'high',
            title: 'Reserve state not refreshed before operation',
            description: 'Operating on stale reserve data. Interest may not be properly accrued.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Call refresh_reserve() or accrue_interest() before state changes.',
          });
        }
      }
    });
  }

  return findings;
}
