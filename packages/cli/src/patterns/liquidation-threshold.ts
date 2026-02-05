import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL183: Liquidation Threshold Manipulation
 * 
 * Detects vulnerabilities in liquidation mechanisms that can be
 * manipulated to cause unfair liquidations or stolen collateral.
 * 
 * Real-world exploit: Solend - Attacker lowered liquidation threshold
 * and inflated liquidation bonus to profit from wrongful liquidations.
 */
export function checkLiquidationThreshold(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const { rust, idl, path } = input;

  if (idl) {
    const liquidationInstructions = idl.instructions.filter(ix =>
      ix.name.toLowerCase().includes('liquidat') ||
      ix.name.toLowerCase().includes('threshold') ||
      ix.name.toLowerCase().includes('collateral')
    );

    for (const ix of liquidationInstructions) {
      const hasAdminCheck = ix.accounts?.some(acc =>
        (acc.name.toLowerCase().includes('admin') || 
         acc.name.toLowerCase().includes('authority')) &&
        acc.isSigner
      );

      const hasTimelock = ix.accounts?.some(acc =>
        acc.name.toLowerCase().includes('timelock') ||
        acc.name.toLowerCase().includes('delay')
      );

      if (ix.name.toLowerCase().includes('update') || ix.name.toLowerCase().includes('set')) {
        if (!hasAdminCheck || !hasTimelock) {
          findings.push({
            id: 'SOL183',
            severity: 'critical',
            title: 'Liquidation Parameter Change Without Safeguards',
            description: `Instruction "${ix.name}" can modify liquidation parameters without ${!hasAdminCheck ? 'admin verification' : 'timelock delay'}.`,
            location: { file: path, line: 1 },
            recommendation: 'Require admin signer and timelock for liquidation parameter changes.',
          });
        }
      }
    }
  }

  if (!rust) return findings;

  const vulnerablePatterns = [
    { pattern: /liquidation_threshold\s*=/, desc: 'Direct liquidation threshold assignment' },
    { pattern: /liquidation_bonus\s*=/, desc: 'Direct liquidation bonus assignment' },
    { pattern: /collateral_factor\s*=/, desc: 'Direct collateral factor assignment' },
    { pattern: /max_liquidation/, desc: 'Maximum liquidation setting' },
  ];

  const lines = rust.content.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    for (const { pattern, desc } of vulnerablePatterns) {
      if (pattern.test(line)) {
        const context = lines.slice(Math.max(0, i - 20), Math.min(lines.length, i + 10)).join('\n');
        
        // Check for proper safeguards
        if (!context.includes('require_admin') && 
            !context.includes('timelock') &&
            !context.includes('delay') &&
            !context.includes('governance')) {
          findings.push({
            id: 'SOL183',
            severity: 'high',
            title: 'Liquidation Parameter Manipulation Risk',
            description: `${desc} - parameter can be modified without proper safeguards.`,
            location: { file: path, line: i + 1 },
            recommendation: 'Add governance voting, timelocks, and bounds checking for liquidation parameter changes.',
          });
        }
      }
    }
  }

  return findings;
}
