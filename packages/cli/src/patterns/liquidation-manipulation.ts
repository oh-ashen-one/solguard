import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL135: Liquidation Threshold Manipulation (Solend Auth Bypass - $16K at risk)
 * 
 * Detects vulnerabilities where liquidation parameters can be manipulated
 * through admin bypass or improper validation.
 */
export function checkLiquidationManipulation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];

  if (!input.rust || !input.rust.files) return findings;

  for (const file of input.rust.files) {
    const lines = file.lines;
    const content = file.content;

    lines.forEach((line, index) => {
      const lineNum = index + 1;
      const lineLower = line.toLowerCase();

      // Pattern 1: Liquidation threshold update without proper auth
      if ((lineLower.includes('liquidation') && lineLower.includes('threshold')) ||
          lineLower.includes('ltv') || lineLower.includes('collateral_factor')) {
        const fnEnd = Math.min(lines.length, index + 20);
        const fnBody = lines.slice(index, fnEnd).join('\n').toLowerCase();
        
        if (fnBody.includes('update') || fnBody.includes('set')) {
          if (!fnBody.includes('admin') && !fnBody.includes('authority') && 
              !fnBody.includes('multisig') && !fnBody.includes('governance')) {
            findings.push({
              id: `SOL135-${findings.length + 1}`,
              pattern: 'Liquidation Threshold Manipulation',
              severity: 'critical',
              title: 'Liquidation parameter update without proper authorization',
              description: 'Liquidation threshold/LTV can be modified without admin check. Attacker can make all positions liquidatable (Solend exploit).',
              location: { file: file.path, line: lineNum },
              suggestion: 'Require admin signature and timelock for parameter changes.',
            });
          }
        }
      }

      // Pattern 2: Lending market account passed without validation
      if (lineLower.includes('lending_market') || lineLower.includes('reserve_config')) {
        if (line.includes('AccountInfo') && !content.includes('has_one = lending_market')) {
          findings.push({
            id: `SOL135-${findings.length + 1}`,
            pattern: 'Liquidation Threshold Manipulation',
            severity: 'critical',
            title: 'Lending market account not properly validated',
            description: 'Lending market can be passed without verification. Attacker can create fake market with malicious parameters.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Add has_one constraint or verify market.key() against known market.',
          });
        }
      }

      // Pattern 3: Liquidation bonus manipulation
      if (lineLower.includes('liquidation_bonus') || lineLower.includes('bonus_rate')) {
        const fnEnd = Math.min(lines.length, index + 15);
        const fnBody = lines.slice(index, fnEnd).join('\n').toLowerCase();
        
        if (!fnBody.includes('max_bonus') && !fnBody.includes('cap') && !fnBody.includes('limit')) {
          findings.push({
            id: `SOL135-${findings.length + 1}`,
            pattern: 'Liquidation Threshold Manipulation',
            severity: 'high',
            title: 'Liquidation bonus without upper bound',
            description: 'Liquidation bonus can be set without maximum limit. Excessive bonus drains protocol reserves.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Cap liquidation bonus: require!(bonus <= MAX_LIQUIDATION_BONUS)',
          });
        }
      }

      // Pattern 4: Reserve config update function
      if (lineLower.includes('update_reserve') || lineLower.includes('update_config')) {
        const fnEnd = Math.min(lines.length, index + 30);
        const fnBody = lines.slice(index, fnEnd).join('\n');
        
        // Check for market validation
        if (fnBody.includes('lending_market') && !fnBody.includes('has_one')) {
          findings.push({
            id: `SOL135-${findings.length + 1}`,
            pattern: 'Liquidation Threshold Manipulation',
            severity: 'critical',
            title: 'Reserve update without market ownership check',
            description: 'Reserve configuration can be updated by passing any lending market. Attacker can create market they own to bypass auth.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Verify reserve belongs to the lending market: has_one = lending_market',
          });
        }
      }
    });
  }

  return findings;
}
