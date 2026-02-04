import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL133: Bonding Curve Manipulation (Nirvana Finance Exploit - $3.5M)
 * 
 * Detects vulnerabilities in bonding curve implementations where
 * flash loans or large trades can manipulate the curve to mint
 * tokens at favorable rates.
 */
export function checkBondingCurveManipulation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];

  if (!input.rust || !input.rust.files) return findings;

  for (const file of input.rust.files) {
    const lines = file.lines;
    const content = file.content;

    lines.forEach((line, index) => {
      const lineNum = index + 1;
      const lineLower = line.toLowerCase();

      // Pattern 1: Bonding curve without flash loan protection
      if (lineLower.includes('bonding_curve') || lineLower.includes('bonding curve') ||
          lineLower.includes('price_curve') || lineLower.includes('mint_price')) {
        const fileContent = content.toLowerCase();
        
        if (!fileContent.includes('flash_loan') && !fileContent.includes('same_slot') && 
            !fileContent.includes('cooldown') && !fileContent.includes('rate_limit')) {
          findings.push({
            id: `SOL133-${findings.length + 1}`,
            pattern: 'Bonding Curve Manipulation',
            severity: 'critical',
            title: 'Bonding curve without flash loan protection',
            description: 'Bonding curve implementation lacks flash loan protection. Attacker can use flash loans to manipulate price and mint at favorable rates (Nirvana Finance exploit).',
            location: { file: file.path, line: lineNum },
            suggestion: 'Add flash loan protection: check slot difference, implement cooldowns, or use TWAP.',
          });
        }
      }

      // Pattern 2: Price calculated from current reserves only
      if ((lineLower.includes('reserve') || lineLower.includes('supply')) && 
          (lineLower.includes('price') || lineLower.includes('rate'))) {
        const fnEnd = Math.min(lines.length, index + 10);
        const fnBody = lines.slice(index, fnEnd).join('\n').toLowerCase();
        
        if (!fnBody.includes('twap') && !fnBody.includes('oracle') && !fnBody.includes('average')) {
          findings.push({
            id: `SOL133-${findings.length + 1}`,
            pattern: 'Bonding Curve Manipulation',
            severity: 'high',
            title: 'Price derived from spot reserves without averaging',
            description: 'Price calculated from current reserves without TWAP or oracle verification. Vulnerable to same-transaction manipulation.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Use time-weighted average price (TWAP) or external oracle for price reference.',
          });
        }
      }

      // Pattern 3: Large mint/buy without limits
      if ((lineLower.includes('mint') || lineLower.includes('buy')) && 
          lineLower.includes('amount')) {
        const fnEnd = Math.min(lines.length, index + 20);
        const fnBody = lines.slice(index, fnEnd).join('\n').toLowerCase();
        
        if (!fnBody.includes('max_amount') && !fnBody.includes('limit') && 
            !fnBody.includes('cap') && !fnBody.includes('ceiling')) {
          findings.push({
            id: `SOL133-${findings.length + 1}`,
            pattern: 'Bonding Curve Manipulation',
            severity: 'high',
            title: 'Unbounded mint/buy operation',
            description: 'Mint or buy operation has no maximum limit. Large purchases can significantly move the bonding curve.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Implement per-transaction and per-user limits: require!(amount <= config.max_single_trade)',
          });
        }
      }

      // Pattern 4: Immediate redemption after mint
      if (lineLower.includes('redeem') || lineLower.includes('sell') || lineLower.includes('burn')) {
        const fileContent = content.toLowerCase();
        if (!fileContent.includes('lock_period') && !fileContent.includes('vesting') && 
            !fileContent.includes('cooldown') && !fileContent.includes('delay')) {
          findings.push({
            id: `SOL133-${findings.length + 1}`,
            pattern: 'Bonding Curve Manipulation',
            severity: 'medium',
            title: 'No lock period for redemption',
            description: 'Tokens can be redeemed immediately after minting. Enables atomic arbitrage attacks.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Add vesting or lock period: require!(user.mint_slot + LOCK_SLOTS <= clock.slot)',
          });
        }
      }
    });
  }

  return findings;
}
