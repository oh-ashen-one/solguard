import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL133: Bonding Curve Manipulation
 * Detects vulnerabilities in bonding curve implementations
 * Real-world: Nirvana Finance ($3.5M exploit)
 */
export function checkBondingCurveManipulation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];

  if (input.rust?.content) {
    const content = input.rust.content;
    const lines = content.split('\n');

    // Check for bonding curve patterns
    const bondingPatterns = [
      /bonding_curve|bond_curve/i,
      /price_curve|pricing_curve/i,
      /reserve.*supply|supply.*reserve/i,
      /mint_price|burn_price/i,
    ];

    const hasBondingCurve = bondingPatterns.some(p => p.test(content));

    if (hasBondingCurve) {
      // Check for price manipulation via reserve/supply ratio
      if (!content.includes('min_price') && !content.includes('max_price')) {
        findings.push({
          id: 'SOL133',
          title: 'Missing Bonding Curve Price Bounds',
          severity: 'critical',
          description: 'Bonding curves should have minimum and maximum price bounds to prevent extreme manipulation.',
          location: { file: input.path, line: 1 },
          suggestion: 'Add price bounds: require!(price >= MIN_PRICE && price <= MAX_PRICE, PriceOutOfBounds)',
          cwe: 'CWE-20',
        });
      }

      // Check for flash loan resistance
      if (!content.includes('same_slot') && !content.includes('last_update_slot')) {
        findings.push({
          id: 'SOL133',
          title: 'Bonding Curve Flash Loan Vulnerability',
          severity: 'critical',
          description: 'Bonding curves are vulnerable to flash loan attacks without same-slot protection.',
          location: { file: input.path, line: 1 },
          suggestion: 'Add flash loan protection: require!(current_slot > last_interaction_slot, SameSlotNotAllowed)',
          cwe: 'CWE-362',
        });
      }

      // Check for invariant validation
      for (let i = 0; i < lines.length; i++) {
        if (lines[i].match(/mint|burn/i) && lines[i].includes('(')) {
          if (!content.includes('invariant') && !content.includes('k =')) {
            findings.push({
              id: 'SOL133',
              title: 'Missing Bonding Curve Invariant Check',
              severity: 'high',
              description: 'Bonding curve operations should validate the curve invariant (e.g., x*y=k) after each operation.',
              location: { file: input.path, line: i + 1 },
              suggestion: 'Verify invariant after operations: let new_k = reserve * supply; require!(new_k >= old_k, InvariantViolation)',
              cwe: 'CWE-682',
            });
            break;
          }
        }
      }
    }
  }

  return findings;
}
