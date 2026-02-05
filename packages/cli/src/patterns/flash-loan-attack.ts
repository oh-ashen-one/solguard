import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL180: Flash Loan Attack Vectors
 * 
 * Detects code patterns vulnerable to flash loan attacks where
 * attackers borrow large amounts within a single transaction.
 * 
 * Real-world exploits: Nirvana ($3.5M), Crema ($8.8M), Mango ($116M)
 */
export function checkFlashLoanAttack(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const { rust, idl, path } = input;

  // Check IDL for vulnerable patterns
  if (idl) {
    for (const ix of idl.instructions) {
      const name = ix.name.toLowerCase();
      // High-value operations susceptible to flash loans
      if (name.includes('swap') || name.includes('borrow') || 
          name.includes('liquidate') || name.includes('stake') ||
          name.includes('withdraw') || name.includes('claim')) {
        
        const hasSlotCheck = ix.accounts?.some(acc =>
          acc.name.toLowerCase().includes('slot') ||
          acc.name.toLowerCase().includes('clock')
        );

        if (!hasSlotCheck) {
          findings.push({
            id: 'SOL180',
            severity: 'high',
            title: 'Flash Loan Susceptible Operation',
            description: `Instruction "${ix.name}" performs value operations without apparent slot/timing checks for flash loan protection.`,
            location: { file: path, line: 1 },
            recommendation: 'Implement same-slot checks, cooldown periods, or TWAP oracles to prevent flash loan exploitation.',
          });
        }
      }
    }
  }

  if (!rust) return findings;

  const vulnerablePatterns = [
    { pattern: /get_price.*\(\)/, check: 'twap', desc: 'Spot price without TWAP' },
    { pattern: /oracle.*price/, check: 'stale', desc: 'Oracle price without staleness check' },
    { pattern: /collateral.*ratio/, check: 'flash', desc: 'Collateral ratio calculation' },
    { pattern: /liquidity.*amount/, check: 'depth', desc: 'Liquidity amount without depth check' },
  ];

  const lines = rust.content.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    for (const { pattern, check, desc } of vulnerablePatterns) {
      if (pattern.test(line)) {
        const context = lines.slice(Math.max(0, i - 15), Math.min(lines.length, i + 15)).join('\n');
        const hasMitigation = 
          (check === 'twap' && context.includes('twap')) ||
          (check === 'stale' && (context.includes('stale') || context.includes('last_update'))) ||
          (check === 'flash' && (context.includes('same_slot') || context.includes('cooldown'))) ||
          (check === 'depth' && context.includes('min_liquidity'));

        if (!hasMitigation) {
          findings.push({
            id: 'SOL180',
            severity: 'high',
            title: 'Flash Loan Attack Vector',
            description: `${desc} - may be exploitable via flash loan manipulation.`,
            location: { file: path, line: i + 1 },
            recommendation: 'Use TWAP oracles, staleness checks, same-slot restrictions, or minimum liquidity requirements.',
          });
        }
      }
    }
  }

  return findings;
}
