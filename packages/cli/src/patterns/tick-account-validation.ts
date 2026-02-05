import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL188: Tick Account Validation (CLMM)
 * 
 * Detects insufficient validation of tick accounts in Concentrated
 * Liquidity Market Makers (CLMMs).
 * 
 * Real-world exploit: Crema Finance - $8.8M stolen using fake tick
 * accounts that bypassed owner verification.
 */
export function checkTickAccountValidation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const { rust, idl, path } = input;

  if (idl) {
    const clmmInstructions = idl.instructions.filter(ix =>
      ix.name.toLowerCase().includes('tick') ||
      ix.name.toLowerCase().includes('position') ||
      ix.name.toLowerCase().includes('liquidity') ||
      ix.name.toLowerCase().includes('swap')
    );

    for (const ix of clmmInstructions) {
      const tickAccounts = ix.accounts?.filter(acc =>
        acc.name.toLowerCase().includes('tick') ||
        acc.name.toLowerCase().includes('position')
      );

      for (const acc of tickAccounts || []) {
        findings.push({
          id: 'SOL188',
          severity: 'high',
          title: 'Tick Account Requires Strict Validation',
          description: `Account "${acc.name}" in instruction "${ix.name}" - ensure PDA derivation and owner validation.`,
          location: { file: path, line: 1 },
          recommendation: 'Validate tick accounts via PDA derivation with pool key. Verify owner is the protocol.',
        });
      }
    }
  }

  if (!rust) return findings;

  const vulnerablePatterns = [
    { pattern: /tick_account/, desc: 'Tick account reference' },
    { pattern: /tick_state/, desc: 'Tick state access' },
    { pattern: /position_state/, desc: 'Position state access' },
    { pattern: /fee_growth/, desc: 'Fee growth calculation' },
    { pattern: /claim.*fees/, desc: 'Fee claiming operation' },
  ];

  const lines = rust.content.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    for (const { pattern, desc } of vulnerablePatterns) {
      if (pattern.test(line)) {
        const context = lines.slice(Math.max(0, i - 15), Math.min(lines.length, i + 15)).join('\n');
        
        // Check for proper validation
        const hasValidation = 
          context.includes('find_program_address') ||
          context.includes('seeds =') ||
          context.includes('owner ==') ||
          context.includes('constraint = ');

        if (!hasValidation) {
          findings.push({
            id: 'SOL188',
            severity: 'critical',
            title: 'Missing Tick Account Validation',
            description: `${desc} - tick/position account not validated via PDA or owner check.`,
            location: { file: path, line: i + 1 },
            recommendation: 'Derive tick accounts from pool seeds and validate owner is the protocol program.',
          });
          break;
        }
      }
    }
  }

  return findings;
}
