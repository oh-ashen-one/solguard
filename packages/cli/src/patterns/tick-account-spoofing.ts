import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL131: Tick Account Spoofing
 * Detects vulnerabilities where tick accounts in CLMM protocols can be spoofed
 * Real-world: Crema Finance ($8.8M exploit)
 */
export function checkTickAccountSpoofing(input: PatternInput): Finding[] {
  const findings: Finding[] = [];

  if (input.rust?.content) {
    const content = input.rust.content;
    const lines = content.split('\n');

    // Check for tick account usage without proper validation
    const tickPatterns = [
      /tick_array|tick_account|tick_state/i,
      /get_tick|load_tick/i,
      /tick_lower|tick_upper/i,
    ];

    const hasTickOperations = tickPatterns.some(p => p.test(content));
    
    if (hasTickOperations) {
      // Check for missing owner validation on tick accounts
      if (!content.includes('owner ==') && !content.includes('check_owner')) {
        findings.push({
          id: 'SOL131',
          title: 'Tick Account Spoofing Risk',
          severity: 'critical',
          description: 'Tick accounts in CLMM protocols must validate ownership to prevent spoofed tick data injection.',
          location: { file: input.path, line: 1 },
          suggestion: 'Always verify tick account ownership matches the expected pool program. Use constraints like #[account(owner = pool_program)].',
          cwe: 'CWE-284',
        });
      }

      // Check for tick bounds validation
      if (content.includes('tick') && !content.includes('tick_spacing')) {
        for (let i = 0; i < lines.length; i++) {
          if (lines[i].includes('tick') && !lines[i].includes('//')) {
            findings.push({
              id: 'SOL131',
              title: 'Missing Tick Bounds Validation',
              severity: 'high',
              description: 'Tick values should be validated against tick_spacing to ensure they are valid tick boundaries.',
              location: { file: input.path, line: i + 1 },
              suggestion: 'Validate tick values: require!(tick % tick_spacing == 0, InvalidTick)',
              cwe: 'CWE-20',
            });
            break;
          }
        }
      }
    }
  }

  return findings;
}
