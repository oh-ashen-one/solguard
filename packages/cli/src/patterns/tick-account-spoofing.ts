import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL131: Tick Account Spoofing (Crema Finance Exploit - $8.8M)
 * 
 * Detects vulnerabilities where tick/price accounts can be spoofed
 * due to missing owner verification, allowing manipulation of 
 * concentrated liquidity positions.
 */
export function checkTickAccountSpoofing(input: PatternInput): Finding[] {
  const findings: Finding[] = [];

  if (!input.rust || !input.rust.files) return findings;

  for (const file of input.rust.files) {
    const lines = file.lines;
    const content = file.content;

    // Check for tick-related structures without proper validation
    const tickKeywords = ['tick', 'price_tick', 'tick_array', 'tick_state', 'tick_account'];
    
    lines.forEach((line, index) => {
      const lineNum = index + 1;
      const lineLower = line.toLowerCase();

      // Pattern 1: Tick account passed as AccountInfo without owner check
      if (lineLower.includes('tick') && line.includes('AccountInfo')) {
        if (!content.includes('owner =') || !content.includes('constraint =')) {
          findings.push({
            id: `SOL131-${findings.length + 1}`,
            pattern: 'Tick Account Spoofing',
            severity: 'critical',
            title: 'Tick account without owner verification',
            description: 'Tick/price account passed as AccountInfo without verifying owner. Attacker can create fake tick account to manipulate prices (Crema Finance exploit).',
            location: { file: file.path, line: lineNum },
            suggestion: 'Add owner constraint: #[account(owner = expected_program::ID)] or verify tick.owner == expected_program::ID',
          });
        }
      }

      // Pattern 2: CLMM/AMM tick operations without validation
      if ((lineLower.includes('get_tick') || lineLower.includes('update_tick') || lineLower.includes('tick_data')) 
          && !content.includes('verify_tick') && !content.includes('validate_tick')) {
        findings.push({
          id: `SOL131-${findings.length + 1}`,
          pattern: 'Tick Account Spoofing',
          severity: 'high',
          title: 'Tick operation without validation',
          description: 'Tick data accessed or modified without explicit validation. Could allow spoofed tick injection.',
          location: { file: file.path, line: lineNum },
          suggestion: 'Validate tick account derivation matches expected seeds and owner before use.',
        });
      }

      // Pattern 3: Fee calculation from untrusted tick
      if ((lineLower.includes('fee') || lineLower.includes('reward')) && lineLower.includes('tick')) {
        const fnEnd = Math.min(lines.length, index + 15);
        const fnBody = lines.slice(index, fnEnd).join('\n');
        
        if (!fnBody.includes('verify') && !fnBody.includes('validate') && !fnBody.includes('constraint')) {
          findings.push({
            id: `SOL131-${findings.length + 1}`,
            pattern: 'Tick Account Spoofing',
            severity: 'critical',
            title: 'Fee/reward calculation from potentially spoofed tick',
            description: 'Fees or rewards calculated using tick data without validation. Attacker can claim excessive fees with fake tick data.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Always verify tick account authenticity before using its data for calculations.',
          });
        }
      }
    });
  }

  return findings;
}
