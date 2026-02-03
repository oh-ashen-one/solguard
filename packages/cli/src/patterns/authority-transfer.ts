import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL056: Authority Transfer Vulnerabilities
 * Issues with transferring ownership/authority.
 */
export function checkAuthorityTransfer(input: PatternInput): Finding[] {
  const findings: Finding[] = [];

  if (!input.rust || !input.rust.files) return findings;

  for (const file of input.rust.files) {
    const lines = file.lines;

    lines.forEach((line, index) => {
      const lineNum = index + 1;

      // Pattern 1: Direct authority overwrite without two-step
      if ((line.includes('authority =') || line.includes('admin =') || line.includes('owner =')) &&
          !line.includes('pending')) {
        const contextStart = Math.max(0, index - 10);
        const context = lines.slice(contextStart, index + 5).join('\n');

        if (!context.includes('pending') && !context.includes('accept') && 
            !context.includes('two_step')) {
          findings.push({
            id: `SOL056-${findings.length + 1}`,
            pattern: 'Authority Transfer Vulnerability',
            severity: 'medium',
            title: 'Direct authority transfer without two-step',
            description: 'Authority transferred directly. Wrong address = permanent loss of control.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Use two-step transfer: set pending_authority, then accept_authority.',
          });
        }
      }

      // Pattern 2: Transfer to zero/default address
      if (line.includes('authority') && line.includes('Pubkey::default()')) {
        findings.push({
          id: `SOL056-${findings.length + 1}`,
          pattern: 'Authority Transfer Vulnerability',
          severity: 'high',
          title: 'Authority set to default/zero pubkey',
          description: 'Setting authority to Pubkey::default() likely locks the account permanently.',
          location: { file: file.path, line: lineNum },
          suggestion: 'Validate: require!(new_authority != Pubkey::default())',
        });
      }

      // Pattern 3: No event on authority change
      if (line.includes('set_authority') || 
          (line.includes('authority') && line.includes('=') && !line.includes('=='))) {
        const contextEnd = Math.min(lines.length, index + 10);
        const context = lines.slice(index, contextEnd).join('\n');

        if (!context.includes('emit') && !context.includes('msg!') && 
            !context.includes('Event')) {
          findings.push({
            id: `SOL056-${findings.length + 1}`,
            pattern: 'Authority Transfer Vulnerability',
            severity: 'low',
            title: 'Authority change without event',
            description: 'Authority changes should emit events for off-chain tracking.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Emit event: emit!(AuthorityChanged { old, new })',
          });
        }
      }
    });
  }

  return findings;
}
