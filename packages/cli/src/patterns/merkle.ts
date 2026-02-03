import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL048: Merkle/Airdrop Vulnerabilities
 * Issues with merkle proofs and airdrops.
 */
export function checkMerkle(input: PatternInput): Finding[] {
  const findings: Finding[] = [];

  if (!input.rust || !input.rust.files) return findings;

  for (const file of input.rust.files) {
    const lines = file.lines;
    const content = file.content;

    if (!content.includes('merkle') && !content.includes('airdrop') && 
        !content.includes('whitelist') && !content.includes('proof')) {
      continue;
    }

    lines.forEach((line, index) => {
      const lineNum = index + 1;

      // Pattern 1: Merkle proof without leaf hashing
      if (line.includes('verify') && content.includes('merkle')) {
        const contextStart = Math.max(0, index - 10);
        const context = lines.slice(contextStart, index + 10).join('\n');

        if (!context.includes('hash') && !context.includes('keccak') && 
            !context.includes('sha256')) {
          findings.push({
            id: `SOL048-${findings.length + 1}`,
            pattern: 'Merkle Vulnerability',
            severity: 'high',
            title: 'Merkle verification without proper hashing',
            description: 'Merkle proof verification may not hash leaf properly.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Hash leaf data: leaf = hash(address, amount) before verification.',
          });
        }
      }

      // Pattern 2: Airdrop claim without tracking
      if (line.includes('claim') && (content.includes('airdrop') || content.includes('merkle'))) {
        const fnEnd = Math.min(lines.length, index + 25);
        const fnBody = lines.slice(index, fnEnd).join('\n');

        if (!fnBody.includes('claimed') && !fnBody.includes('used') && 
            !fnBody.includes('bitmap')) {
          findings.push({
            id: `SOL048-${findings.length + 1}`,
            pattern: 'Merkle Vulnerability',
            severity: 'critical',
            title: 'Airdrop claim without tracking',
            description: 'Claims not tracked. Same proof can be used multiple times.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Track claims in bitmap or claimed_accounts set.',
          });
        }
      }

      // Pattern 3: Merkle root update without verification
      if (line.includes('merkle_root') && (line.includes('=') || line.includes('set'))) {
        const contextStart = Math.max(0, index - 10);
        const context = lines.slice(contextStart, index + 5).join('\n');

        if (!context.includes('admin') && !context.includes('authority') &&
            !context.includes('require')) {
          findings.push({
            id: `SOL048-${findings.length + 1}`,
            pattern: 'Merkle Vulnerability',
            severity: 'critical',
            title: 'Merkle root update without authorization',
            description: 'Anyone can change merkle root. Attacker could add themselves.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Restrict to admin: require!(authority.key() == config.admin)',
          });
        }
      }
    });
  }

  return findings;
}
