import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL022: Program Upgrade Authority Risk
 * Upgradeable programs without proper authority management are risky.
 */
export function checkUpgradeAuthority(input: PatternInput): Finding[] {
  const findings: Finding[] = [];

  if (!input.rust || !input.rust.files) return findings;

  for (const file of input.rust.files) {
    const lines = file.lines;
    const content = file.content;

    // Check for upgrade-related concerns
    if (content.includes('upgrade') || content.includes('BpfUpgradeable')) {
      lines.forEach((line, index) => {
        const lineNum = index + 1;

        // Pattern 1: Upgrade authority without multisig
        if (line.includes('upgrade_authority') || line.includes('UpgradeAuthority')) {
          const contextStart = Math.max(0, index - 10);
          const contextEnd = Math.min(lines.length, index + 10);
          const context = lines.slice(contextStart, contextEnd).join('\n').toLowerCase();

          if (!context.includes('multisig') && !context.includes('squad') && !context.includes('governance')) {
            findings.push({
              id: `SOL022-${findings.length + 1}`,
              pattern: 'Program Upgrade Authority Risk',
              severity: 'medium',
              title: 'Upgrade authority may be single-key',
              description: 'Upgrade authority without multisig protection. A compromised key could rug the program.',
              location: { file: file.path, line: lineNum },
              suggestion: 'Use a multisig (Squads, Realms) for upgrade authority, or set to immutable after audit.',
            });
          }
        }

        // Pattern 2: Setting upgrade authority to None (immutable)
        if (line.includes('set_upgrade_authority') && line.includes('None')) {
          findings.push({
            id: `SOL022-${findings.length + 1}`,
            pattern: 'Program Upgrade Authority Risk',
            severity: 'info',
            title: 'Program being made immutable',
            description: 'Setting upgrade authority to None makes the program immutable. Ensure thorough auditing first.',
            location: { file: file.path, line: lineNum },
            suggestion: 'This is good for security, but ensure the program is fully audited and tested first.',
          });
        }
      });
    }

    // Check for data upgrade patterns
    lines.forEach((line, index) => {
      const lineNum = index + 1;

      // Pattern 3: Account data migration without version check
      if (line.includes('migrate') || line.includes('upgrade_data')) {
        const contextStart = Math.max(0, index - 10);
        const context = lines.slice(contextStart, index + 5).join('\n');

        if (!context.includes('version') && !context.includes('discriminator')) {
          findings.push({
            id: `SOL022-${findings.length + 1}`,
            pattern: 'Program Upgrade Authority Risk',
            severity: 'high',
            title: 'Data migration without version check',
            description: 'Account data migration without version/discriminator check. Could corrupt data or allow exploits.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Always check account version/discriminator before migrating data structures.',
          });
        }
      }
    });
  }

  return findings;
}
