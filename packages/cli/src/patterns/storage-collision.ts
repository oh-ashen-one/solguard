import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL034: Storage/Discriminator Collision
 * Account type confusion via discriminator collisions.
 */
export function checkStorageCollision(input: PatternInput): Finding[] {
  const findings: Finding[] = [];

  if (!input.rust || !input.rust.files) return findings;

  // Track all struct names and their discriminators
  const structDiscriminators = new Map<string, { file: string; line: number }>();

  for (const file of input.rust.files) {
    const lines = file.lines;

    lines.forEach((line, index) => {
      const lineNum = index + 1;

      // Pattern 1: Manual discriminator that might collide
      if (line.includes('DISCRIMINATOR') || line.includes('discriminator')) {
        const contextStart = Math.max(0, index - 2);
        const contextEnd = Math.min(lines.length, index + 2);
        const context = lines.slice(contextStart, contextEnd).join('\n');

        // Check for short discriminators
        const discMatch = context.match(/\[(\d+)(?:,\s*\d+)*\]/);
        if (discMatch) {
          const bytes = discMatch[0].split(',').length;
          if (bytes < 8) {
            findings.push({
              id: `SOL034-${findings.length + 1}`,
              pattern: 'Storage/Discriminator Collision',
              severity: 'high',
              title: 'Short discriminator increases collision risk',
              description: `Discriminator is only ${bytes} bytes. Anchor uses 8 bytes to minimize collision risk.`,
              location: { file: file.path, line: lineNum },
              suggestion: 'Use full 8-byte discriminator (first 8 bytes of SHA256 of account name).',
            });
          }
        }
      }

      // Pattern 2: Account struct without #[account] (no auto discriminator)
      if (line.includes('pub struct') && line.match(/\w+Account|\w+State|\w+Data/)) {
        const structName = line.match(/pub struct\s+(\w+)/)?.[1];
        const contextStart = Math.max(0, index - 3);
        const preceding = lines.slice(contextStart, index).join('\n');

        if (!preceding.includes('#[account]') && !preceding.includes('#[derive(')) {
          findings.push({
            id: `SOL034-${findings.length + 1}`,
            pattern: 'Storage/Discriminator Collision',
            severity: 'medium',
            title: `Account struct '${structName}' may lack discriminator`,
            description: 'Account-like struct without #[account] macro. No automatic type discrimination.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Add #[account] derive macro for automatic 8-byte discriminator.',
          });
        }
      }

      // Pattern 3: Zero-copy without explicit discriminator handling
      if (line.includes('#[zero_copy]') || line.includes('zero_copy')) {
        const contextEnd = Math.min(lines.length, index + 15);
        const afterContext = lines.slice(index, contextEnd).join('\n');

        if (!afterContext.includes('discriminator') && !afterContext.includes('AccountDiscriminator')) {
          findings.push({
            id: `SOL034-${findings.length + 1}`,
            pattern: 'Storage/Discriminator Collision',
            severity: 'medium',
            title: 'Zero-copy account without explicit discriminator',
            description: 'Zero-copy accounts need careful discriminator handling to prevent type confusion.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Ensure zero-copy account has proper discriminator validation.',
          });
        }
      }
    });
  }

  return findings;
}
