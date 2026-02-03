import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL033: Signature Replay Vulnerability
 * Missing nonce/replay protection for signed messages.
 */
export function checkSignatureReplay(input: PatternInput): Finding[] {
  const findings: Finding[] = [];

  if (!input.rust || !input.rust.files) return findings;

  for (const file of input.rust.files) {
    const lines = file.lines;
    const content = file.content;

    // Skip if no signature verification
    if (!content.includes('ed25519') && !content.includes('signature') && !content.includes('verify')) {
      continue;
    }

    lines.forEach((line, index) => {
      const lineNum = index + 1;

      // Pattern 1: Signature verification without nonce
      if (line.includes('verify') || line.includes('ed25519_program')) {
        const contextStart = Math.max(0, index - 20);
        const contextEnd = Math.min(lines.length, index + 10);
        const context = lines.slice(contextStart, contextEnd).join('\n').toLowerCase();

        const hasReplayProtection = context.includes('nonce') ||
                                    context.includes('sequence') ||
                                    context.includes('used') ||
                                    context.includes('consumed') ||
                                    context.includes('slot') ||
                                    context.includes('expir');

        if (!hasReplayProtection) {
          findings.push({
            id: `SOL033-${findings.length + 1}`,
            pattern: 'Signature Replay Vulnerability',
            severity: 'critical',
            title: 'Signature verification without replay protection',
            description: 'Signature can be reused. Attacker could replay valid signatures for unauthorized actions.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Include nonce in signed message and track used nonces, or add expiration timestamp.',
          });
        }
      }

      // Pattern 2: Message without domain separator
      if (line.includes('sign') || line.includes('message')) {
        const contextStart = Math.max(0, index - 5);
        const context = lines.slice(contextStart, index + 3).join('\n');

        if (context.includes('hash') || context.includes('digest')) {
          if (!context.includes('domain') && !context.includes('program_id') && 
              !context.includes('chain')) {
            findings.push({
              id: `SOL033-${findings.length + 1}`,
              pattern: 'Signature Replay Vulnerability',
              severity: 'high',
              title: 'Signed message may lack domain separation',
              description: 'Message hash without domain separator. Signatures might be valid across different programs/chains.',
              location: { file: file.path, line: lineNum },
              suggestion: 'Include program_id and chain identifier in signed message hash.',
            });
          }
        }
      }
    });
  }

  return findings;
}
