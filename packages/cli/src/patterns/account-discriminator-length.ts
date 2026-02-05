import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL220: Account Discriminator Length
 */
export function checkAccountDiscriminatorLength(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const { rust, path } = input;
  if (!rust) return findings;

  const lines = rust.content.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (/discriminator.*\[.*;\s*[1-7]\s*\]/.test(line)) {
      findings.push({
        id: 'SOL220',
        severity: 'high',
        title: 'Short Discriminator',
        description: 'Discriminator less than 8 bytes increases collision risk.',
        location: { file: path, line: i + 1 },
        recommendation: 'Use 8-byte discriminators for account type safety.',
      });
    }
  }
  return findings;
}
