import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL214: PDA Seed Injection
 * 
 * Detects vulnerabilities where user input can influence PDA seeds
 * leading to account confusion or unauthorized access.
 */
export function checkSeedInjection(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const { rust, path } = input;

  if (!rust) return findings;

  const patterns = [
    { pattern: /seeds.*=.*\[.*user_input/i, desc: 'User input in seeds' },
    { pattern: /find_program_address.*args/i, desc: 'Args in PDA derivation' },
    { pattern: /seeds.*concat/i, desc: 'Dynamic seed concatenation' },
  ];

  const lines = rust.content.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    for (const { pattern, desc } of patterns) {
      if (pattern.test(line)) {
        findings.push({
          id: 'SOL214',
          severity: 'critical',
          title: 'PDA Seed Injection Risk',
          description: `${desc} - user-controlled seeds can lead to account confusion.`,
          location: { file: path, line: i + 1 },
          recommendation: 'Sanitize and validate all user inputs used in PDA seeds.',
        });
      }
    }
  }

  return findings;
}
