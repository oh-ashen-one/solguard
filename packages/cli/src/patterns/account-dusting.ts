import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL215: Account Dusting Attack
 * 
 * Detects vulnerabilities to dusting attacks where tiny amounts
 * are sent to trigger unwanted account creation or tracking.
 */
export function checkAccountDusting(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const { rust, path } = input;

  if (!rust) return findings;

  const patterns = [
    { pattern: /init_if_needed/i, desc: 'Init if needed pattern' },
    { pattern: /create.*account.*any/i, desc: 'Any amount account creation' },
    { pattern: /minimum.*balance.*0/i, desc: 'Zero minimum balance' },
  ];

  const lines = rust.content.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    for (const { pattern, desc } of patterns) {
      if (pattern.test(line)) {
        findings.push({
          id: 'SOL215',
          severity: 'medium',
          title: 'Account Dusting Risk',
          description: `${desc} - could allow dusting attacks.`,
          location: { file: path, line: i + 1 },
          recommendation: 'Require minimum amounts for account initialization.',
        });
      }
    }
  }

  return findings;
}
