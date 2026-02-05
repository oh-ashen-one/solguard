import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL217: Network Congestion Handling
 * 
 * Real-world exploit: Grape Protocol - 17-hour outage
 */
export function checkGrapeProtocol(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const { rust, path } = input;
  if (!rust) return findings;

  const patterns = [
    { pattern: /network.*congestion/i, desc: 'Network congestion handling' },
    { pattern: /retry.*backoff/i, desc: 'Retry with backoff' },
    { pattern: /timeout.*handling/i, desc: 'Timeout handling' },
  ];

  const lines = rust.content.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    for (const { pattern, desc } of patterns) {
      if (pattern.test(line)) {
        findings.push({
          id: 'SOL217',
          severity: 'low',
          title: 'Network Handling Pattern',
          description: `${desc} - ensure graceful degradation.`,
          location: { file: path, line: i + 1 },
          recommendation: 'Implement exponential backoff and circuit breakers.',
        });
      }
    }
  }
  return findings;
}
