import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL218: Integer Truncation
 */
export function checkIntegerTruncation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const { rust, path } = input;
  if (!rust) return findings;

  const patterns = [
    { pattern: /as\s+u8/, desc: 'Cast to u8' },
    { pattern: /as\s+u16/, desc: 'Cast to u16' },
    { pattern: /as\s+u32/, desc: 'Cast to u32' },
    { pattern: /as\s+i8/, desc: 'Cast to i8' },
    { pattern: /as\s+i16/, desc: 'Cast to i16' },
    { pattern: /as\s+i32/, desc: 'Cast to i32' },
  ];

  const lines = rust.content.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    for (const { pattern, desc } of patterns) {
      if (pattern.test(line)) {
        findings.push({
          id: 'SOL218',
          severity: 'high',
          title: 'Integer Truncation Risk',
          description: `${desc} - may truncate larger values causing unexpected behavior.`,
          location: { file: path, line: i + 1 },
          recommendation: 'Use try_into() with error handling instead of as casts.',
        });
      }
    }
  }
  return findings;
}
