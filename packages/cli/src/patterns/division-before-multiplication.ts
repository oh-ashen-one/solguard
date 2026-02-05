import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL219: Division Before Multiplication
 */
export function checkDivisionBeforeMultiplication(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const { rust, path } = input;
  if (!rust) return findings;

  // Look for patterns like (a / b) * c which can lose precision
  const lines = rust.content.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (/\(.*\/.*\)\s*\*/.test(line) || /\.div\(.*\)\.mul/.test(line)) {
      findings.push({
        id: 'SOL219',
        severity: 'high',
        title: 'Division Before Multiplication',
        description: 'Division before multiplication can cause precision loss.',
        location: { file: path, line: i + 1 },
        recommendation: 'Perform multiplication before division to preserve precision.',
      });
    }
  }
  return findings;
}
