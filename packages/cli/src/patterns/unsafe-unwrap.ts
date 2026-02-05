import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/** SOL222: Unsafe Unwrap */
export function checkUnsafeUnwrap(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const { rust, path } = input;
  if (!rust) return findings;

  const lines = rust.content.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (/\.unwrap\(\)/.test(line) && !line.includes('//') && !line.trim().startsWith('//')) {
      findings.push({
        id: 'SOL222',
        severity: 'medium',
        title: 'Unsafe Unwrap',
        description: 'unwrap() can panic on None/Err.',
        location: { file: path, line: i + 1 },
        recommendation: 'Use ? operator or ok_or() for proper error handling.',
      });
    }
  }
  return findings;
}
