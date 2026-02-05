import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/** SOL221: Missing Return Statement */
export function checkMissingReturn(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const { rust, path } = input;
  if (!rust) return findings;

  const lines = rust.content.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (/err!\s*\(/.test(line) && !lines.slice(i, i + 3).join('').includes('return')) {
      findings.push({
        id: 'SOL221',
        severity: 'high',
        title: 'Missing Return After Error',
        description: 'Error macro without return may continue execution.',
        location: { file: path, line: i + 1 },
        recommendation: 'Use return err!() or ? operator.',
      });
    }
  }
  return findings;
}
