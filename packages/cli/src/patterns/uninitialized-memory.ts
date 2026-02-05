import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/** SOL225: Uninitialized Memory */
export function checkUninitializedMemory(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const { rust, path } = input;
  if (!rust) return findings;

  const lines = rust.content.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (/MaybeUninit::uninit/.test(line) || /mem::uninitialized/.test(line)) {
      findings.push({
        id: 'SOL225',
        severity: 'high',
        title: 'Uninitialized Memory',
        description: 'Use of potentially uninitialized memory.',
        location: { file: path, line: i + 1 },
        recommendation: 'Initialize all memory before use.',
      });
    }
  }
  return findings;
}
