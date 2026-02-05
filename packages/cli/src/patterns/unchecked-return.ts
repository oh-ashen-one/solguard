import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/** SOL224: Unchecked Return Value */
export function checkUncheckedReturn(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const { rust, path } = input;
  if (!rust) return findings;

  const lines = rust.content.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (/invoke\s*\(/.test(line) && !line.includes('?') && !line.includes('let ') && line.endsWith(';')) {
      findings.push({
        id: 'SOL224',
        severity: 'critical',
        title: 'Unchecked CPI Return',
        description: 'CPI invoke without checking return value.',
        location: { file: path, line: i + 1 },
        recommendation: 'Always use ? or check Result from invoke().',
      });
    }
  }
  return findings;
}
