import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL025: Lamport Balance Vulnerabilities
 * Improper lamport balance checks and manipulations.
 */
export function checkLamportBalance(input: PatternInput): Finding[] {
  const findings: Finding[] = [];

  if (!input.rust || !input.rust.files) return findings;

  for (const file of input.rust.files) {
    const lines = file.lines;

    lines.forEach((line, index) => {
      const lineNum = index + 1;

      // Pattern 1: Lamport balance check before CPI
      if (line.includes('lamports()') && (line.includes('==') || line.includes('>'))) {
        const contextEnd = Math.min(lines.length, index + 15);
        const afterContext = lines.slice(index, contextEnd).join('\n');

        if (afterContext.includes('invoke') || afterContext.includes('transfer')) {
          findings.push({
            id: `SOL025-${findings.length + 1}`,
            pattern: 'Lamport Balance Vulnerability',
            severity: 'high',
            title: 'Balance check before CPI may be bypassed',
            description: 'Checking lamport balance before CPI is unsafe. The balance could change during CPI execution.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Move balance checks after CPI, or use reentrancy guards to prevent manipulation.',
          });
        }
      }

      // Pattern 2: Direct lamport manipulation without rent check
      if (line.includes('lamports.borrow_mut') || line.includes('**lamports')) {
        const contextStart = Math.max(0, index - 10);
        const context = lines.slice(contextStart, index + 5).join('\n');

        if (!context.includes('rent') && !context.includes('Rent::get') && !context.includes('rent_exempt')) {
          findings.push({
            id: `SOL025-${findings.length + 1}`,
            pattern: 'Lamport Balance Vulnerability',
            severity: 'medium',
            title: 'Lamport manipulation without rent consideration',
            description: 'Directly modifying lamports without checking rent exemption requirements.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Ensure accounts remain rent-exempt after lamport modifications.',
          });
        }
      }

      // Pattern 3: Using == for balance comparison (floating point style bug)
      if (line.includes('lamports') && line.includes('==') && !line.includes('== 0')) {
        findings.push({
          id: `SOL025-${findings.length + 1}`,
          pattern: 'Lamport Balance Vulnerability',
          severity: 'low',
          title: 'Exact lamport comparison may be fragile',
          description: 'Using == for lamport comparison. Due to fees and rent, exact matches are often unreliable.',
          location: { file: file.path, line: lineNum },
          suggestion: 'Consider using >= or <= for lamport comparisons, with appropriate tolerance.',
        });
      }

      // Pattern 4: Sending all lamports (account closing pattern)
      if ((line.includes('lamports()') || line.includes('lamports =')) && 
          (line.includes('= 0') || line.includes('**') && line.includes('-='))) {
        const contextStart = Math.max(0, index - 5);
        const context = lines.slice(contextStart, index + 3).join('\n');

        if (!context.includes('close') && !context.includes('zero') && !context.includes('closed')) {
          findings.push({
            id: `SOL025-${findings.length + 1}`,
            pattern: 'Lamport Balance Vulnerability',
            severity: 'high',
            title: 'Account zeroed without proper closing logic',
            description: 'Setting lamports to zero without using Anchor close or proper cleanup.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Use #[account(close = destination)] in Anchor, or zero discriminator and data properly.',
          });
        }
      }
    });
  }

  return findings;
}
