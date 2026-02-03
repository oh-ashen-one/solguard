import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL055: Program ID Vulnerabilities
 * Issues with program ID handling and validation.
 */
export function checkProgramId(input: PatternInput): Finding[] {
  const findings: Finding[] = [];

  if (!input.rust || !input.rust.files) return findings;

  for (const file of input.rust.files) {
    const lines = file.lines;

    lines.forEach((line, index) => {
      const lineNum = index + 1;

      // Pattern 1: Program ID from user input
      if (line.includes('program_id') && 
          (line.includes('args.') || line.includes('input.') || line.includes('params.'))) {
        findings.push({
          id: `SOL055-${findings.length + 1}`,
          pattern: 'Program ID Vulnerability',
          severity: 'critical',
          title: 'Program ID from user input',
          description: 'Program ID comes from user input. Attacker could substitute malicious program.',
          location: { file: file.path, line: lineNum },
          suggestion: 'Hardcode or validate program IDs: require!(pid == &expected::ID)',
        });
      }

      // Pattern 2: CPI without program ID check
      if (line.includes('invoke') && !line.includes('invoke_signed')) {
        const contextStart = Math.max(0, index - 10);
        const context = lines.slice(contextStart, index + 3).join('\n');

        if (!context.includes('check_id') && !context.includes('== &') && 
            !context.includes('program::ID')) {
          findings.push({
            id: `SOL055-${findings.length + 1}`,
            pattern: 'Program ID Vulnerability',
            severity: 'high',
            title: 'CPI to potentially unvalidated program',
            description: 'Invoking program without explicit ID validation.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Verify program: require!(program.key() == &expected::ID)',
          });
        }
      }

      // Pattern 3: Using ID from account info
      if (line.includes('.key()') && line.includes('program')) {
        const contextEnd = Math.min(lines.length, index + 5);
        const context = lines.slice(index, contextEnd).join('\n');

        if (context.includes('invoke') && !context.includes('require') && 
            !context.includes('check') && !context.includes('==')) {
          findings.push({
            id: `SOL055-${findings.length + 1}`,
            pattern: 'Program ID Vulnerability',
            severity: 'high',
            title: 'Using program key without verification',
            description: 'Program key from account used in CPI without validation.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Validate program ID before using in CPI.',
          });
        }
      }
    });
  }

  return findings;
}
