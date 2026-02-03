import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL032: Missing Time Lock
 * Critical operations without time-delayed execution.
 */
export function checkTimeLock(input: PatternInput): Finding[] {
  const findings: Finding[] = [];

  if (!input.rust || !input.rust.files) return findings;

  for (const file of input.rust.files) {
    const lines = file.lines;
    const content = file.content;

    // Operations that should have time locks
    const criticalOps = [
      'upgrade', 'migrate', 'set_admin', 'set_authority', 'set_fee',
      'pause', 'emergency', 'withdraw_all', 'drain'
    ];

    lines.forEach((line, index) => {
      const lineNum = index + 1;

      if (line.includes('pub fn')) {
        const fnNameMatch = line.match(/pub fn\s+(\w+)/);
        if (fnNameMatch) {
          const fnName = fnNameMatch[1].toLowerCase();
          const isCritical = criticalOps.some(op => fnName.includes(op));

          if (isCritical) {
            // Check for time lock patterns
            const fnEnd = Math.min(lines.length, index + 40);
            const fnBody = lines.slice(index, fnEnd).join('\n').toLowerCase();

            const hasTimeLock = fnBody.includes('timelock') ||
                               fnBody.includes('time_lock') ||
                               fnBody.includes('delay') ||
                               fnBody.includes('pending') ||
                               fnBody.includes('queue') ||
                               (fnBody.includes('timestamp') && fnBody.includes('>='));

            if (!hasTimeLock) {
              findings.push({
                id: `SOL032-${findings.length + 1}`,
                pattern: 'Missing Time Lock',
                severity: 'medium',
                title: `Critical operation '${fnNameMatch[1]}' without time lock`,
                description: 'Critical admin operation executes immediately. Time locks allow users to exit before harmful changes.',
                location: { file: file.path, line: lineNum },
                suggestion: 'Implement queue-execute pattern with minimum delay (e.g., 24-48 hours).',
              });
            }
          }
        }
      }

      // Check for fee changes without caps
      if ((line.includes('fee') || line.includes('rate')) && 
          (line.includes('=') || line.includes('set'))) {
        const contextStart = Math.max(0, index - 5);
        const contextEnd = Math.min(lines.length, index + 5);
        const context = lines.slice(contextStart, contextEnd).join('\n');

        if (!context.includes('max') && !context.includes('MAX') && 
            !context.includes('cap') && !context.includes('<=')) {
          findings.push({
            id: `SOL032-${findings.length + 1}`,
            pattern: 'Missing Time Lock',
            severity: 'medium',
            title: 'Fee/rate change without maximum cap',
            description: 'Fees can be changed without upper bound. Malicious admin could set 100% fees.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Add maximum fee cap: require!(new_fee <= MAX_FEE)',
          });
        }
      }
    });
  }

  return findings;
}
