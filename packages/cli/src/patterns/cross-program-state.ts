import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL024: Cross-Program State Dependency
 * Relying on external program state without proper validation.
 */
export function checkCrossProgramState(input: PatternInput): Finding[] {
  const findings: Finding[] = [];

  if (!input.rust || !input.rust.files) return findings;

  for (const file of input.rust.files) {
    const lines = file.lines;

    lines.forEach((line, index) => {
      const lineNum = index + 1;

      // Pattern 1: Reading external program account without owner check
      if (line.includes('try_from_slice') || line.includes('deserialize')) {
        const contextStart = Math.max(0, index - 10);
        const context = lines.slice(contextStart, index + 1).join('\n');

        // Look for external program reads
        if (context.includes('AccountInfo') && !context.includes('owner =') && 
            !context.includes('.owner') && !context.includes('check_id')) {
          findings.push({
            id: `SOL024-${findings.length + 1}`,
            pattern: 'Cross-Program State Dependency',
            severity: 'high',
            title: 'External account deserialized without owner validation',
            description: 'Reading and deserializing external account data without verifying the owning program.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Always verify account.owner matches expected program before deserializing.',
          });
        }
      }

      // Pattern 2: Composability with unverified programs
      if (line.includes('invoke') || line.includes('invoke_signed')) {
        const contextStart = Math.max(0, index - 5);
        const context = lines.slice(contextStart, index + 1).join('\n');

        // Check if program ID is validated
        if (context.includes('program_id') && !context.includes('check_id') && 
            !context.includes('key ==') && !context.includes('== &')) {
          findings.push({
            id: `SOL024-${findings.length + 1}`,
            pattern: 'Cross-Program State Dependency',
            severity: 'high',
            title: 'CPI to unvalidated program',
            description: 'Cross-program invocation without explicit program ID validation.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Verify program_id matches expected program (e.g., spl_token::ID) before CPI.',
          });
        }
      }

      // Pattern 3: Relying on external program state for critical decisions
      const criticalOps = ['transfer', 'withdraw', 'liquidate', 'swap', 'borrow'];
      const hasCriticalOp = criticalOps.some(op => line.toLowerCase().includes(op));
      
      if (hasCriticalOp) {
        const contextStart = Math.max(0, index - 20);
        const context = lines.slice(contextStart, index + 1).join('\n').toLowerCase();

        // Check for external state reads before critical ops
        if ((context.includes('pool') || context.includes('reserve') || context.includes('vault')) &&
            !context.includes('refresh') && !context.includes('update')) {
          findings.push({
            id: `SOL024-${findings.length + 1}`,
            pattern: 'Cross-Program State Dependency',
            severity: 'medium',
            title: 'Critical operation using potentially stale external state',
            description: 'Critical operation depends on external program state that may be stale.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Refresh external state (e.g., refresh_reserve) before critical operations.',
          });
        }
      }
    });
  }

  return findings;
}
