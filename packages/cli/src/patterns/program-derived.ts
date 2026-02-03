import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL050: Program-Derived Signing Issues
 * Advanced PDA and signing vulnerabilities.
 */
export function checkProgramDerived(input: PatternInput): Finding[] {
  const findings: Finding[] = [];

  if (!input.rust || !input.rust.files) return findings;

  for (const file of input.rust.files) {
    const lines = file.lines;

    lines.forEach((line, index) => {
      const lineNum = index + 1;

      // Pattern 1: PDA seed collision risk
      if (line.includes('seeds =') && line.includes('[')) {
        const seedContent = line.match(/seeds\s*=\s*\[([^\]]+)\]/)?.[1] || '';
        const seedCount = seedContent.split(',').length;

        if (seedCount === 1 && !seedContent.includes('.key()')) {
          findings.push({
            id: `SOL050-${findings.length + 1}`,
            pattern: 'Program-Derived Signing Issue',
            severity: 'medium',
            title: 'Single static seed for PDA',
            description: 'PDA with single static seed. Multiple entities may collide.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Include unique identifiers in seeds (user pubkey, mint, etc.).',
          });
        }
      }

      // Pattern 2: Seeds from untrusted sources
      if (line.includes('seeds') && (line.includes('args.') || line.includes('input.'))) {
        const contextStart = Math.max(0, index - 5);
        const context = lines.slice(contextStart, index + 3).join('\n');

        if (!context.includes('validate') && !context.includes('require') &&
            !context.includes('check')) {
          findings.push({
            id: `SOL050-${findings.length + 1}`,
            pattern: 'Program-Derived Signing Issue',
            severity: 'high',
            title: 'PDA seeds from user input without validation',
            description: 'User-controlled seeds could lead to unexpected PDA derivation.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Validate user-provided seed data before PDA derivation.',
          });
        }
      }

      // Pattern 3: invoke_signed with dynamic seeds
      if (line.includes('invoke_signed')) {
        const contextStart = Math.max(0, index - 10);
        const context = lines.slice(contextStart, index + 5).join('\n');

        if (context.includes('vec!') || context.includes('.push(')) {
          findings.push({
            id: `SOL050-${findings.length + 1}`,
            pattern: 'Program-Derived Signing Issue',
            severity: 'high',
            title: 'Dynamic seed construction for signing',
            description: 'Seeds built dynamically. Ensure resulting PDA is validated.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Verify dynamically constructed seeds match expected PDA.',
          });
        }
      }

      // Pattern 4: Multiple PDAs with similar seeds
      if (line.includes('find_program_address')) {
        const fnStart = Math.max(0, index - 30);
        const fnContext = lines.slice(fnStart, index + 1).join('\n');
        const pdaCount = (fnContext.match(/find_program_address/g) || []).length;

        if (pdaCount > 2) {
          findings.push({
            id: `SOL050-${findings.length + 1}`,
            pattern: 'Program-Derived Signing Issue',
            severity: 'low',
            title: 'Multiple PDA derivations in function',
            description: 'Many PDAs derived. Ensure seeds are distinct to avoid collision.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Use distinct seed prefixes for different PDA types.',
          });
        }
      }
    });
  }

  return findings;
}
