import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL036: Input Validation Issues
 * Missing or inadequate input parameter validation.
 */
export function checkInputValidation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];

  if (!input.rust || !input.rust.files) return findings;

  for (const file of input.rust.files) {
    const lines = file.lines;

    lines.forEach((line, index) => {
      const lineNum = index + 1;

      // Pattern 1: Amount parameter without zero check
      if (line.includes('amount:') && (line.includes('u64') || line.includes('u128'))) {
        const fnEnd = Math.min(lines.length, index + 20);
        const fnBody = lines.slice(index, fnEnd).join('\n');

        if (!fnBody.includes('amount > 0') && !fnBody.includes('amount != 0') &&
            !fnBody.includes('require!') && !fnBody.includes('> 0')) {
          findings.push({
            id: `SOL036-${findings.length + 1}`,
            pattern: 'Input Validation Issues',
            severity: 'medium',
            title: 'Amount parameter without zero check',
            description: 'Amount parameter accepted without validation. Zero amounts may cause unexpected behavior.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Add validation: require!(amount > 0, MyError::InvalidAmount)',
          });
        }
      }

      // Pattern 2: Array/slice index without bounds check
      if (line.match(/\[\s*\w+\s*\]/) && !line.includes('.get(') && !line.includes('.get_mut(')) {
        if (line.includes('args.') || line.includes('input.') || line.includes('data[')) {
          const contextStart = Math.max(0, index - 3);
          const context = lines.slice(contextStart, index + 1).join('\n');

          if (!context.includes('.len()') && !context.includes('< ') && !context.includes('require!')) {
            findings.push({
              id: `SOL036-${findings.length + 1}`,
              pattern: 'Input Validation Issues',
              severity: 'high',
              title: 'Array access without bounds check',
              description: 'Direct array indexing may panic on out-of-bounds access.',
              location: { file: file.path, line: lineNum },
              suggestion: 'Use .get() with proper error handling, or validate index < array.len()',
            });
          }
        }
      }

      // Pattern 3: Percentage/basis points without range check
      if (line.includes('percentage') || line.includes('basis_points') || line.includes('bps')) {
        const contextEnd = Math.min(lines.length, index + 10);
        const context = lines.slice(index, contextEnd).join('\n');

        if (!context.includes('<= 100') && !context.includes('<= 10000') && 
            !context.includes('MAX') && !context.includes('require!')) {
          findings.push({
            id: `SOL036-${findings.length + 1}`,
            pattern: 'Input Validation Issues',
            severity: 'medium',
            title: 'Percentage/BPS without range validation',
            description: 'Percentage values should be bounded (e.g., <= 100% or <= 10000 bps).',
            location: { file: file.path, line: lineNum },
            suggestion: 'Add range check: require!(bps <= 10000, MyError::InvalidPercentage)',
          });
        }
      }

      // Pattern 4: Pubkey parameter without validation
      if (line.includes('Pubkey') && line.includes('args.')) {
        const contextEnd = Math.min(lines.length, index + 10);
        const context = lines.slice(index, contextEnd).join('\n');

        if (!context.includes('!= Pubkey::default()') && !context.includes('system_program::ID') &&
            !context.includes('require!')) {
          findings.push({
            id: `SOL036-${findings.length + 1}`,
            pattern: 'Input Validation Issues',
            severity: 'low',
            title: 'Pubkey parameter without default check',
            description: 'Pubkey from args may be default (all zeros). Could cause unexpected behavior.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Validate pubkey: require!(key != Pubkey::default())',
          });
        }
      }
    });
  }

  return findings;
}
