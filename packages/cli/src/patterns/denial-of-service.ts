import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL035: Denial of Service Vulnerabilities
 * Patterns that could allow DoS attacks.
 */
export function checkDenialOfService(input: PatternInput): Finding[] {
  const findings: Finding[] = [];

  if (!input.rust || !input.rust.files) return findings;

  for (const file of input.rust.files) {
    const lines = file.lines;

    lines.forEach((line, index) => {
      const lineNum = index + 1;

      // Pattern 1: Unbounded loops
      if (line.includes('for') || line.includes('while')) {
        const loopMatch = line.match(/for\s+\w+\s+in\s+(.+?)\s*\{/) ||
                         line.match(/while\s+(.+?)\s*\{/);
        
        if (loopMatch) {
          const contextStart = Math.max(0, index - 5);
          const context = lines.slice(contextStart, index + 1).join('\n');

          // Check if loop bound is validated
          if (!context.includes('MAX') && !context.includes('max') && 
              !context.includes('limit') && !context.includes('..')) {
            if (context.includes('.len()') || context.includes('.iter()')) {
              findings.push({
                id: `SOL035-${findings.length + 1}`,
                pattern: 'Denial of Service',
                severity: 'high',
                title: 'Potentially unbounded loop',
                description: 'Loop iterates over collection without explicit size limit. Could exceed compute budget.',
                location: { file: file.path, line: lineNum },
                suggestion: 'Add maximum iteration limit: for item in collection.iter().take(MAX_ITEMS)',
              });
            }
          }
        }
      }

      // Pattern 2: Vec without capacity limit on push
      if (line.includes('.push(') || line.includes('vec!')) {
        const contextStart = Math.max(0, index - 10);
        const context = lines.slice(contextStart, index + 3).join('\n');

        if (!context.includes('MAX') && !context.includes('capacity') && 
            !context.includes('with_capacity') && !context.includes('len()')) {
          if (context.includes('loop') || context.includes('for') || context.includes('while')) {
            findings.push({
              id: `SOL035-${findings.length + 1}`,
              pattern: 'Denial of Service',
              severity: 'medium',
              title: 'Unbounded vector growth in loop',
              description: 'Vector grows in loop without size limit. Could cause memory exhaustion.',
              location: { file: file.path, line: lineNum },
              suggestion: 'Add capacity check: require!(vec.len() < MAX_SIZE)',
            });
          }
        }
      }

      // Pattern 3: External call in loop (amplification)
      if ((line.includes('invoke') || line.includes('transfer')) && 
          (line.includes('for') || line.includes('while') || 
           lines.slice(Math.max(0, index - 10), index).join('\n').includes('for'))) {
        findings.push({
          id: `SOL035-${findings.length + 1}`,
          pattern: 'Denial of Service',
          severity: 'high',
          title: 'CPI/transfer in loop',
          description: 'External calls in loop multiply compute cost. Could exceed transaction limits.',
          location: { file: file.path, line: lineNum },
          suggestion: 'Batch operations or limit iterations. Consider pull-over-push pattern.',
        });
      }

      // Pattern 4: Account realloc in hot path
      if (line.includes('realloc') && !line.includes('MAX')) {
        findings.push({
          id: `SOL035-${findings.length + 1}`,
          pattern: 'Denial of Service',
          severity: 'medium',
          title: 'Account reallocation without size limit',
          description: 'Account realloc without maximum size could be exploited for DoS.',
          location: { file: file.path, line: lineNum },
          suggestion: 'Add maximum size: realloc(min(new_size, MAX_SIZE), ...)',
        });
      }

      // Pattern 5: String/bytes from user without length check
      if (line.includes('String') || line.includes('Vec<u8>')) {
        if (line.includes('args.') || line.includes('params.') || line.includes('input')) {
          const contextStart = Math.max(0, index - 3);
          const context = lines.slice(contextStart, index + 3).join('\n');

          if (!context.includes('.len()') && !context.includes('MAX') && !context.includes('limit')) {
            findings.push({
              id: `SOL035-${findings.length + 1}`,
              pattern: 'Denial of Service',
              severity: 'medium',
              title: 'Unbounded user input',
              description: 'String/bytes from user input without length validation.',
              location: { file: file.path, line: lineNum },
              suggestion: 'Validate input length: require!(input.len() <= MAX_INPUT_SIZE)',
            });
          }
        }
      }
    });
  }

  return findings;
}
