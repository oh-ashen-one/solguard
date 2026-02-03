import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL051: Account Size Vulnerabilities
 * Issues with account space allocation and reallocation.
 */
export function checkAccountSize(input: PatternInput): Finding[] {
  const findings: Finding[] = [];

  if (!input.rust || !input.rust.files) return findings;

  for (const file of input.rust.files) {
    const lines = file.lines;

    lines.forEach((line, index) => {
      const lineNum = index + 1;

      // Pattern 1: Hardcoded small space that may overflow
      if (line.includes('space =') || line.includes('space:')) {
        const spaceMatch = line.match(/space\s*[=:]\s*(\d+)/);
        if (spaceMatch) {
          const space = parseInt(spaceMatch[1]);
          if (space < 100 && space !== 8) { // 8 is just discriminator
            findings.push({
              id: `SOL051-${findings.length + 1}`,
              pattern: 'Account Size Vulnerability',
              severity: 'medium',
              title: 'Small account space allocation',
              description: `Account space ${space} bytes may be insufficient for future fields.`,
              location: { file: file.path, line: lineNum },
              suggestion: 'Use calculated size: space = 8 + std::mem::size_of::<YourStruct>()',
            });
          }
        }
      }

      // Pattern 2: realloc without checking max size
      if (line.includes('realloc(') || line.includes('.realloc')) {
        const contextStart = Math.max(0, index - 5);
        const context = lines.slice(contextStart, index + 3).join('\n');

        if (!context.includes('MAX') && !context.includes('max') && 
            !context.includes('<=') && !context.includes('limit')) {
          findings.push({
            id: `SOL051-${findings.length + 1}`,
            pattern: 'Account Size Vulnerability',
            severity: 'high',
            title: 'Account realloc without size limit',
            description: 'Realloc without maximum bound could grow account indefinitely.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Add maximum: let new_size = std::cmp::min(requested, MAX_SIZE)',
          });
        }
      }

      // Pattern 3: Vec in account without size consideration
      if (line.includes('Vec<') && (line.includes('pub') || line.includes(':'))) {
        const contextStart = Math.max(0, index - 5);
        const context = lines.slice(contextStart, index + 1).join('\n');

        if (context.includes('#[account') || context.includes('struct')) {
          findings.push({
            id: `SOL051-${findings.length + 1}`,
            pattern: 'Account Size Vulnerability',
            severity: 'medium',
            title: 'Dynamic Vec in account structure',
            description: 'Vec in account requires careful space management and realloc.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Consider fixed-size array or implement proper realloc logic.',
          });
        }
      }
    });
  }

  return findings;
}
