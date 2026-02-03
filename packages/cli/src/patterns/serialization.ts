import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL054: Serialization Vulnerabilities
 * Issues with data serialization and deserialization.
 */
export function checkSerialization(input: PatternInput): Finding[] {
  const findings: Finding[] = [];

  if (!input.rust || !input.rust.files) return findings;

  for (const file of input.rust.files) {
    const lines = file.lines;

    lines.forEach((line, index) => {
      const lineNum = index + 1;

      // Pattern 1: Unchecked deserialization
      if (line.includes('try_from_slice') || line.includes('deserialize')) {
        if (!line.includes('?') && !line.includes('unwrap_or') && 
            !line.includes('map_err')) {
          findings.push({
            id: `SOL054-${findings.length + 1}`,
            pattern: 'Serialization Vulnerability',
            severity: 'medium',
            title: 'Deserialization without error handling',
            description: 'Deserialization may fail on malformed data.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Handle deserialization errors: data.try_from_slice()?.into()',
          });
        }
      }

      // Pattern 2: Direct byte manipulation
      if (line.includes('data.borrow_mut()') || line.includes('&mut data[')) {
        const contextStart = Math.max(0, index - 5);
        const context = lines.slice(contextStart, index + 3).join('\n');

        if (!context.includes('len()') && !context.includes('size_of')) {
          findings.push({
            id: `SOL054-${findings.length + 1}`,
            pattern: 'Serialization Vulnerability',
            severity: 'high',
            title: 'Direct byte manipulation without size check',
            description: 'Writing bytes without verifying buffer size.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Verify data length before writing: require!(data.len() >= SIZE)',
          });
        }
      }

      // Pattern 3: Borsh without validation
      if (line.includes('BorshDeserialize') && !line.includes('BorshSchema')) {
        // Check if struct has validation
        const contextEnd = Math.min(lines.length, index + 20);
        const context = lines.slice(index, contextEnd).join('\n');

        if (!context.includes('validate') && !context.includes('is_valid')) {
          findings.push({
            id: `SOL054-${findings.length + 1}`,
            pattern: 'Serialization Vulnerability',
            severity: 'low',
            title: 'Borsh deserialization without post-validation',
            description: 'Deserialized data not validated. Malformed data could pass.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Add validation method and call after deserialization.',
          });
        }
      }
    });
  }

  return findings;
}
