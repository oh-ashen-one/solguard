import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL307: Checked Math Validation
 * Comprehensive detection of unsafe arithmetic operations
 * Real-world: BlockSec rBPF integer overflow, numerous overflow exploits
 */
export function checkCheckedMathValidation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];

  if (input.rust?.content) {
    const content = input.rust.content;
    const lines = content.split('\n');

    // Track if we're in an unsafe block
    let inUnsafe = false;
    let unsafeDepth = 0;

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];

      // Track unsafe blocks
      if (line.includes('unsafe {')) {
        inUnsafe = true;
        unsafeDepth = 1;
      }
      if (inUnsafe) {
        unsafeDepth += (line.match(/\{/g) || []).length - (line.match(/\}/g) || []).length;
        if (unsafeDepth <= 0) inUnsafe = false;
      }

      // Skip comments
      if (line.trim().startsWith('//') || line.trim().startsWith('*')) continue;

      // Check for raw arithmetic operators (not in comparisons)
      const arithmeticMatch = line.match(/(\w+)\s*([+\-*\/])\s*(\w+)/);
      if (arithmeticMatch && !line.includes('==') && !line.includes('!=') && 
          !line.includes('<=') && !line.includes('>=') && !line.includes('//')) {
        
        const [, left, op, right] = arithmeticMatch;
        
        // Skip if it's a checked operation
        if (line.includes('checked_') || line.includes('saturating_') || 
            line.includes('wrapping_') || line.includes('overflowing_')) {
          continue;
        }

        // Skip obvious non-numeric operations
        if (left.match(/^(str|String|Vec|&)/) || right.match(/^(str|String|Vec|&)/)) {
          continue;
        }

        // Determine severity based on context
        const isHighRisk = /amount|balance|price|value|fee|reward|stake|deposit/i.test(line);
        const isMediumRisk = /count|index|len|size|total/i.test(line);

        if (isHighRisk) {
          findings.push({
            id: 'SOL307',
            title: 'Unchecked Financial Arithmetic',
            severity: 'critical',
            description: `Unchecked ${op} operation on financial value can overflow/underflow.`,
            location: { file: input.path, line: i + 1 },
            suggestion: `Use checked: ${left}.checked_${op === '+' ? 'add' : op === '-' ? 'sub' : op === '*' ? 'mul' : 'div'}(${right}).ok_or(MathError)?`,
            cwe: op === '+' || op === '*' ? 'CWE-190' : 'CWE-191',
          });
        } else if (isMediumRisk) {
          findings.push({
            id: 'SOL307',
            title: 'Unchecked Arithmetic',
            severity: 'high',
            description: `Unchecked ${op} operation can overflow/underflow.`,
            location: { file: input.path, line: i + 1 },
            suggestion: `Use checked: ${left}.checked_${op === '+' ? 'add' : op === '-' ? 'sub' : op === '*' ? 'mul' : 'div'}(${right}).unwrap_or_default()`,
            cwe: op === '+' || op === '*' ? 'CWE-190' : 'CWE-191',
          });
        }
      }

      // Check for type casting without validation
      if (line.includes(' as ') && !line.includes('// safe')) {
        const castMatch = line.match(/(\w+)\s+as\s+(u\d+|i\d+|usize|isize)/);
        if (castMatch) {
          const [, , targetType] = castMatch;
          
          // Downcasting is dangerous
          const sizes: Record<string, number> = { u8: 8, u16: 16, u32: 32, u64: 64, u128: 128, usize: 64 };
          const sourceMatch = line.match(/(u\d+|i\d+|usize)/);
          
          if (sourceMatch && sizes[sourceMatch[1]] > (sizes[targetType] || 64)) {
            findings.push({
              id: 'SOL307',
              title: 'Unsafe Downcast',
              severity: 'high',
              description: `Casting to smaller type ${targetType} can truncate value.`,
              location: { file: input.path, line: i + 1 },
              suggestion: `Use try_into: let val: ${targetType} = big_val.try_into().map_err(|_| ErrorCode::Overflow)?`,
              cwe: 'CWE-681',
            });
          }
        }
      }

      // Check for power operations
      if (line.includes('.pow(') && !line.includes('checked_pow') && !line.includes('saturating_pow')) {
        findings.push({
          id: 'SOL307',
          title: 'Unchecked Power Operation',
          severity: 'high',
          description: 'Exponentiation can quickly overflow.',
          location: { file: input.path, line: i + 1 },
          suggestion: 'Use checked_pow: base.checked_pow(exp).ok_or(MathError)?',
          cwe: 'CWE-190',
        });
      }

      // Check for shift operations
      if ((line.includes('<<') || line.includes('>>')) && !line.includes('checked_')) {
        findings.push({
          id: 'SOL307',
          title: 'Unchecked Bit Shift',
          severity: 'medium',
          description: 'Bit shifts with large values can overflow or produce unexpected results.',
          location: { file: input.path, line: i + 1 },
          suggestion: 'Use checked_shl/checked_shr: val.checked_shl(bits).ok_or(ShiftError)?',
          cwe: 'CWE-190',
        });
      }

      // Check for division by potentially zero value
      if (line.includes('/') && !line.includes('//') && !line.includes('checked_div')) {
        const divMatch = line.match(/\/\s*(\w+)/);
        if (divMatch) {
          const divisor = divMatch[1];
          // Check if divisor is validated nearby
          const nearbyLines = lines.slice(Math.max(0, i - 5), i).join('\n');
          if (!nearbyLines.includes(`${divisor} != 0`) && !nearbyLines.includes(`${divisor} > 0`) &&
              !nearbyLines.includes(`${divisor} == 0`)) {
            findings.push({
              id: 'SOL307',
              title: 'Potential Division by Zero',
              severity: 'high',
              description: 'Division without zero-check on divisor.',
              location: { file: input.path, line: i + 1 },
              suggestion: `Validate divisor: require!(${divisor} > 0, DivisionByZero); or use checked_div`,
              cwe: 'CWE-369',
            });
          }
        }
      }
    }

    // Global check: ensure overflow-checks is enabled
    if (!content.includes('overflow-checks') && !content.includes('#![deny(arithmetic_overflow)]')) {
      findings.push({
        id: 'SOL307',
        title: 'No Overflow Protection Configured',
        severity: 'medium',
        description: 'Consider enabling overflow-checks in Cargo.toml for additional safety.',
        location: { file: input.path, line: 1 },
        suggestion: 'Add to Cargo.toml: [profile.release] overflow-checks = true',
        cwe: 'CWE-190',
      });
    }
  }

  return findings;
}
