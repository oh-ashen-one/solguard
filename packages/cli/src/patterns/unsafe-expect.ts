import type { Finding } from '../commands/audit.js';
import type { ParsedIdl } from '../parsers/idl.js';
import type { ParsedRust } from '../parsers/rust.js';

/**
 * SOL250: Unsafe expect() and unwrap() Usage
 * Detects patterns that could panic in production
 * Reference: Multiple exploits caused by unexpected panics in error paths
 */
export function checkUnsafeExpect(idl: ParsedIdl | null, rust: ParsedRust | null): Finding[] {
  const findings: Finding[] = [];

  if (rust) {
    for (const fn of rust.functions) {
      const content = fn.body;

      // Check for unwrap() usage
      const unwrapMatches = content.match(/\.unwrap\(\)/g);
      if (unwrapMatches && unwrapMatches.length > 0) {
        findings.push({
          id: 'SOL250',
          severity: 'high',
          title: 'Unsafe unwrap() Usage',
          description: `Found ${unwrapMatches.length} unwrap() call(s). Program will panic if value is None/Err.`,
          location: `Function: ${fn.name}`,
          recommendation: 'Replace unwrap() with proper error handling using ? operator or match statement.',
        });
      }

      // Check for expect() usage with generic messages
      const expectMatches = content.match(/\.expect\s*\(\s*["'][^"']*["']\s*\)/g);
      if (expectMatches) {
        for (const match of expectMatches) {
          const message = match.match(/["']([^"']*)["']/)?.[1] || '';
          if (message.length < 10 || message === 'error' || message === 'failed') {
            findings.push({
              id: 'SOL250',
              severity: 'medium',
              title: 'expect() With Uninformative Message',
              description: `expect() with generic message "${message}". Won't help debugging panics.`,
              location: `Function: ${fn.name}`,
              recommendation: 'Use descriptive expect messages or replace with proper error handling.',
            });
          }
        }
      }

      // Check for panic!() usage
      if (content.includes('panic!')) {
        findings.push({
          id: 'SOL250',
          severity: 'high',
          title: 'Explicit panic!() Usage',
          description: 'Explicit panic!() found. Panics abort the transaction but waste compute units.',
          location: `Function: ${fn.name}`,
          recommendation: 'Return ProgramError instead of panicking. Panics provide worse UX.',
        });
      }

      // Check for unreachable!() usage
      if (content.includes('unreachable!')) {
        findings.push({
          id: 'SOL250',
          severity: 'medium',
          title: 'unreachable!() Usage',
          description: 'unreachable!() found. If this path IS reachable, program will panic.',
          location: `Function: ${fn.name}`,
          recommendation: 'Ensure code path is truly unreachable. Consider returning error instead.',
        });
      }

      // Check for todo!() in production code
      if (content.includes('todo!') || content.includes('unimplemented!')) {
        findings.push({
          id: 'SOL250',
          severity: 'critical',
          title: 'Unimplemented Code Path',
          description: 'todo!() or unimplemented!() found. This code path will panic if reached.',
          location: `Function: ${fn.name}`,
          recommendation: 'Remove todo!() before deployment. Implement or return NotImplemented error.',
        });
      }

      // Check for assert!() without custom message
      const assertMatches = content.match(/assert!\s*\([^,)]+\)/g);
      if (assertMatches && assertMatches.length > 0) {
        findings.push({
          id: 'SOL250',
          severity: 'medium',
          title: 'assert!() Without Message',
          description: `${assertMatches.length} assert!() call(s) without custom error message.`,
          location: `Function: ${fn.name}`,
          recommendation: 'Use assert!(condition, "message") or require! macro with custom error.',
        });
      }

      // Check for indexing that could panic
      const indexMatches = content.match(/\[\s*\d+\s*\]|\[\s*\w+\s*\]/g);
      if (indexMatches && indexMatches.length > 2) {
        if (!content.includes('.get(') && !content.includes('get_unchecked')) {
          findings.push({
            id: 'SOL250',
            severity: 'medium',
            title: 'Array Indexing Without Bounds Check',
            description: 'Direct array indexing detected. Out-of-bounds access will panic.',
            location: `Function: ${fn.name}`,
            recommendation: 'Use .get() for safe indexing or verify bounds before access.',
          });
        }
      }

      // Check for division that could panic
      if (content.includes('/') && !content.includes('checked_div')) {
        if (content.match(/\/\s*\w+/) && !content.includes('/ 0')) {
          findings.push({
            id: 'SOL250',
            severity: 'medium',
            title: 'Division Without Zero Check',
            description: 'Division by variable without checking for zero. Division by zero will panic.',
            location: `Function: ${fn.name}`,
            recommendation: 'Use checked_div() or validate divisor is non-zero before dividing.',
          });
        }
      }

      // Check for Option/Result chains without handling
      if (content.includes('.map(') || content.includes('.and_then(')) {
        if (content.match(/\.(map|and_then)\([^)]+\)\s*\.(unwrap|expect)/)) {
          findings.push({
            id: 'SOL250',
            severity: 'medium',
            title: 'Functional Chain Ending in Unwrap',
            description: 'Option/Result chain ends with unwrap(). The entire chain could fail.',
            location: `Function: ${fn.name}`,
            recommendation: 'Use ? operator instead of unwrap() at end of chain, or handle None/Err case.',
          });
        }
      }

      // Check for safe patterns (positive finding)
      if (content.includes('.ok_or(') || content.includes('.ok_or_else(') ||
          content.includes('.map_err(') || content.includes('?')) {
        // Good error handling detected - no finding needed
      } else if (content.includes('Result') || content.includes('Option')) {
        findings.push({
          id: 'SOL250',
          severity: 'low',
          title: 'Result/Option Without Error Propagation',
          description: 'Result/Option types used without ? operator for error propagation.',
          location: `Function: ${fn.name}`,
          recommendation: 'Use ? operator to propagate errors. Convert errors with map_err() if needed.',
        });
      }
    }
  }

  return findings;
}
