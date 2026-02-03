import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL053: Account Order Dependencies
 * Issues with account ordering and indexing assumptions.
 */
export function checkAccountOrder(input: PatternInput): Finding[] {
  const findings: Finding[] = [];

  if (!input.rust || !input.rust.files) return findings;

  for (const file of input.rust.files) {
    const lines = file.lines;

    lines.forEach((line, index) => {
      const lineNum = index + 1;

      // Pattern 1: Hardcoded account index
      if (line.match(/accounts\[\d+\]/) || line.match(/remaining_accounts\[\d+\]/)) {
        findings.push({
          id: `SOL053-${findings.length + 1}`,
          pattern: 'Account Order Dependency',
          severity: 'medium',
          title: 'Hardcoded account array index',
          description: 'Fixed index assumes specific account order. Could break with changes.',
          location: { file: file.path, line: lineNum },
          suggestion: 'Use named accounts or validate account at index matches expected type.',
        });
      }

      // Pattern 2: remaining_accounts iteration without validation
      if (line.includes('remaining_accounts') && 
          (line.includes('iter()') || line.includes('for'))) {
        const contextEnd = Math.min(lines.length, index + 15);
        const context = lines.slice(index, contextEnd).join('\n');

        if (!context.includes('owner') && !context.includes('key') && 
            !context.includes('check')) {
          findings.push({
            id: `SOL053-${findings.length + 1}`,
            pattern: 'Account Order Dependency',
            severity: 'high',
            title: 'Iterating remaining_accounts without validation',
            description: 'Processing remaining accounts without validating each one.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Validate owner/type of each account before processing.',
          });
        }
      }

      // Pattern 3: Account slice assumptions
      if (line.includes('..') && line.includes('accounts')) {
        findings.push({
          id: `SOL053-${findings.length + 1}`,
          pattern: 'Account Order Dependency',
          severity: 'medium',
          title: 'Account slice operation',
          description: 'Slicing accounts assumes specific count/order.',
          location: { file: file.path, line: lineNum },
          suggestion: 'Validate account count and types when using slices.',
        });
      }
    });
  }

  return findings;
}
