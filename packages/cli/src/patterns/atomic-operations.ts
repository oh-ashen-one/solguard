import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL099: Atomic Operations
 * Detects issues with operation atomicity and partial execution
 */
export function checkAtomicOperations(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rust = input.rust;

  if (!rust || !rust.content) return findings;

  // Check for multiple state changes
  const stateChanges = (rust.content.match(/\.try_borrow_mut|mut\s+\w+\s*=/g) || []).length;
  if (stateChanges > 3) {
    // Check if there's error handling between changes
    if (!rust.content.includes('?') || rust.content.indexOf('?') > rust.content.lastIndexOf('borrow_mut')) {
      findings.push({
        id: 'SOL099',
        severity: 'high',
        title: 'Multiple State Changes Without Atomicity',
        description: `${stateChanges} state changes - partial execution may leave inconsistent state`,
        location: input.path,
        recommendation: 'Validate all conditions before any state changes, or use transactions',
      });
    }
  }

  // Check for CPI between state changes
  const cpiPattern = /\.try_borrow_mut[\s\S]*?invoke[\s\S]*?\.try_borrow_mut/;
  if (cpiPattern.test(rust.content)) {
    findings.push({
      id: 'SOL099',
      severity: 'high',
      title: 'CPI Between State Changes',
      description: 'CPI call between local state changes - reentrancy risk',
      location: input.path,
      recommendation: 'Complete all local state changes before CPI, or after',
    });
  }

  // Check for early return after partial changes
  const earlyReturn = /\.try_borrow_mut[\s\S]*?return\s+(?:Ok|Err)/;
  if (earlyReturn.test(rust.content)) {
    findings.push({
      id: 'SOL099',
      severity: 'medium',
      title: 'Early Return After State Change',
      description: 'Returning after partial state modification may be intentional or bug',
      location: input.path,
      recommendation: 'Verify early returns are safe and state is consistent',
    });
  }

  return findings;
}
