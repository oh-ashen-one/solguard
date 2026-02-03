import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL122: Account Close Destination
 * Detects issues with where closed account lamports go
 */
export function checkAccountCloseDestination(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rust = input.rust;

  if (!rust || !rust.content) return findings;

  if (!rust.content.includes('close')) return findings;

  // Check for close to system account
  if (rust.content.includes('close') && rust.content.includes('system_program')) {
    findings.push({
      id: 'SOL122',
      severity: 'high',
      title: 'Close to System Program',
      description: 'Closing account to system program loses lamports permanently',
      location: input.path,
      recommendation: 'Close to a user-controlled account instead',
    });
  }

  // Check for close without destination validation
  if (rust.content.includes('close =') && !rust.content.includes('has_one')) {
    findings.push({
      id: 'SOL122',
      severity: 'medium',
      title: 'Close Destination Not Constrained',
      description: 'Close destination not validated with has_one',
      location: input.path,
      recommendation: 'Add has_one constraint to validate close destination',
    });
  }

  return findings;
}
