import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL093: Address Lookup Table Security
 * Detects issues with ALT usage and validation
 */
export function checkLookupTable(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rust = input.rust;

  if (!rust || !rust.content) return findings;

  const hasAlt = rust.content.includes('AddressLookupTable') ||
                 rust.content.includes('lookup_table') ||
                 rust.content.includes('LookupTable');

  if (!hasAlt) return findings;

  // Check for ALT validation
  if (rust.content.includes('lookup_table')) {
    if (!rust.content.includes('authority') && !rust.content.includes('owner')) {
      findings.push({
        id: 'SOL093',
        severity: 'high',
        title: 'Lookup Table Without Authority Check',
        description: 'Using ALT without verifying its authority/ownership',
        location: input.path,
        recommendation: 'Verify lookup table authority before using addresses',
      });
    }
  }

  // Check for deactivated ALT handling
  if (rust.content.includes('DeactivationSlot')) {
    findings.push({
      id: 'SOL093',
      severity: 'medium',
      title: 'ALT Deactivation Handling',
      description: 'Ensure program handles deactivated lookup tables gracefully',
      location: input.path,
      recommendation: 'Check if ALT is active before use',
    });
  }

  // Check for ALT in CPI
  if (rust.content.includes('invoke') && hasAlt) {
    findings.push({
      id: 'SOL093',
      severity: 'low',
      title: 'ALT With CPI',
      description: 'Using ALT with CPI - ensure accounts are properly resolved',
      location: input.path,
      recommendation: 'ALT addresses are resolved client-side, not in CPI',
    });
  }

  return findings;
}
