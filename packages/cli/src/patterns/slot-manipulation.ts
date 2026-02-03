import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL095: Slot Number Manipulation
 * Detects risky slot-based logic
 */
export function checkSlotManipulation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rust = input.rust;

  if (!rust || !rust.content) return findings;

  const hasSlot = rust.content.includes('slot') || rust.content.includes('Slot');
  if (!hasSlot) return findings;

  // Check for slot equality comparison
  const slotEquality = /slot\s*==\s*\d+|slot\s*==\s*\w+/i;
  if (slotEquality.test(rust.content)) {
    findings.push({
      id: 'SOL095',
      severity: 'high',
      title: 'Exact Slot Comparison',
      description: 'Checking for exact slot number - may never match',
      location: input.path,
      recommendation: 'Use range comparisons (>= slot) instead of equality',
    });
  }

  // Check for slot arithmetic
  if (rust.content.includes('slot') && (rust.content.includes('+') || rust.content.includes('-'))) {
    if (!rust.content.includes('checked_') && !rust.content.includes('saturating_')) {
      findings.push({
        id: 'SOL095',
        severity: 'medium',
        title: 'Unchecked Slot Arithmetic',
        description: 'Slot arithmetic without overflow protection',
        location: input.path,
        recommendation: 'Use checked_add/checked_sub for slot calculations',
      });
    }
  }

  // Check for slot-based randomness
  if (rust.content.includes('slot') && 
      (rust.content.includes('random') || rust.content.includes('%') || rust.content.includes('hash'))) {
    findings.push({
      id: 'SOL095',
      severity: 'critical',
      title: 'Slot Used for Randomness',
      description: 'Slot numbers are predictable and should not be used for randomness',
      location: input.path,
      recommendation: 'Use VRF or Switchboard for secure randomness',
    });
  }

  return findings;
}
