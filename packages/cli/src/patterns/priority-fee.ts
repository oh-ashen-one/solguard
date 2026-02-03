import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL094: Priority Fee Handling
 * Detects issues with compute unit pricing and priority fees
 */
export function checkPriorityFee(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rust = input.rust;

  if (!rust || !rust.content) return findings;

  // Check for hardcoded compute units
  if (rust.content.includes('request_units') || rust.content.includes('compute_units')) {
    const hardcodedUnits = /request_units\s*\(\s*\d{4,}/;
    if (hardcodedUnits.test(rust.content)) {
      findings.push({
        id: 'SOL094',
        severity: 'low',
        title: 'Hardcoded Compute Units',
        description: 'Compute units are hardcoded - may be insufficient or wasteful',
        location: input.path,
        recommendation: 'Calculate compute units dynamically or make configurable',
      });
    }
  }

  // Check for fee calculations
  if (rust.content.includes('fee') && rust.content.includes('lamports')) {
    if (!rust.content.includes('checked_') && !rust.content.includes('saturating_')) {
      findings.push({
        id: 'SOL094',
        severity: 'medium',
        title: 'Unchecked Fee Calculation',
        description: 'Fee calculation without overflow protection',
        location: input.path,
        recommendation: 'Use checked arithmetic for fee calculations',
      });
    }
  }

  // Check for priority fee extraction
  if (rust.content.includes('priority') && rust.content.includes('fee')) {
    if (rust.content.includes('take') || rust.content.includes('extract')) {
      findings.push({
        id: 'SOL094',
        severity: 'medium',
        title: 'Priority Fee Extraction',
        description: 'Program extracts priority fees - ensure proper accounting',
        location: input.path,
        recommendation: 'Track fee extraction and ensure user consent',
      });
    }
  }

  return findings;
}
