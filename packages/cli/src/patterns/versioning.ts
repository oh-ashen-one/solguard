import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL098: Account Versioning
 * Detects issues with account schema versioning and migrations
 */
export function checkVersioning(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rust = input.rust;

  if (!rust || !rust.content) return findings;

  // Check for version field in account structs
  if (rust.content.includes('#[account]') && rust.content.includes('pub struct')) {
    if (!rust.content.includes('version') && !rust.content.includes('Version')) {
      findings.push({
        id: 'SOL098',
        severity: 'low',
        title: 'Account Without Version Field',
        description: 'Account struct lacks version field for future migrations',
        location: input.path,
        recommendation: 'Add version: u8 field for schema versioning',
      });
    }
  }

  // Check for migration handling
  if (rust.content.includes('version') && rust.content.includes('migrate')) {
    if (!rust.content.includes('match') && !rust.content.includes('if version')) {
      findings.push({
        id: 'SOL098',
        severity: 'medium',
        title: 'Migration Without Version Check',
        description: 'Migration logic without explicit version handling',
        location: input.path,
        recommendation: 'Match on version and migrate appropriately',
      });
    }
  }

  // Check for backwards compatibility
  if (rust.content.includes('realloc') || rust.content.includes('resize')) {
    if (!rust.content.includes('version')) {
      findings.push({
        id: 'SOL098',
        severity: 'medium',
        title: 'Account Resize Without Versioning',
        description: 'Resizing accounts without version tracking',
        location: input.path,
        recommendation: 'Update version when changing account structure',
      });
    }
  }

  return findings;
}
