import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL138: Program Migration Security
 * Detects vulnerabilities during program upgrades and data migrations
 * 
 * Risks include:
 * - State corruption during migration
 * - Breaking changes in account structure
 * - Unauthorized upgrades
 */
export function checkProgramMigration(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rust = input.rust;
  if (!rust) return findings;

  const content = rust.content;
  const lines = content.split('\n');

  lines.forEach((line, i) => {
    // Check for version field in accounts
    if (/struct\s+\w+\s*\{/i.test(line)) {
      const structContent = lines.slice(i, Math.min(lines.length, i + 20)).join('\n');
      const structEnd = structContent.indexOf('}');
      const structBody = structContent.substring(0, structEnd);
      
      if (!/version|schema_version|account_version/i.test(structBody)) {
        findings.push({
          id: 'SOL138',
          name: 'Missing Account Version Field',
          severity: 'medium',
          message: 'Account struct without version field makes migrations difficult',
          location: `${input.path}:${i + 1}`,
          snippet: line.trim(),
          fix: 'Add version: u8 field to support future migrations',
        });
      }
    }

    // Check for migration function safety
    if (/migrate|migration|upgrade.*account/i.test(line)) {
      const nearbyContent = lines.slice(Math.max(0, i - 10), Math.min(lines.length, i + 20)).join('\n');
      
      // Check for version validation
      if (!/old_version|from_version|check.*version/i.test(nearbyContent)) {
        findings.push({
          id: 'SOL138',
          name: 'Migration Version Check Missing',
          severity: 'high',
          message: 'Migration without version check can corrupt already-migrated accounts',
          location: `${input.path}:${i + 1}`,
          snippet: line.trim(),
          fix: 'Validate account version before migration to prevent double-migration',
        });
      }

      // Check for authority validation
      if (!/admin|authority|upgrade_authority/i.test(nearbyContent)) {
        findings.push({
          id: 'SOL138',
          name: 'Migration Authority Missing',
          severity: 'critical',
          message: 'Anyone can call migration function - should be admin only',
          location: `${input.path}:${i + 1}`,
          snippet: line.trim(),
          fix: 'Restrict migration to program upgrade authority',
        });
      }
    }

    // Check for reallocation during migration
    if (/realloc|resize.*account|extend.*space/i.test(line)) {
      const nearbyContent = lines.slice(Math.max(0, i - 5), Math.min(lines.length, i + 5)).join('\n');
      
      if (!/zero_init|zero.*new|memset.*0/i.test(nearbyContent)) {
        findings.push({
          id: 'SOL138',
          name: 'Reallocation Without Zero Init',
          severity: 'high',
          message: 'Account reallocation may expose uninitialized memory',
          location: `${input.path}:${i + 1}`,
          snippet: line.trim(),
          fix: 'Use realloc::zero = true or manually zero new space',
        });
      }
    }

    // Check for feature flags
    if (/feature.*flag|is_enabled|feature_gate/i.test(line)) {
      findings.push({
        id: 'SOL138',
        name: 'Feature Flag Detected',
        severity: 'info',
        message: 'Feature flags help safe rollouts - ensure proper sunset timeline',
        location: `${input.path}:${i + 1}`,
        snippet: line.trim(),
        fix: 'Document feature flag lifecycle and removal plan',
      });
    }
  });

  return findings;
}
