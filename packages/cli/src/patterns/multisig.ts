import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL097: Multisig Security
 * Detects issues in multisig implementations
 */
export function checkMultisig(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rust = input.rust;

  if (!rust || !rust.content) return findings;

  const hasMultisig = rust.content.includes('multisig') ||
                      rust.content.includes('multi_sig') ||
                      rust.content.includes('threshold');

  if (!hasMultisig) return findings;

  // Check for threshold validation
  if (rust.content.includes('threshold')) {
    if (!rust.content.includes('<=') && !rust.content.includes('members')) {
      findings.push({
        id: 'SOL097',
        severity: 'high',
        title: 'Threshold Not Validated Against Members',
        description: 'Threshold may exceed total members count',
        location: input.path,
        recommendation: 'Ensure threshold <= members.len()',
      });
    }
  }

  // Check for duplicate signer detection
  if (!rust.content.includes('unique') && !rust.content.includes('duplicate')) {
    findings.push({
      id: 'SOL097',
      severity: 'critical',
      title: 'No Duplicate Signer Check',
      description: 'Same signer could sign multiple times to reach threshold',
      location: input.path,
      recommendation: 'Track unique signers and reject duplicates',
    });
  }

  // Check for signer removal risks
  if (rust.content.includes('remove') && rust.content.includes('member')) {
    if (!rust.content.includes('threshold')) {
      findings.push({
        id: 'SOL097',
        severity: 'high',
        title: 'Member Removal Without Threshold Adjustment',
        description: 'Removing members may make threshold unreachable',
        location: input.path,
        recommendation: 'Adjust threshold when removing members if needed',
      });
    }
  }

  return findings;
}
