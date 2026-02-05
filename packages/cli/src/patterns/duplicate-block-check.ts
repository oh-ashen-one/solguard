import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL195: Duplicate Block/Slot Assumptions
 * 
 * Detects assumptions about slot uniqueness that could be
 * violated during network partitions or duplicate block scenarios.
 * 
 * Real-world vulnerability: Solana Duplicate Block Bug
 */
export function checkDuplicateBlockCheck(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const { rust, path } = input;

  if (!rust) return findings;

  const riskyPatterns = [
    { pattern: /slot.*unique/, desc: 'Assumption of slot uniqueness' },
    { pattern: /block_hash.*cache/, desc: 'Block hash caching' },
    { pattern: /recent_blockhash.*permanent/, desc: 'Permanent blockhash storage' },
  ];

  const lines = rust.content.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    for (const { pattern, desc } of riskyPatterns) {
      if (pattern.test(line)) {
        findings.push({
          id: 'SOL195',
          severity: 'medium',
          title: 'Block/Slot Uniqueness Assumption',
          description: `${desc} - may fail during network partitions.`,
          location: { file: path, line: i + 1 },
          recommendation: 'Do not assume slot/block uniqueness. Handle potential duplicates gracefully.',
        });
      }
    }
  }

  return findings;
}
