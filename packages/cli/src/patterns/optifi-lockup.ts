import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL203: Fund Lockup Bug Prevention
 * 
 * Detects patterns that could lead to permanent fund lockups
 * due to programming errors.
 * 
 * Real-world exploit: OptiFi - $661K permanently locked due to
 * accidental program closure.
 */
export function checkOptifiLockup(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const { rust, idl, path } = input;

  if (idl) {
    // Check for close instructions
    const closeInstructions = idl.instructions.filter(ix =>
      ix.name.toLowerCase().includes('close') ||
      ix.name.toLowerCase().includes('destroy') ||
      ix.name.toLowerCase().includes('terminate')
    );

    for (const ix of closeInstructions) {
      findings.push({
        id: 'SOL203',
        severity: 'high',
        title: 'Account/Program Close Function',
        description: `Instruction "${ix.name}" can permanently close accounts - ensure proper fund recovery.`,
        location: { file: path, line: 1 },
        recommendation: 'Verify all funds are withdrawn before closing. Add confirmation requirements.',
      });
    }
  }

  if (!rust) return findings;

  const lockupPatterns = [
    { pattern: /close_account/, desc: 'Account closure' },
    { pattern: /set_buffer.*authority.*None/, desc: 'Removing buffer authority' },
    { pattern: /program.*close/, desc: 'Program closure' },
    { pattern: /self_destruct/i, desc: 'Self destruct' },
  ];

  const lines = rust.content.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    for (const { pattern, desc } of lockupPatterns) {
      if (pattern.test(line)) {
        const context = lines.slice(Math.max(0, i - 10), i + 10).join('\n');
        if (!context.includes('withdraw') && !context.includes('transfer')) {
          findings.push({
            id: 'SOL203',
            severity: 'critical',
            title: 'Fund Lockup Risk',
            description: `${desc} - may permanently lock funds if balance not zero.`,
            location: { file: path, line: i + 1 },
            recommendation: 'Always withdraw all funds before closing accounts. Add balance checks.',
          });
        }
      }
    }
  }

  return findings;
}
