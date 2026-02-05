import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL192: DDoS Protection
 * 
 * Detects patterns vulnerable to denial of service attacks through
 * resource exhaustion or spam transactions.
 * 
 * Real-world exploits: Jito DDoS, Phantom wallet DDoS
 */
export function checkDdosProtection(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const { rust, idl, path } = input;

  if (idl) {
    for (const ix of idl.instructions) {
      // Check for expensive operations without rate limiting
      const accountCount = ix.accounts?.length || 0;
      if (accountCount > 10) {
        findings.push({
          id: 'SOL192',
          severity: 'medium',
          title: 'High Account Count Instruction',
          description: `Instruction "${ix.name}" uses ${accountCount} accounts - may be expensive to spam.`,
          location: { file: path, line: 1 },
          recommendation: 'Consider adding rate limiting or minimum fee requirements.',
        });
      }
    }
  }

  if (!rust) return findings;

  const vulnerablePatterns = [
    { pattern: /loop\s*\{/, desc: 'Unbounded loop' },
    { pattern: /while\s+true/, desc: 'Infinite loop potential' },
    { pattern: /for.*0\.\.n/, desc: 'Variable-length loop' },
    { pattern: /Vec::with_capacity.*input/, desc: 'User-controlled vector allocation' },
    { pattern: /resize.*input/, desc: 'User-controlled resize' },
  ];

  const lines = rust.content.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    for (const { pattern, desc } of vulnerablePatterns) {
      if (pattern.test(line)) {
        const context = lines.slice(i, Math.min(lines.length, i + 10)).join('\n');
        if (!context.includes('max_') && !context.includes('limit')) {
          findings.push({
            id: 'SOL192',
            severity: 'high',
            title: 'DoS via Resource Exhaustion',
            description: `${desc} - could be exploited to exhaust compute units.`,
            location: { file: path, line: i + 1 },
            recommendation: 'Add maximum iteration limits and validate all user-controlled sizes.',
          });
        }
      }
    }
  }

  return findings;
}
