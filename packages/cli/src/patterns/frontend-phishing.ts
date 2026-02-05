import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL191: Frontend Phishing/Hijacking
 * 
 * Detects patterns that could indicate frontend vulnerabilities
 * leading to phishing or transaction manipulation.
 * 
 * Real-world exploit: Parcl Front-End - compromised frontend
 * led to malicious transaction signing.
 */
export function checkFrontendPhishing(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const { rust, path } = input;

  if (!rust) return findings;

  const vulnerablePatterns = [
    { pattern: /window\.solana/i, desc: 'Direct wallet access' },
    { pattern: /signTransaction.*auto/i, desc: 'Auto transaction signing' },
    { pattern: /signAllTransactions/i, desc: 'Batch transaction signing' },
    { pattern: /localStorage.*wallet/i, desc: 'Wallet data in localStorage' },
    { pattern: /postMessage.*wallet/i, desc: 'Cross-origin wallet communication' },
  ];

  const lines = rust.content.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    for (const { pattern, desc } of vulnerablePatterns) {
      if (pattern.test(line)) {
        findings.push({
          id: 'SOL191',
          severity: 'high',
          title: 'Frontend Security Concern',
          description: `${desc} - ensure proper validation and user confirmation for all transactions.`,
          location: { file: path, line: i + 1 },
          recommendation: 'Always show transaction simulation to users. Implement Content Security Policy.',
        });
      }
    }
  }

  return findings;
}
