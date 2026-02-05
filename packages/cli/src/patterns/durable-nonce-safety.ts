import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL194: Durable Nonce Safety
 * 
 * Detects potential issues with durable nonce usage that could
 * lead to transaction replay or stuck transactions.
 * 
 * Real-world vulnerability: Solana Durable Nonce Bug
 */
export function checkDurableNonceSafety(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const { rust, idl, path } = input;

  if (idl) {
    for (const ix of idl.instructions) {
      const hasNonceAccount = ix.accounts?.some(acc =>
        acc.name.toLowerCase().includes('nonce')
      );

      if (hasNonceAccount) {
        findings.push({
          id: 'SOL194',
          severity: 'medium',
          title: 'Durable Nonce Usage',
          description: `Instruction "${ix.name}" uses durable nonce - ensure proper nonce advancement.`,
          location: { file: path, line: 1 },
          recommendation: 'Always advance nonce after use. Handle nonce account validation properly.',
        });
      }
    }
  }

  if (!rust) return findings;

  const noncePatterns = [
    { pattern: /durable_nonce/, desc: 'Durable nonce usage' },
    { pattern: /nonce_account/, desc: 'Nonce account reference' },
    { pattern: /advance_nonce/, desc: 'Nonce advancement' },
  ];

  const lines = rust.content.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    for (const { pattern, desc } of noncePatterns) {
      if (pattern.test(line)) {
        findings.push({
          id: 'SOL194',
          severity: 'low',
          title: 'Durable Nonce Pattern',
          description: `${desc} - verify nonce is properly advanced and validated.`,
          location: { file: path, line: i + 1 },
          recommendation: 'Ensure nonce advancement is atomic with the main operation.',
        });
      }
    }
  }

  return findings;
}
