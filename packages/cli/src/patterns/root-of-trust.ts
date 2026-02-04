import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL147: Root of Trust Establishment
 * Detects missing or weak root of trust validation
 * Real-world: Cashio exploit ($52M) - failed to establish proper root of trust
 */
export function checkRootOfTrust(input: PatternInput): Finding[] {
  const findings: Finding[] = [];

  if (input.rust?.content) {
    const content = input.rust.content;
    const lines = content.split('\n');

    // Check for patterns that need root of trust
    const trustPatterns = [
      /collateral|backing|reserve/i,
      /mint_to|token::mint/i,
      /oracle|price_feed/i,
      /validator|authority/i,
    ];

    const needsTrust = trustPatterns.some(p => p.test(content));

    if (needsTrust) {
      // Check for proper account chain validation
      if (content.includes('collateral') || content.includes('backing')) {
        if (!content.includes('validate') && !content.includes('verify_chain')) {
          findings.push({
            id: 'SOL147',
            title: 'Missing Collateral Validation Chain',
            severity: 'critical',
            description: 'Collateral accounts must validate the entire ownership chain back to a trusted root.',
            location: { file: input.path, line: 1 },
            suggestion: 'Validate chain: verify(crate.collateral) → verify(collateral.pool) → verify(pool.authority == TRUSTED_ROOT)',
            cwe: 'CWE-345',
          });
        }
      }

      // Check for hardcoded trusted accounts
      if (!content.includes('const') || !content.match(/TRUSTED|ROOT|ADMIN/i)) {
        if (content.includes('owner') || content.includes('authority')) {
          findings.push({
            id: 'SOL147',
            title: 'No Hardcoded Root of Trust',
            severity: 'high',
            description: 'Establish root of trust with compile-time constant addresses.',
            location: { file: input.path, line: 1 },
            suggestion: 'Define trusted roots: pub const TRUSTED_ORACLE: Pubkey = pubkey!("...");',
            cwe: 'CWE-345',
          });
        }
      }

      // Check for oracle source validation
      if (content.includes('oracle') || content.includes('price')) {
        if (!content.includes('oracle_program') && !content.includes('oracle_source')) {
          findings.push({
            id: 'SOL147',
            title: 'Unvalidated Oracle Source',
            severity: 'critical',
            description: 'Oracle data must be validated as coming from a trusted oracle program.',
            location: { file: input.path, line: 1 },
            suggestion: 'Validate oracle: require!(price_account.owner == &PYTH_PROGRAM_ID || price_account.owner == &SWITCHBOARD_ID)',
            cwe: 'CWE-345',
          });
        }
      }

      // Check for transitive trust without validation
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        // Pattern: accessing nested account without validating intermediate
        if (line.match(/\..*\..*\.key|\..*\..*\.owner/)) {
          findings.push({
            id: 'SOL147',
            title: 'Transitive Trust Without Validation',
            severity: 'high',
            description: 'Accessing nested account properties without validating each level in the chain.',
            location: { file: input.path, line: i + 1 },
            suggestion: 'Validate each level: validate(a) → validate(a.b) → use(a.b.c)',
            cwe: 'CWE-345',
          });
          break;
        }
      }
    }
  }

  return findings;
}
