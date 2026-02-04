import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL144: Unchecked Account in CPI
 * Detects passing unvalidated accounts to cross-program invocations
 * Real-world: Metaplex Candy Machine exploit, various Anchor programs
 */
export function checkUncheckedAccountCpi(input: PatternInput): Finding[] {
  const findings: Finding[] = [];

  if (input.rust?.content) {
    const content = input.rust.content;
    const lines = content.split('\n');

    // Check for CPI patterns
    const cpiPatterns = [
      /invoke_signed|invoke\(/i,
      /CpiContext|cpi::/i,
      /AccountMeta::new/i,
    ];

    const hasCpi = cpiPatterns.some(p => p.test(content));

    if (hasCpi) {
      // Check for UncheckedAccount in CPI context
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        
        if (line.includes('UncheckedAccount') && !line.includes('/// CHECK')) {
          findings.push({
            id: 'SOL144',
            title: 'Undocumented UncheckedAccount',
            severity: 'high',
            description: 'UncheckedAccount must have /// CHECK documentation explaining why it\'s safe.',
            location: { file: input.path, line: i + 1 },
            suggestion: 'Add documentation: /// CHECK: This account is validated in [explain where/how]',
            cwe: 'CWE-20',
          });
        }
      }

      // Check for AccountInfo passed to CPI without validation
      if (content.includes('AccountInfo') && content.includes('invoke')) {
        if (!content.includes('owner ==') && !content.includes('key() ==')) {
          findings.push({
            id: 'SOL144',
            title: 'Unvalidated Account in CPI',
            severity: 'critical',
            description: 'Accounts passed to CPI must be validated (owner, key, or constraints) before invocation.',
            location: { file: input.path, line: 1 },
            suggestion: 'Validate before CPI: require!(account.owner == &expected_program_id, InvalidAccountOwner)',
            cwe: 'CWE-345',
          });
        }
      }

      // Check for remaining_accounts CPI usage
      if (content.includes('remaining_accounts') && content.includes('invoke')) {
        findings.push({
          id: 'SOL144',
          title: 'Remaining Accounts in CPI',
          severity: 'high',
          description: 'remaining_accounts passed to CPI are dangerous and must be thoroughly validated.',
          location: { file: input.path, line: 1 },
          suggestion: 'Validate each: for acc in remaining_accounts { require!(validate_account(acc), InvalidAccount) }',
          cwe: 'CWE-20',
        });
      }

      // Check for writable accounts in CPI
      if (content.includes('AccountMeta::new(') && !content.includes('is_writable')) {
        for (let i = 0; i < lines.length; i++) {
          if (lines[i].includes('AccountMeta::new(') && lines[i].includes('true')) {
            findings.push({
              id: 'SOL144',
              title: 'Writable Account Without Validation',
              severity: 'high',
              description: 'Writable accounts in CPI must be validated to prevent unauthorized modifications.',
              location: { file: input.path, line: i + 1 },
              suggestion: 'Validate writable accounts before CPI and verify post-CPI state if needed.',
              cwe: 'CWE-284',
            });
            break;
          }
        }
      }
    }
  }

  return findings;
}
