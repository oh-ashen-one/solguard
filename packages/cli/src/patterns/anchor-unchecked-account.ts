import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL149: Anchor Unchecked Account
 * Detects misuse of UncheckedAccount and AccountInfo in Anchor programs
 * Real-world: Candy Machine exploits, Solend malicious market
 */
export function checkAnchorUncheckedAccount(input: PatternInput): Finding[] {
  const findings: Finding[] = [];

  if (input.rust?.content) {
    const content = input.rust.content;
    const lines = content.split('\n');

    // Check for Anchor-specific patterns
    const isAnchor = content.includes('anchor_lang') || content.includes('#[program]') || content.includes('#[account]');

    if (isAnchor) {
      // Track CHECK comments
      let hasCheckComment = false;

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];

        // Track CHECK documentation
        if (line.includes('/// CHECK:') || line.includes('// CHECK:')) {
          hasCheckComment = true;
        }

        // Check for UncheckedAccount without documentation
        if (line.includes('UncheckedAccount') && !hasCheckComment) {
          findings.push({
            id: 'SOL149',
            title: 'UncheckedAccount Without CHECK Documentation',
            severity: 'critical',
            description: 'UncheckedAccount must have /// CHECK: documentation explaining validation.',
            location: { file: input.path, line: i + 1 },
            suggestion: '/// CHECK: Validated in [instruction] by checking [what]. Then: pub unchecked: UncheckedAccount<\'info>',
            cwe: 'CWE-20',
          });
        }

        // Check for AccountInfo in Anchor (should use typed accounts)
        if (line.includes('AccountInfo<\'info>') && !line.includes('remaining_accounts')) {
          if (!hasCheckComment) {
            findings.push({
              id: 'SOL149',
              title: 'Raw AccountInfo in Anchor',
              severity: 'high',
              description: 'Prefer typed accounts over raw AccountInfo in Anchor. If necessary, document why.',
              location: { file: input.path, line: i + 1 },
              suggestion: 'Use typed accounts: Account<\'info, MyAccount> or if raw needed: /// CHECK: reason',
              cwe: 'CWE-20',
            });
          }
        }

        // Reset CHECK tracking after account field
        if (line.includes('pub ') && line.includes(':')) {
          hasCheckComment = false;
        }
      }

      // Check for init without payer
      if (content.includes('#[account(init') && !content.includes('payer')) {
        findings.push({
          id: 'SOL149',
          title: 'Init Without Payer',
          severity: 'high',
          description: 'Account initialization must specify payer.',
          location: { file: input.path, line: 1 },
          suggestion: '#[account(init, payer = user, space = 8 + DataAccount::SIZE)]',
          cwe: 'CWE-20',
        });
      }

      // Check for missing space calculation
      if (content.includes('#[account(init') && !content.includes('space')) {
        findings.push({
          id: 'SOL149',
          title: 'Init Without Space',
          severity: 'critical',
          description: 'Account initialization must specify space to prevent buffer overflows.',
          location: { file: input.path, line: 1 },
          suggestion: '#[account(init, payer = user, space = 8 + size_of::<DataAccount>())]',
          cwe: 'CWE-131',
        });
      }

      // Check for missing seeds in PDA accounts
      if (content.includes('#[account(') && content.includes('seeds') && !content.includes('bump')) {
        findings.push({
          id: 'SOL149',
          title: 'PDA Seeds Without Bump',
          severity: 'high',
          description: 'PDA accounts should store and validate bump for consistency.',
          location: { file: input.path, line: 1 },
          suggestion: '#[account(seeds = [b"prefix", user.key().as_ref()], bump = data.bump)]',
          cwe: 'CWE-20',
        });
      }
    }
  }

  return findings;
}
