import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL309: Incinerator/Burn Attack Detection
 * Detects vulnerabilities in token burning mechanisms
 * Real-world: Schrodinger's NFT incinerator exploit (Solens)
 */
export function checkIncineratorAttack(input: PatternInput): Finding[] {
  const findings: Finding[] = [];

  if (input.rust?.content) {
    const content = input.rust.content;
    const lines = content.split('\n');

    // Detect burn/incinerator patterns
    const hasBurn = /burn|incinerat|destroy|close_account/i.test(content);

    if (hasBurn) {
      // Check for burn destination validation
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];

        // Burning with arbitrary destination
        if (line.includes('burn') || line.includes('close_account')) {
          const contextLines = lines.slice(i, Math.min(i + 10, lines.length)).join('\n');
          
          // Check if destination is hardcoded or validated
          if (!contextLines.includes('INCINERATOR') && !contextLines.includes('system_program') &&
              !contextLines.includes('1111111111111111111111111111111') && contextLines.includes('destination')) {
            findings.push({
              id: 'SOL309',
              title: 'Arbitrary Burn Destination',
              severity: 'high',
              description: 'Burn/close operations should use system incinerator or validated destinations.',
              location: { file: input.path, line: i + 1 },
              suggestion: 'Use incinerator: close_account(CpiContext::new(token_program, CloseAccount { destination: INCINERATOR }))',
              cwe: 'CWE-284',
            });
            break;
          }
        }
      }

      // Check for burn authority validation
      if (content.includes('burn') && !content.includes('mint_authority') && !content.includes('burn_authority')) {
        findings.push({
          id: 'SOL309',
          title: 'Missing Burn Authority Check',
          severity: 'critical',
          description: 'Token burns must validate burn authority to prevent unauthorized burning.',
          location: { file: input.path, line: 1 },
          suggestion: 'Validate authority: #[account(constraint = mint.mint_authority.unwrap() == authority.key())]',
          cwe: 'CWE-863',
        });
      }

      // Check for rent recovery on close
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (line.includes('close') && !line.includes('//')) {
          const contextLines = lines.slice(i, Math.min(i + 8, lines.length)).join('\n');
          if (!contextLines.includes('lamports') && !contextLines.includes('rent')) {
            findings.push({
              id: 'SOL309',
              title: 'Rent Not Recovered on Close',
              severity: 'low',
              description: 'Account closure should transfer remaining lamports to avoid rent loss.',
              location: { file: input.path, line: i + 1 },
              suggestion: 'Recover rent: **account.lamports.borrow_mut() = 0; **destination.lamports.borrow_mut() += rent;',
              cwe: 'CWE-404',
            });
            break;
          }
        }
      }

      // Check for burn reentrancy
      if (content.includes('burn') && content.includes('invoke')) {
        for (let i = 0; i < lines.length; i++) {
          if (lines[i].includes('burn') && lines[i].includes('invoke')) {
            // Check if state is updated before CPI
            const beforeCPI = lines.slice(Math.max(0, i - 10), i).join('\n');
            if (!beforeCPI.includes('.amount') && !beforeCPI.includes('supply') && !beforeCPI.includes('balance')) {
              findings.push({
                id: 'SOL309',
                title: 'Burn Before State Update',
                severity: 'high',
                description: 'Update internal state before calling external burn to prevent reentrancy.',
                location: { file: input.path, line: i + 1 },
                suggestion: 'Update first: internal_balance -= amount; then burn_tokens(ctx)?;',
                cwe: 'CWE-696',
              });
              break;
            }
          }
        }
      }

      // Check for total supply tracking
      if (content.includes('burn') && content.includes('mint')) {
        if (!content.includes('total_supply') && !content.includes('supply')) {
          findings.push({
            id: 'SOL309',
            title: 'No Supply Tracking',
            severity: 'medium',
            description: 'Burning/minting should track total supply for accurate accounting.',
            location: { file: input.path, line: 1 },
            suggestion: 'Track supply: mint_data.supply = mint_data.supply.checked_sub(burn_amount)?',
            cwe: 'CWE-682',
          });
        }
      }

      // Check for NFT burning edge cases
      if (content.includes('nft') && content.includes('burn')) {
        // Check if metadata is also burned
        if (!content.includes('metadata') || !content.includes('master_edition')) {
          findings.push({
            id: 'SOL309',
            title: 'Incomplete NFT Burn',
            severity: 'medium',
            description: 'NFT burns should also close metadata and edition accounts.',
            location: { file: input.path, line: 1 },
            suggestion: 'Full burn: burn_token() + close_metadata() + close_edition()',
            cwe: 'CWE-459',
          });
        }
      }
    }

    // Check for incinerator address constant
    if (content.includes('close') || content.includes('burn')) {
      if (!content.includes('11111111111111111111111111111111')) {
        // Look for safe patterns
        if (!content.includes('INCINERATOR') && !content.includes('system_program::ID')) {
          findings.push({
            id: 'SOL309',
            title: 'Consider Using System Incinerator',
            severity: 'info',
            description: 'For permanent burns, consider using the system incinerator address.',
            location: { file: input.path, line: 1 },
            suggestion: 'Use incinerator: pub const INCINERATOR: Pubkey = pubkey!("1nc1nerator11111111111111111111111111111111")',
            cwe: 'CWE-664',
          });
        }
      }
    }
  }

  return findings;
}
