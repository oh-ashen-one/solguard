import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL150: Cross-Program Invocation Safety
 * Comprehensive CPI safety checks beyond basic validation
 * Real-world: Various exploits through malicious CPI
 */
export function checkCrossProgamInvocationSafety(input: PatternInput): Finding[] {
  const findings: Finding[] = [];

  if (input.rust?.content) {
    const content = input.rust.content;
    const lines = content.split('\n');

    // Check for CPI patterns
    const cpiExists = content.includes('invoke') || content.includes('CpiContext');

    if (cpiExists) {
      // Check for return data validation
      if (content.includes('invoke') && !content.includes('get_return_data') && !content.includes('return_data')) {
        findings.push({
          id: 'SOL150',
          title: 'CPI Return Data Not Validated',
          severity: 'medium',
          description: 'CPI return data should be checked when the called program returns meaningful data.',
          location: { file: input.path, line: 1 },
          suggestion: 'Check return data: let (program_id, data) = get_return_data().ok_or(NoReturnData)?; validate(data)?;',
          cwe: 'CWE-754',
        });
      }

      // Check for CPI to token program without validation
      if (content.includes('spl_token') || content.includes('Token::')) {
        if (!content.includes('token::ID') && !content.includes('TOKEN_PROGRAM_ID')) {
          findings.push({
            id: 'SOL150',
            title: 'Token Program Not Validated',
            severity: 'critical',
            description: 'CPI to token operations must validate the token program ID.',
            location: { file: input.path, line: 1 },
            suggestion: 'Validate: require!(token_program.key() == &spl_token::ID, InvalidTokenProgram)',
            cwe: 'CWE-345',
          });
        }
      }

      // Check for account state after CPI
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (line.match(/invoke|cpi::/i)) {
          // Check if account is reloaded after CPI
          const contextAfter = lines.slice(i + 1, Math.min(i + 10, lines.length)).join('\n');
          if (!contextAfter.includes('reload') && !contextAfter.includes('try_borrow_data')) {
            findings.push({
              id: 'SOL150',
              title: 'Account Not Reloaded After CPI',
              severity: 'high',
              description: 'Account data may be stale after CPI. Reload if you need current state.',
              location: { file: input.path, line: i + 1 },
              suggestion: 'Reload after CPI: account.reload()?; // or ctx.accounts.account.reload()?;',
              cwe: 'CWE-662',
            });
            break;
          }
        }
      }

      // Check for CPI with mutable accounts
      if (content.includes('AccountMeta::new(') || content.includes('is_writable: true')) {
        if (!content.includes('signer_seeds') && content.includes('mut')) {
          findings.push({
            id: 'SOL150',
            title: 'Mutable Account CPI Without PDA Signing',
            severity: 'high',
            description: 'CPI with mutable accounts may need PDA signing for proper authorization.',
            location: { file: input.path, line: 1 },
            suggestion: 'Use invoke_signed when program needs to sign: invoke_signed(&ix, accounts, &[&signer_seeds])',
            cwe: 'CWE-284',
          });
        }
      }

      // Check for CPI depth awareness
      if (content.includes('invoke') && !content.includes('depth') && !content.includes('MAX_CPI_DEPTH')) {
        findings.push({
          id: 'SOL150',
          title: 'CPI Depth Not Considered',
          severity: 'low',
          description: 'Solana has a max CPI depth of 4. Deeply nested CPIs may fail.',
          location: { file: input.path, line: 1 },
          suggestion: 'Document CPI depth expectations. Consider depth in composability design.',
          cwe: 'CWE-674',
        });
      }
    }
  }

  return findings;
}
