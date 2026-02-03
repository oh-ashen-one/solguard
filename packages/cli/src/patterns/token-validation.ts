import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL023: Token Account Validation
 * Comprehensive token/mint validation checks.
 */
export function checkTokenValidation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];

  if (!input.rust || !input.rust.files) return findings;

  for (const file of input.rust.files) {
    const lines = file.lines;

    lines.forEach((line, index) => {
      const lineNum = index + 1;

      // Pattern 1: Token account without mint validation
      if (line.includes('TokenAccount') || line.includes('token_account')) {
        const contextStart = Math.max(0, index - 10);
        const contextEnd = Math.min(lines.length, index + 3);
        const context = lines.slice(contextStart, contextEnd).join('\n');

        if (!context.includes('token::mint') && !context.includes('mint =') && 
            !context.includes('.mint') && !context.includes('mint:')) {
          // Check if it's a constraint block
          if (context.includes('#[account(') || context.includes('constraint')) {
            findings.push({
              id: `SOL023-${findings.length + 1}`,
              pattern: 'Token Account Validation',
              severity: 'high',
              title: 'Token account without mint validation',
              description: 'TokenAccount used without validating it belongs to expected mint.',
              location: { file: file.path, line: lineNum },
              suggestion: 'Add token::mint constraint: #[account(token::mint = expected_mint)]',
            });
          }
        }
      }

      // Pattern 2: Associated token account without proper derivation check
      if (line.includes('associated_token') || line.includes('AssociatedToken')) {
        const contextStart = Math.max(0, index - 5);
        const context = lines.slice(contextStart, index + 3).join('\n');

        if (!context.includes('associated_token::mint') && !context.includes('associated_token::authority')) {
          if (context.includes('#[account(')) {
            findings.push({
              id: `SOL023-${findings.length + 1}`,
              pattern: 'Token Account Validation',
              severity: 'high',
              title: 'Associated token missing derivation constraints',
              description: 'Associated token account without proper mint/authority derivation validation.',
              location: { file: file.path, line: lineNum },
              suggestion: 'Add constraints: associated_token::mint = mint, associated_token::authority = owner',
            });
          }
        }
      }

      // Pattern 3: Mint authority check missing
      if (line.includes('mint_to') || line.includes('MintTo')) {
        const contextStart = Math.max(0, index - 15);
        const context = lines.slice(contextStart, index + 1).join('\n');

        if (!context.includes('mint_authority') && !context.includes('authority.key')) {
          findings.push({
            id: `SOL023-${findings.length + 1}`,
            pattern: 'Token Account Validation',
            severity: 'critical',
            title: 'Mint operation without authority validation',
            description: 'Minting tokens without validating mint authority. Could allow unauthorized minting.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Verify mint_authority matches expected authority before minting.',
          });
        }
      }

      // Pattern 4: Token decimals not validated
      if ((line.includes('amount') || line.includes('Amount')) && 
          (line.includes('*') || line.includes('pow'))) {
        const contextStart = Math.max(0, index - 5);
        const context = lines.slice(contextStart, index + 3).join('\n');

        if (!context.includes('decimals') && (context.includes('10') || context.includes('1e'))) {
          findings.push({
            id: `SOL023-${findings.length + 1}`,
            pattern: 'Token Account Validation',
            severity: 'medium',
            title: 'Hardcoded decimal assumption',
            description: 'Amount calculation with hardcoded decimal multiplier. Different tokens have different decimals.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Read decimals from mint account instead of hardcoding (e.g., 10^6 for USDC, 10^9 for SOL).',
          });
        }
      }
    });
  }

  return findings;
}
