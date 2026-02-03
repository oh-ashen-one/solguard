import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL038: Token-2022 Compatibility
 * Issues with Token-2022 program extensions.
 */
export function checkToken2022(input: PatternInput): Finding[] {
  const findings: Finding[] = [];

  if (!input.rust || !input.rust.files) return findings;

  for (const file of input.rust.files) {
    const lines = file.lines;
    const content = file.content;

    // Skip if no token operations
    if (!content.includes('token') && !content.includes('Token')) {
      continue;
    }

    lines.forEach((line, index) => {
      const lineNum = index + 1;

      // Pattern 1: Hardcoded Token Program ID
      if (line.includes('spl_token::ID') || line.includes('TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA')) {
        findings.push({
          id: `SOL038-${findings.length + 1}`,
          pattern: 'Token-2022 Compatibility',
          severity: 'medium',
          title: 'Hardcoded Token Program ID excludes Token-2022',
          description: 'Using spl_token::ID directly excludes Token-2022 tokens.',
          location: { file: file.path, line: lineNum },
          suggestion: 'Use spl_token_2022::check_spl_token_program_account() or anchor_spl::token_interface.',
        });
      }

      // Pattern 2: Not handling transfer fee extension
      if (line.includes('transfer') && content.includes('token')) {
        const contextStart = Math.max(0, index - 10);
        const contextEnd = Math.min(lines.length, index + 10);
        const context = lines.slice(contextStart, contextEnd).join('\n');

        if (!context.includes('transfer_fee') && !context.includes('TransferFee') &&
            !context.includes('get_fee')) {
          findings.push({
            id: `SOL038-${findings.length + 1}`,
            pattern: 'Token-2022 Compatibility',
            severity: 'low',
            title: 'Transfer without Token-2022 fee consideration',
            description: 'Token-2022 tokens may have transfer fees. Amount received could be less than sent.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Check for transfer fee extension and adjust amounts accordingly.',
          });
        }
      }

      // Pattern 3: Not handling confidential transfers
      if (content.includes('Token') && !content.includes('confidential')) {
        // Only report once per file
        if (lineNum === 1) {
          findings.push({
            id: `SOL038-${findings.length + 1}`,
            pattern: 'Token-2022 Compatibility',
            severity: 'info',
            title: 'No confidential transfer handling',
            description: 'Token-2022 confidential transfers not handled. May need special support.',
            location: { file: file.path, line: 1 },
            suggestion: 'Consider if your protocol should support confidential transfer tokens.',
          });
        }
      }

      // Pattern 4: Account size assumptions
      if (line.includes('165') || line.includes('TokenAccount::LEN')) {
        findings.push({
          id: `SOL038-${findings.length + 1}`,
          pattern: 'Token-2022 Compatibility',
          severity: 'medium',
          title: 'Hardcoded token account size',
          description: 'Token-2022 accounts with extensions are larger than 165 bytes.',
          location: { file: file.path, line: lineNum },
          suggestion: 'Use get_account_len() or ExtensionType::try_calculate_account_len() for Token-2022.',
        });
      }
    });
  }

  return findings;
}
