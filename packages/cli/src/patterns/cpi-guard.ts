import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL040: CPI Guard Vulnerabilities
 * Issues with CPI guard and program execution safety.
 */
export function checkCpiGuard(input: PatternInput): Finding[] {
  const findings: Finding[] = [];

  if (!input.rust || !input.rust.files) return findings;

  for (const file of input.rust.files) {
    const lines = file.lines;
    const content = file.content;

    lines.forEach((line, index) => {
      const lineNum = index + 1;

      // Pattern 1: invoke_signed with user-controlled accounts
      if (line.includes('invoke_signed') || line.includes('invoke')) {
        const contextStart = Math.max(0, index - 5);
        const contextEnd = Math.min(lines.length, index + 5);
        const context = lines.slice(contextStart, contextEnd).join('\n');

        // Check if accounts come from ctx.remaining_accounts
        if (context.includes('remaining_accounts') || context.includes('to_account_infos')) {
          findings.push({
            id: `SOL040-${findings.length + 1}`,
            pattern: 'CPI Guard Vulnerability',
            severity: 'high',
            title: 'CPI with user-controlled accounts',
            description: 'CPI using remaining_accounts or dynamic account lists. Attacker could inject malicious accounts.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Validate all accounts before CPI. Prefer explicit account declarations.',
          });
        }
      }

      // Pattern 2: Missing CPI guard for token operations
      if (content.includes('token::') && !content.includes('cpi_guard')) {
        if (line.includes('token::transfer') || line.includes('token::approve')) {
          findings.push({
            id: `SOL040-${findings.length + 1}`,
            pattern: 'CPI Guard Vulnerability',
            severity: 'info',
            title: 'Token CPI without CPI guard consideration',
            description: 'Token-2022 CPI Guard extension can block CPIs. Check if your users might have it enabled.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Handle CpiGuard extension or document that CPI-guarded accounts are not supported.',
          });
        }
      }

      // Pattern 3: Program-derived signer without seed validation
      if (line.includes('invoke_signed') && line.includes('&[&[')) {
        const contextStart = Math.max(0, index - 10);
        const context = lines.slice(contextStart, index + 3).join('\n');

        // Check if seeds are validated
        if (!context.includes('find_program_address') && !context.includes('bump')) {
          findings.push({
            id: `SOL040-${findings.length + 1}`,
            pattern: 'CPI Guard Vulnerability',
            severity: 'high',
            title: 'invoke_signed without validated seeds',
            description: 'PDA seeds for signing not clearly validated. Could sign for wrong PDA.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Store and validate bump seed. Use find_program_address to verify PDA.',
          });
        }
      }

      // Pattern 4: Recursive CPI (reentrancy via callback)
      if (line.includes('invoke') && content.includes('#[instruction]')) {
        const contextStart = Math.max(0, index - 30);
        const context = lines.slice(contextStart, index + 5).join('\n');

        // Check if this might be a callback
        if (context.includes('callback') || context.includes('hook') || 
            context.includes('on_')) {
          findings.push({
            id: `SOL040-${findings.length + 1}`,
            pattern: 'CPI Guard Vulnerability',
            severity: 'high',
            title: 'Potential recursive CPI via callback',
            description: 'CPI in callback/hook could enable recursive calls and reentrancy.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Use reentrancy guards or ensure callback cannot trigger another callback.',
          });
        }
      }

      // Pattern 5: Unchecked return value from CPI
      if ((line.includes('invoke(') || line.includes('invoke_signed(')) && 
          !line.includes('?') && !line.includes('unwrap') && !line.includes('expect')) {
        findings.push({
          id: `SOL040-${findings.length + 1}`,
          pattern: 'CPI Guard Vulnerability',
          severity: 'high',
          title: 'CPI return value not checked',
          description: 'CPI result not handled. Failed CPI might go unnoticed.',
          location: { file: file.path, line: lineNum },
          suggestion: 'Always handle CPI result: invoke(...)? or handle the ProgramError.',
        });
      }
    });
  }

  return findings;
}
