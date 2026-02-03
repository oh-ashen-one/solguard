import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL039: Memo and Logging Issues
 * Security issues with logging and memo programs.
 */
export function checkMemoLogging(input: PatternInput): Finding[] {
  const findings: Finding[] = [];

  if (!input.rust || !input.rust.files) return findings;

  for (const file of input.rust.files) {
    const lines = file.lines;

    lines.forEach((line, index) => {
      const lineNum = index + 1;

      // Pattern 1: Logging sensitive data
      if (line.includes('msg!') || line.includes('sol_log')) {
        const logContent = line.match(/msg!\s*\(\s*["']([^"']+)/)?.[1]?.toLowerCase() || '';
        
        const sensitiveTerms = ['secret', 'key', 'password', 'private', 'seed', 'mnemonic'];
        if (sensitiveTerms.some(term => logContent.includes(term) || line.toLowerCase().includes(term))) {
          findings.push({
            id: `SOL039-${findings.length + 1}`,
            pattern: 'Memo and Logging Issues',
            severity: 'high',
            title: 'Potentially sensitive data in logs',
            description: 'Log message may contain sensitive information. Logs are publicly visible on-chain.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Never log secrets, keys, or sensitive data. All logs are public.',
          });
        }
      }

      // Pattern 2: Memo program required but not validated
      if (line.includes('memo') || line.includes('Memo')) {
        const contextStart = Math.max(0, index - 5);
        const context = lines.slice(contextStart, index + 3).join('\n');

        if (context.includes('AccountInfo') && !context.includes('check_id') && 
            !context.includes('MemoV2') && !context.includes('spl_memo')) {
          findings.push({
            id: `SOL039-${findings.length + 1}`,
            pattern: 'Memo and Logging Issues',
            severity: 'medium',
            title: 'Memo program not validated',
            description: 'Memo account passed without validating it belongs to the memo program.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Validate memo program: require!(memo.key == &spl_memo::ID)',
          });
        }
      }

      // Pattern 3: Debug logging in production
      if (line.includes('#[cfg(debug_assertions)]') && line.includes('msg!')) {
        // Actually this is fine, skip it
      } else if (line.includes('dbg!') || line.includes('println!') || line.includes('eprintln!')) {
        findings.push({
          id: `SOL039-${findings.length + 1}`,
          pattern: 'Memo and Logging Issues',
          severity: 'low',
          title: 'Debug macros in code',
          description: 'dbg!/println!/eprintln! should not be in production Solana programs.',
          location: { file: file.path, line: lineNum },
          suggestion: 'Remove debug macros or wrap in #[cfg(debug_assertions)].',
        });
      }

      // Pattern 4: Excessive logging (compute cost)
      if (line.includes('msg!')) {
        const fnStart = Math.max(0, index - 30);
        const precedingCode = lines.slice(fnStart, index + 1).join('\n');
        const msgCount = (precedingCode.match(/msg!/g) || []).length;

        if (msgCount > 5) {
          findings.push({
            id: `SOL039-${findings.length + 1}`,
            pattern: 'Memo and Logging Issues',
            severity: 'low',
            title: 'Excessive logging',
            description: 'Multiple msg! calls increase compute cost. Consider reducing logs.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Minimize logging in production. Each msg! consumes compute units.',
          });
        }
      }
    });
  }

  return findings;
}
