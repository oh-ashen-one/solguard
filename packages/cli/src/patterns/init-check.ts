import type { Finding } from '../commands/audit.js';
import type { ParsedRust } from '../parsers/rust.js';
import type { PatternInput } from './index.js';

/**
 * SOL006: Missing Initialization Check
 * 
 * Detects accounts that may be used without verifying they've been initialized.
 * The famous Wormhole hack ($320M) was caused by this vulnerability.
 * 
 * NOTE: Anchor's Account<'info, T> type automatically validates the discriminator
 * during deserialization, which effectively acts as an initialization check.
 * We focus on AccountInfo and UncheckedAccount which bypass these checks.
 */
export function checkMissingInitCheck(input: PatternInput): Finding[] {
  const rust = input.rust;
  const findings: Finding[] = [];
  
  if (!rust?.files) return findings;
  
  let counter = 1;
  
  for (const file of rust.files) {
    const lines = file.content.split('\n');
    
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const lineNum = i + 1;
      
      // Detect direct UncheckedAccount usage (always risky)
      if (line.includes('UncheckedAccount') && !line.includes('/// CHECK:')) {
        // Look for CHECK comment above
        const prevLines = lines.slice(Math.max(0, i - 3), i).join('\n');
        if (!prevLines.includes('/// CHECK:') && !prevLines.includes('// CHECK:')) {
          findings.push({
            id: `SOL006-${counter++}`,
            pattern: 'unchecked-account',
            severity: 'high',
            title: 'UncheckedAccount without safety documentation',
            description: 'UncheckedAccount is used without a /// CHECK: comment explaining why it\'s safe. While sometimes necessary, unchecked accounts are a common source of vulnerabilities and should be documented.',
            location: {
              file: file.path,
              line: lineNum,
            },
            code: line.trim(),
            suggestion: `Add a CHECK comment explaining why this account is safe:
/// CHECK: This account is safe because [your reason here]
pub my_account: UncheckedAccount<'info>,

Or use a typed Account with appropriate constraints if possible.`,
          });
        }
      }
    }
  }
  
  return findings;
}
