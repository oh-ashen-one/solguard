/**
 * SOL012: Arbitrary CPI Detection
 * 
 * Detects when invoke/invoke_signed is called with an unconstrained
 * program_id that could be controlled by an attacker.
 * 
 * Vulnerable pattern:
 *   invoke(&ix, &[...])?;  // program_id comes from user input
 * 
 * Safe pattern:
 *   invoke(&ix, &[...])?;  // program_id is hardcoded or validated
 */

import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

export function checkArbitraryCpi(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  
  if (!input.rust?.content) return findings;
  
  const { content, functions } = input.rust;
  const lines = content.split('\n');
  
  // Look for invoke calls where program_id isn't validated
  for (const func of functions) {
    const funcBody = func.body || '';
    
    // Check for invoke or invoke_signed calls
    const invokeMatches = funcBody.matchAll(/invoke(?:_signed)?\s*\(\s*&?\s*(\w+)/g);
    
    for (const match of invokeMatches) {
      const instructionVar = match[1];
      
      // Check if the instruction's program_id is from an account (potentially user-controlled)
      // Pattern: Instruction { program_id: ctx.accounts.*.key(), ... }
      // or: Instruction::new_with_*(*_account.key, ...)
      
      const accountKeyPattern = new RegExp(
        `${instructionVar}\\s*=.*(?:program_id\\s*:\\s*\\*?\\w+\\.key\\(\\)|Instruction::new_with_\\w+\\([^,]+\\.key)`,
        'i'
      );
      
      if (accountKeyPattern.test(funcBody)) {
        // Check if there's a constraint or validation
        const hasConstraint = /(?:constraint\s*=|#\[account\([^)]*address\s*=)/.test(funcBody) ||
          /program_id\s*==\s*(?:spl_token::id\(\)|token_program::ID|system_program::ID)/.test(funcBody);
        
        if (!hasConstraint) {
          // Find the line number
          let lineNum = 1;
          for (let i = 0; i < lines.length; i++) {
            if (lines[i].includes('invoke')) {
              lineNum = i + 1;
              break;
            }
          }
          
          findings.push({
            pattern: 'SOL012',
            severity: 'critical',
            title: 'Arbitrary CPI - Unconstrained Program ID',
            description: `Function '${func.name}' invokes a CPI where the target program_id may be user-controlled. An attacker could substitute a malicious program.`,
            location: `${input.path}:${lineNum}`,
            recommendation: 'Validate the program_id against a known constant (e.g., spl_token::id()) or use Anchor\'s Program<T> type which auto-validates.',
          });
        }
      }
    }
  }
  
  // Also check for raw account key usage in CPI
  const dangerousPatterns = [
    /invoke\([^)]+accounts\[\d+\]\.key/,
    /invoke_signed\([^)]+remaining_accounts/,
    /CpiContext::new\(\s*\w+\.to_account_info\(\)/,
  ];
  
  for (const pattern of dangerousPatterns) {
    const match = content.match(pattern);
    if (match) {
      let lineNum = 1;
      for (let i = 0; i < lines.length; i++) {
        if (pattern.test(lines[i])) {
          lineNum = i + 1;
          break;
        }
      }
      
      findings.push({
        pattern: 'SOL012',
        severity: 'high',
        title: 'Arbitrary CPI - Dynamic Program Reference',
        description: 'CPI call uses a dynamically indexed account or remaining_accounts for the program reference. Ensure the program ID is validated.',
        location: `${input.path}:${lineNum}`,
        recommendation: 'Explicitly validate the program ID matches the expected program before invoking.',
      });
    }
  }
  
  return findings;
}
