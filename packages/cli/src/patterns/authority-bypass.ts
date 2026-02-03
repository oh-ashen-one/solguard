import type { Finding } from '../commands/audit.js';
import type { ParsedRust } from '../parsers/rust.js';
import type { PatternInput } from './index.js';

/**
 * SOL005: Authority Bypass Detection
 * 
 * Detects when sensitive operations (transfers, withdrawals, admin actions)
 * don't verify the authority before execution.
 */
export function checkAuthorityBypass(input: PatternInput): Finding[] {
  const rust = input.rust;
  const findings: Finding[] = [];
  
  if (!rust?.files) return findings;
  
  let counter = 1;
  
  for (const file of rust.files) {
    const lines = file.content.split('\n');
    
    // Track functions and their authority checks
    let inFunction = false;
    let functionName = '';
    let functionStart = 0;
    let hasAuthorityCheck = false;
    let isSensitiveOperation = false;
    let braceDepth = 0;
    
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const lineNum = i + 1;
      
      // Detect function start
      const fnMatch = line.match(/pub\s+fn\s+(\w+)/);
      if (fnMatch) {
        // Check previous function if it was sensitive without auth check
        if (inFunction && isSensitiveOperation && !hasAuthorityCheck) {
          // Skip initialize functions - they create accounts, not modify existing ones
          if (!/^init|initialize|create|new/i.test(functionName)) {
            findings.push({
              id: `SOL005-${counter++}`,
              pattern: 'authority-bypass',
              severity: 'critical',
              title: `Function '${functionName}' may lack authority verification`,
              description: `The function '${functionName}' performs sensitive operations but doesn't appear to verify authority before execution. An attacker could potentially call this function and bypass intended access controls.`,
              location: {
                file: file.path,
                line: functionStart,
              },
              suggestion: `Add authority verification at the start of the function:
require!(ctx.accounts.authority.key() == expected_authority, ErrorCode::Unauthorized);

Or use Anchor's has_one constraint:
#[account(has_one = authority)]`,
            });
          }
        }
        
        inFunction = true;
        functionName = fnMatch[1];
        functionStart = lineNum;
        hasAuthorityCheck = false;
        isSensitiveOperation = false;
        braceDepth = 0;
      }
      
      // Track brace depth
      braceDepth += (line.match(/{/g) || []).length;
      braceDepth -= (line.match(/}/g) || []).length;
      
      // Detect function end
      if (inFunction && braceDepth <= 0 && line.includes('}')) {
        // Check this function (skip initialize functions)
        if (isSensitiveOperation && !hasAuthorityCheck && !/^init|initialize|create|new/i.test(functionName)) {
          findings.push({
            id: `SOL005-${counter++}`,
            pattern: 'authority-bypass',
            severity: 'critical',
            title: `Function '${functionName}' may lack authority verification`,
            description: `The function '${functionName}' performs sensitive operations but doesn't appear to verify authority before execution. An attacker could potentially call this function and bypass intended access controls.`,
            location: {
              file: file.path,
              line: functionStart,
            },
            suggestion: `Add authority verification at the start of the function:
require!(ctx.accounts.authority.key() == expected_authority, ErrorCode::Unauthorized);

Or use Anchor's has_one constraint:
#[account(has_one = authority)]`,
          });
        }
        inFunction = false;
      }
      
      if (!inFunction) continue;
      
      // Detect sensitive operations
      const sensitivePatterns = [
        /\.transfer\s*\(/,           // SOL transfers
        /\.withdraw\s*\(/,           // Withdrawals
        /transfer_checked/,          // SPL token transfers
        /invoke_signed/,             // CPIs with signer seeds
        /set_authority/,             // Authority changes
        /close_account/,             // Account closure
        /\.sub\s*\(/,                // Balance subtraction
        /balance\s*[-=]/,            // Balance modification
        /mint_to/,                   // Token minting
        /burn/,                      // Token burning
        /freeze/,                    // Account freezing
        /\.authority\s*=/,           // Authority assignment
        /admin/i,                    // Admin operations
      ];
      
      for (const pattern of sensitivePatterns) {
        if (pattern.test(line)) {
          isSensitiveOperation = true;
          break;
        }
      }
      
      // Detect authority checks
      const authCheckPatterns = [
        /require!\s*\([^)]*authority/i,
        /require!\s*\([^)]*admin/i,
        /require!\s*\([^)]*owner/i,
        /require_keys_eq!/,  // Anchor's key comparison macro
        /\.key\(\)\s*==\s*.*authority/,
        /has_one\s*=\s*authority/,
        /has_one\s*=\s*owner/,
        /has_one\s*=\s*admin/,
        /constraint\s*=.*authority/,
        /Signer<'info>/,  // If authority is a Signer, it's implicitly checked
        /authority:\s*Signer/,  // Authority declared as Signer in struct
      ];
      
      for (const pattern of authCheckPatterns) {
        if (pattern.test(line)) {
          hasAuthorityCheck = true;
          break;
        }
      }
      
      // Also check if we're in a struct that has has_one constraint
      // (these get executed before the function body)
      if (/has_one\s*=/.test(line) || /constraint\s*=.*==/.test(line)) {
        hasAuthorityCheck = true;
      }
    }
  }
  
  return findings;
}
