import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL009: Account Type Confusion
 * 
 * Detects when accounts might be confused for each other:
 * - Similar account names without type discrimination
 * - Missing account type validation
 * - Accounts that could be swapped by attacker
 */
export function checkAccountConfusion(input: PatternInput): Finding[] {
  const rust = input.rust;
  const findings: Finding[] = [];
  
  if (!rust?.files) return findings;
  
  let counter = 1;
  
  for (const file of rust.files) {
    const lines = file.content.split('\n');
    const content = file.content;
    
    // Find Accounts structs and their members
    const structPattern = /#\[derive\(Accounts\)\]\s*pub\s+struct\s+(\w+)[^{]*\{([^}]+)\}/g;
    
    let structMatch;
    while ((structMatch = structPattern.exec(content)) !== null) {
      const structName = structMatch[1];
      const structBody = structMatch[2];
      const structStartLine = content.substring(0, structMatch.index).split('\n').length;
      
      // Find accounts within this struct only
      const accountPattern = /pub\s+(\w+):\s*Account<'info,\s*(\w+)>/g;
      const accounts: { name: string; dataType: string; line: number }[] = [];
      
      let accountMatch;
      while ((accountMatch = accountPattern.exec(structBody)) !== null) {
        const lineOffset = structBody.substring(0, accountMatch.index).split('\n').length;
        accounts.push({
          name: accountMatch[1],
          dataType: accountMatch[2],
          line: structStartLine + lineOffset,
        });
      }
      
      // Check for confusable accounts WITHIN THE SAME STRUCT
      for (let i = 0; i < accounts.length; i++) {
        for (let j = i + 1; j < accounts.length; j++) {
          const a = accounts[i];
          const b = accounts[j];
          
          // Same underlying data type but different names (could be swapped)
          if (a.dataType === b.dataType && a.name !== b.name) {
            // Check if there's discrimination logic
            const hasDiscrimination = new RegExp(
              `${a.name}.*!=.*${b.name}|${b.name}.*!=.*${a.name}|` +
              `constraint.*${a.name}.*${b.name}|constraint.*${b.name}.*${a.name}`
            ).test(structBody);
            
            if (!hasDiscrimination) {
              findings.push({
                id: `SOL009-${counter++}`,
                pattern: 'account-confusion',
                severity: 'high',
                title: `Accounts '${a.name}' and '${b.name}' in '${structName}' may be confusable`,
                description: `Both '${a.name}' and '${b.name}' are of type ${a.dataType} within the same instruction context. An attacker might pass the same account for both, or swap them, leading to unexpected behavior. This is especially dangerous in transfer/swap operations.`,
                location: {
                  file: file.path,
                  line: a.line,
                },
                suggestion: `Add constraints to ensure accounts are different:
#[account(
    constraint = ${a.name}.key() != ${b.name}.key() @ ErrorCode::SameAccount
)]

Or use different account types/discriminators for different purposes.`,
              });
            }
          }
        }
      }
    }
    
    // Check for AccountInfo with data access (separate scan)
    const accountInfoPattern = /pub\s+(\w+):\s*(AccountInfo|UncheckedAccount)<'info>/g;
    let aiMatch;
    while ((aiMatch = accountInfoPattern.exec(content)) !== null) {
      const accountName = aiMatch[1];
      const accountType = aiMatch[2];
      const lineNum = content.substring(0, aiMatch.index).split('\n').length;
      
      // Skip known safe patterns
      if (/system_program|rent|clock|token_program|^_/.test(accountName)) continue;
      
      // Check if there's a CHECK comment
      const prevLines = lines.slice(Math.max(0, lineNum - 4), lineNum).join('\n');
      if (prevLines.includes('CHECK:')) continue;
      
      // Check if data is read from this account
      const usagePattern = new RegExp(`${accountName}\\s*\\.\\s*(data|try_borrow_data|deserialize)`);
      if (usagePattern.test(content)) {
        findings.push({
          id: `SOL009-${counter++}`,
          pattern: 'untyped-account-data-access',
          severity: 'high',
          title: `Untyped account '${accountName}' has data accessed`,
          description: `The account '${accountName}' is declared as ${accountType} but its data is accessed. Without type validation, an attacker could pass any account with arbitrary data, potentially bypassing security checks.`,
          location: {
            file: file.path,
            line: lineNum,
          },
          code: lines[lineNum - 1]?.trim() || '',
          suggestion: `Use a typed Account instead:
pub ${accountName}: Account<'info, YourDataType>,

Or manually validate the account discriminator:
let data = ${accountName}.try_borrow_data()?;
require!(data[..8] == YourDataType::DISCRIMINATOR, ErrorCode::InvalidAccount);`,
        });
      }
    }
  }
  
  return findings;
}
