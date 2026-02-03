/**
 * SOL013: Duplicate Mutable Accounts Detection
 * 
 * Detects when the same account could be passed multiple times as
 * different mutable parameters, leading to aliasing bugs.
 * 
 * Vulnerable pattern:
 *   pub from: Account<'info, TokenAccount>,
 *   pub to: Account<'info, TokenAccount>,
 *   // No constraint that from != to
 * 
 * Exploit: Pass the same account as both `from` and `to`
 */

import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

export function checkDuplicateMutable(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  
  if (!input.rust?.content) return findings;
  
  const { content, structs } = input.rust;
  const lines = content.split('\n');
  
  // Find account structs (Anchor contexts)
  for (const struct of structs) {
    // Skip non-account structs
    if (!struct.body?.includes('Account<') && !struct.body?.includes('AccountInfo<')) {
      continue;
    }
    
    // Extract mutable accounts
    const mutableAccounts: { name: string; type: string; line: number }[] = [];
    
    // Match patterns like: #[account(mut)] pub name: Account<...>
    const accountPattern = /#\[account\([^)]*mut[^)]*\)\]\s*pub\s+(\w+)\s*:\s*([^,\n]+)/g;
    const body = struct.body || '';
    
    let match;
    while ((match = accountPattern.exec(body)) !== null) {
      mutableAccounts.push({
        name: match[1],
        type: match[2].trim(),
        line: 0, // Will find later
      });
    }
    
    // Also check for AccountInfo with is_writable
    const accountInfoPattern = /pub\s+(\w+)\s*:\s*AccountInfo<[^>]+>/g;
    while ((match = accountInfoPattern.exec(body)) !== null) {
      // These are potentially mutable if used with write
      mutableAccounts.push({
        name: match[1],
        type: match[2] || 'AccountInfo',
        line: 0,
      });
    }
    
    // Find accounts with same type but no constraint ensuring they're different
    const typeGroups = new Map<string, string[]>();
    
    for (const acc of mutableAccounts) {
      // Normalize the type (remove lifetimes, generics for comparison)
      const normalizedType = acc.type
        .replace(/<'[^>]+>/, '')
        .replace(/Account<[^,]+,\s*/, '')
        .replace(/>$/, '')
        .trim();
      
      if (!typeGroups.has(normalizedType)) {
        typeGroups.set(normalizedType, []);
      }
      typeGroups.get(normalizedType)!.push(acc.name);
    }
    
    // Check for potential duplicates
    for (const [type, accounts] of typeGroups) {
      if (accounts.length >= 2) {
        // Check if there's a constraint preventing duplicates
        const hasNotEqualConstraint = accounts.every((acc, i) => {
          const otherAccs = accounts.filter((_, j) => j !== i);
          return otherAccs.some(other => {
            // Look for constraint = acc.key() != other.key()
            const pattern = new RegExp(
              `constraint\\s*=.*(?:${acc}\\.key\\(\\)\\s*!=\\s*${other}\\.key\\(\\)|${other}\\.key\\(\\)\\s*!=\\s*${acc}\\.key\\(\\))`,
              'i'
            );
            return pattern.test(body);
          });
        });
        
        if (!hasNotEqualConstraint) {
          // Find the line number of the struct
          let lineNum = 1;
          for (let i = 0; i < lines.length; i++) {
            if (lines[i].includes(`struct ${struct.name}`)) {
              lineNum = i + 1;
              break;
            }
          }
          
          findings.push({
            pattern: 'SOL013',
            severity: 'high',
            title: 'Duplicate Mutable Accounts Possible',
            description: `Struct '${struct.name}' has multiple mutable accounts of type '${type}' (${accounts.join(', ')}) without constraints ensuring they are different. An attacker could pass the same account for multiple parameters.`,
            location: `${input.path}:${lineNum}`,
            recommendation: `Add constraint: ${accounts[0]}.key() != ${accounts[1]}.key()`,
          });
        }
      }
    }
  }
  
  return findings;
}
