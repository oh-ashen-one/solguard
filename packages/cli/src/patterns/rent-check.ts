/**
 * SOL014: Missing Rent Exemption Check
 * 
 * Detects when accounts are created or modified without ensuring
 * rent exemption, which could lead to account deletion.
 * 
 * Vulnerable pattern:
 *   **account.lamports.borrow_mut() = new_lamports;  // No rent check
 * 
 * Safe pattern:
 *   let rent = Rent::get()?;
 *   require!(new_lamports >= rent.minimum_balance(account_size));
 */

import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

export function checkRentExemption(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  
  if (!input.rust?.content) return findings;
  
  const { content, functions } = input.rust;
  const lines = content.split('\n');
  
  for (const func of functions) {
    const funcBody = func.body || '';
    
    // Check for lamport modifications without rent checks
    const modifiesLamports = /\*\*\w+\.lamports\.borrow_mut\(\)|\*\*\w+\.try_borrow_mut_lamports\(\)/.test(funcBody);
    
    // Check for account creation
    const createsAccount = /create_account|system_instruction::create_account|init\s*,/.test(funcBody);
    
    // Check for lamport transfers
    const transfersLamports = /transfer\s*\(|sub_lamports|add_lamports/.test(funcBody);
    
    if (modifiesLamports || transfersLamports) {
      // Check if rent is being validated
      const hasRentCheck = /Rent::get\(\)|rent\.minimum_balance|is_rent_exempt|rent_exempt/.test(funcBody);
      
      if (!hasRentCheck) {
        let lineNum = 1;
        for (let i = 0; i < lines.length; i++) {
          if (/lamports\.borrow_mut|transfer\s*\(|sub_lamports/.test(lines[i])) {
            lineNum = i + 1;
            break;
          }
        }
        
        findings.push({
          pattern: 'SOL014',
          severity: 'medium',
          title: 'Missing Rent Exemption Check',
          description: `Function '${func.name}' modifies account lamports without verifying rent exemption. If lamports drop below rent-exempt minimum, the account may be garbage collected.`,
          location: `${input.path}:${lineNum}`,
          recommendation: 'Use Rent::get()?.minimum_balance(data_len) to ensure accounts remain rent-exempt after lamport changes.',
        });
      }
    }
    
    // Check for close operations that might not handle rent properly
    if (/close\s*=|\.close\(/.test(funcBody)) {
      const handlesRentOnClose = /\.to_account_info\(\),\s*\w+\.to_account_info\(\)/.test(funcBody) ||
        /close_account/.test(funcBody);
      
      // This is usually handled by Anchor, but flag raw implementations
      if (!handlesRentOnClose && !/#\[account\([^)]*close/.test(funcBody)) {
        findings.push({
          pattern: 'SOL014',
          severity: 'low',
          title: 'Manual Account Close - Verify Rent Handling',
          description: `Function '${func.name}' appears to close an account. Ensure all lamports are transferred to a destination before zeroing data.`,
          location: `${input.path}`,
          recommendation: 'Use Anchor\'s close constraint or ensure lamports are fully transferred before zeroing account data.',
        });
      }
    }
  }
  
  // Global check: look for raw account creation without rent
  const rawCreatePattern = /system_instruction::create_account\s*\([^)]+\)/g;
  let match;
  while ((match = rawCreatePattern.exec(content)) !== null) {
    // Check if Rent::get is nearby
    const context = content.slice(Math.max(0, match.index - 500), match.index + match[0].length + 200);
    if (!/Rent::get\(\)|minimum_balance/.test(context)) {
      let lineNum = 1;
      let charCount = 0;
      for (let i = 0; i < lines.length; i++) {
        charCount += lines[i].length + 1;
        if (charCount >= match.index) {
          lineNum = i + 1;
          break;
        }
      }
      
      findings.push({
        pattern: 'SOL014',
        severity: 'medium',
        title: 'Account Creation Without Rent Calculation',
        description: 'create_account instruction found without nearby Rent::get() call. Hardcoded lamport values may become insufficient.',
        location: `${input.path}:${lineNum}`,
        recommendation: 'Calculate lamports dynamically: Rent::get()?.minimum_balance(space)',
      });
    }
  }
  
  return findings;
}
