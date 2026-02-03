/**
 * SOL015: Type Cosplay Attack Detection
 * 
 * Detects when account data deserialization doesn't verify the account
 * type discriminator, allowing one account type to masquerade as another.
 * 
 * Vulnerable pattern:
 *   let data = MyStruct::try_from_slice(&account.data)?;  // No type check
 * 
 * Safe pattern:
 *   // Anchor auto-adds discriminator, or manually:
 *   require!(account.data[0..8] == MyStruct::DISCRIMINATOR);
 */

import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

export function checkTypeCosplay(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  
  if (!input.rust?.content) return findings;
  
  const { content, functions, structs } = input.rust;
  const lines = content.split('\n');
  
  // Check for manual deserialization without discriminator checks
  const deserializePatterns = [
    /try_from_slice\s*\(\s*&?\s*\w+\.data/,
    /deserialize\s*\(\s*&mut\s*&\w+\.data/,
    /BorshDeserialize::deserialize\s*\(/,
    /unpack\s*\(\s*&?\s*\w+\.data/,
  ];
  
  for (const pattern of deserializePatterns) {
    const matches = content.matchAll(new RegExp(pattern.source, 'g'));
    
    for (const match of matches) {
      // Check if there's a discriminator check nearby
      const startIndex = Math.max(0, match.index! - 300);
      const endIndex = Math.min(content.length, match.index! + 300);
      const context = content.slice(startIndex, endIndex);
      
      const hasDiscriminator = 
        /discriminator|DISCRIMINATOR|type_check|account_type/.test(context) ||
        /data\[0\]|data\[0\.\.8\]|data\[\.\.8\]/.test(context) ||
        /Account::try_from|AccountDeserialize/.test(context);  // Anchor handles this
      
      if (!hasDiscriminator) {
        let lineNum = 1;
        let charCount = 0;
        for (let i = 0; i < lines.length; i++) {
          charCount += lines[i].length + 1;
          if (charCount >= match.index!) {
            lineNum = i + 1;
            break;
          }
        }
        
        findings.push({
          pattern: 'SOL015',
          severity: 'critical',
          title: 'Type Cosplay - Missing Discriminator Check',
          description: 'Account data is deserialized without verifying the account type discriminator. An attacker could pass a different account type with matching data layout.',
          location: `${input.path}:${lineNum}`,
          recommendation: 'Use Anchor\'s Account<T> type (auto-validates discriminator) or manually check the first 8 bytes match the expected type discriminator.',
        });
      }
    }
  }
  
  // Check for structs that should have discriminators
  for (const struct of structs) {
    // Skip if it's an Anchor account (has #[account])
    if (struct.decorators?.includes('#[account]')) continue;
    
    // Check if it's used as account data but doesn't have a discriminator field
    const isAccountData = struct.body?.includes('Pubkey') || 
      struct.body?.includes('lamports') ||
      content.includes(`Account<'info, ${struct.name}>`);
    
    const hasDiscriminator = struct.body?.includes('discriminator') ||
      struct.decorators?.includes('zero_copy') ||  // Anchor zero_copy has implicit
      struct.decorators?.includes('#[account]');
    
    if (isAccountData && !hasDiscriminator) {
      let lineNum = 1;
      for (let i = 0; i < lines.length; i++) {
        if (lines[i].includes(`struct ${struct.name}`)) {
          lineNum = i + 1;
          break;
        }
      }
      
      findings.push({
        pattern: 'SOL015',
        severity: 'high',
        title: 'Account Struct Without Discriminator',
        description: `Struct '${struct.name}' appears to be account data but lacks a discriminator field. This may allow type confusion attacks.`,
        location: `${input.path}:${lineNum}`,
        recommendation: 'Add #[account] attribute (Anchor) or a discriminator field as the first 8 bytes.',
      });
    }
  }
  
  // Check for raw AccountInfo usage without proper validation
  const rawAccountPattern = /\.try_borrow_data\(\)|\.data\.borrow\(\)/g;
  let match;
  while ((match = rawAccountPattern.exec(content)) !== null) {
    const context = content.slice(Math.max(0, match.index - 400), match.index + 200);
    
    // If we're reading data, ensure there's type validation
    if (!/owner|key\(\)\s*==|discriminator|data\[0\]/.test(context)) {
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
        pattern: 'SOL015',
        severity: 'medium',
        title: 'Raw Account Data Access',
        description: 'Raw account data is accessed without visible type validation. Ensure the account type is verified before parsing.',
        location: `${input.path}:${lineNum}`,
        recommendation: 'Verify account discriminator and owner before interpreting account data.',
      });
    }
  }
  
  return findings;
}
