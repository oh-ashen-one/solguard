import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

export function checkAccountOwnership(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';
  const fileName = input.rust?.filePath || 'unknown';

  // Check for missing owner field validation
  const ownerPatterns = [
    /\.owner\s*(?:!=|==)/g,
    /owner:\s*\w+/g,
    /has_one\s*=\s*owner/g,
  ];

  // Check if there are account operations without owner checks
  if (content.includes('AccountInfo') || content.includes('#[account')) {
    const hasOwnerCheck = ownerPatterns.some(p => p.test(content));
    
    // Look for potential unsafe patterns
    const unsafeAccessPatterns = [
      /\.data\.borrow_mut\(\)/g,
      /\.try_borrow_mut_data\(\)/g,
    ];

    for (const pattern of unsafeAccessPatterns) {
      const matches = [...content.matchAll(pattern)];
      for (const match of matches) {
        const contextStart = Math.max(0, match.index! - 500);
        const contextEnd = Math.min(content.length, match.index! + 200);
        const context = content.substring(contextStart, contextEnd);
        
        const hasLocalOwnerCheck = /\.owner\s*(?:!=|==)|owner\.key|owner_check/.test(context);
        if (!hasLocalOwnerCheck) {
          const lineNumber = content.substring(0, match.index).split('\n').length;
          findings.push({
            id: 'SOL161',
            title: 'Mutable Data Access Without Owner Check',
            severity: 'critical',
            description: 'Account data is being mutated without apparent owner validation. Any program could potentially modify this data.',
            location: { file: fileName, line: lineNumber },
            recommendation: 'Verify account.owner == expected_program_id before modifying account data.',
          });
        }
      }
    }
  }

  // Check for token account ownership validation
  if (content.includes('TokenAccount') || content.includes('token_account') || content.includes('spl_token')) {
    const tokenAccountPatterns = [
      /token_account/gi,
      /user_token/gi,
      /source_account/gi,
      /destination_account/gi,
    ];

    for (const pattern of tokenAccountPatterns) {
      const matches = [...content.matchAll(pattern)];
      for (const match of matches) {
        const contextStart = Math.max(0, match.index! - 400);
        const contextEnd = Math.min(content.length, match.index! + 400);
        const context = content.substring(contextStart, contextEnd);
        
        if (!context.includes('.owner') && !context.includes('authority') && 
            !context.includes('has_one') && !context.includes('constraint')) {
          const lineNumber = content.substring(0, match.index).split('\n').length;
          findings.push({
            id: 'SOL161',
            title: 'Token Account Without Owner Validation',
            severity: 'high',
            description: 'Token account used without validating ownership. Users may pass token accounts they do not own.',
            location: { file: fileName, line: lineNumber },
            recommendation: 'Verify token_account.owner == expected_owner before operations.',
          });
          break;
        }
      }
    }
  }

  // Check for PDA ownership assumption
  const pdaPattern = /find_program_address|create_program_address/g;
  const pdaMatches = [...content.matchAll(pdaPattern)];
  for (const match of pdaMatches) {
    const contextEnd = Math.min(content.length, match.index! + 500);
    const context = content.substring(match.index!, contextEnd);
    
    if (!context.includes('.owner') && !context.includes('owner ==')) {
      const lineNumber = content.substring(0, match.index).split('\n').length;
      findings.push({
        id: 'SOL161',
        title: 'PDA Used Without Owner Verification',
        severity: 'medium',
        description: 'PDA address derived but ownership not explicitly verified. Ensure PDA is owned by expected program.',
        location: { file: fileName, line: lineNumber },
        recommendation: 'After deriving PDA, verify account.owner == program_id to ensure it was created by this program.',
      });
    }
  }

  // Check for system account ownership
  if (content.includes('system_program') || content.includes('SystemProgram')) {
    const systemAccounts = [...content.matchAll(/system_account|new_account|payer/gi)];
    for (const match of systemAccounts) {
      const contextEnd = Math.min(content.length, match.index! + 300);
      const context = content.substring(match.index!, contextEnd);
      
      if (!context.includes('system_program') && !context.includes('owner')) {
        const lineNumber = content.substring(0, match.index).split('\n').length;
        findings.push({
          id: 'SOL161',
          title: 'System Account Ownership Not Verified',
          severity: 'medium',
          description: 'System-owned account used without verifying it is owned by System Program.',
          location: { file: fileName, line: lineNumber },
          recommendation: 'Verify account.owner == system_program::ID for system accounts.',
        });
      }
    }
  }

  // Check for program-specific account ownership
  const programOwnedPattern = /owner\s*=\s*(?:crate::)?[A-Z][A-Za-z]+/g;
  if (!programOwnedPattern.test(content) && content.includes('#[account')) {
    // Check if any accounts should specify owner
    const accountStructs = [...content.matchAll(/#\[account\([^\)]+\)\]\s*pub\s+(\w+)/g)];
    for (const match of accountStructs) {
      const constraints = match[0];
      if (!constraints.includes('owner') && !constraints.includes('init') && 
          !constraints.includes('seeds')) {
        const lineNumber = content.substring(0, match.index).split('\n').length;
        findings.push({
          id: 'SOL161',
          title: 'Account Without Owner Specification',
          severity: 'medium',
          description: 'Anchor account without explicit owner constraint. May accept accounts from any program.',
          location: { file: fileName, line: lineNumber },
          recommendation: 'Add owner = <program> constraint or use Account<T> type which enforces program ownership.',
        });
      }
    }
  }

  return findings;
}
