import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

export function checkCallbackAttack(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';
  const fileName = input.rust?.filePath || 'unknown';

  // Check for callback-based vulnerabilities
  const callbackPatterns = [
    /callback/gi,
    /on_complete/gi,
    /after_transfer/gi,
    /hook/gi,
    /receiver/gi,
  ];

  for (const pattern of callbackPatterns) {
    const matches = [...content.matchAll(pattern)];
    for (const match of matches) {
      const contextEnd = Math.min(content.length, match.index! + 1500);
      const functionContext = content.substring(match.index!, contextEnd);
      
      // Check for reentrancy protection
      if (!functionContext.includes('nonreentrant') && !functionContext.includes('lock') &&
          !functionContext.includes('in_progress') && !functionContext.includes('entered')) {
        const lineNumber = content.substring(0, match.index).split('\n').length;
        findings.push({
          id: 'SOL170',
          title: 'Callback Without Reentrancy Guard',
          severity: 'critical',
          description: 'Callback mechanism without reentrancy protection. Malicious contracts can re-enter during callback.',
          location: { file: fileName, line: lineNumber },
          recommendation: 'Implement reentrancy guard: set flag before callback, check flag on entry.',
        });
      }

      // Check for state finalization before callback
      if (functionContext.includes('invoke') || functionContext.includes('CpiContext')) {
        const beforeInvoke = functionContext.split(/invoke|CpiContext/)[0];
        if (!beforeInvoke.includes('=') || beforeInvoke.length < 50) {
          const lineNumber = content.substring(0, match.index).split('\n').length;
          findings.push({
            id: 'SOL170',
            title: 'Callback Before State Update',
            severity: 'high',
            description: 'State may not be updated before callback invocation. Vulnerable to read-only reentrancy.',
            location: { file: fileName, line: lineNumber },
            recommendation: 'Finalize all state changes before invoking external callbacks.',
          });
        }
      }
    }
  }

  // Check for flash callback vulnerabilities
  const flashCallbackPatterns = [
    /flash_callback/gi,
    /flash_loan_callback/gi,
    /on_flash_loan/gi,
  ];

  for (const pattern of flashCallbackPatterns) {
    const matches = [...content.matchAll(pattern)];
    for (const match of matches) {
      const contextEnd = Math.min(content.length, match.index! + 1500);
      const functionContext = content.substring(match.index!, contextEnd);
      
      // Check for repayment verification
      if (!functionContext.includes('repay') && !functionContext.includes('return') &&
          !functionContext.includes('balance')) {
        const lineNumber = content.substring(0, match.index).split('\n').length;
        findings.push({
          id: 'SOL170',
          title: 'Flash Callback Without Repayment Check',
          severity: 'critical',
          description: 'Flash loan callback without verifying repayment. Borrower may not repay.',
          location: { file: fileName, line: lineNumber },
          recommendation: 'Verify loan + fee is repaid after callback returns.',
        });
      }

      // Check for initiator validation
      if (!functionContext.includes('initiator') && !functionContext.includes('caller') &&
          !functionContext.includes('sender')) {
        const lineNumber = content.substring(0, match.index).split('\n').length;
        findings.push({
          id: 'SOL170',
          title: 'Flash Callback Without Initiator Check',
          severity: 'high',
          description: 'Flash loan callback without validating initiator. Could be called by anyone.',
          location: { file: fileName, line: lineNumber },
          recommendation: 'Verify callback was initiated by expected flash loan provider.',
        });
      }
    }
  }

  // Check for token receiver hooks (Token-2022)
  if (content.includes('token_2022') || content.includes('TransferHook')) {
    const hookPatterns = [
      /TransferHook/gi,
      /execute_hook/gi,
      /transfer_hook/gi,
    ];

    for (const pattern of hookPatterns) {
      const matches = [...content.matchAll(pattern)];
      for (const match of matches) {
        const contextEnd = Math.min(content.length, match.index! + 1000);
        const functionContext = content.substring(match.index!, contextEnd);
        
        // Check for compute budget
        if (!functionContext.includes('compute') && !functionContext.includes('budget')) {
          const lineNumber = content.substring(0, match.index).split('\n').length;
          findings.push({
            id: 'SOL170',
            title: 'Transfer Hook Without Compute Consideration',
            severity: 'medium',
            description: 'Token-2022 transfer hook without compute budget handling. Complex hooks may cause transfers to fail.',
            location: { file: fileName, line: lineNumber },
            recommendation: 'Consider compute budget impact of transfer hooks on dependent operations.',
          });
        }
      }
    }
  }

  // Check for CPI callback vulnerabilities
  const cpiCallbackPattern = /return_data|get_return_data|sol_get_return_data/gi;
  const cpiMatches = [...content.matchAll(cpiCallbackPattern)];
  
  for (const match of cpiMatches) {
    const contextEnd = Math.min(content.length, match.index! + 800);
    const functionContext = content.substring(match.index!, contextEnd);
    
    // Check for return data validation
    if (!functionContext.includes('program_id') && !functionContext.includes('verify')) {
      const lineNumber = content.substring(0, match.index).split('\n').length;
      findings.push({
        id: 'SOL170',
        title: 'CPI Return Data Without Source Validation',
        severity: 'high',
        description: 'CPI return data read without verifying source program. Malicious programs can set return data.',
        location: { file: fileName, line: lineNumber },
        recommendation: 'Verify return data program_id matches expected CPI target.',
      });
    }
  }

  // Check for arbitrary callback invocation
  const arbitraryCallbackPattern = /callback_program|callback_ix|user_callback/gi;
  const arbitraryMatches = [...content.matchAll(arbitraryCallbackPattern)];
  
  for (const match of arbitraryMatches) {
    const contextEnd = Math.min(content.length, match.index! + 1000);
    const functionContext = content.substring(match.index!, contextEnd);
    
    // Check for program whitelist
    if (!functionContext.includes('whitelist') && !functionContext.includes('allowed') &&
        !functionContext.includes('trusted')) {
      const lineNumber = content.substring(0, match.index).split('\n').length;
      findings.push({
        id: 'SOL170',
        title: 'Arbitrary Callback Program',
        severity: 'critical',
        description: 'User can specify arbitrary callback program. Malicious programs can be invoked.',
        location: { file: fileName, line: lineNumber },
        recommendation: 'Whitelist allowed callback programs or restrict to specific trusted programs.',
      });
    }
  }

  return findings;
}
