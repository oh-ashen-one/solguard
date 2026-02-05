import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

export function checkEscrowSafety(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';
  const fileName = input.rust?.filePath || 'unknown';

  // Check for escrow release conditions
  const escrowPatterns = [
    /fn\s+(?:release|withdraw)_escrow/gi,
    /fn\s+complete_escrow/gi,
    /escrow.*release/gi,
  ];

  for (const pattern of escrowPatterns) {
    const matches = [...content.matchAll(pattern)];
    for (const match of matches) {
      const contextEnd = Math.min(content.length, match.index! + 1500);
      const functionContext = content.substring(match.index!, contextEnd);
      
      // Check for conditional release
      if (!functionContext.includes('require!') && !functionContext.includes('if ') &&
          !functionContext.includes('match ')) {
        const lineNumber = content.substring(0, match.index).split('\n').length;
        findings.push({
          id: 'SOL165',
          title: 'Unconditional Escrow Release',
          severity: 'critical',
          description: 'Escrow release without apparent conditions. Funds may be released without meeting contract requirements.',
          location: { file: fileName, line: lineNumber },
          recommendation: 'Implement clear release conditions (e.g., both parties approve, deadline passed, deliverable confirmed).',
        });
      }

      // Check for dispute handling
      if (!functionContext.includes('dispute') && !functionContext.includes('refund') &&
          !functionContext.includes('cancel')) {
        const lineNumber = content.substring(0, match.index).split('\n').length;
        findings.push({
          id: 'SOL165',
          title: 'Escrow Without Dispute Mechanism',
          severity: 'high',
          description: 'Escrow without apparent dispute resolution. Locked funds may become unrecoverable.',
          location: { file: fileName, line: lineNumber },
          recommendation: 'Implement dispute mechanism with timeout-based automatic resolution.',
        });
      }
    }
  }

  // Check for escrow timeout handling
  if (content.includes('escrow') || content.includes('Escrow')) {
    const hasTimeout = content.includes('timeout') || content.includes('deadline') ||
                       content.includes('expiry') || content.includes('expire');
    
    if (!hasTimeout) {
      findings.push({
        id: 'SOL165',
        title: 'Escrow Without Timeout',
        severity: 'high',
        description: 'Escrow mechanism without timeout handling. Funds can be locked indefinitely.',
        location: { file: fileName, line: 1 },
        recommendation: 'Add deadline/timeout after which escrowed funds can be reclaimed by depositor.',
      });
    }
  }

  // Check for multi-party escrow safety
  const multiPartyPattern = /parties|participants|signers_required|threshold/gi;
  const multiPartyMatches = [...content.matchAll(multiPartyPattern)];
  
  if (multiPartyMatches.length > 0 && content.includes('escrow')) {
    for (const match of multiPartyMatches) {
      const contextEnd = Math.min(content.length, match.index! + 1000);
      const functionContext = content.substring(match.index!, contextEnd);
      
      // Check for quorum validation
      if (!functionContext.includes('quorum') && !functionContext.includes('threshold') &&
          !functionContext.includes('required_signatures')) {
        const lineNumber = content.substring(0, match.index).split('\n').length;
        findings.push({
          id: 'SOL165',
          title: 'Multi-Party Escrow Without Quorum',
          severity: 'high',
          description: 'Multi-party escrow without clear quorum requirements.',
          location: { file: fileName, line: lineNumber },
          recommendation: 'Define clear quorum (e.g., 2/3 parties) required to release escrowed funds.',
        });
      }
    }
  }

  // Check for partial release safety
  const partialReleasePattern = /partial_release|release_amount|withdraw_amount/gi;
  const partialMatches = [...content.matchAll(partialReleasePattern)];
  
  for (const match of partialMatches) {
    const contextEnd = Math.min(content.length, match.index! + 800);
    const functionContext = content.substring(match.index!, contextEnd);
    
    if (!functionContext.includes('remaining') && !functionContext.includes('balance') &&
        !functionContext.includes('total')) {
      const lineNumber = content.substring(0, match.index).split('\n').length;
      findings.push({
        id: 'SOL165',
        title: 'Partial Escrow Release Without Balance Track',
        severity: 'high',
        description: 'Partial escrow release without tracking remaining balance. Over-withdrawal may be possible.',
        location: { file: fileName, line: lineNumber },
        recommendation: 'Track and validate remaining escrow balance on each partial release.',
      });
    }
  }

  // Check for escrow state tracking
  const escrowStatePattern = /EscrowState|escrow_status|state/gi;
  const stateMatches = [...content.matchAll(escrowStatePattern)];
  
  if (content.includes('escrow') && stateMatches.length === 0) {
    findings.push({
      id: 'SOL165',
      title: 'Escrow Without State Machine',
      severity: 'medium',
      description: 'Escrow without apparent state tracking. State machine helps prevent invalid transitions.',
      location: { file: fileName, line: 1 },
      recommendation: 'Implement state enum (Created, Funded, Released, Disputed, Cancelled) and validate transitions.',
    });
  }

  // Check for reentrancy in escrow
  if (content.includes('escrow') && content.includes('transfer')) {
    const transferPattern = /transfer|invoke/gi;
    const transferMatches = [...content.matchAll(transferPattern)];
    
    for (const match of transferMatches) {
      const contextStart = Math.max(0, match.index! - 300);
      const contextEnd = Math.min(content.length, match.index! + 300);
      const context = content.substring(contextStart, contextEnd);
      
      // Check if state is updated before transfer
      if (context.includes('escrow') && !context.includes('= true') && 
          !context.includes('= false') && !context.includes('status')) {
        const lineNumber = content.substring(0, match.index).split('\n').length;
        findings.push({
          id: 'SOL165',
          title: 'Potential Escrow Reentrancy',
          severity: 'high',
          description: 'Transfer before state update in escrow context. Reentrancy may allow multiple releases.',
          location: { file: fileName, line: lineNumber },
          recommendation: 'Update escrow state (mark as released) before transferring funds.',
        });
      }
    }
  }

  return findings;
}
