import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

export function checkFeeExtraction(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';
  const fileName = input.rust?.filePath || 'unknown';

  // Check for fee bypass vulnerabilities
  const transferPatterns = [
    /fn\s+transfer\s*\(/gi,
    /fn\s+send\s*\(/gi,
    /transfer_checked/gi,
    /Transfer\s*\{/gi,
  ];

  for (const pattern of transferPatterns) {
    const matches = [...content.matchAll(pattern)];
    for (const match of matches) {
      const contextStart = Math.max(0, match.index! - 500);
      const contextEnd = Math.min(content.length, match.index! + 1000);
      const context = content.substring(contextStart, contextEnd);
      
      // Check if fee is calculated but could be bypassed
      if (context.includes('fee') && !context.includes('require!') && 
          !context.includes('constraint') && !context.includes('checked_sub')) {
        const lineNumber = content.substring(0, match.index).split('\n').length;
        findings.push({
          id: 'SOL158',
          title: 'Potential Fee Bypass Vulnerability',
          severity: 'high',
          description: 'Transfer function with fee calculation that may be bypassable. Ensure fees cannot be skipped through alternate code paths.',
          location: { file: fileName, line: lineNumber },
          recommendation: 'Enforce fee collection in all transfer paths. Use require! to validate fee payment.',
        });
      }
    }
  }

  // Check for referral fee exploitation
  if (content.includes('referral') || content.includes('affiliate')) {
    const referralPatterns = [
      /referral_fee/gi,
      /affiliate_fee/gi,
      /referrer/gi,
    ];

    for (const pattern of referralPatterns) {
      const matches = [...content.matchAll(pattern)];
      for (const match of matches) {
        const contextEnd = Math.min(content.length, match.index! + 1000);
        const functionContext = content.substring(match.index!, contextEnd);
        
        // Check for self-referral prevention
        if (!functionContext.includes('!= user') && !functionContext.includes('!= sender') &&
            !functionContext.includes('referrer != ')) {
          const lineNumber = content.substring(0, match.index).split('\n').length;
          findings.push({
            id: 'SOL158',
            title: 'Self-Referral Fee Exploitation',
            severity: 'high',
            description: 'Referral fee system without self-referral prevention. Users can refer themselves to extract fees.',
            location: { file: fileName, line: lineNumber },
            recommendation: 'Prevent self-referral: require!(referrer != user.key(), ErrorCode::SelfReferral)',
          });
        }

        // Check for referral fee cap
        if (!functionContext.includes('max_referral') && !functionContext.includes('MAX_FEE') &&
            !functionContext.includes('cap') && !functionContext.includes('limit')) {
          const lineNumber = content.substring(0, match.index).split('\n').length;
          findings.push({
            id: 'SOL158',
            title: 'Uncapped Referral Fee',
            severity: 'medium',
            description: 'Referral fee without maximum cap. Excessive fees can drain protocol funds.',
            location: { file: fileName, line: lineNumber },
            recommendation: 'Implement maximum referral fee cap (e.g., 10% of transaction).',
          });
        }
      }
    }
  }

  // Check for protocol fee manipulation
  if (content.includes('protocol_fee') || content.includes('treasury_fee')) {
    const hasAdminCheck = content.includes('admin') || content.includes('authority') || 
                          content.includes('has_one') || content.includes('constraint');
    if (!hasAdminCheck) {
      findings.push({
        id: 'SOL158',
        title: 'Unprotected Protocol Fee Modification',
        severity: 'critical',
        description: 'Protocol/treasury fee can potentially be modified without admin authorization.',
        location: { file: fileName, line: 1 },
        recommendation: 'Restrict fee modifications to authorized admin accounts with proper access control.',
      });
    }
  }

  // Check for fee calculation precision
  const feeCalcPattern = /fee\s*[*\/=]\s*(?:\d+|amount|value)/gi;
  const feeCalcMatches = [...content.matchAll(feeCalcPattern)];
  for (const match of feeCalcMatches) {
    const context = content.substring(match.index!, match.index! + 200);
    
    // Check for integer division precision loss
    if (context.includes('/') && !context.includes('checked_div') && !context.includes('as u128')) {
      const lineNumber = content.substring(0, match.index).split('\n').length;
      findings.push({
        id: 'SOL158',
        title: 'Fee Calculation Precision Loss',
        severity: 'medium',
        description: 'Fee calculation uses integer division which can cause precision loss. Small amounts may result in zero fees.',
        location: { file: fileName, line: lineNumber },
        recommendation: 'Use checked_div and consider using u128 for intermediate calculations. Handle dust amounts appropriately.',
      });
    }
  }

  // Check for fee-on-transfer token handling
  if (content.includes('transfer') && content.includes('token')) {
    if (!content.includes('amount_received') && !content.includes('actual_amount') &&
        !content.includes('balance_after') && !content.includes('expected_amount')) {
      findings.push({
        id: 'SOL158',
        title: 'Missing Fee-on-Transfer Token Support',
        severity: 'medium',
        description: 'Token transfers without checking actual received amount. Fee-on-transfer tokens (Token-2022) can cause accounting errors.',
        location: { file: fileName, line: 1 },
        recommendation: 'For Token-2022, check actual balance change rather than assuming transfer amount equals received amount.',
      });
    }
  }

  // Check for swap fee extraction
  const swapPatterns = [
    /fn\s+swap\s*\(/gi,
    /fn\s+exchange\s*\(/gi,
  ];

  for (const pattern of swapPatterns) {
    const matches = [...content.matchAll(pattern)];
    for (const match of matches) {
      const contextEnd = Math.min(content.length, match.index! + 1500);
      const functionContext = content.substring(match.index!, contextEnd);
      
      if (functionContext.includes('fee') && !functionContext.includes('fee_account') &&
          !functionContext.includes('treasury')) {
        const lineNumber = content.substring(0, match.index).split('\n').length;
        findings.push({
          id: 'SOL158',
          title: 'Swap Fee Without Collection Account',
          severity: 'medium',
          description: 'Swap fee calculated but no apparent collection account. Fees may not be properly collected.',
          location: { file: fileName, line: lineNumber },
          recommendation: 'Ensure swap fees are transferred to designated treasury/fee account.',
        });
      }
    }
  }

  return findings;
}
