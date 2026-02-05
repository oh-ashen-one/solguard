import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

export function checkFrontRunning(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';
  const fileName = input.rust?.filePath || 'unknown';

  // Check for swap operations without slippage protection
  const swapPatterns = [
    /fn\s+swap\s*\(/gi,
    /fn\s+exchange\s*\(/gi,
    /fn\s+trade\s*\(/gi,
    /token_swap/gi,
    /swap_exact/gi,
  ];

  const slippagePatterns = [
    /min_amount/i,
    /minimum_out/i,
    /slippage/i,
    /min_expected/i,
    /amount_threshold/i,
    /min_receive/i,
    /expected_min/i,
  ];

  for (const swapPattern of swapPatterns) {
    const matches = [...content.matchAll(swapPattern)];
    for (const match of matches) {
      const contextEnd = Math.min(content.length, match.index! + 2000);
      const functionContext = content.substring(match.index!, contextEnd);
      
      const hasSlippageProtection = slippagePatterns.some(p => p.test(functionContext));
      if (!hasSlippageProtection) {
        const lineNumber = content.substring(0, match.index).split('\n').length;
        findings.push({
          id: 'SOL153',
          title: 'Swap Without Slippage Protection',
          severity: 'critical',
          description: 'Token swap operation detected without apparent slippage protection. Attackers can sandwich the transaction to extract value through front-running and back-running.',
          location: { file: fileName, line: lineNumber },
          recommendation: 'Implement minimum output amount parameter and validate received tokens meet the threshold. Consider using commit-reveal schemes for large trades.',
        });
      }
    }
  }

  // Check for initialization without commit-reveal
  const initPatterns = [
    /pub\s+fn\s+initialize\s*\(/g,
    /fn\s+create_pool\s*\(/gi,
    /fn\s+init_\w+\s*\(/gi,
  ];

  for (const pattern of initPatterns) {
    const matches = [...content.matchAll(pattern)];
    for (const match of matches) {
      const contextEnd = Math.min(content.length, match.index! + 1500);
      const functionContext = content.substring(match.index!, contextEnd);
      
      if (!functionContext.includes('commit') && !functionContext.includes('reveal') && 
          !functionContext.includes('hash') && !functionContext.includes('merkle')) {
        const lineNumber = content.substring(0, match.index).split('\n').length;
        findings.push({
          id: 'SOL153',
          title: 'Initialization Front-Running Risk',
          severity: 'high',
          description: 'Initialization function without commit-reveal pattern. Attackers watching the mempool can front-run initialization to claim authority or favorable positions.',
          location: { file: fileName, line: lineNumber },
          recommendation: 'Consider using PDA derivation from user pubkey, commit-reveal schemes, or time-locked initialization.',
        });
      }
    }
  }

  // Check for bid/auction without time protection
  const auctionPatterns = [
    /fn\s+place_bid\s*\(/gi,
    /fn\s+bid\s*\(/gi,
    /fn\s+auction/gi,
  ];

  for (const pattern of auctionPatterns) {
    const matches = [...content.matchAll(pattern)];
    for (const match of matches) {
      const contextEnd = Math.min(content.length, match.index! + 1500);
      const functionContext = content.substring(match.index!, contextEnd);
      
      if (!functionContext.includes('deadline') && !functionContext.includes('end_time') && 
          !functionContext.includes('auction_end')) {
        const lineNumber = content.substring(0, match.index).split('\n').length;
        findings.push({
          id: 'SOL153',
          title: 'Auction Without Time Bounds',
          severity: 'medium',
          description: 'Auction/bidding function without apparent time bounds. This can lead to indefinite auctions or front-running of bids.',
          location: { file: fileName, line: lineNumber },
          recommendation: 'Implement clear auction deadlines and consider sealed-bid mechanisms to prevent front-running.',
        });
      }
    }
  }

  // Check for price-sensitive operations without deadline
  const deadlinePatterns = [
    /deadline/i,
    /expiry/i,
    /valid_until/i,
    /expires_at/i,
  ];

  if (content.includes('amount_in') || content.includes('amount_out')) {
    const hasDeadline = deadlinePatterns.some(p => p.test(content));
    if (!hasDeadline) {
      findings.push({
        id: 'SOL153',
        title: 'Missing Transaction Deadline',
        severity: 'medium',
        description: 'Price-sensitive operation without transaction deadline. Transactions can be held in mempool and executed at unfavorable times.',
        location: { file: fileName, line: 1 },
        recommendation: 'Add a deadline parameter and reject transactions that exceed it. Use Clock::get() to check current time against deadline.',
      });
    }
  }

  return findings;
}
