import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

export function checkBorrowRate(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';
  const fileName = input.rust?.filePath || 'unknown';

  // Check for interest rate calculation patterns
  const interestPatterns = [
    /fn\s+(?:calculate_)?interest/gi,
    /fn\s+accrue_interest/gi,
    /borrow_rate/gi,
    /supply_rate/gi,
    /interest_rate/gi,
  ];

  for (const pattern of interestPatterns) {
    const matches = [...content.matchAll(pattern)];
    for (const match of matches) {
      const contextEnd = Math.min(content.length, match.index! + 1500);
      const functionContext = content.substring(match.index!, contextEnd);
      
      // Check for utilization rate in interest calculation
      if (!functionContext.includes('utilization') && functionContext.includes('rate')) {
        const lineNumber = content.substring(0, match.index).split('\n').length;
        findings.push({
          id: 'SOL166',
          title: 'Interest Rate Without Utilization',
          severity: 'high',
          description: 'Interest rate calculation without considering utilization rate. Rates may not respond to market conditions.',
          location: { file: fileName, line: lineNumber },
          recommendation: 'Calculate interest based on utilization: borrow_rate = base_rate + utilization * slope',
        });
      }

      // Check for rate bounds
      if (!functionContext.includes('max_rate') && !functionContext.includes('min_rate') &&
          !functionContext.includes('cap') && !functionContext.includes('floor')) {
        const lineNumber = content.substring(0, match.index).split('\n').length;
        findings.push({
          id: 'SOL166',
          title: 'Unbounded Interest Rate',
          severity: 'high',
          description: 'Interest rate without maximum cap. Extreme rates could make positions immediately liquidatable.',
          location: { file: fileName, line: lineNumber },
          recommendation: 'Implement interest rate caps to prevent exploitation during high utilization.',
        });
      }
    }
  }

  // Check for accrual timing issues
  const accrualPatterns = [
    /accrue/gi,
    /compound/gi,
    /update_rate/gi,
  ];

  for (const pattern of accrualPatterns) {
    const matches = [...content.matchAll(pattern)];
    for (const match of matches) {
      const contextEnd = Math.min(content.length, match.index! + 1000);
      const functionContext = content.substring(match.index!, contextEnd);
      
      // Check for time delta in accrual
      if (!functionContext.includes('time_elapsed') && !functionContext.includes('last_update') &&
          !functionContext.includes('delta') && !functionContext.includes('duration')) {
        const lineNumber = content.substring(0, match.index).split('\n').length;
        findings.push({
          id: 'SOL166',
          title: 'Interest Accrual Without Time Delta',
          severity: 'critical',
          description: 'Interest accrual without time-based calculation. Repeated calls could compound interest incorrectly.',
          location: { file: fileName, line: lineNumber },
          recommendation: 'Calculate interest based on (current_time - last_accrual_time). Store last_accrual_timestamp.',
        });
      }
    }
  }

  // Check for borrow health monitoring
  if (content.includes('borrow') && (content.includes('health') || content.includes('collateral'))) {
    const healthPattern = /health_factor|collateral_ratio|ltv/gi;
    const matches = [...content.matchAll(healthPattern)];
    
    for (const match of matches) {
      const contextEnd = Math.min(content.length, match.index! + 1000);
      const functionContext = content.substring(match.index!, contextEnd);
      
      // Check for liquidation threshold
      if (!functionContext.includes('liquidation_threshold') && !functionContext.includes('min_health')) {
        const lineNumber = content.substring(0, match.index).split('\n').length;
        findings.push({
          id: 'SOL166',
          title: 'Missing Liquidation Threshold',
          severity: 'high',
          description: 'Health factor calculated without clear liquidation threshold.',
          location: { file: fileName, line: lineNumber },
          recommendation: 'Define clear liquidation threshold (e.g., health_factor < 1.0 triggers liquidation).',
        });
      }
    }
  }

  // Check for flash borrow protection
  if (content.includes('borrow')) {
    const borrowFnPattern = /fn\s+borrow\s*\(/gi;
    const matches = [...content.matchAll(borrowFnPattern)];
    
    for (const match of matches) {
      const contextEnd = Math.min(content.length, match.index! + 1500);
      const functionContext = content.substring(match.index!, contextEnd);
      
      // Check for same-block borrow protection
      if (!functionContext.includes('flash') && !functionContext.includes('callback') &&
          !functionContext.includes('same_slot') && !functionContext.includes('lock')) {
        const lineNumber = content.substring(0, match.index).split('\n').length;
        findings.push({
          id: 'SOL166',
          title: 'Borrow Without Flash Protection',
          severity: 'high',
          description: 'Borrow function without flash loan protection. Users may borrow and repay in same transaction.',
          location: { file: fileName, line: lineNumber },
          recommendation: 'Implement same-slot borrow restriction or proper flash loan fee structure.',
        });
      }
    }
  }

  // Check for reserve factor handling
  if (content.includes('reserve') && content.includes('interest')) {
    if (!content.includes('reserve_factor') && !content.includes('protocol_fee')) {
      findings.push({
        id: 'SOL166',
        title: 'Missing Reserve Factor',
        severity: 'medium',
        description: 'Interest calculations without reserve factor. Protocol may not accumulate sufficient reserves.',
        location: { file: fileName, line: 1 },
        recommendation: 'Implement reserve factor to accumulate protocol-owned liquidity from interest.',
      });
    }
  }

  // Check for rate model complexity
  const kinkPattern = /kink|optimal_utilization|threshold/gi;
  if (content.includes('interest') && !kinkPattern.test(content)) {
    findings.push({
      id: 'SOL166',
      title: 'Simple Interest Rate Model',
      severity: 'low',
      description: 'Interest model appears to be linear. Consider kinked model for better capital efficiency.',
      location: { file: fileName, line: 1 },
      recommendation: 'Implement kinked rate model: low rates below optimal utilization, high rates above.',
    });
  }

  return findings;
}
