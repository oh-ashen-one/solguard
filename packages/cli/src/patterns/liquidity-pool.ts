import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

export function checkLiquidityPool(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';
  const fileName = input.rust?.filePath || 'unknown';

  // Check for constant product formula manipulation
  const swapPatterns = [
    /fn\s+swap/gi,
    /fn\s+exchange/gi,
    /constant_product/gi,
    /x\s*\*\s*y\s*=\s*k/gi,
  ];

  for (const pattern of swapPatterns) {
    const matches = [...content.matchAll(pattern)];
    for (const match of matches) {
      const contextEnd = Math.min(content.length, match.index! + 1500);
      const functionContext = content.substring(match.index!, contextEnd);
      
      // Check for invariant preservation
      if (!functionContext.includes('invariant') && !functionContext.includes('product') &&
          functionContext.includes('reserve')) {
        const lineNumber = content.substring(0, match.index).split('\n').length;
        findings.push({
          id: 'SOL160',
          title: 'AMM Swap Without Invariant Check',
          severity: 'critical',
          description: 'AMM swap operation without verifying constant product invariant is preserved. Attackers can manipulate reserves.',
          location: { file: fileName, line: lineNumber },
          recommendation: 'Verify k = reserve_a * reserve_b is preserved (accounting for fees) after each swap.',
        });
      }
    }
  }

  // Check for liquidity provision attacks
  const addLiquidityPatterns = [
    /fn\s+add_liquidity/gi,
    /fn\s+deposit_liquidity/gi,
    /fn\s+provide_liquidity/gi,
  ];

  for (const pattern of addLiquidityPatterns) {
    const matches = [...content.matchAll(pattern)];
    for (const match of matches) {
      const contextEnd = Math.min(content.length, match.index! + 1500);
      const functionContext = content.substring(match.index!, contextEnd);
      
      // Check for proportional deposit requirement
      if (!functionContext.includes('ratio') && !functionContext.includes('proportion') &&
          !functionContext.includes('balanced')) {
        const lineNumber = content.substring(0, match.index).split('\n').length;
        findings.push({
          id: 'SOL160',
          title: 'Unbalanced Liquidity Addition',
          severity: 'high',
          description: 'Liquidity addition without requiring proportional deposits. Can cause pool imbalance and arbitrage opportunities.',
          location: { file: fileName, line: lineNumber },
          recommendation: 'Require deposits in proportion to current pool reserves, or implement single-sided deposit with appropriate fee.',
        });
      }

      // Check for first depositor attack protection
      if (!functionContext.includes('min_liquidity') && !functionContext.includes('MINIMUM_LIQUIDITY') &&
          !functionContext.includes('initial_mint')) {
        const lineNumber = content.substring(0, match.index).split('\n').length;
        findings.push({
          id: 'SOL160',
          title: 'First Depositor Attack Vector',
          severity: 'critical',
          description: 'No minimum liquidity lock for first depositor. Attacker can manipulate initial price by depositing minimal amounts.',
          location: { file: fileName, line: lineNumber },
          recommendation: 'Lock minimum liquidity tokens (e.g., 1000 units) to dead address on first deposit to prevent manipulation.',
        });
      }
    }
  }

  // Check for withdrawal attacks
  const removeLiquidityPatterns = [
    /fn\s+remove_liquidity/gi,
    /fn\s+withdraw_liquidity/gi,
    /fn\s+burn_liquidity/gi,
  ];

  for (const pattern of removeLiquidityPatterns) {
    const matches = [...content.matchAll(pattern)];
    for (const match of matches) {
      const contextEnd = Math.min(content.length, match.index! + 1500);
      const functionContext = content.substring(match.index!, contextEnd);
      
      // Check for minimum output amounts
      if (!functionContext.includes('min_a') && !functionContext.includes('min_b') &&
          !functionContext.includes('min_amount') && !functionContext.includes('minimum')) {
        const lineNumber = content.substring(0, match.index).split('\n').length;
        findings.push({
          id: 'SOL160',
          title: 'Liquidity Removal Without Minimum Output',
          severity: 'high',
          description: 'Liquidity withdrawal without minimum output amounts. Vulnerable to sandwich attacks.',
          location: { file: fileName, line: lineNumber },
          recommendation: 'Require minimum output amounts for both tokens to protect against front-running.',
        });
      }
    }
  }

  // Check for flash loan resistance
  if (content.includes('pool') || content.includes('liquidity') || content.includes('reserve')) {
    const hasFlashProtection = 
      content.includes('flash_loan_fee') ||
      content.includes('callback') ||
      content.includes('repay') ||
      content.includes('lock_') ||
      content.includes('reentrancy');

    if (!hasFlashProtection && (content.includes('borrow') || content.includes('loan'))) {
      findings.push({
        id: 'SOL160',
        title: 'Pool Without Flash Loan Protection',
        severity: 'high',
        description: 'Liquidity pool may be vulnerable to flash loan attacks. No apparent flash loan fee or protection mechanism.',
        location: { file: fileName, line: 1 },
        recommendation: 'Implement flash loan fees or use callbacks to ensure borrowed funds are returned with fee.',
      });
    }
  }

  // Check for reserve manipulation
  if (content.includes('reserve') || content.includes('Reserve')) {
    const reserveUpdatePattern = /reserve\w*\s*[+\-]=|reserve\w*\s*=\s*\w/gi;
    const matches = [...content.matchAll(reserveUpdatePattern)];
    
    for (const match of matches) {
      const contextStart = Math.max(0, match.index! - 300);
      const contextEnd = Math.min(content.length, match.index! + 300);
      const context = content.substring(contextStart, contextEnd);
      
      if (!context.includes('require!') && !context.includes('checked_') && 
          !context.includes('overflow')) {
        const lineNumber = content.substring(0, match.index).split('\n').length;
        findings.push({
          id: 'SOL160',
          title: 'Unprotected Reserve Update',
          severity: 'critical',
          description: 'Pool reserve update without apparent validation. Reserves can potentially be manipulated.',
          location: { file: fileName, line: lineNumber },
          recommendation: 'Use checked arithmetic and validate reserve changes match actual token transfers.',
        });
      }
    }
  }

  // Check for LP token minting accuracy
  if (content.includes('lp_token') || content.includes('liquidity_token') || content.includes('shares')) {
    const mintPattern = /mint\w*\s*=|lp_amount|shares_to_mint/gi;
    const matches = [...content.matchAll(mintPattern)];
    
    for (const match of matches) {
      const contextEnd = Math.min(content.length, match.index! + 500);
      const context = content.substring(match.index!, contextEnd);
      
      if (context.includes('/') && !context.includes('checked_div') && !context.includes('as u128')) {
        const lineNumber = content.substring(0, match.index).split('\n').length;
        findings.push({
          id: 'SOL160',
          title: 'LP Token Calculation Precision',
          severity: 'medium',
          description: 'LP token calculation may have precision issues due to integer division.',
          location: { file: fileName, line: lineNumber },
          recommendation: 'Use u128 for intermediate calculations and checked arithmetic to prevent precision loss.',
        });
      }
    }
  }

  return findings;
}
