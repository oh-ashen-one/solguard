import type { Finding } from '../commands/audit.js';
import type { ParsedIdl } from '../parsers/idl.js';
import type { ParsedRust } from '../parsers/rust.js';

/**
 * SOL441-SOL450: Cross-Margin Trading Security
 * 
 * Cross-margin systems share collateral across positions,
 * creating unique risks around account health calculation.
 */
export function checkCrossMargin(input: { idl?: ParsedIdl; rust?: ParsedRust }): Finding[] {
  const findings: Finding[] = [];
  
  if (input.rust?.sourceCode) {
    const code = input.rust.sourceCode;
    
    // SOL441: Portfolio margin calculation
    if (/cross_margin|portfolio_margin/i.test(code) && 
        !/aggregate|total_risk|net_exposure/.test(code)) {
      findings.push({
        id: 'SOL441',
        severity: 'critical',
        title: 'Cross-Margin Risk Not Aggregated',
        description: 'Cross-margin requires aggregating risk across all positions.',
        location: 'Margin calculation',
        recommendation: 'Calculate net exposure across all positions for margin requirements.',
      });
    }
    
    // SOL442: Correlation assumptions
    if (/cross_margin/i.test(code) && 
        /hedge|offset/i.test(code) &&
        !/correlation|stress_test/.test(code)) {
      findings.push({
        id: 'SOL442',
        severity: 'high',
        title: 'Hedging Assumptions Without Stress Testing',
        description: 'Hedge offsets assume correlations that may break in volatility.',
        location: 'Risk offsetting',
        recommendation: 'Apply haircuts to hedge offsets and stress test correlations.',
      });
    }
    
    // SOL443: Withdrawal during open positions
    if (/withdraw/i.test(code) && 
        /margin|collateral/i.test(code) &&
        !/health_check|margin_check/.test(code)) {
      findings.push({
        id: 'SOL443',
        severity: 'critical',
        title: 'Withdrawal Without Margin Check',
        description: 'Withdrawals must verify account stays above margin requirements.',
        location: 'Withdrawal logic',
        recommendation: 'Check post-withdrawal margin ratio before allowing withdrawal.',
      });
    }
    
    // SOL444: Real-time health factor
    if (/health|margin_ratio/i.test(code) && 
        !/real_time|live|current_price/.test(code)) {
      findings.push({
        id: 'SOL444',
        severity: 'high',
        title: 'Health Factor Not Real-Time',
        description: 'Health factor must use current prices for accurate risk assessment.',
        location: 'Health calculation',
        recommendation: 'Calculate health factor using real-time oracle prices.',
      });
    }
    
    // SOL445: Cascade liquidation risk
    if (/liquidat/i.test(code) && 
        /cross_margin|multiple.*position/i.test(code) &&
        !/cascade|sequential|order/.test(code)) {
      findings.push({
        id: 'SOL445',
        severity: 'high',
        title: 'Liquidation Cascade Not Handled',
        description: 'Cross-margin liquidations can trigger cascading effects.',
        location: 'Liquidation sequence',
        recommendation: 'Order liquidations to minimize cascade effects.',
      });
    }
    
    // SOL446: Unrealized PnL in margin
    if (/unrealized|paper.*pnl/i.test(code) && 
        /margin|collateral/i.test(code) &&
        !/discount|haircut/.test(code)) {
      findings.push({
        id: 'SOL446',
        severity: 'high',
        title: 'Unrealized PnL Counted at Full Value',
        description: 'Unrealized profits should be discounted when calculating margin.',
        location: 'PnL handling',
        recommendation: 'Apply haircut to unrealized PnL in margin calculations.',
      });
    }
    
    // SOL447: Sub-account isolation
    if (/sub_account|sub-account/i.test(code) && 
        !/isolate|separate|independent/.test(code)) {
      findings.push({
        id: 'SOL447',
        severity: 'medium',
        title: 'Sub-Account Isolation Missing',
        description: 'Sub-accounts should be isolated to prevent cross-contamination.',
        location: 'Account structure',
        recommendation: 'Ensure sub-accounts have independent margin calculations.',
      });
    }
    
    // SOL448: Collateral weight changes
    if (/collateral_weight|asset_weight/i.test(code) && 
        !/rebalance|adjust|update_weight/.test(code)) {
      findings.push({
        id: 'SOL448',
        severity: 'medium',
        title: 'Collateral Weight Changes Not Handled',
        description: 'Weight changes should trigger health recalculation.',
        location: 'Weight management',
        recommendation: 'Recalculate all account health when collateral weights change.',
      });
    }
    
    // SOL449: Maximum utilization
    if (/utilization|borrowing/i.test(code) && 
        /margin/i.test(code) &&
        !/max_util|cap_utilization/.test(code)) {
      findings.push({
        id: 'SOL449',
        severity: 'medium',
        title: 'No Maximum Utilization Cap',
        description: 'Unbounded utilization can lead to liquidity crises.',
        location: 'Utilization tracking',
        recommendation: 'Cap utilization rates and implement circuit breakers.',
      });
    }
    
    // SOL450: Emergency deleveraging
    if (/cross_margin/i.test(code) && 
        !/emergency|circuit_breaker|halt/.test(code)) {
      findings.push({
        id: 'SOL450',
        severity: 'high',
        title: 'No Emergency Deleveraging Mechanism',
        description: 'Cross-margin systems need emergency deleveraging for extreme events.',
        location: 'Emergency handling',
        recommendation: 'Implement emergency deleveraging and trading halts.',
      });
    }
  }
  
  return findings;
}
