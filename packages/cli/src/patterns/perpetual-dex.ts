import type { Finding } from '../commands/audit.js';
import type { ParsedIdl } from '../parsers/idl.js';
import type { ParsedRust } from '../parsers/rust.js';

/**
 * SOL431-SOL440: Perpetual DEX Security Patterns
 * 
 * Perpetual protocols (Drift, Mango, Zeta) have complex risks:
 * funding rate manipulation, position manipulation, liquidation cascades.
 */
export function checkPerpetualDex(input: { idl?: ParsedIdl; rust?: ParsedRust }): Finding[] {
  const findings: Finding[] = [];
  
  if (input.rust?.sourceCode) {
    const code = input.rust.sourceCode;
    
    // SOL431: Funding rate manipulation
    if (/funding_rate|funding_payment/i.test(code) && 
        !/twap|time_weighted|rate_limit/.test(code)) {
      findings.push({
        id: 'SOL431',
        severity: 'critical',
        title: 'Funding Rate Manipulation Risk',
        description: 'Funding rates without TWAP can be manipulated with large orders.',
        location: 'Funding rate calculation',
        recommendation: 'Use time-weighted average price for funding rate calculations.',
      });
    }
    
    // SOL432: Position size limits missing
    if (/position|open_interest/i.test(code) && 
        /perp|perpetual|futures/i.test(code) &&
        !/max_position|position_limit|size_limit/.test(code)) {
      findings.push({
        id: 'SOL432',
        severity: 'high',
        title: 'No Position Size Limits',
        description: 'Unlimited position sizes can cause liquidity imbalances.',
        location: 'Position management',
        recommendation: 'Implement per-user and global position size limits.',
      });
    }
    
    // SOL433: Leverage bounds check
    if (/leverage|margin_ratio/i.test(code) && 
        !/max_leverage|min_margin/.test(code)) {
      findings.push({
        id: 'SOL433',
        severity: 'high',
        title: 'Leverage Bounds Not Enforced',
        description: 'Maximum leverage should be enforced to limit protocol risk.',
        location: 'Leverage calculation',
        recommendation: 'Enforce maximum leverage limits per market and user.',
      });
    }
    
    // SOL434: Liquidation price manipulation
    if (/liquidation_price|liq_price/i.test(code) && 
        !/oracle_check|price_band/.test(code)) {
      findings.push({
        id: 'SOL434',
        severity: 'critical',
        title: 'Liquidation Triggerable via Price Manipulation',
        description: 'Liquidations can be triggered by manipulating oracle prices.',
        location: 'Liquidation trigger',
        recommendation: 'Add price band checks and oracle confidence validation.',
      });
    }
    
    // SOL435: Partial liquidation missing
    if (/liquidat/i.test(code) && 
        /position/i.test(code) &&
        !/partial|gradual|incremental/.test(code)) {
      findings.push({
        id: 'SOL435',
        severity: 'high',
        title: 'No Partial Liquidation',
        description: 'Full liquidations cause cascade effects and worse prices.',
        location: 'Liquidation logic',
        recommendation: 'Implement partial/incremental liquidation mechanism.',
      });
    }
    
    // SOL436: Insurance fund check
    if (/perp|perpetual|futures/i.test(code) && 
        /liquidat|bankrupt/i.test(code) &&
        !/insurance_fund|socialized_loss/.test(code)) {
      findings.push({
        id: 'SOL436',
        severity: 'high',
        title: 'No Insurance Fund for Bad Debt',
        description: 'Underwater positions need insurance fund to cover bad debt.',
        location: 'Loss handling',
        recommendation: 'Implement insurance fund and socialized loss mechanism.',
      });
    }
    
    // SOL437: Order staleness
    if (/order|trade/i.test(code) && 
        /perp/i.test(code) &&
        !/expire|valid_until|stale/.test(code)) {
      findings.push({
        id: 'SOL437',
        severity: 'medium',
        title: 'Orders Can Become Stale',
        description: 'Orders without expiry can be filled at outdated prices.',
        location: 'Order handling',
        recommendation: 'Add order expiry and stale order protection.',
      });
    }
    
    // SOL438: Mark price divergence
    if (/mark_price|index_price/i.test(code) && 
        !/divergence|spread_check|band/.test(code)) {
      findings.push({
        id: 'SOL438',
        severity: 'high',
        title: 'Mark Price Can Diverge From Index',
        description: 'Large mark/index price divergence enables arbitrage exploits.',
        location: 'Price calculation',
        recommendation: 'Limit mark price divergence from index price.',
      });
    }
    
    // SOL439: ADL (auto-deleveraging) fairness
    if (/adl|auto_deleverage|counterparty_liquidation/i.test(code) && 
        !/ranking|priority|pnl_sort/.test(code)) {
      findings.push({
        id: 'SOL439',
        severity: 'medium',
        title: 'ADL Mechanism May Be Unfair',
        description: 'Auto-deleveraging should prioritize high-profit positions.',
        location: 'ADL logic',
        recommendation: 'Rank ADL counterparties by profit/leverage ratio.',
      });
    }
    
    // SOL440: Settlement price manipulation
    if (/settl|expir/i.test(code) && 
        /perp|futures/i.test(code) &&
        !/twap|vwap|settlement_window/.test(code)) {
      findings.push({
        id: 'SOL440',
        severity: 'high',
        title: 'Settlement Price Manipulatable',
        description: 'Single-point settlement prices can be manipulated.',
        location: 'Settlement logic',
        recommendation: 'Use TWAP/VWAP over settlement window for final price.',
      });
    }
  }
  
  return findings;
}
