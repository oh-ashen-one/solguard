import type { Finding } from '../commands/audit.js';
import type { ParsedIdl } from '../parsers/idl.js';
import type { ParsedRust } from '../parsers/rust.js';

/**
 * SOL411-SOL420: DEX Aggregator Security Patterns
 * 
 * DEX aggregators like Jupiter face unique challenges:
 * route validation, intermediate token safety, slippage manipulation.
 */
export function checkDexAggregator(input: { idl?: ParsedIdl; rust?: ParsedRust }): Finding[] {
  const findings: Finding[] = [];
  
  if (input.rust?.sourceCode) {
    const code = input.rust.sourceCode;
    
    // SOL411: Route validation missing
    if (/route|swap_path|hop/i.test(code) && 
        /aggregat|jupiter/i.test(code) &&
        !/validate_route|verify_path/.test(code)) {
      findings.push({
        id: 'SOL411',
        severity: 'critical',
        title: 'DEX Route Validation Missing',
        description: 'Aggregator routes should be validated to prevent malicious routing.',
        location: 'Route processing',
        recommendation: 'Validate each hop in the swap route before execution.',
      });
    }
    
    // SOL412: Intermediate token not validated
    if (/intermediate|hop_token|mid_token/i.test(code) && 
        !/whitelist|allowed_token|verify_token/.test(code)) {
      findings.push({
        id: 'SOL412',
        severity: 'high',
        title: 'Intermediate Token Not Whitelisted',
        description: 'Swap routes using unknown intermediate tokens can enable drain attacks.',
        location: 'Multi-hop swap',
        recommendation: 'Whitelist allowed intermediate tokens in multi-hop swaps.',
      });
    }
    
    // SOL413: Quote vs execution mismatch
    if (/quote|expected_amount/i.test(code) && 
        /execute|swap/i.test(code) &&
        !/compare|verify_quote|match_quote/.test(code)) {
      findings.push({
        id: 'SOL413',
        severity: 'high',
        title: 'Quote vs Execution Amount Mismatch Risk',
        description: 'Quoted amounts should be verified against actual execution.',
        location: 'Swap execution',
        recommendation: 'Verify executed amount against quoted amount within tolerance.',
      });
    }
    
    // SOL414: Platform fee manipulation
    if (/platform_fee|referral_fee|protocol_fee/i.test(code) && 
        !/max_fee|fee_cap|validate_fee/.test(code)) {
      findings.push({
        id: 'SOL414',
        severity: 'high',
        title: 'Unbounded Platform Fee',
        description: 'Platform fees should have maximum caps to prevent excessive extraction.',
        location: 'Fee handling',
        recommendation: 'Cap platform fees and validate fee parameters.',
      });
    }
    
    // SOL415: Flash loan in route
    if (/route|swap_path/i.test(code) && 
        !/flash_loan_check|no_flash_loan/.test(code)) {
      findings.push({
        id: 'SOL415',
        severity: 'high',
        title: 'Flash Loan Route Not Blocked',
        description: 'Routes containing flash loans can enable atomic arbitrage attacks.',
        location: 'Route validation',
        recommendation: 'Detect and optionally block flash loan usage in routes.',
      });
    }
    
    // SOL416: Minimum output not enforced
    if (/swap|exchange/i.test(code) && 
        /aggregat/i.test(code) &&
        !/minimum_out|min_amount_out|slippage/.test(code)) {
      findings.push({
        id: 'SOL416',
        severity: 'critical',
        title: 'Minimum Output Amount Not Enforced',
        description: 'Swaps without minimum output can result in total loss to MEV.',
        location: 'Swap execution',
        recommendation: 'Always enforce minimum output amount on aggregator swaps.',
      });
    }
    
    // SOL417: Price impact not checked
    if (/swap|route/i.test(code) && 
        !/price_impact|impact_check|max_impact/.test(code)) {
      findings.push({
        id: 'SOL417',
        severity: 'high',
        title: 'Price Impact Not Validated',
        description: 'Large swaps should check price impact before execution.',
        location: 'Swap logic',
        recommendation: 'Calculate and limit price impact for user protection.',
      });
    }
    
    // SOL418: AMM pool validation
    if (/pool|amm|liquidity/i.test(code) && 
        /aggregat/i.test(code) &&
        !/verify_pool|validate_pool|pool_check/.test(code)) {
      findings.push({
        id: 'SOL418',
        severity: 'high',
        title: 'AMM Pool Not Validated',
        description: 'Routes through unvalidated pools can lead to fake liquidity attacks.',
        location: 'Pool selection',
        recommendation: 'Validate pool authenticity before including in routes.',
      });
    }
    
    // SOL419: Shared account exposure
    if (/shared_account|common_intermediary/i.test(code) && 
        !/isolate|separate|atomic/.test(code)) {
      findings.push({
        id: 'SOL419',
        severity: 'medium',
        title: 'Shared Account State Between Routes',
        description: 'Shared intermediary accounts can cause cross-contamination.',
        location: 'Route isolation',
        recommendation: 'Isolate state between concurrent swap routes.',
      });
    }
    
    // SOL420: Referrer manipulation
    if (/referrer|referral/i.test(code) && 
        !/verify_referrer|referrer_check/.test(code)) {
      findings.push({
        id: 'SOL420',
        severity: 'low',
        title: 'Referrer Address Not Validated',
        description: 'Referrer addresses should be validated to prevent fee theft.',
        location: 'Referral system',
        recommendation: 'Validate referrer addresses against known registry.',
      });
    }
  }
  
  return findings;
}
