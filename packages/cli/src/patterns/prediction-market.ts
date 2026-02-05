import type { Finding } from '../commands/audit.js';
import type { ParsedIdl } from '../parsers/idl.js';
import type { ParsedRust } from '../parsers/rust.js';

/**
 * SOL451-SOL460: Prediction Market Security
 * 
 * Prediction markets face unique challenges around
 * resolution, oracle manipulation, and liquidity.
 */
export function checkPredictionMarket(input: { idl?: ParsedIdl; rust?: ParsedRust }): Finding[] {
  const findings: Finding[] = [];
  
  if (input.rust?.sourceCode) {
    const code = input.rust.sourceCode;
    
    // SOL451: Resolution oracle trust
    if (/resolv|settle.*outcome/i.test(code) && 
        !/multi_oracle|uma|reality\.eth|quorum/.test(code)) {
      findings.push({
        id: 'SOL451',
        severity: 'critical',
        title: 'Single Oracle Resolution Risk',
        description: 'Single oracle resolution can be manipulated or fail.',
        location: 'Market resolution',
        recommendation: 'Use decentralized oracle systems or multi-oracle quorum.',
      });
    }
    
    // SOL452: Dispute mechanism missing
    if (/resolv|outcome/i.test(code) && 
        /market|predict/i.test(code) &&
        !/dispute|challenge|appeal/.test(code)) {
      findings.push({
        id: 'SOL452',
        severity: 'high',
        title: 'No Dispute Mechanism',
        description: 'Market resolutions should have dispute/appeal process.',
        location: 'Resolution logic',
        recommendation: 'Implement dispute window and resolution appeals.',
      });
    }
    
    // SOL453: Invalid market outcomes
    if (/outcome|result/i.test(code) && 
        /market/i.test(code) &&
        !/invalid|cancel|void/.test(code)) {
      findings.push({
        id: 'SOL453',
        severity: 'high',
        title: 'No Invalid Market Handling',
        description: 'Markets may need to be voided if resolution is impossible.',
        location: 'Market lifecycle',
        recommendation: 'Add ability to void markets and refund participants.',
      });
    }
    
    // SOL454: AMM invariant for binary markets
    if (/amm|liquidity/i.test(code) && 
        /binary|prediction/i.test(code) &&
        !/lmsr|cpmm|constant_sum/.test(code)) {
      findings.push({
        id: 'SOL454',
        severity: 'high',
        title: 'Improper AMM for Prediction Market',
        description: 'Binary prediction markets need specific AMM mechanisms (LMSR, etc.).',
        location: 'AMM logic',
        recommendation: 'Use LMSR or appropriate constant-function market maker.',
      });
    }
    
    // SOL455: Liquidity withdrawal before resolution
    if (/withdraw.*liquidity|remove.*liquidity/i.test(code) && 
        /prediction|market/i.test(code) &&
        !/lock|freeze|resolution_pending/.test(code)) {
      findings.push({
        id: 'SOL455',
        severity: 'high',
        title: 'LP Can Withdraw Before Resolution',
        description: 'LPs withdrawing before resolution can leave market insolvent.',
        location: 'LP management',
        recommendation: 'Lock LP funds until market resolution.',
      });
    }
    
    // SOL456: Share price manipulation
    if (/share.*price|outcome.*price/i.test(code) && 
        !/price_impact|slippage|max_trade/.test(code)) {
      findings.push({
        id: 'SOL456',
        severity: 'high',
        title: 'Share Price Manipulatable',
        description: 'Large trades can manipulate outcome share prices.',
        location: 'Pricing mechanism',
        recommendation: 'Add trade size limits and price impact calculations.',
      });
    }
    
    // SOL457: Conditional market linking
    if (/conditional|dependent.*market/i.test(code) && 
        !/verify_parent|check_condition/.test(code)) {
      findings.push({
        id: 'SOL457',
        severity: 'high',
        title: 'Conditional Market Linking Not Verified',
        description: 'Conditional markets must verify parent market state.',
        location: 'Market linking',
        recommendation: 'Verify parent market resolution before conditional payout.',
      });
    }
    
    // SOL458: Time manipulation
    if (/deadline|end_time|resolve_time/i.test(code) && 
        /market/i.test(code) &&
        !/unix_timestamp|clock_constraint/.test(code)) {
      findings.push({
        id: 'SOL458',
        severity: 'medium',
        title: 'Market Timing Not Using Trusted Clock',
        description: 'Market timing should use blockchain timestamp.',
        location: 'Timing logic',
        recommendation: 'Use Solana clock sysvar for market timing.',
      });
    }
    
    // SOL459: Redemption rounding
    if (/redeem|claim.*winning/i.test(code) && 
        !/round_down|precision/.test(code)) {
      findings.push({
        id: 'SOL459',
        severity: 'medium',
        title: 'Redemption Rounding Issue',
        description: 'Share redemption should round consistently to prevent dust attacks.',
        location: 'Redemption logic',
        recommendation: 'Always round down on redemption calculations.',
      });
    }
    
    // SOL460: Market creation spam
    if (/create.*market/i.test(code) && 
        !/fee|stake|whitelist/.test(code)) {
      findings.push({
        id: 'SOL460',
        severity: 'low',
        title: 'No Market Creation Cost',
        description: 'Free market creation enables spam and resource exhaustion.',
        location: 'Market creation',
        recommendation: 'Require stake or fee for market creation.',
      });
    }
  }
  
  return findings;
}
