import type { Finding } from '../commands/audit.js';
import type { ParsedIdl } from '../parsers/idl.js';
import type { ParsedRust } from '../parsers/rust.js';

/**
 * SOL461-SOL470: Social-Fi Security Patterns
 * 
 * Social finance protocols (friend.tech clones, social tokens)
 * have unique risks around creator keys, bonding curves, and exit scams.
 */
export function checkSocialFi(input: { idl?: ParsedIdl; rust?: ParsedRust }): Finding[] {
  const findings: Finding[] = [];
  
  if (input.rust?.sourceCode) {
    const code = input.rust.sourceCode;
    
    // SOL461: Creator key concentration
    if (/creator|influencer|subject/i.test(code) && 
        /key|share|token/i.test(code) &&
        !/max_holding|concentration_limit/.test(code)) {
      findings.push({
        id: 'SOL461',
        severity: 'high',
        title: 'Creator Key Concentration Not Limited',
        description: 'Creators can hold excessive keys enabling dump attacks.',
        location: 'Key ownership',
        recommendation: 'Limit creator self-holding to prevent market manipulation.',
      });
    }
    
    // SOL462: Bonding curve exit scam
    if (/bonding_curve|price_curve/i.test(code) && 
        /social|creator|key/i.test(code) &&
        !/lock|vesting|cooldown/.test(code)) {
      findings.push({
        id: 'SOL462',
        severity: 'critical',
        title: 'Bonding Curve Exit Scam Risk',
        description: 'Creators can dump keys instantly, extracting liquidity.',
        location: 'Sell mechanism',
        recommendation: 'Add selling cooldowns or vesting for creator holdings.',
      });
    }
    
    // SOL463: Fee extraction
    if (/protocol_fee|creator_fee/i.test(code) && 
        /social/i.test(code) &&
        !/fee_cap|max_fee/.test(code)) {
      findings.push({
        id: 'SOL463',
        severity: 'high',
        title: 'Unbounded Social-Fi Fees',
        description: 'High fees can make key trading uneconomical.',
        location: 'Fee structure',
        recommendation: 'Cap total fees at reasonable percentage.',
      });
    }
    
    // SOL464: Identity verification
    if (/creator|profile/i.test(code) && 
        /register|create/i.test(code) &&
        !/verify|twitter|proof/.test(code)) {
      findings.push({
        id: 'SOL464',
        severity: 'medium',
        title: 'No Creator Identity Verification',
        description: 'Impersonators can create fake creator profiles.',
        location: 'Registration',
        recommendation: 'Require social media verification for creator profiles.',
      });
    }
    
    // SOL465: Follower manipulation
    if (/follower|subscriber|fan/i.test(code) && 
        /count|number/i.test(code) &&
        !/unique|sybil/.test(code)) {
      findings.push({
        id: 'SOL465',
        severity: 'medium',
        title: 'Follower Count Manipulatable',
        description: 'Sybil accounts can inflate follower metrics.',
        location: 'Social metrics',
        recommendation: 'Implement sybil resistance for follower counting.',
      });
    }
    
    // SOL466: Whale protection
    if (/buy|purchase/i.test(code) && 
        /key|share/i.test(code) &&
        !/max_buy|purchase_limit/.test(code)) {
      findings.push({
        id: 'SOL466',
        severity: 'high',
        title: 'No Whale Protection',
        description: 'Whales can corner the market on creator keys.',
        location: 'Purchase logic',
        recommendation: 'Implement per-transaction and per-wallet purchase limits.',
      });
    }
    
    // SOL467: Price curve manipulation
    if (/price.*curve|bonding/i.test(code) && 
        !/smooth|continuous|monotonic/.test(code)) {
      findings.push({
        id: 'SOL467',
        severity: 'high',
        title: 'Price Curve Can Be Manipulated',
        description: 'Discontinuous curves enable arbitrage exploits.',
        location: 'Pricing mechanism',
        recommendation: 'Use monotonically increasing, continuous bonding curves.',
      });
    }
    
    // SOL468: Content gating bypass
    if (/gated|exclusive|access/i.test(code) && 
        /content|media/i.test(code) &&
        !/verify_ownership|check_key/.test(code)) {
      findings.push({
        id: 'SOL468',
        severity: 'medium',
        title: 'Content Gating Can Be Bypassed',
        description: 'Gated content access must verify key ownership on-chain.',
        location: 'Access control',
        recommendation: 'Verify key ownership for every gated content access.',
      });
    }
    
    // SOL469: Referral system abuse
    if (/referral|invite/i.test(code) && 
        /social/i.test(code) &&
        !/limit|cap|cooldown/.test(code)) {
      findings.push({
        id: 'SOL469',
        severity: 'low',
        title: 'Referral System Exploitable',
        description: 'Self-referral and referral farming can drain rewards.',
        location: 'Referral logic',
        recommendation: 'Add referral limits and prevent self-referral.',
      });
    }
    
    // SOL470: Chat/messaging security
    if (/message|chat|dm/i.test(code) && 
        /social/i.test(code) &&
        !/encrypt|sign/.test(code)) {
      findings.push({
        id: 'SOL470',
        severity: 'medium',
        title: 'Social Messages Not Encrypted',
        description: 'User messages should be encrypted for privacy.',
        location: 'Messaging system',
        recommendation: 'Implement end-to-end encryption for social messaging.',
      });
    }
  }
  
  return findings;
}
