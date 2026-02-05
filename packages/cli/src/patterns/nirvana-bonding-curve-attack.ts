// SOL739: Nirvana Finance Bonding Curve Flash Loan Attack (Jul 2022 - $3.5M)
// Based on the Nirvana exploit where flash loans manipulated the bonding curve

import type { ParsedRust } from '../parsers/rust.js';
import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * Nirvana Finance Bonding Curve Attack Patterns
 * 
 * In July 2022, an attacker exploited Nirvana Finance's bonding curve mechanism
 * using a ~$10M flash loan to manipulate token prices and mint at inflated rates.
 * The attacker (later identified as a security engineer) drained $3.5M.
 * 
 * Key vulnerabilities:
 * 1. Custom pricing mechanisms vulnerable to flash loans
 * 2. Bonding curve manipulation through large purchases
 * 3. Missing rate limits on minting
 * 4. No cooldown periods between large operations
 */

export function checkNirvanaBondingCurveAttack(parsed: ParsedRust): Finding[] {
  const findings: Finding[] = [];

  // Detect bonding curve patterns
  const bondingCurvePatterns = [
    /bonding_curve|pricing_curve|token_curve/i,
    /mint_price|buy_price|curve_price/i,
    /exponential_curve|linear_curve|polynomial/i,
    /rising_floor|floor_price|backing_price/i,
  ];

  // Check for flash loan protection
  const flashProtectionPatterns = [
    /flash_loan_guard|anti_flash|flash_protection/i,
    /cooldown|rate_limit|time_lock/i,
    /max_per_block|max_per_slot/i,
  ];

  for (const func of parsed.functions) {
    const content = func.content.toLowerCase();
    
    // Check if function handles bonding curves
    const hasBondingCurve = bondingCurvePatterns.some(p => p.test(content));
    
    if (hasBondingCurve) {
      const hasFlashProtection = flashProtectionPatterns.some(p => p.test(content));
      
      if (!hasFlashProtection) {
        findings.push({
          id: 'SOL663',
          severity: 'critical',
          title: 'Nirvana-style Bonding Curve Without Flash Protection',
          description: `Function '${func.name}' implements bonding curve pricing without flash loan protection`,
          location: func.location,
          recommendation: 'Add cooldown periods between purchases, rate limits per slot, and max transaction size limits. Consider using TWAPs for pricing.',
        });
      }

      // Check for minting rate limits
      if (/mint|issue|create.*token/i.test(content)) {
        if (!/max_mint|mint_limit|cap/i.test(content)) {
          findings.push({
            id: 'SOL664',
            severity: 'high',
            title: 'Unlimited Bonding Curve Minting',
            description: `Function '${func.name}' allows unlimited minting via bonding curve`,
            location: func.location,
            recommendation: 'Implement per-transaction and per-epoch minting caps to prevent curve manipulation.',
          });
        }
      }
    }
  }

  // Check for price oracle manipulation in custom curves
  const customPricingPatterns = [
    /calculate_price|compute_price|get_price/i,
    /price_for_amount|amount_for_price/i,
  ];

  for (const func of parsed.functions) {
    const content = func.content.toLowerCase();
    
    const hasCustomPricing = customPricingPatterns.some(p => p.test(content));
    
    if (hasCustomPricing) {
      // Check if using external oracle
      if (!/pyth|switchboard|chainlink|oracle/i.test(content)) {
        findings.push({
          id: 'SOL665',
          severity: 'medium',
          title: 'Custom Pricing Without External Oracle',
          description: `Function '${func.name}' uses custom pricing without external oracle validation`,
          location: func.location,
          recommendation: 'Consider using external oracles (Pyth, Switchboard) to validate bonding curve prices against market rates.',
        });
      }
    }
  }

  return findings;
}

// Check for treasury/liquidity drain patterns
export function checkProtocolOwnedLiquidityDrain(parsed: ParsedRust): Finding[] {
  const findings: Finding[] = [];

  // Protocol-owned liquidity patterns
  const polPatterns = [
    /protocol_owned|treasury|reserve_fund/i,
    /backing_pool|liquidity_backing/i,
  ];

  const drainIndicators = [
    /withdraw|transfer|drain/i,
    /redeem|burn.*for|exchange/i,
  ];

  for (const func of parsed.functions) {
    const content = func.content.toLowerCase();
    
    const hasPol = polPatterns.some(p => p.test(content));
    const hasDrain = drainIndicators.some(p => p.test(content));
    
    if (hasPol && hasDrain) {
      // Check for rate limiting
      if (!/rate_limit|daily_limit|cooldown/i.test(content)) {
        findings.push({
          id: 'SOL666',
          severity: 'high',
          title: 'Protocol Liquidity Drain Without Rate Limit',
          description: `Function '${func.name}' allows draining protocol liquidity without rate limits`,
          location: func.location,
          recommendation: 'Implement withdrawal rate limits (e.g., max 10% of TVL per day) and emergency pause mechanisms.',
        });
      }
    }
  }

  return findings;
}

// Export combined check
export function checkNirvanaStyleExploits(input: PatternInput): Finding[] {
  if (!input.rust) return [];
  return [
    ...checkNirvanaBondingCurveAttack(input.rust),
    ...checkProtocolOwnedLiquidityDrain(input.rust),
  ];
}
