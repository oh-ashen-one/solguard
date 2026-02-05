// SOL740: Solend Authentication Bypass Pattern (Aug 2021 - $2M at risk)
// Based on the Solend exploit where admin checks were bypassed by creating new lending markets

import type { ParsedRust } from '../parsers/rust.js';
import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * Solend Authentication Bypass Patterns (August 2021)
 * 
 * An attacker exploited an insecure authentication check in Solend's 
 * `UpdateReserveConfig` function. By creating a new lending market and 
 * passing it as an account they owned, the attacker bypassed admin checks.
 * 
 * This allowed:
 * 1. Lowering liquidation thresholds (making accounts liquidatable)
 * 2. Increasing liquidation bonuses (inflating profits)
 * 3. $2M at risk, 5 users wrongfully liquidated ($16K)
 * 
 * Key vulnerabilities:
 * 1. Market account passed without proper derivation checks
 * 2. Admin verification only checked account ownership, not PDA derivation
 * 3. Reserve config updates without proper market validation
 */

export function checkSolendAuthBypass(parsed: ParsedRust): Finding[] {
  const findings: Finding[] = [];

  // Detect reserve/config update patterns
  const configUpdatePatterns = [
    /update.*config|config.*update/i,
    /set.*param|param.*set/i,
    /modify.*reserve|reserve.*modify/i,
    /change.*threshold|threshold.*change/i,
  ];

  // Proper validation patterns
  const validationPatterns = [
    /seeds\s*=.*market|market.*seeds/i,
    /has_one\s*=\s*lending_market/i,
    /lending_market\.key\s*==|check.*lending_market/i,
    /derive.*market_authority/i,
  ];

  for (const func of parsed.functions) {
    const content = func.content.toLowerCase();
    
    // Check if function updates configurations
    const isConfigUpdate = configUpdatePatterns.some(p => p.test(content));
    
    if (isConfigUpdate) {
      const hasProperValidation = validationPatterns.some(p => p.test(content));
      
      if (!hasProperValidation) {
        findings.push({
          id: 'SOL667',
          severity: 'critical',
          title: 'Solend-style Auth Bypass: Missing Market Derivation',
          description: `Function '${func.name}' updates configuration without proper market PDA derivation`,
          location: func.location,
          recommendation: 'Derive market authority from PDA and verify the lending market account was created by this program. Use `has_one` constraints in Anchor.',
        });
      }
    }
  }

  // Check for liquidation parameter manipulation
  const liquidationPatterns = [
    /liquidation_threshold|ltv_ratio/i,
    /liquidation_bonus|liquidator_fee/i,
    /close_factor|collateral_factor/i,
  ];

  for (const func of parsed.functions) {
    const content = func.content.toLowerCase();
    
    const handlesLiquidation = liquidationPatterns.some(p => p.test(content));
    
    if (handlesLiquidation) {
      // Check for parameter bounds
      if (!/min.*threshold|max.*bonus|bound|limit/i.test(content)) {
        findings.push({
          id: 'SOL668',
          severity: 'high',
          title: 'Unbounded Liquidation Parameters',
          description: `Function '${func.name}' sets liquidation parameters without bounds checking`,
          location: func.location,
          recommendation: 'Add min/max bounds for liquidation thresholds (e.g., 50-95%) and bonuses (e.g., 5-15%) to prevent manipulation.',
        });
      }

      // Check for timelock on parameter changes
      if (!/timelock|delay|pending/i.test(content)) {
        findings.push({
          id: 'SOL669',
          severity: 'medium',
          title: 'No Timelock on Liquidation Parameter Changes',
          description: `Function '${func.name}' allows immediate liquidation parameter changes`,
          location: func.location,
          recommendation: 'Implement timelock (e.g., 24-48 hours) for liquidation parameter changes to allow users to adjust positions.',
        });
      }
    }
  }

  return findings;
}

// Check for lending market creation/validation patterns
export function checkLendingMarketValidation(parsed: ParsedRust): Finding[] {
  const findings: Finding[] = [];

  // Lending market patterns
  const marketPatterns = [
    /lending_market|market_account/i,
    /create_market|init_market/i,
    /market_authority|market_owner/i,
  ];

  for (const func of parsed.functions) {
    const content = func.content.toLowerCase();
    
    const handlesMarket = marketPatterns.some(p => p.test(content));
    
    if (handlesMarket) {
      // Check for program ownership verification
      if (!/owner\s*==\s*program_id|\.owner\s*==\s*&crate::id/i.test(content)) {
        findings.push({
          id: 'SOL670',
          severity: 'critical',
          title: 'Missing Lending Market Program Ownership Check',
          description: `Function '${func.name}' handles lending market without verifying program ownership`,
          location: func.location,
          recommendation: 'Always verify that lending market accounts are owned by your program. Use `Account<LendingMarket>` in Anchor which auto-checks ownership.',
        });
      }
    }
  }

  return findings;
}

// Export combined check
export function checkSolendStyleExploits(input: PatternInput): Finding[] {
  if (!input.rust) return [];
  return [
    ...checkSolendAuthBypass(input.rust),
    ...checkLendingMarketValidation(input.rust),
  ];
}
