// SOL738: Crema Finance CLMM Tick Spoofing Pattern (Jul 2022 - $8.8M)
// Based on the Crema Finance exploit where fake tick accounts bypassed owner verification

import type { ParsedRust } from '../parsers/rust.js';
import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * Crema Finance CLMM Tick Spoofing Patterns
 * 
 * The Crema Finance exploit in July 2022 resulted in ~$8.8M in losses.
 * The attacker created fake tick accounts that bypassed owner verification,
 * then used flash loans to manipulate transaction fee data.
 * 
 * Key vulnerabilities:
 * 1. Missing owner verification on tick accounts
 * 2. Flash loan fee manipulation
 * 3. Excessive fee claims based on fake data
 * 4. Missing PDA derivation checks for CLMM positions
 */

export function checkCremaTickSpoofing(parsed: ParsedRust): Finding[] {
  const findings: Finding[] = [];

  // Check for tick account patterns without proper verification
  const tickPatterns = [
    /tick_account|tick_array|tick_state/i,
    /position_tick|lower_tick|upper_tick/i,
    /tick_spacing|tick_index/i,
  ];

  const ownerCheckPatterns = [
    /owner\s*==|\.owner\s*==/i,
    /check_owner|verify_owner/i,
    /has_one\s*=\s*owner/i,
    /constraint\s*=\s*.*owner/i,
  ];

  for (const func of parsed.functions) {
    const content = func.content.toLowerCase();
    
    // Check if function handles tick accounts
    const handlesTicks = tickPatterns.some(p => p.test(content));
    
    if (handlesTicks) {
      // Check for owner verification
      const hasOwnerCheck = ownerCheckPatterns.some(p => p.test(content));
      
      if (!hasOwnerCheck) {
        findings.push({
          id: 'SOL659',
          severity: 'critical',
          title: 'Crema-style Tick Account Owner Bypass',
          description: `Function '${func.name}' handles tick accounts without verifying ownership`,
          location: func.location,
          recommendation: 'Always verify tick account ownership through PDA derivation or explicit owner checks. Use `has_one = pool` or similar constraints in Anchor.',
        });
      }

      // Check for fee manipulation vulnerabilities
      if (/fee|reward|collect/i.test(content)) {
        if (!/flash_loan_guard|borrowing_disabled/i.test(content)) {
          findings.push({
            id: 'SOL660',
            severity: 'high',
            title: 'Fee Collection Without Flash Loan Guard',
            description: `Function '${func.name}' collects fees without flash loan protection`,
            location: func.location,
            recommendation: 'Implement flash loan guards when collecting fees. Consider time-locks or cooldowns for large fee claims.',
          });
        }
      }
    }
  }

  // Check for CLMM position verification
  const positionPatterns = [
    /position_state|liquidity_position/i,
    /concentrated_liquidity|clmm/i,
  ];

  for (const func of parsed.functions) {
    const content = func.content.toLowerCase();
    
    const handlesPositions = positionPatterns.some(p => p.test(content));
    
    if (handlesPositions) {
      // Check for PDA derivation
      if (!/find_program_address|create_program_address/i.test(content)) {
        if (!/seeds\s*=|#\[account.*seeds/i.test(content)) {
          findings.push({
            id: 'SOL661',
            severity: 'high',
            title: 'CLMM Position Without PDA Verification',
            description: `Function '${func.name}' handles positions without PDA derivation checks`,
            location: func.location,
            recommendation: 'Derive position accounts from PDAs with pool address and position index as seeds.',
          });
        }
      }
    }
  }

  return findings;
}

// Check for flash loan vulnerabilities in AMM/CLMM contexts
export function checkClmmFlashLoanSafety(parsed: ParsedRust): Finding[] {
  const findings: Finding[] = [];

  const flashLoanIndicators = [
    /flash_loan|flash_borrow|instant_loan/i,
    /borrow.*repay|loan.*return/i,
  ];

  const priceManipulationRisks = [
    /swap.*fee|fee.*swap/i,
    /liquidity.*add|add.*liquidity/i,
    /tick.*cross|cross.*tick/i,
  ];

  for (const func of parsed.functions) {
    const content = func.content.toLowerCase();
    
    const hasFlashLoan = flashLoanIndicators.some(p => p.test(content));
    const hasPriceRisk = priceManipulationRisks.some(p => p.test(content));
    
    if (hasFlashLoan && hasPriceRisk) {
      // Check for same-block protection
      if (!/slot.*check|block.*same|same.*transaction/i.test(content)) {
        findings.push({
          id: 'SOL662',
          severity: 'critical',
          title: 'CLMM Flash Loan Price Manipulation Risk',
          description: `Function '${func.name}' combines flash loans with price-sensitive operations`,
          location: func.location,
          recommendation: 'Implement slot checks to prevent same-block manipulation. Use TWAPs or external oracles for critical price decisions.',
        });
      }
    }
  }

  return findings;
}

// Export combined check
export function checkCremaStyleExploits(input: PatternInput): Finding[] {
  if (!input.rust) return [];
  return [
    ...checkCremaTickSpoofing(input.rust),
    ...checkClmmFlashLoanSafety(input.rust),
  ];
}
