import type { Finding } from '../commands/audit.js';
import type { ParsedIdl } from '../parsers/idl.js';
import type { ParsedRust } from '../parsers/rust.js';

type PatternInput = { idl: ParsedIdl | null; rust: ParsedRust | null };

/**
 * SOL521-SOL540: Advanced DeFi & Protocol Security Patterns
 * Real-world attack vectors from 2024-2025 incidents.
 */

// SOL521: Flash Loan Re-entrancy
export function checkFlashLoanReentrancy(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (input.rust?.sourceCode) {
    const code = input.rust.sourceCode;
    if (/flash_loan|flash_borrow/.test(code) && !/reentrancy_guard|nonreentrant/.test(code)) {
      findings.push({
        id: 'SOL521',
        severity: 'critical',
        title: 'Flash Loan Re-entrancy Risk',
        description: 'Flash loan logic lacks re-entrancy protection.',
        location: 'Flash loan handler',
        recommendation: 'Implement re-entrancy guard for flash loan callbacks.',
      });
    }
  }
  return findings;
}

// SOL522: Price Feed Staleness
export function checkPriceFeedStaleness(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (input.rust?.sourceCode) {
    const code = input.rust.sourceCode;
    if (/get_price|price_feed|oracle/.test(code) && !/stale|fresh|max_age|timestamp/.test(code)) {
      findings.push({
        id: 'SOL522',
        severity: 'high',
        title: 'Price Feed Staleness Not Checked',
        description: 'Oracle price feeds used without checking staleness.',
        location: 'Price feed access',
        recommendation: 'Always check price feed timestamp against maximum allowed age.',
      });
    }
  }
  return findings;
}

// SOL523: Insufficient Liquidity Check
export function checkInsufficientLiquidityCheck(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (input.rust?.sourceCode) {
    const code = input.rust.sourceCode;
    if (/swap|exchange|trade/.test(code) && !/min_liquidity|liquidity_check|pool_balance/.test(code)) {
      findings.push({
        id: 'SOL523',
        severity: 'high',
        title: 'Insufficient Liquidity Check',
        description: 'Swap operations without minimum liquidity verification.',
        location: 'Swap logic',
        recommendation: 'Check pool liquidity before executing swaps to prevent exploitation.',
      });
    }
  }
  return findings;
}

// SOL524: Unbounded Loop in Critical Path
export function checkUnboundedLoopCriticalPath(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (input.rust?.sourceCode) {
    const code = input.rust.sourceCode;
    if (/for.*in.*\.iter\(\)|while\s+\w+/.test(code) && !/\.take\(|max_iterations|limit/.test(code)) {
      findings.push({
        id: 'SOL524',
        severity: 'high',
        title: 'Unbounded Loop in Critical Path',
        description: 'Loops without iteration limits may cause compute exhaustion.',
        location: 'Loop constructs',
        recommendation: 'Add maximum iteration limits to all loops.',
      });
    }
  }
  return findings;
}

// SOL525: Missing Slippage Protection
export function checkMissingSlippageProtection(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (input.rust?.sourceCode) {
    const code = input.rust.sourceCode;
    if (/swap|exchange|trade/.test(code) && !/slippage|min_out|max_in|minimum_amount/.test(code)) {
      findings.push({
        id: 'SOL525',
        severity: 'high',
        title: 'Missing Slippage Protection',
        description: 'Swap operations without slippage tolerance parameters.',
        location: 'Swap functions',
        recommendation: 'Add minimum output amount parameter and validate before execution.',
      });
    }
  }
  return findings;
}

// SOL526: Sandwich Attack Vulnerability
export function checkSandwichAttackVuln(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (input.rust?.sourceCode) {
    const code = input.rust.sourceCode;
    if (/amm|swap|pool/.test(code) && !/deadline|commit_reveal|private_mempool/.test(code)) {
      findings.push({
        id: 'SOL526',
        severity: 'high',
        title: 'Sandwich Attack Vulnerability',
        description: 'DEX operations vulnerable to sandwich attacks without deadline.',
        location: 'AMM/DEX logic',
        recommendation: 'Implement transaction deadline and consider commit-reveal schemes.',
      });
    }
  }
  return findings;
}

// SOL527: Improper Decimal Handling
export function checkImproperDecimalHandling(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (input.rust?.sourceCode) {
    const code = input.rust.sourceCode;
    if (/amount.*\*|price.*\//.test(code) && !/decimals|scale|normalize/.test(code)) {
      findings.push({
        id: 'SOL527',
        severity: 'high',
        title: 'Improper Decimal Handling',
        description: 'Token math without proper decimal normalization.',
        location: 'Token calculations',
        recommendation: 'Always normalize decimals when calculating with different tokens.',
      });
    }
  }
  return findings;
}

// SOL528: Vault Share Manipulation
export function checkVaultShareManipulation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (input.rust?.sourceCode) {
    const code = input.rust.sourceCode;
    if (/shares|vault_token|lp_token/.test(code) && !/min_shares|dead_shares|first_deposit/.test(code)) {
      findings.push({
        id: 'SOL528',
        severity: 'critical',
        title: 'Vault Share Manipulation Risk',
        description: 'Vault vulnerable to share inflation/deflation attacks.',
        location: 'Vault share calculation',
        recommendation: 'Implement minimum share requirements and virtual shares for protection.',
      });
    }
  }
  return findings;
}

// SOL529: Interest Rate Manipulation
export function checkInterestRateManipulation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (input.rust?.sourceCode) {
    const code = input.rust.sourceCode;
    if (/interest_rate|borrow_rate|supply_rate/.test(code) && !/max_rate|rate_cap|rate_limit/.test(code)) {
      findings.push({
        id: 'SOL529',
        severity: 'high',
        title: 'Interest Rate Manipulation Risk',
        description: 'Interest rates without caps can be manipulated to extreme values.',
        location: 'Interest calculation',
        recommendation: 'Implement rate caps and gradual rate changes.',
      });
    }
  }
  return findings;
}

// SOL530: Liquidation Threshold Bypass
export function checkLiquidationThresholdBypass(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (input.rust?.sourceCode) {
    const code = input.rust.sourceCode;
    if (/liquidate|health_factor|collateral_ratio/.test(code) && !/atomic_check|pre_check/.test(code)) {
      findings.push({
        id: 'SOL530',
        severity: 'critical',
        title: 'Liquidation Threshold Bypass Risk',
        description: 'Liquidation checks may be bypassed through flash loan manipulation.',
        location: 'Liquidation logic',
        recommendation: 'Verify health factor atomically and consider flash loan scenarios.',
      });
    }
  }
  return findings;
}

// SOL531: Reward Calculation Rounding
export function checkRewardCalculationRounding(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (input.rust?.sourceCode) {
    const code = input.rust.sourceCode;
    if (/reward.*\/|distribute.*amount/.test(code) && !/checked_div|round_down|precision/.test(code)) {
      findings.push({
        id: 'SOL531',
        severity: 'medium',
        title: 'Reward Calculation Rounding Issues',
        description: 'Reward distribution may have rounding errors favoring attackers.',
        location: 'Reward calculation',
        recommendation: 'Use checked division and round in protocol-favorable direction.',
      });
    }
  }
  return findings;
}

// SOL532: Governance Quorum Manipulation
export function checkGovernanceQuorumManipulation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (input.rust?.sourceCode) {
    const code = input.rust.sourceCode;
    if (/quorum|vote_threshold|proposal/.test(code) && !/snapshot|block_vote|delegation/.test(code)) {
      findings.push({
        id: 'SOL532',
        severity: 'high',
        title: 'Governance Quorum Manipulation',
        description: 'Governance voting without snapshot enables flash loan voting attacks.',
        location: 'Governance voting',
        recommendation: 'Use voting power snapshots and implement vote delegation properly.',
      });
    }
  }
  return findings;
}

// SOL533: NFT Metadata Manipulation
export function checkNftMetadataManipulation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (input.rust?.sourceCode) {
    const code = input.rust.sourceCode;
    if (/metadata|uri|attributes/.test(code) && !/immutable|frozen|verify_metadata/.test(code)) {
      findings.push({
        id: 'SOL533',
        severity: 'medium',
        title: 'NFT Metadata Manipulation Risk',
        description: 'NFT metadata can be changed after minting.',
        location: 'NFT metadata handling',
        recommendation: 'Make metadata immutable or implement proper update controls.',
      });
    }
  }
  return findings;
}

// SOL534: Royalty Bypass Pattern
export function checkRoyaltyBypassPattern(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (input.rust?.sourceCode) {
    const code = input.rust.sourceCode;
    if (/transfer.*nft|nft.*transfer/.test(code) && !/royalty|creator_fee|enforce_royalty/.test(code)) {
      findings.push({
        id: 'SOL534',
        severity: 'medium',
        title: 'Royalty Bypass Pattern',
        description: 'NFT transfers may bypass creator royalties.',
        location: 'NFT transfer logic',
        recommendation: 'Enforce royalties through programmable NFTs or transfer hooks.',
      });
    }
  }
  return findings;
}

// SOL535: Unstaking Cooldown Bypass
export function checkUnstakingCooldownBypass(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (input.rust?.sourceCode) {
    const code = input.rust.sourceCode;
    if (/unstake|withdraw_stake/.test(code) && !/cooldown|unbonding_period|delay/.test(code)) {
      findings.push({
        id: 'SOL535',
        severity: 'medium',
        title: 'Unstaking Cooldown Bypass',
        description: 'Staking protocol allows instant unstaking without cooldown.',
        location: 'Unstaking logic',
        recommendation: 'Implement unstaking cooldown period to prevent gaming.',
      });
    }
  }
  return findings;
}

// SOL536: Fee Manipulation Attack
export function checkFeeManipulationAttack(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (input.rust?.sourceCode) {
    const code = input.rust.sourceCode;
    if (/fee.*=|set_fee|update_fee/.test(code) && !/max_fee|fee_cap|timelock/.test(code)) {
      findings.push({
        id: 'SOL536',
        severity: 'high',
        title: 'Fee Manipulation Attack Vector',
        description: 'Protocol fees can be set to extreme values without limits.',
        location: 'Fee configuration',
        recommendation: 'Implement fee caps and timelock for fee changes.',
      });
    }
  }
  return findings;
}

// SOL537: Improper Token Transfer Validation
export function checkImproperTokenTransferValidation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (input.rust?.sourceCode) {
    const code = input.rust.sourceCode;
    if (/transfer|spl_token.*transfer/.test(code) && !/balance_before|balance_after|check_transfer/.test(code)) {
      findings.push({
        id: 'SOL537',
        severity: 'high',
        title: 'Improper Token Transfer Validation',
        description: 'Token transfer success not properly validated.',
        location: 'Token transfers',
        recommendation: 'Verify balance changes after transfers, especially for fee-on-transfer tokens.',
      });
    }
  }
  return findings;
}

// SOL538: Merkle Proof Manipulation
export function checkMerkleProofManipulation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (input.rust?.sourceCode) {
    const code = input.rust.sourceCode;
    if (/merkle|proof|root/.test(code) && !/leaf_hash|sorted|ordered/.test(code)) {
      findings.push({
        id: 'SOL538',
        severity: 'high',
        title: 'Merkle Proof Manipulation Risk',
        description: 'Merkle proof verification may be vulnerable to second preimage attacks.',
        location: 'Merkle proof verification',
        recommendation: 'Hash leaf nodes with domain separator, use sorted tree construction.',
      });
    }
  }
  return findings;
}

// SOL539: Cross-Margin Collateral Risk
export function checkCrossMarginCollateralRisk(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (input.rust?.sourceCode) {
    const code = input.rust.sourceCode;
    if (/margin|collateral|position/.test(code) && !/isolation|cross_margin_check|position_limit/.test(code)) {
      findings.push({
        id: 'SOL539',
        severity: 'high',
        title: 'Cross-Margin Collateral Risk',
        description: 'Cross-margin positions may cascade liquidations.',
        location: 'Margin calculation',
        recommendation: 'Implement position limits and cross-collateral risk checks.',
      });
    }
  }
  return findings;
}

// SOL540: Funding Rate Manipulation
export function checkFundingRateManipulation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (input.rust?.sourceCode) {
    const code = input.rust.sourceCode;
    if (/funding_rate|perp|perpetual/.test(code) && !/funding_cap|rate_limit|twap/.test(code)) {
      findings.push({
        id: 'SOL540',
        severity: 'high',
        title: 'Funding Rate Manipulation',
        description: 'Perpetual funding rates can be manipulated without caps.',
        location: 'Funding rate calculation',
        recommendation: 'Use TWAP for funding rate calculation and implement rate caps.',
      });
    }
  }
  return findings;
}

// Functions are exported inline
