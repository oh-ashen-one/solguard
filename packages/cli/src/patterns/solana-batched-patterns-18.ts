/**
 * Solana Batched Patterns 18 - Business Logic Vulnerabilities
 * Based on Sec3 2025 Report: Business Logic accounts for 38.5% of all findings
 * 20 patterns targeting protocol-specific logic flaws
 */

import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

// SOL593: Incorrect State Machine Transitions
export function checkIncorrectStateMachine(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';

  // Check for state transitions without validation
  if (/state\s*=\s*State::\w+/.test(content) && 
      !/match\s+.*state|if\s+.*state\s*==/.test(content)) {
    findings.push({
      id: 'SOL593',
      title: 'Incorrect State Machine Transitions',
      severity: 'high',
      category: 'business-logic',
      description: 'State transitions without proper current state validation can lead to invalid protocol states',
      location: input.path,
      recommendation: 'Implement explicit state machine with validated transitions'
    });
  }

  return findings;
}

// SOL594: Missing Invariant Checks
export function checkMissingInvariantChecks(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';

  // AMM/DEX without constant product check
  if (/swap|exchange|trade/i.test(content) && 
      /(reserve_a|reserve_b|liquidity)/i.test(content) &&
      !/k\s*==|constant_product|invariant/.test(content)) {
    findings.push({
      id: 'SOL594',
      title: 'Missing Invariant Checks',
      severity: 'critical',
      category: 'business-logic',
      description: 'AMM operations without invariant validation can lead to fund extraction',
      location: input.path,
      recommendation: 'Enforce constant product (k = x * y) or other invariants before and after operations'
    });
  }

  return findings;
}

// SOL595: Unrestricted Protocol Parameter Updates
export function checkUnrestrictedParameterUpdate(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';

  // Parameter updates without bounds
  if (/update.*config|set.*param|configure/i.test(content) &&
      /(fee|rate|threshold|limit)/i.test(content) &&
      !/require!?\s*\(.*<|\.max\(|\.min\(|bounds/.test(content)) {
    findings.push({
      id: 'SOL595',
      title: 'Unrestricted Protocol Parameter Updates',
      severity: 'high',
      category: 'business-logic',
      description: 'Protocol parameters can be set to extreme values without bounds checking',
      location: input.path,
      recommendation: 'Enforce minimum and maximum bounds on all protocol parameters'
    });
  }

  return findings;
}

// SOL596: Incorrect Accounting Updates
export function checkIncorrectAccounting(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';

  // Balance updates that might not match transfers
  if (/\.balance\s*[+-]=/.test(content) || /\.amount\s*[+-]=/.test(content)) {
    if (!/transfer|checked_add|checked_sub/.test(content)) {
      findings.push({
        id: 'SOL596',
        title: 'Incorrect Accounting Updates',
        severity: 'critical',
        category: 'business-logic',
        description: 'Internal accounting may not match actual token transfers, leading to fund discrepancies',
        location: input.path,
        recommendation: 'Ensure internal balances are updated atomically with actual transfers'
      });
    }
  }

  return findings;
}

// SOL597: Missing Settlement Validation
export function checkMissingSettlementValidation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';

  // Settlement without amount validation
  if (/settle|finalize|complete/i.test(content) &&
      /order|position|trade/i.test(content) &&
      !/assert|require|ensure|verify.*amount/.test(content)) {
    findings.push({
      id: 'SOL597',
      title: 'Missing Settlement Validation',
      severity: 'high',
      category: 'business-logic',
      description: 'Settlement operations without proper validation can lead to incorrect fund distribution',
      location: input.path,
      recommendation: 'Validate all amounts and conditions before settlement finalization'
    });
  }

  return findings;
}

// SOL598: Inconsistent Fee Calculation
export function checkInconsistentFeeCalculation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';

  // Multiple fee calculations that may be inconsistent
  const feeCalcMatches = content.match(/fee.*[*\/]|[*\/].*fee/gi);
  if (feeCalcMatches && feeCalcMatches.length > 1) {
    findings.push({
      id: 'SOL598',
      title: 'Inconsistent Fee Calculation',
      severity: 'medium',
      category: 'business-logic',
      description: 'Multiple fee calculation methods may lead to inconsistencies and arbitrage opportunities',
      location: input.path,
      recommendation: 'Centralize fee calculation logic in a single function with consistent rounding'
    });
  }

  return findings;
}

// SOL599: Missing Cooldown Period
export function checkMissingCooldownPeriod(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';

  // Sensitive operations without cooldown
  if (/withdraw|unstake|redeem/i.test(content) &&
      !/cooldown|delay|lock.*period|timelock/.test(content)) {
    findings.push({
      id: 'SOL599',
      title: 'Missing Cooldown Period',
      severity: 'medium',
      category: 'business-logic',
      description: 'Sensitive operations without cooldown periods enable flash loan attacks',
      location: input.path,
      recommendation: 'Implement cooldown periods for large withdrawals and unstaking operations'
    });
  }

  return findings;
}

// SOL600: Incorrect Share Calculation
export function checkIncorrectShareCalculation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';

  // Share/LP token calculations
  if (/shares?.*[*\/]|[*\/].*shares?/i.test(content) ||
      /lp.*token.*[*\/]|[*\/].*lp.*token/i.test(content)) {
    if (!/total_supply.*==.*0|supply.*>.*0/.test(content)) {
      findings.push({
        id: 'SOL600',
        title: 'Incorrect Share Calculation',
        severity: 'critical',
        category: 'business-logic',
        description: 'Share calculations without zero supply checks can lead to first depositor attacks',
        location: input.path,
        recommendation: 'Handle zero supply edge cases and consider minimum liquidity locks'
      });
    }
  }

  return findings;
}

// SOL601: Missing Epoch Boundary Handling
export function checkMissingEpochBoundary(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';

  // Epoch-dependent logic without boundary handling
  if (/epoch|Clock::get/i.test(content) &&
      /reward|stake|interest/i.test(content) &&
      !/epoch.*change|new.*epoch|epoch.*boundary/.test(content)) {
    findings.push({
      id: 'SOL601',
      title: 'Missing Epoch Boundary Handling',
      severity: 'medium',
      category: 'business-logic',
      description: 'Epoch-dependent calculations may behave incorrectly at boundaries',
      location: input.path,
      recommendation: 'Handle epoch transitions explicitly in reward and staking calculations'
    });
  }

  return findings;
}

// SOL602: Incorrect Order Matching Logic
export function checkIncorrectOrderMatching(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';

  // Order book operations
  if (/order.*book|match.*order|fill.*order/i.test(content)) {
    if (!/price.*check|best.*bid|best.*ask|priority/.test(content)) {
      findings.push({
        id: 'SOL602',
        title: 'Incorrect Order Matching Logic',
        severity: 'high',
        category: 'business-logic',
        description: 'Order matching without proper price-time priority can be exploited',
        location: input.path,
        recommendation: 'Implement proper price-time priority in order matching'
      });
    }
  }

  return findings;
}

// SOL603: Missing Position Size Limits
export function checkMissingPositionLimits(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';

  // Position/leverage operations
  if (/position|leverage|margin/i.test(content) &&
      /open|increase|add/i.test(content) &&
      !/max.*position|position.*limit|size.*limit/.test(content)) {
    findings.push({
      id: 'SOL603',
      title: 'Missing Position Size Limits',
      severity: 'high',
      category: 'business-logic',
      description: 'Unbounded position sizes can lead to protocol insolvency',
      location: input.path,
      recommendation: 'Implement maximum position size limits relative to protocol capacity'
    });
  }

  return findings;
}

// SOL604: Incorrect Liquidation Priority
export function checkIncorrectLiquidationPriority(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';

  // Liquidation logic
  if (/liquidat/i.test(content)) {
    if (!/health.*factor|margin.*ratio|priority|queue/.test(content)) {
      findings.push({
        id: 'SOL604',
        title: 'Incorrect Liquidation Priority',
        severity: 'high',
        category: 'business-logic',
        description: 'Liquidation without proper prioritization can lead to bad debt accumulation',
        location: input.path,
        recommendation: 'Prioritize liquidations by health factor and position size'
      });
    }
  }

  return findings;
}

// SOL605: Missing Partial Fill Handling
export function checkMissingPartialFillHandling(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';

  // Order filling without partial handling
  if (/fill.*order|execute.*order/i.test(content) &&
      !/partial|remaining|filled.*amount/.test(content)) {
    findings.push({
      id: 'SOL605',
      title: 'Missing Partial Fill Handling',
      severity: 'medium',
      category: 'business-logic',
      description: 'Orders without partial fill handling may fail unnecessarily or be exploited',
      location: input.path,
      recommendation: 'Implement proper partial fill logic with remaining amount tracking'
    });
  }

  return findings;
}

// SOL606: Incorrect Utilization Rate Calculation
export function checkIncorrectUtilizationRate(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';

  // Utilization rate in lending
  if (/utilization.*rate|borrowed.*\/.*supply/i.test(content)) {
    if (!/\.min\(|cap|100|10000|MAX/.test(content)) {
      findings.push({
        id: 'SOL606',
        title: 'Incorrect Utilization Rate Calculation',
        severity: 'high',
        category: 'business-logic',
        description: 'Utilization rate without caps can exceed 100% and break interest calculations',
        location: input.path,
        recommendation: 'Cap utilization rate at 100% (or protocol maximum)'
      });
    }
  }

  return findings;
}

// SOL607: Missing Dust Threshold Handling
export function checkMissingDustThreshold(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';

  // Operations without dust handling
  if (/transfer|withdraw|redeem/i.test(content) &&
      /amount/i.test(content) &&
      !/dust|minimum.*amount|\.saturating/.test(content)) {
    findings.push({
      id: 'SOL607',
      title: 'Missing Dust Threshold Handling',
      severity: 'low',
      category: 'business-logic',
      description: 'Operations with very small amounts (dust) can cause accounting issues',
      location: input.path,
      recommendation: 'Implement minimum amount thresholds to prevent dust accumulation'
    });
  }

  return findings;
}

// SOL608: Incorrect Rebase Token Handling
export function checkIncorrectRebaseHandling(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';

  // Rebase or elastic supply tokens
  if (/rebase|elastic|reflect/i.test(content)) {
    if (!/shares|internal.*balance/.test(content)) {
      findings.push({
        id: 'SOL608',
        title: 'Incorrect Rebase Token Handling',
        severity: 'high',
        category: 'business-logic',
        description: 'Rebase tokens require share-based accounting, not direct balance tracking',
        location: input.path,
        recommendation: 'Use internal share representation for rebase token balances'
      });
    }
  }

  return findings;
}

// SOL609: Missing Cross-Collateral Validation
export function checkMissingCrossCollateralValidation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';

  // Multiple collateral types
  if (/collateral.*type|multi.*collateral/i.test(content)) {
    if (!/correlation|combined.*value|cross.*margin/.test(content)) {
      findings.push({
        id: 'SOL609',
        title: 'Missing Cross-Collateral Validation',
        severity: 'high',
        category: 'business-logic',
        description: 'Multi-collateral systems need correlation and combined risk assessment',
        location: input.path,
        recommendation: 'Implement cross-collateral risk calculation with correlation factors'
      });
    }
  }

  return findings;
}

// SOL610: Incorrect Interest Accrual
export function checkIncorrectInterestAccrual(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';

  // Interest calculations
  if (/interest.*accrue|accrue.*interest|compound/i.test(content)) {
    if (!/time.*elapsed|block.*delta|last.*update/.test(content)) {
      findings.push({
        id: 'SOL610',
        title: 'Incorrect Interest Accrual',
        severity: 'high',
        category: 'business-logic',
        description: 'Interest accrual without proper time tracking leads to incorrect calculations',
        location: input.path,
        recommendation: 'Track time elapsed since last accrual for accurate interest calculations'
      });
    }
  }

  return findings;
}

// SOL611: Missing Reserve Factor Application
export function checkMissingReserveFactor(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';

  // Lending protocols without reserve
  if (/lending|borrow|supply/i.test(content) &&
      /interest|yield/i.test(content) &&
      !/reserve.*factor|protocol.*fee|treasury.*cut/.test(content)) {
    findings.push({
      id: 'SOL611',
      title: 'Missing Reserve Factor Application',
      severity: 'medium',
      category: 'business-logic',
      description: 'Lending protocols without reserve factors cannot build insurance reserves',
      location: input.path,
      recommendation: 'Implement reserve factor to build protocol reserves from interest spread'
    });
  }

  return findings;
}

// SOL612: Incorrect Slashing Condition
export function checkIncorrectSlashingCondition(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';

  // Slashing in staking
  if (/slash/i.test(content)) {
    if (!/evidence|proof|violation/.test(content)) {
      findings.push({
        id: 'SOL612',
        title: 'Incorrect Slashing Condition',
        severity: 'critical',
        category: 'business-logic',
        description: 'Slashing without proper violation evidence can lead to unfair fund loss',
        location: input.path,
        recommendation: 'Require cryptographic evidence of violations before slashing'
      });
    }
  }

  return findings;
}
