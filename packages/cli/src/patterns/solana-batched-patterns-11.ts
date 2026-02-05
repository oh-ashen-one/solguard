import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

// SOL311-SOL330: Additional vulnerability patterns from audit reports and exploits

/**
 * SOL311: Port Max Withdraw Bug
 * Vulnerability discovered in Port Finance - max withdraw calculation error
 */
export function checkPortMaxWithdrawBug(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rustCode = input.rust?.content || '';
  
  // Check for max withdraw calculation without proper bounds
  if (/max_withdraw|maximum_withdraw|withdraw_max/.test(rustCode)) {
    if (!/min\s*\(|\.min\(/.test(rustCode)) {
      findings.push({
        id: 'SOL311',
        title: 'Port Max Withdraw Bug Pattern',
        severity: 'high',
        description: 'Max withdraw calculation without proper bounds checking. Port Finance had a bug where max withdraw could exceed available liquidity.',
        location: input.path,
        recommendation: 'Use min() to cap max_withdraw to actual available balance. Always validate withdraw amounts against pool liquidity.'
      });
    }
  }
  
  return findings;
}

/**
 * SOL312: Jet Governance Vulnerability
 * Issues found in Jet Protocol governance
 */
export function checkJetGovernanceVuln(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rustCode = input.rust?.content || '';
  
  // Check for governance without proper proposal validation
  if (/governance|proposal|vote/.test(rustCode) && /execute|process/.test(rustCode)) {
    if (!/proposal_state|is_valid|check_proposal/.test(rustCode)) {
      findings.push({
        id: 'SOL312',
        title: 'Jet Governance Vulnerability Pattern',
        severity: 'high',
        description: 'Governance proposal execution without proper state validation. Jet Protocol had vulnerabilities in governance proposal handling.',
        location: input.path,
        recommendation: 'Validate proposal state before execution. Check voting period has ended, quorum reached, and proposal not already executed.'
      });
    }
  }
  
  return findings;
}

/**
 * SOL313: Semantic Inconsistency (Stake Pool)
 * Sec3 discovered semantic inconsistency in Solana Stake Pool
 */
export function checkSemanticInconsistency(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rustCode = input.rust?.content || '';
  
  // Check for stake operations with potential inconsistencies
  if (/stake|unstake|delegation/.test(rustCode)) {
    if (/state\s*=|status\s*=/.test(rustCode) && !/atomic|transaction/.test(rustCode)) {
      findings.push({
        id: 'SOL313',
        title: 'Semantic Inconsistency Vulnerability',
        severity: 'high',
        description: 'Potential semantic inconsistency in state updates. Stake Pool audit revealed vulnerabilities where state could be inconsistent between operations.',
        location: input.path,
        recommendation: 'Ensure atomic state updates. All related state changes should happen in a single transaction with proper ordering.'
      });
    }
  }
  
  return findings;
}

/**
 * SOL314: SPL Token Approve Revocation Issue
 * Sneaky ways to bypass token approval revocations
 */
export function checkTokenApproveRevocation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rustCode = input.rust?.content || '';
  
  // Check for approve/delegate handling
  if (/approve|delegate/.test(rustCode)) {
    if (!/revoke|reset_delegate/.test(rustCode)) {
      findings.push({
        id: 'SOL314',
        title: 'Token Approval Revocation Missing',
        severity: 'medium',
        description: 'Token approvals should have clear revocation mechanisms. Residual approvals can be exploited.',
        location: input.path,
        recommendation: 'Implement proper revocation. Consider auto-expiring approvals or single-use delegates.'
      });
    }
  }
  
  return findings;
}

/**
 * SOL315: LP Token Fair Pricing
 * OtterSec identified $200M at risk from LP token oracle manipulation
 */
export function checkLpTokenFairPricing(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rustCode = input.rust?.content || '';
  
  // Check for LP token pricing
  if (/lp_token|liquidity_token/.test(rustCode) && /price|value|worth/.test(rustCode)) {
    if (!/fair_price|sqrt|geometric_mean/.test(rustCode)) {
      findings.push({
        id: 'SOL315',
        title: 'LP Token Fair Pricing Missing',
        severity: 'critical',
        description: 'LP token valuation without fair pricing formula. $200M was at risk from LP token oracle manipulation attacks.',
        location: input.path,
        recommendation: 'Use fair LP pricing formulas (e.g., sqrt(reserve0 * reserve1) * 2 / totalSupply). Never use spot prices for LP valuation.'
      });
    }
  }
  
  return findings;
}

/**
 * SOL316: Signature Set Fabrication (Wormhole-detailed)
 * Detailed check for Wormhole-style signature verification bypass
 */
export function checkSignatureSetFabrication(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rustCode = input.rust?.content || '';
  
  // Check for signature verification
  if (/signature|verify|guardian|validator/.test(rustCode)) {
    if (/AccountInfo|UncheckedAccount/.test(rustCode) && !/program_id\s*==|owner\s*==/.test(rustCode)) {
      findings.push({
        id: 'SOL316',
        title: 'Signature Set Fabrication Risk',
        severity: 'critical',
        description: 'Signature verification using unchecked accounts. Wormhole exploit used fake SignatureSet account to bypass validation.',
        location: input.path,
        recommendation: 'Always verify account ownership and program ID before trusting signature data. Use PDA-derived signature accounts.'
      });
    }
  }
  
  return findings;
}

/**
 * SOL317: Candy Machine Zero Account Exploit
 * Check for Candy Machine style exploits where zero accounts bypass validation
 */
export function checkCandyMachineZeroAccount(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rustCode = input.rust?.content || '';
  
  // Check for NFT minting patterns
  if (/mint|nft|candy/.test(rustCode)) {
    if (/#\[account\(zero\)\]/.test(rustCode) && !/#\[account\(zero,/.test(rustCode)) {
      findings.push({
        id: 'SOL317',
        title: 'Candy Machine Zero Account Vulnerability',
        severity: 'high',
        description: 'Using #[account(zero)] without additional constraints. Candy Machine exploit allowed bypassing initialization.',
        location: input.path,
        recommendation: 'Use #[account(zero, ...additional_constraints)] to ensure proper validation even on zero-initialized accounts.'
      });
    }
  }
  
  return findings;
}

/**
 * SOL318: Cope Roulette Style Revert Exploit
 * Exploiting reverting transactions for guaranteed outcomes
 */
export function checkRevertExploit(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rustCode = input.rust?.content || '';
  
  // Check for randomness or game logic
  if (/random|rng|game|bet|lottery|roulette/.test(rustCode)) {
    if (!/commit.*reveal|vrf|switchboard/.test(rustCode)) {
      findings.push({
        id: 'SOL318',
        title: 'Transaction Revert Exploit Risk',
        severity: 'high',
        description: 'Game/betting logic vulnerable to revert-based exploits. Cope Roulette showed how reverting unfavorable outcomes guarantees wins.',
        location: input.path,
        recommendation: 'Use commit-reveal schemes or VRF (Switchboard/Pyth) for randomness. Never allow same-transaction randomness resolution.'
      });
    }
  }
  
  return findings;
}

/**
 * SOL319: Simulation Detection Bypass
 * Opcodes research on detecting and exploiting transaction simulation
 */
export function checkSimulationDetectionBypass(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rustCode = input.rust?.content || '';
  
  // Check for simulation-dependent logic
  if (/simulation|simulate|preflight/.test(rustCode)) {
    findings.push({
      id: 'SOL319',
      title: 'Simulation Detection Logic',
      severity: 'medium',
      description: 'Code appears to detect or handle transaction simulation differently. This can be exploited or bypassed.',
      location: input.path,
      recommendation: 'Do not rely on simulation detection for security. Simulation behavior can be manipulated by validators.'
    });
  }
  
  return findings;
}

/**
 * SOL320: Cross-Program Authority Delegation Chain
 * Wormhole exploit involved breaking authority delegation chains
 */
export function checkAuthorityDelegationChain(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rustCode = input.rust?.content || '';
  
  // Check for delegated authority patterns
  if (/delegate|authority|signer/.test(rustCode) && /invoke|cpi/.test(rustCode)) {
    if (/AccountInfo.*authority|authority.*AccountInfo/.test(rustCode)) {
      if (!/verify.*authority|check.*authority/.test(rustCode)) {
        findings.push({
          id: 'SOL320',
          title: 'Authority Delegation Chain Vulnerability',
          severity: 'critical',
          description: 'Delegated authority without proper verification chain. Wormhole exploit broke the delegation chain to forge signatures.',
          location: input.path,
          recommendation: 'Verify entire delegation chain. Each hop in authority delegation must be explicitly validated.'
        });
      }
    }
  }
  
  return findings;
}

/**
 * SOL321: Quarry Reward Distribution Vulnerability
 * Issues found in reward distribution mechanisms
 */
export function checkQuarryRewardDistribution(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rustCode = input.rust?.content || '';
  
  // Check for reward distribution patterns
  if (/reward|emission|distribute|claim/.test(rustCode)) {
    if (/rate|per_second|per_slot/.test(rustCode)) {
      if (!/timestamp|last_update|accrue/.test(rustCode)) {
        findings.push({
          id: 'SOL321',
          title: 'Reward Distribution Timing Issue',
          severity: 'high',
          description: 'Reward distribution without proper time-based accrual. Can lead to reward manipulation.',
          location: input.path,
          recommendation: 'Track last_update_time and accrue rewards based on elapsed time. Use saturating math for reward calculations.'
        });
      }
    }
  }
  
  return findings;
}

/**
 * SOL322: Saber Stable Swap Invariant
 * Checking for stable swap curve implementation issues
 */
export function checkStableSwapInvariant(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rustCode = input.rust?.content || '';
  
  // Check for stable swap patterns
  if (/stable.*swap|stableswap|curve/.test(rustCode)) {
    if (/amplification|amp_factor|A\s*=/.test(rustCode)) {
      if (!/invariant|d_value|compute_d/.test(rustCode)) {
        findings.push({
          id: 'SOL322',
          title: 'Stable Swap Invariant Missing',
          severity: 'high',
          description: 'Stable swap with amplification but missing invariant calculation. Can lead to arbitrage or drain attacks.',
          location: input.path,
          recommendation: 'Implement proper StableSwap invariant calculation (D). Validate amplification factor bounds.'
        });
      }
    }
  }
  
  return findings;
}

/**
 * SOL323: Marinade Stake Pool Security
 * Patterns from Marinade Finance audits
 */
export function checkMarinadeStakePoolSecurity(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rustCode = input.rust?.content || '';
  
  // Check for liquid staking patterns
  if (/liquid.*stake|mSOL|stake_pool/.test(rustCode)) {
    if (!/validator_list|stake_account_check/.test(rustCode)) {
      findings.push({
        id: 'SOL323',
        title: 'Liquid Staking Validator Validation',
        severity: 'high',
        description: 'Liquid staking without proper validator list validation. Marinade audits highlighted importance of stake account verification.',
        location: input.path,
        recommendation: 'Validate stake accounts belong to approved validator list. Check stake account state and delegation.'
      });
    }
  }
  
  return findings;
}

/**
 * SOL324: Orca Whirlpool Tick Array Security
 * Patterns from Orca Whirlpools audit
 */
export function checkWhirlpoolTickArraySecurity(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rustCode = input.rust?.content || '';
  
  // Check for CLMM/tick array patterns
  if (/tick_array|whirlpool|clmm/.test(rustCode)) {
    if (!/tick_array_index|valid_tick/.test(rustCode)) {
      findings.push({
        id: 'SOL324',
        title: 'CLMM Tick Array Validation',
        severity: 'high',
        description: 'Concentrated liquidity tick array without proper index validation. Can lead to out-of-bounds or invalid tick access.',
        location: input.path,
        recommendation: 'Validate tick array indices are within bounds. Ensure tick spacing is respected.'
      });
    }
  }
  
  return findings;
}

/**
 * SOL325: Pyth Oracle Integration Security
 * Patterns from Pyth audit (Zellic)
 */
export function checkPythOracleIntegration(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rustCode = input.rust?.content || '';
  
  // Check for Pyth oracle usage
  if (/pyth|price_feed|price_account/.test(rustCode)) {
    if (!/conf|confidence|status|trading/.test(rustCode)) {
      findings.push({
        id: 'SOL325',
        title: 'Pyth Oracle Confidence Check Missing',
        severity: 'high',
        description: 'Pyth oracle usage without checking price confidence interval or trading status.',
        location: input.path,
        recommendation: 'Check price.conf is within acceptable bounds. Verify price.status == Trading. Validate price.publish_time is recent.'
      });
    }
  }
  
  return findings;
}

/**
 * SOL326: Drift Protocol Oracle Guardrails
 * Oracle guardrail patterns from Drift Protocol
 */
export function checkDriftOracleGuardrails(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rustCode = input.rust?.content || '';
  
  // Check for perpetual/leverage oracle usage
  if (/perp|perpetual|leverage|margin/.test(rustCode) && /oracle|price/.test(rustCode)) {
    if (!/oracle_guard|price_divergence|max_spread/.test(rustCode)) {
      findings.push({
        id: 'SOL326',
        title: 'Oracle Guardrails Missing (Drift-style)',
        severity: 'high',
        description: 'Leveraged trading without oracle guardrails. Drift implements price divergence checks and max spread limits.',
        location: input.path,
        recommendation: 'Implement oracle guardrails: max price divergence between sources, staleness checks, confidence intervals.'
      });
    }
  }
  
  return findings;
}

/**
 * SOL327: Solido Liquid Staking Security
 * Patterns from Solido (Lido on Solana) audits
 */
export function checkSolidoLiquidStaking(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rustCode = input.rust?.content || '';
  
  // Check for stSOL-style liquid staking
  if (/stSOL|st_sol|liquid_stake/.test(rustCode)) {
    if (!/exchange_rate|maintain_peg/.test(rustCode)) {
      findings.push({
        id: 'SOL327',
        title: 'Liquid Staking Exchange Rate Security',
        severity: 'high',
        description: 'Liquid staking token without proper exchange rate management. Solido audits emphasized rate manipulation prevention.',
        location: input.path,
        recommendation: 'Implement secure exchange rate updates with time-weighted averaging. Prevent flash manipulation of rates.'
      });
    }
  }
  
  return findings;
}

/**
 * SOL328: Squads Multisig Replay Prevention
 * Patterns from Squads Protocol audit
 */
export function checkSquadsMultisigReplay(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rustCode = input.rust?.content || '';
  
  // Check for multisig patterns
  if (/multisig|multi_sig|threshold/.test(rustCode) && /execute|approve/.test(rustCode)) {
    if (!/sequence|nonce|tx_index/.test(rustCode)) {
      findings.push({
        id: 'SOL328',
        title: 'Multisig Transaction Replay Risk',
        severity: 'critical',
        description: 'Multisig without transaction sequence/nonce. Squads uses sequential tx_index to prevent replay.',
        location: input.path,
        recommendation: 'Use monotonically increasing transaction index. Mark transactions as executed after processing.'
      });
    }
  }
  
  return findings;
}

/**
 * SOL329: Streamflow Vesting Security
 * Patterns from Streamflow vesting/payment audit
 */
export function checkStreamflowVestingSecurity(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rustCode = input.rust?.content || '';
  
  // Check for vesting/streaming patterns
  if (/vesting|stream|cliff|linear_release/.test(rustCode)) {
    if (!/withdrawn_amount|available_to_claim/.test(rustCode)) {
      findings.push({
        id: 'SOL329',
        title: 'Vesting Stream Accounting Error',
        severity: 'high',
        description: 'Token vesting without proper withdrawn amount tracking. Can lead to over-claiming.',
        location: input.path,
        recommendation: 'Track total_amount, withdrawn_amount, and calculate available = vested - withdrawn. Use checked math.'
      });
    }
  }
  
  return findings;
}

/**
 * SOL330: Phoenix DEX Order Book Security
 * Patterns from Phoenix order book audit (OtterSec)
 */
export function checkPhoenixOrderBookSecurity(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rustCode = input.rust?.content || '';
  
  // Check for order book patterns
  if (/order_book|orderbook|bid|ask|limit_order/.test(rustCode)) {
    if (!/match.*engine|price_time_priority/.test(rustCode)) {
      findings.push({
        id: 'SOL330',
        title: 'Order Book Matching Engine Security',
        severity: 'high',
        description: 'Order book without proper matching engine. Phoenix audit emphasized price-time priority and fair matching.',
        location: input.path,
        recommendation: 'Implement price-time priority matching. Validate order prices against tick size. Prevent self-trading.'
      });
    }
  }
  
  return findings;
}
