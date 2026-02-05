/**
 * SolGuard Security Patterns - Batch 12 (SOL401-SOL450)
 * Advanced vulnerability patterns from recent exploits and audit findings
 * Focus: DeFi-specific attacks, economic exploits, and protocol design flaws
 */

import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

// ============================================================================
// ADVANCED ORACLE ATTACKS
// ============================================================================

// SOL401: TWAP Window Manipulation
export function checkTWAPWindowManipulation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/twap|time.*weighted|moving.*average/gi.test(content)) {
    if (!/window.*size|min.*observations|manipulation.*resist/gi.test(content)) {
      findings.push({
        id: 'SOL401',
        severity: 'high',
        title: 'TWAP Window Too Short',
        description: 'Short TWAP windows can still be manipulated with sufficient capital across multiple blocks.',
        location: input.path,
        recommendation: 'Use longer TWAP windows (30+ minutes). Require minimum number of observations.',
      });
    }
  }
  
  return findings;
}

// SOL402: Oracle Heartbeat Missing
export function checkOracleHeartbeatMissing(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/oracle|price.*feed|external.*price/gi.test(content)) {
    if (!/heartbeat|update.*frequency|expected.*interval/gi.test(content)) {
      findings.push({
        id: 'SOL402',
        severity: 'high',
        title: 'Missing Oracle Heartbeat Check',
        description: 'Oracles may stop updating without explicit failure. Check expected update frequency.',
        location: input.path,
        recommendation: 'Verify oracle updates within expected heartbeat interval.',
      });
    }
  }
  
  return findings;
}

// SOL403: On-Chain Oracle Manipulation
export function checkOnChainOracleManipulation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/pool.*price|dex.*price|on.*chain.*oracle/gi.test(content)) {
    if (!/off.*chain|external.*oracle|chainlink|pyth|switchboard/gi.test(content)) {
      findings.push({
        id: 'SOL403',
        severity: 'critical',
        title: 'On-Chain Oracle Vulnerability',
        description: 'On-chain oracles (e.g., DEX spot prices) are trivially manipulable via flash loans.',
        location: input.path,
        recommendation: 'Use off-chain oracles (Pyth, Switchboard) or TWAP with long windows.',
      });
    }
  }
  
  return findings;
}

// ============================================================================
// FLASH LOAN ATTACK VECTORS
// ============================================================================

// SOL404: Flash Loan Governance Attack
export function checkFlashLoanGovernanceAttack(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/governance|vote|proposal|quorum/gi.test(content)) {
    if (/token.*balance|voting.*power.*balance/gi.test(content)) {
      if (!/snapshot|checkpoint|locked.*token|time.*lock/gi.test(content)) {
        findings.push({
          id: 'SOL404',
          severity: 'critical',
          title: 'Flash Loan Governance Attack',
          description: 'Governance based on spot token balance can be attacked with flash loans to pass malicious proposals.',
          location: input.path,
          recommendation: 'Use snapshot-based voting. Require token lock-up for voting power.',
        });
      }
    }
  }
  
  return findings;
}

// SOL405: Flash Loan Arbitrage Protection
export function checkFlashLoanArbitrageProtection(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/arbitrage|price.*diff|cross.*market/gi.test(content)) {
    if (!/fee.*structure|profit.*limit|arb.*protect/gi.test(content)) {
      findings.push({
        id: 'SOL405',
        severity: 'medium',
        title: 'Unprotected Arbitrage Path',
        description: 'Arbitrage opportunities without fee structures allow risk-free value extraction via flash loans.',
        location: input.path,
        recommendation: 'Add fees that make flash loan arbitrage unprofitable.',
      });
    }
  }
  
  return findings;
}

// SOL406: Flash Loan Reentrancy
export function checkFlashLoanReentrancy(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/flash.*loan|callback|execute.*operation/gi.test(content)) {
    if (!/reentrancy.*lock|in.*flash|flash.*guard/gi.test(content)) {
      findings.push({
        id: 'SOL406',
        severity: 'critical',
        title: 'Flash Loan Reentrancy Risk',
        description: 'Flash loan callbacks without reentrancy protection allow recursive exploitation.',
        location: input.path,
        recommendation: 'Add reentrancy guard during flash loan execution. Lock protocol state.',
      });
    }
  }
  
  return findings;
}

// ============================================================================
// LIQUIDITY MINING EXPLOITS
// ============================================================================

// SOL407: Liquidity Mining Vampire Attack
export function checkVampireAttack(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/liquidity.*mining|yield.*farm|incentive/gi.test(content)) {
    if (!/lock.*period|vesting|commitment|exit.*fee/gi.test(content)) {
      findings.push({
        id: 'SOL407',
        severity: 'medium',
        title: 'Vampire Attack Vulnerability',
        description: 'Liquidity incentives without commitment periods allow mercenary capital that leaves immediately.',
        location: input.path,
        recommendation: 'Add lock-up periods, vesting schedules, or exit fees for incentivized liquidity.',
      });
    }
  }
  
  return findings;
}

// SOL408: Reward Token Inflation
export function checkRewardTokenInflation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/reward.*token|emission|mining.*token/gi.test(content)) {
    if (!/max.*supply|emission.*schedule|halving|deflation/gi.test(content)) {
      findings.push({
        id: 'SOL408',
        severity: 'high',
        title: 'Unlimited Reward Token Inflation',
        description: 'Reward tokens without supply caps lead to hyperinflation and value destruction.',
        location: input.path,
        recommendation: 'Cap total supply. Implement emission schedule with declining rates.',
      });
    }
  }
  
  return findings;
}

// SOL409: Staking Sandwich Attack
export function checkStakingSandwichAttack(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/stake|deposit.*reward|add.*liquidity/gi.test(content)) {
    if (!/reward.*start.*time|pro.*rata.*time|time.*weighted/gi.test(content)) {
      findings.push({
        id: 'SOL409',
        severity: 'high',
        title: 'Staking Sandwich Attack',
        description: 'Staking just before reward distribution and unstaking after allows unfair reward capture.',
        location: input.path,
        recommendation: 'Use time-weighted staking for reward calculation. Delay reward eligibility.',
      });
    }
  }
  
  return findings;
}

// ============================================================================
// ECONOMIC EXPLOITS
// ============================================================================

// SOL410: Price Impact Exploitation
export function checkPriceImpactExploitation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/large.*trade|whale|significant.*amount/gi.test(content)) {
    if (!/max.*trade|position.*limit|impact.*fee/gi.test(content)) {
      findings.push({
        id: 'SOL410',
        severity: 'high',
        title: 'Unbounded Trade Size',
        description: 'Large trades without limits can manipulate prices or drain liquidity.',
        location: input.path,
        recommendation: 'Limit maximum trade size per transaction. Add progressive price impact fees.',
      });
    }
  }
  
  return findings;
}

// SOL411: Protocol Insolvency Risk
export function checkProtocolInsolvencyRisk(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/liability|debt|obligation|owed/gi.test(content)) {
    if (!/solvency.*check|collateral.*ratio|reserve.*ratio/gi.test(content)) {
      findings.push({
        id: 'SOL411',
        severity: 'critical',
        title: 'Missing Solvency Checks',
        description: 'Protocols without solvency verification can become insolvent, losing user funds.',
        location: input.path,
        recommendation: 'Continuously verify protocol solvency. Maintain adequate reserves.',
      });
    }
  }
  
  return findings;
}

// SOL412: Yield Farming APY Manipulation
export function checkYieldFarmingAPYManipulation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/apy|apr|yield|return.*rate/gi.test(content)) {
    if (/display|show|advertis|calculate.*apy/gi.test(content)) {
      if (!/actual.*return|real.*yield|sustainable/gi.test(content)) {
        findings.push({
          id: 'SOL412',
          severity: 'medium',
          title: 'Misleading APY Display',
          description: 'Displayed APY may not reflect actual returns, especially with token inflation.',
          location: input.path,
          recommendation: 'Display real yield accounting for token inflation and impermanent loss.',
        });
      }
    }
  }
  
  return findings;
}

// ============================================================================
// VAULT/STRATEGY VULNERABILITIES
// ============================================================================

// SOL413: Vault Strategy Risk
export function checkVaultStrategyRisk(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/vault|strategy|yield.*optimize/gi.test(content)) {
    if (!/loss.*limit|risk.*param|strategy.*whitelist/gi.test(content)) {
      findings.push({
        id: 'SOL413',
        severity: 'high',
        title: 'Unbounded Vault Strategy Risk',
        description: 'Vault strategies without risk limits can expose depositors to unlimited losses.',
        location: input.path,
        recommendation: 'Limit strategy exposure. Whitelist approved strategies. Set loss limits.',
      });
    }
  }
  
  return findings;
}

// SOL414: Vault Share Manipulation
export function checkVaultShareManipulation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/vault.*share|share.*price|assets.*per.*share/gi.test(content)) {
    if (!/min.*assets|donation.*protect|virtual.*assets/gi.test(content)) {
      findings.push({
        id: 'SOL414',
        severity: 'critical',
        title: 'Vault Share Price Manipulation',
        description: 'Vault share price can be manipulated by donating assets directly to the vault.',
        location: input.path,
        recommendation: 'Use virtual assets offset. Protect against donation attacks.',
      });
    }
  }
  
  return findings;
}

// SOL415: Yield Skimming Attack
export function checkYieldSkimmingAttack(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/compound|reinvest|harvest|claim.*yield/gi.test(content)) {
    if (!/compound.*fee|performance.*fee|keeper.*incentive/gi.test(content)) {
      findings.push({
        id: 'SOL415',
        severity: 'medium',
        title: 'Yield Skimming Vulnerability',
        description: 'Without proper fee structure, attackers can front-run harvests to skim yield.',
        location: input.path,
        recommendation: 'Add performance fees on harvest. Incentivize timely compounding.',
      });
    }
  }
  
  return findings;
}

// ============================================================================
// PERPETUAL/DERIVATIVES VULNERABILITIES
// ============================================================================

// SOL416: Funding Rate Manipulation
export function checkFundingRateManipulation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/funding.*rate|perpetual|perp.*swap/gi.test(content)) {
    if (!/funding.*cap|rate.*limit|manipulation.*protect/gi.test(content)) {
      findings.push({
        id: 'SOL416',
        severity: 'high',
        title: 'Funding Rate Manipulation',
        description: 'Uncapped funding rates can be manipulated to extract value from counterparties.',
        location: input.path,
        recommendation: 'Cap funding rates. Use TWAP for rate calculation.',
      });
    }
  }
  
  return findings;
}

// SOL417: Liquidation Cascade
export function checkLiquidationCascade(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/liquidat|margin.*call|forced.*close/gi.test(content)) {
    if (!/cascade.*protect|circuit.*break|gradual.*liquidat/gi.test(content)) {
      findings.push({
        id: 'SOL417',
        severity: 'high',
        title: 'Liquidation Cascade Risk',
        description: 'Mass liquidations can cascade, crashing prices and causing protocol insolvency.',
        location: input.path,
        recommendation: 'Implement gradual liquidation. Add circuit breakers for cascading events.',
      });
    }
  }
  
  return findings;
}

// SOL418: Mark Price Manipulation
export function checkMarkPriceManipulation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/mark.*price|index.*price|fair.*price/gi.test(content)) {
    if (!/oracle.*mark|external.*index|manipulation.*resist/gi.test(content)) {
      findings.push({
        id: 'SOL418',
        severity: 'critical',
        title: 'Mark Price Manipulation',
        description: 'Mark prices derived from internal data can be manipulated for liquidation attacks.',
        location: input.path,
        recommendation: 'Use external oracle for mark price. Implement manipulation-resistant calculation.',
      });
    }
  }
  
  return findings;
}

// SOL419: Insurance Fund Drain
export function checkInsuranceFundDrain(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/insurance.*fund|backstop|reserve.*fund/gi.test(content)) {
    if (!/fund.*limit|claim.*cap|fund.*replenish/gi.test(content)) {
      findings.push({
        id: 'SOL419',
        severity: 'high',
        title: 'Insurance Fund Drain Risk',
        description: 'Insurance funds without claim limits can be drained by manufactured bad debt.',
        location: input.path,
        recommendation: 'Cap per-event claims. Implement fund replenishment mechanism.',
      });
    }
  }
  
  return findings;
}

// SOL420: Basis Trade Exploit
export function checkBasisTradeExploit(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/basis|spot.*perp|cash.*carry/gi.test(content)) {
    if (!/basis.*limit|arb.*fee|spread.*protect/gi.test(content)) {
      findings.push({
        id: 'SOL420',
        severity: 'medium',
        title: 'Basis Trade Exploitation',
        description: 'Large basis trades can destabilize perpetual markets.',
        location: input.path,
        recommendation: 'Monitor and limit basis trades. Add fees for large positions.',
      });
    }
  }
  
  return findings;
}

// ============================================================================
// TOKENOMICS VULNERABILITIES
// ============================================================================

// SOL421: Token Unlock Shock
export function checkTokenUnlockShock(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/unlock|vest|release.*token|cliff/gi.test(content)) {
    if (!/gradual.*unlock|linear.*vest|drip/gi.test(content)) {
      findings.push({
        id: 'SOL421',
        severity: 'medium',
        title: 'Large Token Unlock Risk',
        description: 'Cliff unlocks of large token amounts can crash token price.',
        location: input.path,
        recommendation: 'Use linear vesting instead of cliff. Limit per-period unlock amounts.',
      });
    }
  }
  
  return findings;
}

// SOL422: Concentrated Token Holdings
export function checkConcentratedTokenHoldings(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/token.*distribution|allocation|holder/gi.test(content)) {
    if (!/max.*holding|whale.*limit|concentration/gi.test(content)) {
      findings.push({
        id: 'SOL422',
        severity: 'medium',
        title: 'Token Concentration Risk',
        description: 'Concentrated token holdings create governance and market manipulation risks.',
        location: input.path,
        recommendation: 'Limit maximum holdings per address. Implement transfer limits.',
      });
    }
  }
  
  return findings;
}

// SOL423: Fee Token Extraction
export function checkFeeTokenExtraction(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/protocol.*fee|trading.*fee|fee.*collect/gi.test(content)) {
    if (!/fee.*cap|reasonable.*fee|fee.*vote/gi.test(content)) {
      findings.push({
        id: 'SOL423',
        severity: 'high',
        title: 'Extractive Fee Structure',
        description: 'Uncapped protocol fees can be used to extract excessive value from users.',
        location: input.path,
        recommendation: 'Cap maximum fees. Require governance approval for fee changes.',
      });
    }
  }
  
  return findings;
}

// ============================================================================
// ACCESS CONTROL ADVANCED
// ============================================================================

// SOL424: Emergency Function Abuse
export function checkEmergencyFunctionAbuse(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/emergency|pause|shutdown|kill.*switch/gi.test(content)) {
    if (!/timelock.*emergency|guardian.*only|multi.*approval/gi.test(content)) {
      findings.push({
        id: 'SOL424',
        severity: 'high',
        title: 'Emergency Function Abuse Risk',
        description: 'Emergency functions without proper controls can be abused or accidentally triggered.',
        location: input.path,
        recommendation: 'Require multiple approvals for emergency actions. Add unpause timelock.',
      });
    }
  }
  
  return findings;
}

// SOL425: Admin Key Recovery
export function checkAdminKeyRecovery(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/admin|owner|authority/gi.test(content)) {
    if (!/recovery|backup.*admin|guardian|social.*recovery/gi.test(content)) {
      findings.push({
        id: 'SOL425',
        severity: 'medium',
        title: 'No Admin Key Recovery',
        description: 'Lost admin keys with no recovery mechanism can permanently lock protocol.',
        location: input.path,
        recommendation: 'Implement key recovery mechanism. Use multisig with backup signers.',
      });
    }
  }
  
  return findings;
}

// SOL426: Permissioned Function Exposure
export function checkPermissionedFunctionExposure(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/pub\s+fn|pub\s+async\s+fn|#\[instruction\]/gi.test(content)) {
    if (/internal|private|admin|owner/gi.test(content)) {
      if (!/require.*admin|has_one|constraint|signer/gi.test(content)) {
        findings.push({
          id: 'SOL426',
          severity: 'critical',
          title: 'Permissioned Function Without Access Control',
          description: 'Functions marked as internal/admin may be publicly callable without proper checks.',
          location: input.path,
          recommendation: 'Add explicit access control to all privileged functions.',
        });
      }
    }
  }
  
  return findings;
}

// ============================================================================
// DATA INTEGRITY ADVANCED
// ============================================================================

// SOL427: Merkle Tree Leaf Collision
export function checkMerkleLeafCollision(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/merkle|tree|leaf|proof/gi.test(content)) {
    if (!/leaf.*prefix|domain.*separator|typed.*data/gi.test(content)) {
      findings.push({
        id: 'SOL427',
        severity: 'high',
        title: 'Merkle Leaf Collision Risk',
        description: 'Merkle trees without leaf prefixes can have leaf-node collision attacks.',
        location: input.path,
        recommendation: 'Use different prefixes for leaf and internal nodes. Add domain separator.',
      });
    }
  }
  
  return findings;
}

// SOL428: Hash Collision in Seeds
export function checkHashCollisionInSeeds(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/seed|hash|derive/gi.test(content)) {
    if (/concat|append|combine/gi.test(content)) {
      if (!/length.*prefix|separator|fixed.*length/gi.test(content)) {
        findings.push({
          id: 'SOL428',
          severity: 'high',
          title: 'Seed Concatenation Collision',
          description: 'Concatenating variable-length seeds without separators can cause collisions.',
          location: input.path,
          recommendation: 'Use length-prefixed encoding or fixed separators between seed components.',
        });
      }
    }
  }
  
  return findings;
}

// SOL429: Signature Malleability
export function checkSignatureMalleability(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/signature|verify.*sig|ed25519/gi.test(content)) {
    if (!/low.*s|canonical|strict.*verify/gi.test(content)) {
      findings.push({
        id: 'SOL429',
        severity: 'high',
        title: 'Signature Malleability',
        description: 'Ed25519 signatures are malleable. Two valid signatures can exist for the same message.',
        location: input.path,
        recommendation: 'Use strict signature verification. Canonicalize signatures.',
      });
    }
  }
  
  return findings;
}

// SOL430: Nonce Reuse
export function checkNonceReuse(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/nonce|counter|sequence/gi.test(content)) {
    if (!/increment.*nonce|unique.*nonce|nonce.*check/gi.test(content)) {
      findings.push({
        id: 'SOL430',
        severity: 'critical',
        title: 'Potential Nonce Reuse',
        description: 'Nonce reuse in cryptographic operations can compromise security.',
        location: input.path,
        recommendation: 'Always increment nonces atomically. Verify nonce uniqueness.',
      });
    }
  }
  
  return findings;
}

// ============================================================================
// PROTOCOL DESIGN FLAWS
// ============================================================================

// SOL431: Griefing Attack Vector
export function checkGriefingAttackVector(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/for.*user|iterate|batch|all.*accounts/gi.test(content)) {
    if (!/gas.*limit|max.*batch|paginate/gi.test(content)) {
      findings.push({
        id: 'SOL431',
        severity: 'medium',
        title: 'Griefing Attack Vector',
        description: 'Operations iterating over user data can be griefed by creating many accounts.',
        location: input.path,
        recommendation: 'Limit iterations. Use pagination. Charge for account creation.',
      });
    }
  }
  
  return findings;
}

// SOL432: Front-Running Constructor
export function checkFrontRunningConstructor(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/initialize|create|deploy|setup/gi.test(content)) {
    if (!/already.*init|init.*once|constructor.*lock/gi.test(content)) {
      findings.push({
        id: 'SOL432',
        severity: 'critical',
        title: 'Front-Runnable Initialization',
        description: 'Initialization functions can be front-run to take control of the protocol.',
        location: input.path,
        recommendation: 'Ensure initialization can only happen once. Use deployer checks.',
      });
    }
  }
  
  return findings;
}

// SOL433: Protocol Parameter Bounds
export function checkProtocolParameterBounds(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/set.*param|update.*config|change.*setting/gi.test(content)) {
    if (!/min.*value|max.*value|valid.*range|bound.*check/gi.test(content)) {
      findings.push({
        id: 'SOL433',
        severity: 'high',
        title: 'Unbounded Protocol Parameters',
        description: 'Protocol parameters without bounds can be set to extreme values.',
        location: input.path,
        recommendation: 'Define valid ranges for all configurable parameters.',
      });
    }
  }
  
  return findings;
}

// SOL434: Dust Attack Prevention
export function checkDustAttackPrevention(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/transfer|deposit|stake|lock/gi.test(content)) {
    if (!/min.*amount|dust.*threshold|minimum.*value/gi.test(content)) {
      findings.push({
        id: 'SOL434',
        severity: 'low',
        title: 'Dust Amount Not Prevented',
        description: 'Allowing dust amounts creates inefficiencies and potential attack vectors.',
        location: input.path,
        recommendation: 'Enforce minimum amounts for all value-transfer operations.',
      });
    }
  }
  
  return findings;
}

// SOL435: State Bloat Attack
export function checkStateBloatAttack(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/create.*account|new.*entry|add.*record/gi.test(content)) {
    if (!/rent.*fee|creation.*cost|deposit.*require/gi.test(content)) {
      findings.push({
        id: 'SOL435',
        severity: 'medium',
        title: 'State Bloat Attack Vector',
        description: 'Free account creation allows attackers to bloat protocol state.',
        location: input.path,
        recommendation: 'Require rent deposits for account creation. Charge creation fees.',
      });
    }
  }
  
  return findings;
}

// ============================================================================
// Additional patterns to reach SOL450
// ============================================================================

// SOL436: Withdrawal Queue Manipulation
export function checkWithdrawalQueueManipulation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/withdrawal.*queue|pending.*withdraw|queue/gi.test(content)) {
    if (!/fifo|fair.*order|queue.*protect/gi.test(content)) {
      findings.push({
        id: 'SOL436',
        severity: 'high',
        title: 'Withdrawal Queue Manipulation',
        description: 'Withdrawal queues without fairness guarantees can be manipulated.',
        location: input.path,
        recommendation: 'Implement FIFO ordering. Prevent queue jumping.',
      });
    }
  }
  
  return findings;
}

// SOL437: Epoch Boundary Attack
export function checkEpochBoundaryAttack(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/epoch|period.*end|cycle.*boundary/gi.test(content)) {
    if (!/epoch.*guard|boundary.*protect|transition.*safe/gi.test(content)) {
      findings.push({
        id: 'SOL437',
        severity: 'medium',
        title: 'Epoch Boundary Attack Risk',
        description: 'Operations at epoch boundaries may have different effects than expected.',
        location: input.path,
        recommendation: 'Guard against epoch boundary conditions. Test edge cases.',
      });
    }
  }
  
  return findings;
}

// SOL438: Slashing Condition Exploit
export function checkSlashingConditionExploit(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/slash|penalt|punishment/gi.test(content)) {
    if (!/proportional.*slash|max.*slash|appeal/gi.test(content)) {
      findings.push({
        id: 'SOL438',
        severity: 'high',
        title: 'Slashing Condition Exploit',
        description: 'Slashing without proper safeguards can be exploited to grief honest participants.',
        location: input.path,
        recommendation: 'Cap slashing amounts. Allow appeals. Implement proportional penalties.',
      });
    }
  }
  
  return findings;
}

// SOL439: Orderbook Manipulation
export function checkOrderbookManipulation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/order.*book|bid|ask|limit.*order/gi.test(content)) {
    if (!/spoofing.*protect|wash.*detect|manipulation.*prevent/gi.test(content)) {
      findings.push({
        id: 'SOL439',
        severity: 'high',
        title: 'Orderbook Manipulation Risk',
        description: 'Orderbooks without manipulation detection allow spoofing and wash trading.',
        location: input.path,
        recommendation: 'Implement anti-spoofing measures. Detect wash trading patterns.',
      });
    }
  }
  
  return findings;
}

// SOL440: Settlement Delay Exploit
export function checkSettlementDelayExploit(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/settle|clear|finalize.*trade/gi.test(content)) {
    if (!/atomic.*settle|instant.*settlement|settlement.*guarantee/gi.test(content)) {
      findings.push({
        id: 'SOL440',
        severity: 'medium',
        title: 'Settlement Delay Risk',
        description: 'Delayed settlement creates counterparty risk and manipulation opportunities.',
        location: input.path,
        recommendation: 'Use atomic settlement where possible. Require collateral for delayed settlement.',
      });
    }
  }
  
  return findings;
}

// SOL441-450: Final patterns in this batch
// SOL441: Account Squatting
export function checkAccountSquatting(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/pda|derive.*address|program.*address/gi.test(content)) {
    if (/user.*name|string.*seed|arbitrary.*seed/gi.test(content)) {
      findings.push({
        id: 'SOL441',
        severity: 'medium',
        title: 'Account Squatting Risk',
        description: 'PDAs derived from arbitrary user input can be squatted.',
        location: input.path,
        recommendation: 'Include user pubkey in PDA seeds to prevent squatting.',
      });
    }
  }
  
  return findings;
}

// SOL442: Token Account Hijacking
export function checkTokenAccountHijacking(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/token.*account|associated.*token/gi.test(content)) {
    if (!/create.*ata|init.*ata|ensure.*ata/gi.test(content)) {
      findings.push({
        id: 'SOL442',
        severity: 'high',
        title: 'Token Account Initialization Risk',
        description: 'Creating token accounts for users without proper handling can be exploited.',
        location: input.path,
        recommendation: 'Use associated token accounts. Verify account state before operations.',
      });
    }
  }
  
  return findings;
}

// SOL443: Signer Authority Confusion
export function checkSignerAuthorityConfusion(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/signer|authority|owner/gi.test(content)) {
    if (/multiple|several|both/gi.test(content)) {
      if (!/distinct|separate.*check|each.*verify/gi.test(content)) {
        findings.push({
          id: 'SOL443',
          severity: 'high',
          title: 'Multiple Authority Confusion',
          description: 'Multiple signers/authorities without clear separation can cause authorization bugs.',
          location: input.path,
          recommendation: 'Clearly define and verify each authority role separately.',
        });
      }
    }
  }
  
  return findings;
}

// SOL444: Instruction Introspection Bypass
export function checkInstructionIntrospectionBypass(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/introspect|instruction.*check|sysvar.*instruction/gi.test(content)) {
    if (!/verify.*all|complete.*check|exhaustive/gi.test(content)) {
      findings.push({
        id: 'SOL444',
        severity: 'high',
        title: 'Instruction Introspection Bypass',
        description: 'Incomplete instruction introspection checks can be bypassed.',
        location: input.path,
        recommendation: 'Verify all required instructions in the transaction.',
      });
    }
  }
  
  return findings;
}

// SOL445: CPI Return Data Validation
export function checkCPIReturnDataValidation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/return.*data|get_return_data|cpi.*return/gi.test(content)) {
    if (!/verify.*return|validate.*return|check.*program.*id/gi.test(content)) {
      findings.push({
        id: 'SOL445',
        severity: 'high',
        title: 'CPI Return Data Not Validated',
        description: 'CPI return data must be validated - it could come from any program.',
        location: input.path,
        recommendation: 'Verify return data program ID matches expected program.',
      });
    }
  }
  
  return findings;
}

// SOL446: Anchor Discriminator Override
export function checkAnchorDiscriminatorOverride(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/discriminator|#\[account\]|anchor/gi.test(content)) {
    if (/override|custom.*discriminator|manual.*discriminator/gi.test(content)) {
      findings.push({
        id: 'SOL446',
        severity: 'high',
        title: 'Custom Discriminator Risk',
        description: 'Custom discriminators can conflict with other account types.',
        location: input.path,
        recommendation: 'Use Anchor default discriminators unless absolutely necessary.',
      });
    }
  }
  
  return findings;
}

// SOL447: Zero-Copy Account Deserialization
export function checkZeroCopyDeserialization(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/zero.*copy|AccountLoader|RefMut/gi.test(content)) {
    if (!/size.*check|alignment|padding/gi.test(content)) {
      findings.push({
        id: 'SOL447',
        severity: 'medium',
        title: 'Zero-Copy Alignment Risk',
        description: 'Zero-copy deserialization requires proper alignment and size validation.',
        location: input.path,
        recommendation: 'Verify account size and alignment for zero-copy accounts.',
      });
    }
  }
  
  return findings;
}

// SOL448: Event Emission Tampering
export function checkEventEmissionTampering(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/emit!|emit_cpi|event|log/gi.test(content)) {
    if (!/after.*state|verified.*emit|true.*values/gi.test(content)) {
      findings.push({
        id: 'SOL448',
        severity: 'low',
        title: 'Potentially Misleading Event Emission',
        description: 'Events emitted before state changes may not reflect final state.',
        location: input.path,
        recommendation: 'Emit events after state changes are finalized.',
      });
    }
  }
  
  return findings;
}

// SOL449: Cross-Program Account Confusion
export function checkCrossProgramAccountConfusion(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/cpi|invoke|cross.*program/gi.test(content)) {
    if (/account.*info|remaining.*accounts/gi.test(content)) {
      if (!/verify.*each|check.*all|validate.*accounts/gi.test(content)) {
        findings.push({
          id: 'SOL449',
          severity: 'high',
          title: 'Cross-Program Account Confusion',
          description: 'Accounts passed to CPI without individual validation can be substituted.',
          location: input.path,
          recommendation: 'Validate each account before passing to CPI.',
        });
      }
    }
  }
  
  return findings;
}

// SOL450: Protocol Invariant Check
export function checkProtocolInvariantCheck(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/protocol|pool|vault|treasury/gi.test(content)) {
    if (!/invariant|assert.*total|verify.*sum|balance.*check/gi.test(content)) {
      findings.push({
        id: 'SOL450',
        severity: 'high',
        title: 'Missing Protocol Invariant Check',
        description: 'Protocols should verify critical invariants after each operation.',
        location: input.path,
        recommendation: 'Add invariant checks (e.g., total deposits == sum of user balances).',
      });
    }
  }
  
  return findings;
}

// ============================================================================
// Export all pattern checkers
// ============================================================================

export const batch12Patterns = [
  checkTWAPWindowManipulation,
  checkOracleHeartbeatMissing,
  checkOnChainOracleManipulation,
  checkFlashLoanGovernanceAttack,
  checkFlashLoanArbitrageProtection,
  checkFlashLoanReentrancy,
  checkVampireAttack,
  checkRewardTokenInflation,
  checkStakingSandwichAttack,
  checkPriceImpactExploitation,
  checkProtocolInsolvencyRisk,
  checkYieldFarmingAPYManipulation,
  checkVaultStrategyRisk,
  checkVaultShareManipulation,
  checkYieldSkimmingAttack,
  checkFundingRateManipulation,
  checkLiquidationCascade,
  checkMarkPriceManipulation,
  checkInsuranceFundDrain,
  checkBasisTradeExploit,
  checkTokenUnlockShock,
  checkConcentratedTokenHoldings,
  checkFeeTokenExtraction,
  checkEmergencyFunctionAbuse,
  checkAdminKeyRecovery,
  checkPermissionedFunctionExposure,
  checkMerkleLeafCollision,
  checkHashCollisionInSeeds,
  checkSignatureMalleability,
  checkNonceReuse,
  checkGriefingAttackVector,
  checkFrontRunningConstructor,
  checkProtocolParameterBounds,
  checkDustAttackPrevention,
  checkStateBloatAttack,
  checkWithdrawalQueueManipulation,
  checkEpochBoundaryAttack,
  checkSlashingConditionExploit,
  checkOrderbookManipulation,
  checkSettlementDelayExploit,
  checkAccountSquatting,
  checkTokenAccountHijacking,
  checkSignerAuthorityConfusion,
  checkInstructionIntrospectionBypass,
  checkCPIReturnDataValidation,
  checkAnchorDiscriminatorOverride,
  checkZeroCopyDeserialization,
  checkEventEmissionTampering,
  checkCrossProgramAccountConfusion,
  checkProtocolInvariantCheck,
];

export const batch12PatternInfo = {
  startId: 401,
  endId: 450,
  count: 50,
  categories: [
    'Advanced Oracle Attacks',
    'Flash Loan Attack Vectors',
    'Liquidity Mining Exploits',
    'Economic Exploits',
    'Vault/Strategy Vulnerabilities',
    'Perpetual/Derivatives Vulnerabilities',
    'Tokenomics Vulnerabilities',
    'Access Control Advanced',
    'Data Integrity Advanced',
    'Protocol Design Flaws',
  ],
};
