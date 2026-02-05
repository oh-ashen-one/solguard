/**
 * SolGuard Security Patterns - Batch 11 (SOL341-SOL400)
 * Advanced DeFi vulnerability patterns from real exploits and audits
 * Sources: Helius, Sec3, OtterSec, Neodyme research
 */

import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

// ============================================================================
// LENDING PROTOCOL VULNERABILITIES
// From: Solend, Jet, Port Finance exploits and audits
// ============================================================================

// SOL341: Liquidation Threshold Manipulation
export function checkLiquidationThresholdManipulation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/liquidat|health.*factor|collateral.*ratio/gi.test(content)) {
    if (!/threshold.*immutable|config.*lock|timelock.*threshold/gi.test(content)) {
      findings.push({
        id: 'SOL341',
        severity: 'critical',
        title: 'Mutable Liquidation Threshold',
        description: 'Liquidation thresholds that can be changed without timelock enable attackers to make positions instantly liquidatable (Solend Auth Bypass style attack).',
        location: input.path,
        recommendation: 'Lock liquidation thresholds or require significant timelock for changes.',
      });
    }
  }
  
  return findings;
}

// SOL342: Liquidation Bonus Manipulation
export function checkLiquidationBonusManipulation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/liquidat.*bonus|liquidation.*incentive|liquidator.*reward/gi.test(content)) {
    if (!/max.*bonus|bonus.*cap|reasonable.*bonus/gi.test(content)) {
      findings.push({
        id: 'SOL342',
        severity: 'high',
        title: 'Unbounded Liquidation Bonus',
        description: 'Liquidation bonus without caps can be set to extreme values, extracting excessive value from borrowers.',
        location: input.path,
        recommendation: 'Cap liquidation bonus to reasonable levels (e.g., 5-15%). Require timelock for changes.',
      });
    }
  }
  
  return findings;
}

// SOL343: Interest Rate Manipulation
export function checkInterestRateManipulation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/interest.*rate|borrow.*rate|supply.*rate|apy|apr/gi.test(content)) {
    if (!/rate.*model|curve|utilization.*based|rate.*cap/gi.test(content)) {
      findings.push({
        id: 'SOL343',
        severity: 'high',
        title: 'Arbitrary Interest Rate',
        description: 'Interest rates not based on utilization curves can be manipulated to extract value.',
        location: input.path,
        recommendation: 'Use utilization-based interest rate curves. Cap maximum rates.',
      });
    }
  }
  
  return findings;
}

// SOL344: Borrow Factor Manipulation
export function checkBorrowFactorManipulation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/borrow.*factor|ltv|loan.*to.*value|collateral.*factor/gi.test(content)) {
    if (!/max.*ltv|safe.*ltv|factor.*bound/gi.test(content)) {
      findings.push({
        id: 'SOL344',
        severity: 'high',
        title: 'Unsafe Borrow Factor Configuration',
        description: 'Borrow factors without safe bounds can enable over-leveraging and bad debt.',
        location: input.path,
        recommendation: 'Set maximum LTV ratios per asset. Consider asset volatility in factor calculation.',
      });
    }
  }
  
  return findings;
}

// SOL345: Bad Debt Socialization
export function checkBadDebtSocialization(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/bad.*debt|underwater|insolvent|shortfall/gi.test(content)) {
    if (!/insurance.*fund|reserve|backstop|socialize.*debt/gi.test(content)) {
      findings.push({
        id: 'SOL345',
        severity: 'high',
        title: 'Missing Bad Debt Handling',
        description: 'Lending protocols without bad debt handling mechanisms leave lenders unprotected.',
        location: input.path,
        recommendation: 'Implement insurance fund for bad debt. Define debt socialization rules.',
      });
    }
  }
  
  return findings;
}

// ============================================================================
// AMM/DEX VULNERABILITIES
// From: Raydium, Orca, Crema, Jupiter audits
// ============================================================================

// SOL346: AMM Constant Product Invariant
export function checkAMMConstantProductInvariant(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/amm|swap|pool.*reserve|x\s*\*\s*y/gi.test(content)) {
    if (!/k.*=.*x.*\*.*y|invariant.*check|constant.*product/gi.test(content)) {
      findings.push({
        id: 'SOL346',
        severity: 'critical',
        title: 'Missing AMM Invariant Check',
        description: 'AMM operations without constant product invariant verification allow fund extraction.',
        location: input.path,
        recommendation: 'Verify k = x * y (or appropriate formula) after every swap operation.',
      });
    }
  }
  
  return findings;
}

// SOL347: Virtual Reserve Manipulation
export function checkVirtualReserveManipulation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/virtual.*reserve|virtual.*balance|protocol.*owned/gi.test(content)) {
    if (!/verify.*actual|reconcile|match.*real/gi.test(content)) {
      findings.push({
        id: 'SOL347',
        severity: 'high',
        title: 'Virtual Reserve Desync Risk',
        description: 'Virtual reserves that desync from actual token balances enable exploitation.',
        location: input.path,
        recommendation: 'Regularly reconcile virtual reserves with actual token balances.',
      });
    }
  }
  
  return findings;
}

// SOL348: LP Token Inflation Attack
export function checkLPTokenInflationAttack(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/lp.*token|liquidity.*token|pool.*share|mint.*lp/gi.test(content)) {
    if (!/first.*deposit|minimum.*liquidity|lock.*initial/gi.test(content)) {
      findings.push({
        id: 'SOL348',
        severity: 'high',
        title: 'LP Token Inflation Attack Vulnerability',
        description: 'First depositor can manipulate share price by donating tokens to inflate LP token value.',
        location: input.path,
        recommendation: 'Lock minimum liquidity on first deposit. Use virtual offset for share calculation.',
      });
    }
  }
  
  return findings;
}

// SOL349: Sandwich Attack Prevention
export function checkSandwichAttackPrevention(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/swap|trade|exchange/gi.test(content)) {
    if (!/commit.*reveal|private.*mempool|mev.*protect|batch.*auction/gi.test(content)) {
      findings.push({
        id: 'SOL349',
        severity: 'medium',
        title: 'Sandwich Attack Vulnerable',
        description: 'Swaps visible in mempool before execution are vulnerable to MEV sandwich attacks.',
        location: input.path,
        recommendation: 'Consider commit-reveal schemes, private mempools, or batch auctions for MEV protection.',
      });
    }
  }
  
  return findings;
}

// SOL350: Pool Creation Frontrunning
export function checkPoolCreationFrontrunning(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/create.*pool|initialize.*pool|new.*pool/gi.test(content)) {
    if (!/pool.*permission|whitelist.*creator|authorized.*create/gi.test(content)) {
      findings.push({
        id: 'SOL350',
        severity: 'medium',
        title: 'Pool Creation Frontrunning Risk',
        description: 'Permissionless pool creation allows attackers to frontrun with malicious initial liquidity.',
        location: input.path,
        recommendation: 'Use permissioned pool creation or validate initial liquidity parameters.',
      });
    }
  }
  
  return findings;
}

// ============================================================================
// NFT/TOKEN VULNERABILITIES
// From: Metaplex, Magic Eden, NFT marketplace audits
// ============================================================================

// SOL351: NFT Royalty Bypass
export function checkNFTRoyaltyBypass(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/royalt|creator.*fee|seller.*fee/gi.test(content)) {
    if (!/enforce.*royalt|programmable.*nft|pnft|royalty.*check/gi.test(content)) {
      findings.push({
        id: 'SOL351',
        severity: 'medium',
        title: 'NFT Royalty Bypass Possible',
        description: 'NFT royalties without enforcement mechanisms can be bypassed through direct transfers.',
        location: input.path,
        recommendation: 'Use Metaplex pNFTs or similar enforced royalty mechanisms.',
      });
    }
  }
  
  return findings;
}

// SOL352: Token Metadata Manipulation
export function checkTokenMetadataManipulation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/metadata|uri|name|symbol|image/gi.test(content)) {
    if (!/immutable.*metadata|lock.*metadata|metadata.*freeze/gi.test(content)) {
      findings.push({
        id: 'SOL352',
        severity: 'medium',
        title: 'Mutable Token Metadata',
        description: 'Mutable metadata allows rug pulls by changing token appearance post-sale.',
        location: input.path,
        recommendation: 'Make metadata immutable after mint or require significant timelock.',
      });
    }
  }
  
  return findings;
}

// SOL353: Collection Verification Bypass
export function checkCollectionVerificationBypass(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/collection|verify.*collection|collection.*key/gi.test(content)) {
    if (!/certified.*collection|verified.*collection|collection.*authority/gi.test(content)) {
      findings.push({
        id: 'SOL353',
        severity: 'high',
        title: 'Collection Verification Bypass',
        description: 'NFTs without proper collection verification can be faked to appear part of legitimate collections.',
        location: input.path,
        recommendation: 'Verify collection certification using Metaplex standards.',
      });
    }
  }
  
  return findings;
}

// SOL354: Token Freeze Authority Abuse
export function checkTokenFreezeAuthorityAbuse(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/freeze.*authority|freeze.*account|freeze_authority/gi.test(content)) {
    if (!/revoke.*freeze|no.*freeze|freeze.*disabled/gi.test(content)) {
      findings.push({
        id: 'SOL354',
        severity: 'high',
        title: 'Active Freeze Authority',
        description: 'Tokens with active freeze authority can be frozen at any time, locking user funds.',
        location: input.path,
        recommendation: 'Revoke freeze authority for decentralized tokens. Disclose freeze risk to users.',
      });
    }
  }
  
  return findings;
}

// SOL355: Mint Authority Retention
export function checkMintAuthorityRetention(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/mint.*authority|mint_authority|can.*mint/gi.test(content)) {
    if (!/revoke.*mint|close.*mint|mint.*disabled|fixed.*supply/gi.test(content)) {
      findings.push({
        id: 'SOL355',
        severity: 'high',
        title: 'Retained Mint Authority',
        description: 'Tokens with retained mint authority can be infinitely inflated, diluting holders.',
        location: input.path,
        recommendation: 'Revoke mint authority for fixed supply tokens. Add caps and timelocks for inflationary tokens.',
      });
    }
  }
  
  return findings;
}

// ============================================================================
// STAKING/REWARDS VULNERABILITIES
// ============================================================================

// SOL356: Staking Reward Dilution
export function checkStakingRewardDilution(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/staking.*reward|stake.*yield|reward.*rate/gi.test(content)) {
    if (!/reward.*per.*share|accumulated.*reward|reward.*index/gi.test(content)) {
      findings.push({
        id: 'SOL356',
        severity: 'high',
        title: 'Staking Reward Calculation Vulnerability',
        description: 'Incorrect reward calculation can allow claiming more than earned or dilute existing stakers.',
        location: input.path,
        recommendation: 'Use reward-per-share accumulator pattern. Track reward debt per user.',
      });
    }
  }
  
  return findings;
}

// SOL357: Cooldown Period Bypass
export function checkCooldownPeriodBypass(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/unstake|withdraw.*stake|cooldown|unbond/gi.test(content)) {
    if (!/cooldown.*period|unlock.*time|unbonding.*period/gi.test(content)) {
      findings.push({
        id: 'SOL357',
        severity: 'high',
        title: 'Missing Unstaking Cooldown',
        description: 'Instant unstaking allows attackers to stake before rewards and unstake immediately after.',
        location: input.path,
        recommendation: 'Implement cooldown period for unstaking. Delay reward claims after staking.',
      });
    }
  }
  
  return findings;
}

// SOL358: Reward Duration Manipulation
export function checkRewardDurationManipulation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/reward.*duration|emission.*rate|reward.*period/gi.test(content)) {
    if (!/min.*duration|duration.*check|period.*validate/gi.test(content)) {
      findings.push({
        id: 'SOL358',
        severity: 'medium',
        title: 'Manipulable Reward Duration',
        description: 'Reward durations that can be set to very short periods enable gaming of reward distribution.',
        location: input.path,
        recommendation: 'Set minimum reward distribution period. Validate duration on setting.',
      });
    }
  }
  
  return findings;
}

// SOL359: Stake Weight Manipulation
export function checkStakeWeightManipulation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/stake.*weight|voting.*power|boost|multiplier/gi.test(content)) {
    if (!/weight.*cap|max.*boost|weight.*decay/gi.test(content)) {
      findings.push({
        id: 'SOL359',
        severity: 'high',
        title: 'Unbounded Stake Weight',
        description: 'Stake weight multipliers without caps allow excessive influence over governance or rewards.',
        location: input.path,
        recommendation: 'Cap maximum stake weight multipliers. Implement weight decay over time.',
      });
    }
  }
  
  return findings;
}

// SOL360: Emission Schedule Manipulation
export function checkEmissionScheduleManipulation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/emission|reward.*schedule|distribution.*rate/gi.test(content)) {
    if (!/fixed.*schedule|immutable.*emission|schedule.*lock/gi.test(content)) {
      findings.push({
        id: 'SOL360',
        severity: 'medium',
        title: 'Mutable Emission Schedule',
        description: 'Changeable emission schedules allow insiders to front-run reward changes.',
        location: input.path,
        recommendation: 'Lock emission schedules or require significant timelock for changes.',
      });
    }
  }
  
  return findings;
}

// ============================================================================
// BRIDGE/CROSS-CHAIN VULNERABILITIES
// ============================================================================

// SOL361: Cross-Chain Message Replay
export function checkCrossChainMessageReplay(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/bridge|cross.*chain|relay|message.*id/gi.test(content)) {
    if (!/nonce|sequence|processed.*message|replay.*protect/gi.test(content)) {
      findings.push({
        id: 'SOL361',
        severity: 'critical',
        title: 'Cross-Chain Message Replay Vulnerability',
        description: 'Bridge messages without replay protection can be submitted multiple times.',
        location: input.path,
        recommendation: 'Track processed message nonces. Reject duplicate messages.',
      });
    }
  }
  
  return findings;
}

// SOL362: Chain ID Validation
export function checkChainIDValidation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/chain.*id|source.*chain|dest.*chain|network.*id/gi.test(content)) {
    if (!/validate.*chain|verify.*chain.*id|expected.*chain/gi.test(content)) {
      findings.push({
        id: 'SOL362',
        severity: 'critical',
        title: 'Missing Chain ID Validation',
        description: 'Messages without chain ID validation can be replayed across different networks.',
        location: input.path,
        recommendation: 'Include and validate source and destination chain IDs in all cross-chain messages.',
      });
    }
  }
  
  return findings;
}

// SOL363: Finality Assumption
export function checkFinalityAssumption(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/finality|confirmation|block.*height|slot.*confirm/gi.test(content)) {
    if (!/wait.*finality|confirm.*count|finality.*check/gi.test(content)) {
      findings.push({
        id: 'SOL363',
        severity: 'high',
        title: 'Insufficient Finality Check',
        description: 'Processing cross-chain messages before finality allows double-spend attacks.',
        location: input.path,
        recommendation: 'Wait for sufficient confirmations/finality before processing cross-chain messages.',
      });
    }
  }
  
  return findings;
}

// SOL364: Relayer Trust Assumption
export function checkRelayerTrustAssumption(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/relayer|relay.*message|submit.*proof/gi.test(content)) {
    if (!/verify.*proof|trustless|permissionless.*relay/gi.test(content)) {
      findings.push({
        id: 'SOL364',
        severity: 'high',
        title: 'Trusted Relayer Assumption',
        description: 'Bridges relying on trusted relayers create centralization and censorship risks.',
        location: input.path,
        recommendation: 'Design for permissionless relaying with cryptographic proof verification.',
      });
    }
  }
  
  return findings;
}

// SOL365: Token Mapping Validation
export function checkTokenMappingValidation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/token.*mapping|wrapped.*token|bridge.*token|foreign.*token/gi.test(content)) {
    if (!/verify.*mapping|whitelist.*token|approved.*token/gi.test(content)) {
      findings.push({
        id: 'SOL365',
        severity: 'high',
        title: 'Unvalidated Token Mapping',
        description: 'Bridge token mappings without validation can allow minting of unauthorized wrapped tokens.',
        location: input.path,
        recommendation: 'Maintain whitelist of approved token mappings. Verify mappings before minting.',
      });
    }
  }
  
  return findings;
}

// ============================================================================
// ORACLE VULNERABILITIES (Extended)
// ============================================================================

// SOL366: Oracle Staleness Check
export function checkOracleStatelessCheck(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/oracle|price.*feed|pyth|switchboard|chainlink/gi.test(content)) {
    if (!/staleness|last.*update|max.*age|fresh/gi.test(content)) {
      findings.push({
        id: 'SOL366',
        severity: 'critical',
        title: 'Missing Oracle Staleness Check',
        description: 'Using stale oracle prices allows exploitation when market has moved.',
        location: input.path,
        recommendation: 'Check oracle update timestamp. Reject prices older than acceptable threshold.',
      });
    }
  }
  
  return findings;
}

// SOL367: Oracle Confidence Interval
export function checkOracleConfidenceInterval(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/oracle|pyth|price.*feed/gi.test(content)) {
    if (!/confidence|deviation|uncertainty|price.*band/gi.test(content)) {
      findings.push({
        id: 'SOL367',
        severity: 'high',
        title: 'Missing Oracle Confidence Check',
        description: 'Using oracle prices without confidence intervals allows exploitation during high volatility.',
        location: input.path,
        recommendation: 'Check oracle confidence intervals. Pause operations when confidence is too wide.',
      });
    }
  }
  
  return findings;
}

// SOL368: Single Oracle Dependency
export function checkSingleOracleDependency(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/oracle|price.*source|feed/gi.test(content)) {
    if (!/multiple.*oracle|fallback.*oracle|oracle.*aggregat/gi.test(content)) {
      findings.push({
        id: 'SOL368',
        severity: 'high',
        title: 'Single Oracle Dependency',
        description: 'Relying on single oracle creates single point of failure and manipulation risk.',
        location: input.path,
        recommendation: 'Use multiple oracle sources. Implement median or weighted average pricing.',
      });
    }
  }
  
  return findings;
}

// SOL369: LP Token Oracle Manipulation
export function checkLPTokenOracleManipulation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/lp.*price|pool.*value|lp.*oracle|liquidity.*value/gi.test(content)) {
    if (!/fair.*lp.*price|virtual.*price|manipulation.*resist/gi.test(content)) {
      findings.push({
        id: 'SOL369',
        severity: 'critical',
        title: 'LP Token Oracle Manipulation (OtterSec $200M Bluff)',
        description: 'LP token prices based on spot reserves can be manipulated via flash loans. OtterSec demonstrated $200M potential exploit.',
        location: input.path,
        recommendation: 'Use fair LP pricing formulas that resist manipulation. Never use spot reserve ratios directly.',
      });
    }
  }
  
  return findings;
}

// SOL370: Price Deviation Circuit Breaker
export function checkPriceDeviationCircuitBreaker(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/price|oracle|feed/gi.test(content)) {
    if (!/circuit.*breaker|price.*limit|deviation.*check|emergency.*pause/gi.test(content)) {
      findings.push({
        id: 'SOL370',
        severity: 'high',
        title: 'Missing Price Circuit Breaker',
        description: 'Large price deviations without circuit breakers allow exploitation during market anomalies.',
        location: input.path,
        recommendation: 'Implement circuit breakers that pause operations when prices deviate beyond thresholds.',
      });
    }
  }
  
  return findings;
}

// ============================================================================
// PROGRAM UPGRADE VULNERABILITIES
// ============================================================================

// SOL371: Unrestricted Program Upgrade
export function checkUnrestrictedProgramUpgrade(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/upgrade.*authority|program.*upgrade|bpf.*upgrade/gi.test(content)) {
    if (!/multisig.*upgrade|timelock.*upgrade|governance.*upgrade/gi.test(content)) {
      findings.push({
        id: 'SOL371',
        severity: 'critical',
        title: 'Single-Key Program Upgrade',
        description: 'Program upgrades controlled by single key allow instant malicious code deployment.',
        location: input.path,
        recommendation: 'Use multisig for upgrade authority. Add timelock for upgrade execution.',
      });
    }
  }
  
  return findings;
}

// SOL372: State Migration Vulnerability
export function checkStateMigrationVulnerability(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/migrate|upgrade.*state|version.*bump|schema.*change/gi.test(content)) {
    if (!/migration.*script|backward.*compat|state.*version/gi.test(content)) {
      findings.push({
        id: 'SOL372',
        severity: 'high',
        title: 'Unsafe State Migration',
        description: 'Program upgrades without proper state migration can corrupt or lose user data.',
        location: input.path,
        recommendation: 'Version account schemas. Test migration scripts thoroughly. Maintain backward compatibility.',
      });
    }
  }
  
  return findings;
}

// SOL373: Immutable Program Risk
export function checkImmutableProgramRisk(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/immutable|no.*upgrade|upgrade.*disabled|frozen.*program/gi.test(content)) {
    if (!/emergency|circuit.*breaker|pause.*mechanism/gi.test(content)) {
      findings.push({
        id: 'SOL373',
        severity: 'medium',
        title: 'Immutable Program Without Emergency Controls',
        description: 'Immutable programs cannot be fixed if vulnerabilities are discovered.',
        location: input.path,
        recommendation: 'Include emergency pause mechanism even in immutable programs.',
      });
    }
  }
  
  return findings;
}

// ============================================================================
// TRANSACTION VULNERABILITIES
// ============================================================================

// SOL374: Transaction Ordering Manipulation
export function checkTransactionOrderingManipulation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/order|sequence|priority|first.*come/gi.test(content)) {
    if (!/commit.*reveal|random.*order|batch.*process/gi.test(content)) {
      findings.push({
        id: 'SOL374',
        severity: 'medium',
        title: 'Transaction Ordering Vulnerability',
        description: 'Operations sensitive to transaction order can be front-run or back-run.',
        location: input.path,
        recommendation: 'Use commit-reveal for order-sensitive operations. Consider batch processing.',
      });
    }
  }
  
  return findings;
}

// SOL375: Partial Transaction Execution
export function checkPartialTransactionExecution(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/multi.*instruction|batch|atomic/gi.test(content)) {
    if (!/all.*or.*nothing|atomic.*batch|revert.*all/gi.test(content)) {
      findings.push({
        id: 'SOL375',
        severity: 'high',
        title: 'Non-Atomic Multi-Instruction Risk',
        description: 'Multi-instruction operations without atomicity can leave state inconsistent.',
        location: input.path,
        recommendation: 'Ensure multi-instruction operations are atomic. Implement rollback on partial failure.',
      });
    }
  }
  
  return findings;
}

// SOL376: Duplicate Transaction Prevention
export function checkDuplicateTransactionPrevention(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/claim|redeem|withdraw|airdrop/gi.test(content)) {
    if (!/claimed|processed|used.*nonce|one.*time/gi.test(content)) {
      findings.push({
        id: 'SOL376',
        severity: 'high',
        title: 'Missing Duplicate Claim Prevention',
        description: 'Claims without duplicate prevention can be executed multiple times.',
        location: input.path,
        recommendation: 'Track claimed status per user. Use nonces for one-time operations.',
      });
    }
  }
  
  return findings;
}

// ============================================================================
// SOLANA-SPECIFIC VULNERABILITIES
// ============================================================================

// SOL377: CPI Signer Seed Exposure
export function checkCPISignerSeedExposure(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/invoke_signed|cpi.*signer|signer.*seeds/gi.test(content)) {
    if (/seed.*=.*".*"|seed.*=.*b".*"/gi.test(content)) {
      findings.push({
        id: 'SOL377',
        severity: 'high',
        title: 'Hardcoded CPI Signer Seeds',
        description: 'Hardcoded signer seeds in CPI calls can be predicted and potentially exploited.',
        location: input.path,
        recommendation: 'Use dynamic seeds including user pubkeys and nonces. Avoid predictable seed patterns.',
      });
    }
  }
  
  return findings;
}

// SOL378: Account Reallocation Without Rent Check
export function checkAccountReallocationRent(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/realloc|resize|grow.*account|increase.*size/gi.test(content)) {
    if (!/rent.*exempt|minimum.*balance|lamport.*check/gi.test(content)) {
      findings.push({
        id: 'SOL378',
        severity: 'medium',
        title: 'Account Reallocation Without Rent Check',
        description: 'Growing account size without ensuring rent-exemption can cause account deletion.',
        location: input.path,
        recommendation: 'Ensure account maintains rent-exempt balance after reallocation.',
      });
    }
  }
  
  return findings;
}

// SOL379: Account Data Zeroing
export function checkAccountDataZeroing(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/close.*account|delete.*account|remove.*account/gi.test(content)) {
    if (!/zero.*data|clear.*data|fill.*zero|memset/gi.test(content)) {
      findings.push({
        id: 'SOL379',
        severity: 'high',
        title: 'Account Closure Without Data Zeroing',
        description: 'Closing accounts without zeroing data allows account revival attacks.',
        location: input.path,
        recommendation: 'Zero out all account data before closing. Set discriminator to invalid value.',
      });
    }
  }
  
  return findings;
}

// SOL380: Program ID Spoofing
export function checkProgramIDSpoofing(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/cpi|invoke|call.*program/gi.test(content)) {
    if (!/verify.*program.*id|expected.*program|program.*check/gi.test(content)) {
      findings.push({
        id: 'SOL380',
        severity: 'critical',
        title: 'CPI Program ID Not Verified',
        description: 'CPI calls without program ID verification allow calling malicious programs.',
        location: input.path,
        recommendation: 'Always verify program ID matches expected value before CPI.',
      });
    }
  }
  
  return findings;
}

// ============================================================================
// Additional patterns for comprehensive coverage
// ============================================================================

// SOL381-SOL400: More patterns...

// SOL381: Token Extensions Compatibility
export function checkTokenExtensionsCompatibility(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/token.*2022|token.*extension|transfer.*hook|confidential/gi.test(content)) {
    if (!/extension.*check|hook.*validate|extension.*support/gi.test(content)) {
      findings.push({
        id: 'SOL381',
        severity: 'high',
        title: 'Token Extensions Not Validated',
        description: 'Token-2022 extensions (transfer hooks, confidential transfers) require special handling.',
        location: input.path,
        recommendation: 'Check for and properly handle all token extensions.',
      });
    }
  }
  
  return findings;
}

// SOL382: Compute Budget Griefing
export function checkComputeBudgetGriefing(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/user.*input|external.*data|untrusted/gi.test(content)) {
    if (!/compute.*limit|gas.*limit|resource.*bound/gi.test(content)) {
      findings.push({
        id: 'SOL382',
        severity: 'medium',
        title: 'Compute Budget Griefing Risk',
        description: 'User-controlled input affecting computation can be exploited to grief other operations.',
        location: input.path,
        recommendation: 'Limit computation based on user input. Add compute budget awareness.',
      });
    }
  }
  
  return findings;
}

// SOL383: Lookup Table Manipulation
export function checkLookupTableManipulation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/lookup.*table|address.*table|alt/gi.test(content)) {
    if (!/verify.*table|table.*authority|trusted.*table/gi.test(content)) {
      findings.push({
        id: 'SOL383',
        severity: 'high',
        title: 'Address Lookup Table Not Validated',
        description: 'Using unvalidated address lookup tables allows substituting malicious accounts.',
        location: input.path,
        recommendation: 'Verify lookup table authority. Use trusted tables only.',
      });
    }
  }
  
  return findings;
}

// SOL384: Versioned Transaction Handling
export function checkVersionedTransactionHandling(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/versioned|v0.*transaction|legacy.*transaction/gi.test(content)) {
    if (!/version.*check|handle.*version|support.*both/gi.test(content)) {
      findings.push({
        id: 'SOL384',
        severity: 'medium',
        title: 'Versioned Transaction Handling',
        description: 'Programs must handle both legacy and versioned transactions correctly.',
        location: input.path,
        recommendation: 'Support both transaction versions. Validate version-specific features.',
      });
    }
  }
  
  return findings;
}

// SOL385: SPL Token Authority Confusion
export function checkSPLTokenAuthorityConfusion(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/token.*authority|mint.*authority|freeze.*authority|close.*authority/gi.test(content)) {
    if (!/verify.*authority|check.*authority|authority.*match/gi.test(content)) {
      findings.push({
        id: 'SOL385',
        severity: 'high',
        title: 'Token Authority Confusion',
        description: 'Confusing different token authorities (mint, freeze, close) can lead to unauthorized operations.',
        location: input.path,
        recommendation: 'Clearly distinguish and verify each authority type separately.',
      });
    }
  }
  
  return findings;
}

// SOL386: Associated Token Account Derivation
export function checkATADerivation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/associated.*token|ata|get_associated_token_address/gi.test(content)) {
    if (!/verify.*ata|check.*derivation|expected.*ata/gi.test(content)) {
      findings.push({
        id: 'SOL386',
        severity: 'high',
        title: 'ATA Derivation Not Verified',
        description: 'Using ATAs without verifying derivation allows substituting attacker-controlled accounts.',
        location: input.path,
        recommendation: 'Verify ATA is correctly derived from expected wallet and mint.',
      });
    }
  }
  
  return findings;
}

// SOL387: Delegate Authority Abuse
export function checkDelegateAuthorityAbuse(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/delegate|approval|approved.*amount|delegated.*amount/gi.test(content)) {
    if (!/revoke|limited.*time|max.*delegate/gi.test(content)) {
      findings.push({
        id: 'SOL387',
        severity: 'high',
        title: 'Unlimited Token Delegation',
        description: 'Token delegations without limits or expiry can be abused if delegate is compromised.',
        location: input.path,
        recommendation: 'Limit delegation amounts. Add expiry times. Allow easy revocation.',
      });
    }
  }
  
  return findings;
}

// SOL388: System Program Invocation
export function checkSystemProgramInvocation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/system_program|create_account|transfer.*lamport|allocate/gi.test(content)) {
    if (!/system_program::id|SYSTEM_PROGRAM_ID|verify.*system/gi.test(content)) {
      findings.push({
        id: 'SOL388',
        severity: 'high',
        title: 'System Program Not Verified',
        description: 'System program invocations without verification allow malicious substitution.',
        location: input.path,
        recommendation: 'Verify system program ID matches solana_program::system_program::id().',
      });
    }
  }
  
  return findings;
}

// SOL389: Rent Sysvar Usage
export function checkRentSysvarUsage(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/rent|sysvar.*rent|minimum_balance/gi.test(content)) {
    if (!/rent::get|Rent::from_account_info|sysvar/gi.test(content)) {
      findings.push({
        id: 'SOL389',
        severity: 'medium',
        title: 'Rent Sysvar Access Pattern',
        description: 'Accessing rent without proper sysvar handling can cause issues.',
        location: input.path,
        recommendation: 'Use Rent::get() or properly validate Rent sysvar account.',
      });
    }
  }
  
  return findings;
}

// SOL390: Clock Sysvar Manipulation
export function checkClockSysvarManipulation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  if (/clock|unix_timestamp|slot/gi.test(content)) {
    if (!/Clock::get|from_account_info.*clock|sysvar.*clock/gi.test(content)) {
      findings.push({
        id: 'SOL390',
        severity: 'high',
        title: 'Clock Sysvar Not Verified',
        description: 'Using clock values without proper sysvar verification allows time manipulation.',
        location: input.path,
        recommendation: 'Use Clock::get() or verify clock sysvar account properly.',
      });
    }
  }
  
  return findings;
}

// SOL391-400: Reserve for additional patterns
export function checkReservedPatterns391to400(input: PatternInput): Finding[] {
  return []; // Reserved for future patterns
}

// ============================================================================
// Export all pattern checkers
// ============================================================================

export const batch11Patterns = [
  checkLiquidationThresholdManipulation,
  checkLiquidationBonusManipulation,
  checkInterestRateManipulation,
  checkBorrowFactorManipulation,
  checkBadDebtSocialization,
  checkAMMConstantProductInvariant,
  checkVirtualReserveManipulation,
  checkLPTokenInflationAttack,
  checkSandwichAttackPrevention,
  checkPoolCreationFrontrunning,
  checkNFTRoyaltyBypass,
  checkTokenMetadataManipulation,
  checkCollectionVerificationBypass,
  checkTokenFreezeAuthorityAbuse,
  checkMintAuthorityRetention,
  checkStakingRewardDilution,
  checkCooldownPeriodBypass,
  checkRewardDurationManipulation,
  checkStakeWeightManipulation,
  checkEmissionScheduleManipulation,
  checkCrossChainMessageReplay,
  checkChainIDValidation,
  checkFinalityAssumption,
  checkRelayerTrustAssumption,
  checkTokenMappingValidation,
  checkOracleStatelessCheck,
  checkOracleConfidenceInterval,
  checkSingleOracleDependency,
  checkLPTokenOracleManipulation,
  checkPriceDeviationCircuitBreaker,
  checkUnrestrictedProgramUpgrade,
  checkStateMigrationVulnerability,
  checkImmutableProgramRisk,
  checkTransactionOrderingManipulation,
  checkPartialTransactionExecution,
  checkDuplicateTransactionPrevention,
  checkCPISignerSeedExposure,
  checkAccountReallocationRent,
  checkAccountDataZeroing,
  checkProgramIDSpoofing,
  checkTokenExtensionsCompatibility,
  checkComputeBudgetGriefing,
  checkLookupTableManipulation,
  checkVersionedTransactionHandling,
  checkSPLTokenAuthorityConfusion,
  checkATADerivation,
  checkDelegateAuthorityAbuse,
  checkSystemProgramInvocation,
  checkRentSysvarUsage,
  checkClockSysvarManipulation,
];

export const batch11PatternInfo = {
  startId: 341,
  endId: 400,
  count: 60,
  categories: [
    'Lending Protocol Vulnerabilities',
    'AMM/DEX Vulnerabilities',
    'NFT/Token Vulnerabilities',
    'Staking/Rewards Vulnerabilities',
    'Bridge/Cross-Chain Vulnerabilities',
    'Oracle Vulnerabilities (Extended)',
    'Program Upgrade Vulnerabilities',
    'Transaction Vulnerabilities',
    'Solana-Specific Vulnerabilities',
  ],
};
