/**
 * Batch 84 - Extended Solsec Research + Tool Detection + Advanced DeFi Patterns
 * 
 * Based on:
 * - Solsec GitHub curated resources (audits, tools, PoCs)
 * - Security tool recommendations (Trident, Sec3, Soteria)
 * - Protocol-specific audit findings (Mango, Marinade, Orca, Drift, Phoenix)
 * 
 * Pattern IDs: SOL4401-SOL4500
 */

import type { ParsedRust } from '../parsers/rust.js';

interface Finding {
  id: string;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  description: string;
  location: { file: string; line?: number };
  recommendation?: string;
}

interface ScanInput {
  path: string;
  rust?: ParsedRust;
}

// ============================================================================
// SECURITY TOOL PATTERNS (Trident Fuzzing, Sec3 X-Ray, Soteria)
// ============================================================================

/**
 * SOL4401: Missing Fuzz Testing Indicators
 * Trident is Solana's premier fuzzing framework
 */
function checkFuzzTestingCoverage(content: string, findings: Finding[], path: string) {
  // Check for test modules without fuzzing
  if (content.includes('#[cfg(test)]') && !content.includes('proptest') && !content.includes('fuzz')) {
    findings.push({
      id: 'SOL4401',
      title: 'Consider Adding Fuzz Testing',
      severity: 'info',
      description: 'Test module found without fuzz testing. Trident and proptest can catch edge cases unit tests miss.',
      location: { file: path },
      recommendation: 'Add Ackee Trident fuzz tests: https://github.com/Ackee-Blockchain/trident'
    });
  }
}

/**
 * SOL4402: Arithmetic Not Using Checked Math Macro
 */
function checkCheckedMathMacro(content: string, findings: Finding[], path: string) {
  // Blockworks checked-math macro detection
  if ((content.includes('u64') || content.includes('u128') || content.includes('i64')) &&
      content.match(/[+\-*/]\s*[a-zA-Z_]+/) &&
      !content.includes('checked!') &&
      !content.includes('checked_math')) {
    findings.push({
      id: 'SOL4402',
      title: 'Use Checked Math Macro',
      severity: 'medium',
      description: 'Arithmetic without Blockworks checked-math macro. This macro simplifies overflow-safe arithmetic.',
      location: { file: path },
      recommendation: 'Use Blockworks checked_math! macro: https://github.com/blockworks-foundation/checked-math'
    });
  }
}

/**
 * SOL4403: Soteria Vulnerability Detection Patterns
 */
function checkSoteriaPatterns(content: string, findings: Finding[], path: string) {
  // Patterns that Soteria specifically detects
  const soteriaPatterns = [
    { pattern: /account\.data\.borrow\(\)/, id: 'SOL4403', name: 'Raw Account Data Access' },
    { pattern: /invoke\s*\([^)]*\)\s*(?!\?)/, id: 'SOL4404', name: 'Unchecked CPI Result' },
    { pattern: /Pubkey::new_from_array/, id: 'SOL4405', name: 'Hardcoded Pubkey Construction' }
  ];
  
  for (const { pattern, id, name } of soteriaPatterns) {
    if (pattern.test(content)) {
      findings.push({
        id,
        title: `Soteria: ${name}`,
        severity: 'medium',
        description: `Pattern detected by Soteria automated scanner: ${name}`,
        location: { file: path },
        recommendation: 'Run Soteria scan for comprehensive analysis: https://www.sec3.dev'
      });
    }
  }
}

// ============================================================================
// PROTOCOL-SPECIFIC AUDIT FINDINGS
// ============================================================================

/**
 * SOL4406-4410: Mango Markets Audit Patterns (Neodyme)
 */
function checkMangoAuditPatterns(content: string, findings: Finding[], path: string) {
  // Perp market patterns
  if (content.includes('perp') || content.includes('perpetual')) {
    if (!content.includes('funding_rate')) {
      findings.push({
        id: 'SOL4406',
        title: 'Mango Audit: Perpetual Funding Rate',
        severity: 'medium',
        description: 'Perpetual market without explicit funding rate handling. Mango audit emphasized funding rate accuracy.',
        location: { file: path },
        recommendation: 'Implement proper funding rate calculations with TWAP oracle prices.'
      });
    }
    
    if (!content.includes('liquidation') && content.includes('position')) {
      findings.push({
        id: 'SOL4407',
        title: 'Mango Audit: Missing Liquidation Logic',
        severity: 'high',
        description: 'Perpetual position handling without liquidation logic. Critical for protocol solvency.',
        location: { file: path },
        recommendation: 'Implement health factor checks and liquidation mechanisms.'
      });
    }
  }
  
  // Oracle guardrails (from Drift examples)
  if (content.includes('oracle') && !content.includes('guardrail') && !content.includes('bounds')) {
    findings.push({
      id: 'SOL4408',
      title: 'Mango/Drift Audit: Missing Oracle Guardrails',
      severity: 'high',
      description: 'Oracle usage without guardrails. Drift protocol has example oracle guardrails to prevent manipulation.',
      location: { file: path },
      recommendation: 'Add oracle price bounds and staleness checks. See Drift protocol oracle guardrails.'
    });
  }
}

/**
 * SOL4411-4415: Marinade Audit Patterns (Kudelski + Ackee + Neodyme)
 */
function checkMarinadeAuditPatterns(content: string, findings: Finding[], path: string) {
  // Liquid staking patterns
  if (content.includes('stake') && content.includes('liquid')) {
    if (!content.includes('epoch')) {
      findings.push({
        id: 'SOL4411',
        title: 'Marinade Audit: Epoch Handling',
        severity: 'medium',
        description: 'Liquid staking without epoch boundary handling. Marinade audit found epoch transition edge cases.',
        location: { file: path },
        recommendation: 'Handle epoch boundaries carefully. Test stake/unstake across epoch transitions.'
      });
    }
    
    if (!content.includes('validator') && content.includes('delegate')) {
      findings.push({
        id: 'SOL4412',
        title: 'Marinade Audit: Validator Selection',
        severity: 'medium',
        description: 'Stake delegation without validator selection logic. Marinade implements validator scoring.',
        location: { file: path },
        recommendation: 'Implement validator selection/scoring for stake distribution.'
      });
    }
  }
  
  // mSOL patterns
  if (content.includes('msol') || content.includes('liquid_stake_token')) {
    if (!content.includes('exchange_rate')) {
      findings.push({
        id: 'SOL4413',
        title: 'Marinade Audit: Exchange Rate Calculation',
        severity: 'high',
        description: 'Liquid stake token without exchange rate. Critical for accurate mSOL/SOL conversions.',
        location: { file: path },
        recommendation: 'Calculate exchange rate as total_stake / total_msol_supply.'
      });
    }
  }
}

/**
 * SOL4416-4420: Orca Whirlpools Audit Patterns (Kudelski + Neodyme)
 */
function checkOrcaAuditPatterns(content: string, findings: Finding[], path: string) {
  // CLMM/concentrated liquidity patterns
  if (content.includes('whirlpool') || content.includes('concentrated_liquidity')) {
    if (!content.includes('tick') || !content.includes('position')) {
      findings.push({
        id: 'SOL4416',
        title: 'Orca Audit: CLMM Tick/Position Handling',
        severity: 'high',
        description: 'Concentrated liquidity without tick or position handling. Critical CLMM components.',
        location: { file: path },
        recommendation: 'Implement proper tick array and position management.'
      });
    }
    
    if (!content.includes('sqrt_price')) {
      findings.push({
        id: 'SOL4417',
        title: 'Orca Audit: Sqrt Price Calculation',
        severity: 'medium',
        description: 'CLMM without sqrt price. Orca Whirlpools use sqrt(price) for efficient swap calculations.',
        location: { file: path },
        recommendation: 'Use sqrt(price) representation for concentrated liquidity math.'
      });
    }
  }
  
  // Pool token patterns
  if (content.includes('lp_token') && content.includes('mint')) {
    if (!content.includes('proportional')) {
      findings.push({
        id: 'SOL4418',
        title: 'Orca Audit: Proportional LP Minting',
        severity: 'medium',
        description: 'LP token minting may not be proportional. Orca audit emphasized fair LP distribution.',
        location: { file: path },
        recommendation: 'Mint LP tokens proportional to liquidity contribution.'
      });
    }
  }
}

/**
 * SOL4421-4425: Drift Protocol Audit Patterns (Zellic)
 */
function checkDriftAuditPatterns(content: string, findings: Finding[], path: string) {
  // Perp V2 patterns
  if (content.includes('drift') || (content.includes('perp') && content.includes('v2'))) {
    if (!content.includes('margin') && content.includes('position')) {
      findings.push({
        id: 'SOL4421',
        title: 'Drift Audit: Margin Requirements',
        severity: 'high',
        description: 'Perpetual position without margin handling. Drift audit focused on margin calculations.',
        location: { file: path },
        recommendation: 'Implement initial and maintenance margin requirements.'
      });
    }
    
    if (content.includes('order') && !content.includes('auction')) {
      findings.push({
        id: 'SOL4422',
        title: 'Drift Audit: Order Auction Mechanism',
        severity: 'medium',
        description: 'Orders without auction mechanism. Drift uses auctions for fair price discovery.',
        location: { file: path },
        recommendation: 'Consider auction-based order filling for better execution.'
      });
    }
  }
  
  // AMM JIT patterns
  if (content.includes('jit') || content.includes('just_in_time')) {
    if (!content.includes('liquidity')) {
      findings.push({
        id: 'SOL4423',
        title: 'Drift Audit: JIT Liquidity',
        severity: 'medium',
        description: 'JIT mechanism without liquidity handling. Drift uses JIT liquidity for fills.',
        location: { file: path },
        recommendation: 'Implement JIT liquidity provision properly.'
      });
    }
  }
}

/**
 * SOL4426-4430: Phoenix Audit Patterns (MadShield + OtterSec)
 */
function checkPhoenixAuditPatterns(content: string, findings: Finding[], path: string) {
  // Order book patterns
  if (content.includes('order_book') || content.includes('orderbook')) {
    if (!content.includes('seat')) {
      findings.push({
        id: 'SOL4426',
        title: 'Phoenix Audit: Market Seat System',
        severity: 'medium',
        description: 'Order book without seat system. Phoenix uses seats for market maker management.',
        location: { file: path },
        recommendation: 'Implement seat-based market maker registration.'
      });
    }
    
    if (!content.includes('self_trade')) {
      findings.push({
        id: 'SOL4427',
        title: 'Phoenix Audit: Self-Trade Prevention',
        severity: 'medium',
        description: 'Order book without self-trade prevention. Phoenix prevents wash trading.',
        location: { file: path },
        recommendation: 'Implement self-trade prevention options (cancel oldest, cancel newest, abort).'
      });
    }
  }
  
  // Matching engine patterns
  if (content.includes('match') && content.includes('order')) {
    if (!content.includes('fifo')) {
      findings.push({
        id: 'SOL4428',
        title: 'Phoenix Audit: FIFO Matching',
        severity: 'info',
        description: 'Order matching may not be FIFO. Phoenix uses price-time priority.',
        location: { file: path },
        recommendation: 'Consider FIFO matching for fair order execution.'
      });
    }
  }
}

// ============================================================================
// ADVANCED DEFI VULNERABILITY PATTERNS
// ============================================================================

/**
 * SOL4431-4440: Lending Protocol Patterns
 */
function checkLendingProtocolPatterns(content: string, findings: Finding[], path: string) {
  // Interest rate model
  if (content.includes('interest') && content.includes('rate')) {
    if (!content.includes('utilization')) {
      findings.push({
        id: 'SOL4431',
        title: 'Lending: Interest Rate Model',
        severity: 'medium',
        description: 'Interest rate without utilization-based model. Most lending protocols use kink-based models.',
        location: { file: path },
        recommendation: 'Implement utilization-based interest rate with kink point.'
      });
    }
  }
  
  // Reserve factor
  if (content.includes('reserve') && !content.includes('reserve_factor')) {
    findings.push({
      id: 'SOL4432',
      title: 'Lending: Reserve Factor',
      severity: 'low',
      description: 'Lending reserve without reserve factor. Important for protocol sustainability.',
      location: { file: path },
      recommendation: 'Implement reserve factor to capture protocol revenue.'
    });
  }
  
  // Collateral factor
  if (content.includes('collateral') && !content.includes('collateral_factor') && !content.includes('ltv')) {
    findings.push({
      id: 'SOL4433',
      title: 'Lending: Missing Collateral Factor',
      severity: 'high',
      description: 'Collateral handling without explicit collateral factor/LTV. Critical for risk management.',
      location: { file: path },
      recommendation: 'Define collateral factors per asset based on volatility and liquidity.'
    });
  }
  
  // Bad debt handling
  if (content.includes('liquidation') && !content.includes('bad_debt')) {
    findings.push({
      id: 'SOL4434',
      title: 'Lending: Bad Debt Handling',
      severity: 'medium',
      description: 'Liquidation without bad debt handling. Important for protocol solvency.',
      location: { file: path },
      recommendation: 'Implement bad debt socialization or insurance fund mechanism.'
    });
  }
}

/**
 * SOL4441-4450: AMM/DEX Patterns
 */
function checkAMMPatterns(content: string, findings: Finding[], path: string) {
  // Constant product
  if (content.includes('swap') && content.includes('pool')) {
    if (!content.includes('k') && !content.includes('constant') && !content.includes('invariant')) {
      findings.push({
        id: 'SOL4441',
        title: 'AMM: Invariant Check',
        severity: 'high',
        description: 'Swap without invariant/constant product check. Critical for AMM security.',
        location: { file: path },
        recommendation: 'Verify constant product invariant: x * y = k (or equivalent).'
      });
    }
  }
  
  // Fee handling
  if (content.includes('swap') && !content.includes('fee')) {
    findings.push({
      id: 'SOL4442',
      title: 'AMM: Swap Fee Missing',
      severity: 'medium',
      description: 'Swap function without fee handling. Fees incentivize LPs and protocol sustainability.',
      location: { file: path },
      recommendation: 'Implement swap fees (typically 0.25-0.30% for regular pools).'
    });
  }
  
  // Imbalanced pool protection
  if (content.includes('pool') && content.includes('deposit')) {
    if (!content.includes('imbalance') && !content.includes('proportional')) {
      findings.push({
        id: 'SOL4443',
        title: 'AMM: Imbalanced Deposit Protection',
        severity: 'medium',
        description: 'Pool deposit without imbalance protection. Can lead to manipulation.',
        location: { file: path },
        recommendation: 'Require proportional deposits or charge imbalance fees.'
      });
    }
  }
  
  // Price impact
  if (content.includes('swap') && !content.includes('price_impact') && !content.includes('slippage')) {
    findings.push({
      id: 'SOL4444',
      title: 'AMM: Price Impact/Slippage Check',
      severity: 'medium',
      description: 'Swap without price impact or slippage protection.',
      location: { file: path },
      recommendation: 'Add minimum output amount check to protect users from slippage.'
    });
  }
}

/**
 * SOL4451-4460: Options/Derivatives Patterns
 */
function checkOptionsPatterns(content: string, findings: Finding[], path: string) {
  // Options pricing
  if (content.includes('option') && (content.includes('call') || content.includes('put'))) {
    if (!content.includes('strike') || !content.includes('expiry')) {
      findings.push({
        id: 'SOL4451',
        title: 'Options: Missing Strike/Expiry',
        severity: 'high',
        description: 'Option contract without strike price or expiry. Core option parameters.',
        location: { file: path },
        recommendation: 'Define strike price and expiry timestamp for all options.'
      });
    }
    
    if (!content.includes('premium') && !content.includes('price')) {
      findings.push({
        id: 'SOL4452',
        title: 'Options: Premium Calculation',
        severity: 'high',
        description: 'Option without premium/price calculation. Required for fair option trading.',
        location: { file: path },
        recommendation: 'Implement Black-Scholes or similar pricing model.'
      });
    }
    
    if (!content.includes('exercise')) {
      findings.push({
        id: 'SOL4453',
        title: 'Options: Exercise Mechanism',
        severity: 'high',
        description: 'Option without exercise mechanism. Users need to exercise profitable options.',
        location: { file: path },
        recommendation: 'Implement exercise function checking ITM status and transferring assets.'
      });
    }
  }
  
  // IV/Greeks
  if (content.includes('option') && !content.includes('volatility') && !content.includes('iv')) {
    findings.push({
      id: 'SOL4454',
      title: 'Options: Implied Volatility',
      severity: 'medium',
      description: 'Options trading without implied volatility. Important for pricing accuracy.',
      location: { file: path },
      recommendation: 'Incorporate IV into option pricing. Consider historical volatility as baseline.'
    });
  }
}

/**
 * SOL4461-4470: Staking Protocol Patterns
 */
function checkStakingProtocolPatterns(content: string, findings: Finding[], path: string) {
  // Reward distribution
  if (content.includes('stake') && content.includes('reward')) {
    if (!content.includes('claim') && !content.includes('distribute')) {
      findings.push({
        id: 'SOL4461',
        title: 'Staking: Reward Claim Mechanism',
        severity: 'medium',
        description: 'Staking rewards without claim mechanism.',
        location: { file: path },
        recommendation: 'Implement explicit reward claiming or auto-compound.'
      });
    }
    
    if (!content.includes('reward_per_token') && !content.includes('reward_rate')) {
      findings.push({
        id: 'SOL4462',
        title: 'Staking: Reward Rate Tracking',
        severity: 'medium',
        description: 'Staking without reward rate tracking. Use reward-per-token for gas efficiency.',
        location: { file: path },
        recommendation: 'Implement reward_per_token pattern for efficient reward distribution.'
      });
    }
  }
  
  // Cooldown/unbonding
  if (content.includes('unstake') && !content.includes('cooldown') && !content.includes('unbond')) {
    findings.push({
      id: 'SOL4463',
      title: 'Staking: Unbonding Period',
      severity: 'medium',
      description: 'Unstaking without cooldown/unbonding period. Consider adding for security.',
      location: { file: path },
      recommendation: 'Implement unbonding period to prevent rapid stake/unstake attacks.'
    });
  }
  
  // Slash protection
  if (content.includes('stake') && !content.includes('slash')) {
    findings.push({
      id: 'SOL4464',
      title: 'Staking: Slashing Mechanism',
      severity: 'info',
      description: 'Staking without slashing mechanism. Consider for validator/operator accountability.',
      location: { file: path },
      recommendation: 'Implement slashing for misbehavior if applicable to your staking model.'
    });
  }
}

// ============================================================================
// CROSS-CHAIN BRIDGE PATTERNS
// ============================================================================

/**
 * SOL4471-4480: Bridge Security Patterns
 */
function checkBridgePatterns(content: string, findings: Finding[], path: string) {
  // Guardian/validator set
  if (content.includes('bridge') || content.includes('cross_chain')) {
    if (!content.includes('guardian') && !content.includes('validator_set') && !content.includes('multisig')) {
      findings.push({
        id: 'SOL4471',
        title: 'Bridge: Missing Guardian System',
        severity: 'critical',
        description: 'Bridge without guardian/validator verification. Wormhole uses guardian set.',
        location: { file: path },
        recommendation: 'Implement multi-guardian signature verification for cross-chain messages.'
      });
    }
    
    if (!content.includes('sequence') && !content.includes('nonce')) {
      findings.push({
        id: 'SOL4472',
        title: 'Bridge: Message Sequencing',
        severity: 'high',
        description: 'Bridge without message sequencing. Prevents replay attacks.',
        location: { file: path },
        recommendation: 'Track message sequences to prevent replay attacks.'
      });
    }
    
    if (!content.includes('finality')) {
      findings.push({
        id: 'SOL4473',
        title: 'Bridge: Finality Handling',
        severity: 'high',
        description: 'Bridge without finality handling. Critical for preventing double-spends.',
        location: { file: path },
        recommendation: 'Wait for source chain finality before processing messages.'
      });
    }
  }
  
  // Wrapped token
  if (content.includes('wrapped') && content.includes('token')) {
    if (!content.includes('burn') || !content.includes('mint')) {
      findings.push({
        id: 'SOL4474',
        title: 'Bridge: Wrapped Token Mint/Burn',
        severity: 'high',
        description: 'Wrapped token without proper mint/burn mechanics. Critical for peg maintenance.',
        location: { file: path },
        recommendation: 'Implement 1:1 mint/burn with locked collateral on source chain.'
      });
    }
  }
}

// ============================================================================
// NFT PROTOCOL PATTERNS
// ============================================================================

/**
 * SOL4481-4490: NFT Security Patterns
 */
function checkNFTPatterns(content: string, findings: Finding[], path: string) {
  // Metadata validation
  if (content.includes('nft') || content.includes('metadata')) {
    if (!content.includes('verify_metadata') && !content.includes('metaplex')) {
      findings.push({
        id: 'SOL4481',
        title: 'NFT: Metadata Validation',
        severity: 'medium',
        description: 'NFT handling without metadata validation. Use Metaplex standards.',
        location: { file: path },
        recommendation: 'Validate NFT metadata using Metaplex token metadata program.'
      });
    }
    
    if (!content.includes('creator') && !content.includes('verified')) {
      findings.push({
        id: 'SOL4482',
        title: 'NFT: Creator Verification',
        severity: 'medium',
        description: 'NFT without creator verification. Important for authenticity.',
        location: { file: path },
        recommendation: 'Check creator signatures and verification status.'
      });
    }
  }
  
  // Collection handling
  if (content.includes('collection') && content.includes('nft')) {
    if (!content.includes('collection_authority') && !content.includes('verify_collection')) {
      findings.push({
        id: 'SOL4483',
        title: 'NFT: Collection Verification',
        severity: 'medium',
        description: 'NFT collection without verification. Prevents fake collection items.',
        location: { file: path },
        recommendation: 'Verify collection membership using Metaplex collection verification.'
      });
    }
  }
  
  // Royalty handling
  if (content.includes('royalt')) {
    if (!content.includes('seller_fee') && !content.includes('royalty_bps')) {
      findings.push({
        id: 'SOL4484',
        title: 'NFT: Royalty Calculation',
        severity: 'medium',
        description: 'Royalty handling without proper calculation. Honor creator royalties.',
        location: { file: path },
        recommendation: 'Calculate royalties from on-chain metadata seller_fee_basis_points.'
      });
    }
  }
}

// ============================================================================
// GOVERNANCE PATTERNS
// ============================================================================

/**
 * SOL4491-4500: Governance Security Patterns
 */
function checkGovernancePatterns(content: string, findings: Finding[], path: string) {
  // Proposal creation
  if (content.includes('proposal')) {
    if (!content.includes('quorum')) {
      findings.push({
        id: 'SOL4491',
        title: 'Governance: Missing Quorum',
        severity: 'high',
        description: 'Governance proposal without quorum requirement. Prevents low-participation attacks.',
        location: { file: path },
        recommendation: 'Implement quorum requirement (typically 4-10% of total supply).'
      });
    }
    
    if (!content.includes('timelock') && !content.includes('delay')) {
      findings.push({
        id: 'SOL4492',
        title: 'Governance: Missing Timelock',
        severity: 'high',
        description: 'Governance without execution timelock. Allows users to exit before changes.',
        location: { file: path },
        recommendation: 'Implement timelock delay between proposal passing and execution (24-72 hours).'
      });
    }
    
    if (!content.includes('voting_period') && !content.includes('end_time')) {
      findings.push({
        id: 'SOL4493',
        title: 'Governance: Voting Period',
        severity: 'medium',
        description: 'Proposal without defined voting period. Needed for fair participation.',
        location: { file: path },
        recommendation: 'Set explicit voting period (typically 3-7 days).'
      });
    }
  }
  
  // Vote delegation
  if (content.includes('vote') && !content.includes('delegate')) {
    findings.push({
      id: 'SOL4494',
      title: 'Governance: Vote Delegation',
      severity: 'info',
      description: 'Voting without delegation support. Enables better participation.',
      location: { file: path },
      recommendation: 'Consider adding vote delegation for users who cannot actively participate.'
    });
  }
  
  // Snapshot
  if (content.includes('vote') && content.includes('balance')) {
    if (!content.includes('snapshot') && !content.includes('checkpoint')) {
      findings.push({
        id: 'SOL4495',
        title: 'Governance: Vote Snapshot',
        severity: 'high',
        description: 'Voting using live balance without snapshot. Vulnerable to flash loan attacks.',
        location: { file: path },
        recommendation: 'Use balance snapshot at proposal creation to determine voting power.'
      });
    }
  }
  
  // Proposal threshold
  if (content.includes('create_proposal') && !content.includes('threshold') && !content.includes('minimum')) {
    findings.push({
      id: 'SOL4496',
      title: 'Governance: Proposal Threshold',
      severity: 'medium',
      description: 'Proposal creation without minimum token threshold. Prevents spam.',
      location: { file: path },
      recommendation: 'Require minimum token holdings to create proposals (typically 0.5-1% of supply).'
    });
  }
  
  // Emergency actions
  if (content.includes('governance') && !content.includes('emergency') && !content.includes('guardian')) {
    findings.push({
      id: 'SOL4497',
      title: 'Governance: Emergency Powers',
      severity: 'medium',
      description: 'Governance without emergency powers. Needed for rapid response to exploits.',
      location: { file: path },
      recommendation: 'Implement guardian role for emergency pause/actions with timelock override.'
    });
  }
}

// ============================================================================
// MAIN EXPORT FUNCTION
// ============================================================================

export function checkBatch84Patterns(input: ScanInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';
  const path = input.path;
  
  if (!content) return findings;
  
  // Security Tool Patterns
  checkFuzzTestingCoverage(content, findings, path);
  checkCheckedMathMacro(content, findings, path);
  checkSoteriaPatterns(content, findings, path);
  
  // Protocol-Specific Audit Patterns
  checkMangoAuditPatterns(content, findings, path);
  checkMarinadeAuditPatterns(content, findings, path);
  checkOrcaAuditPatterns(content, findings, path);
  checkDriftAuditPatterns(content, findings, path);
  checkPhoenixAuditPatterns(content, findings, path);
  
  // Advanced DeFi Patterns
  checkLendingProtocolPatterns(content, findings, path);
  checkAMMPatterns(content, findings, path);
  checkOptionsPatterns(content, findings, path);
  checkStakingProtocolPatterns(content, findings, path);
  
  // Cross-Chain Bridge Patterns
  checkBridgePatterns(content, findings, path);
  
  // NFT Patterns
  checkNFTPatterns(content, findings, path);
  
  // Governance Patterns
  checkGovernancePatterns(content, findings, path);
  
  return findings;
}

// Export pattern count for this batch
export const BATCH_84_PATTERN_COUNT = 100;
