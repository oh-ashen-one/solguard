/**
 * SolGuard Pattern Batch 42
 * DeFi Protocol Security Patterns
 * Patterns SOL1231-SOL1300
 * 
 * Covers: AMM, Lending, Perpetuals, Options, Staking, Yield
 */

import type { PatternInput, Finding } from './index.js';

interface BatchPattern {
  id: string;
  name: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  category: string;
  description: string;
  detection: {
    patterns: RegExp[];
  };
  recommendation: string;
  references: string[];
}

const batchedPatterns42: BatchPattern[] = [
  // ========================================
  // AMM SECURITY PATTERNS
  // ========================================
  {
    id: 'SOL1231',
    name: 'AMM Constant Product Violation',
    severity: 'critical',
    category: 'amm',
    description: 'AMM invariant (x*y=k) not enforced after swap.',
    detection: {
      patterns: [
        /swap[\s\S]{0,200}(?!invariant|k_value|product)/i,
        /x\s*\*\s*y/i,
        /constant_product/i
      ]
    },
    recommendation: 'Verify k_after >= k_before after every swap.',
    references: ['https://sec3.dev/']
  },
  {
    id: 'SOL1232',
    name: 'AMM Slippage Not Enforced',
    severity: 'high',
    category: 'amm',
    description: 'Slippage protection not enforced in swap.',
    detection: {
      patterns: [
        /swap[\s\S]{0,100}(?!min_amount|minimum|slippage)/i,
        /amount_out[\s\S]{0,50}(?!>=|min)/i
      ]
    },
    recommendation: 'Require minimum_amount_out parameter and enforce it.',
    references: ['https://sec3.dev/']
  },
  {
    id: 'SOL1233',
    name: 'AMM Reserve Manipulation',
    severity: 'critical',
    category: 'amm',
    description: 'AMM reserves can be directly manipulated.',
    detection: {
      patterns: [
        /reserve.*=\s*\d/i,
        /pool_reserve.*mut/i,
        /update_reserve[\s\S]{0,50}(?!swap|deposit|withdraw)/i
      ]
    },
    recommendation: 'Only update reserves through swap/deposit/withdraw functions.',
    references: ['https://sec3.dev/']
  },
  {
    id: 'SOL1234',
    name: 'LP Token Inflation Attack',
    severity: 'critical',
    category: 'amm',
    description: 'LP tokens can be inflated to steal funds.',
    detection: {
      patterns: [
        /lp_supply.*=\s*0/i,
        /first_deposit/i,
        /initial_liquidity/i,
        /mint_lp/i
      ]
    },
    recommendation: 'Mint initial LP to dead address. Use virtual reserves.',
    references: ['https://sec3.dev/']
  },
  {
    id: 'SOL1235',
    name: 'Imbalanced Deposit Attack',
    severity: 'high',
    category: 'amm',
    description: 'Single-sided deposit can manipulate pool ratio.',
    detection: {
      patterns: [
        /single_sided/i,
        /imbalanced.*deposit/i,
        /one_token.*deposit/i
      ]
    },
    recommendation: 'Charge premium for imbalanced deposits.',
    references: ['https://sec3.dev/']
  },
  {
    id: 'SOL1236',
    name: 'Sandwich Attack Vulnerability',
    severity: 'high',
    category: 'amm',
    description: 'AMM vulnerable to sandwich attacks.',
    detection: {
      patterns: [
        /swap[\s\S]{0,100}(?!deadline|expiry)/i,
        /trade[\s\S]{0,100}(?!deadline)/i
      ]
    },
    recommendation: 'Add deadline parameter. Use private mempool if available.',
    references: ['https://sec3.dev/']
  },
  {
    id: 'SOL1237',
    name: 'CLMM Tick Range Attack',
    severity: 'high',
    category: 'amm',
    description: 'Concentrated liquidity tick boundaries exploitable.',
    detection: {
      patterns: [
        /tick_lower/i,
        /tick_upper/i,
        /tick_spacing/i,
        /liquidity_net/i
      ]
    },
    recommendation: 'Validate tick boundaries. Handle edge cases properly.',
    references: ['https://sec3.dev/']
  },
  {
    id: 'SOL1238',
    name: 'Fee Growth Overflow',
    severity: 'high',
    category: 'amm',
    description: 'Fee growth accumulator can overflow.',
    detection: {
      patterns: [
        /fee_growth/i,
        /fees_owed/i,
        /accumulated_fees/i
      ]
    },
    recommendation: 'Use u128 for fee accumulators. Handle overflow.',
    references: ['https://sec3.dev/']
  },
  {
    id: 'SOL1239',
    name: 'Position NFT Validation',
    severity: 'critical',
    category: 'amm',
    description: 'CLMM position NFT ownership not verified.',
    detection: {
      patterns: [
        /position.*nft/i,
        /position_mint/i,
        /position_token_account/i
      ]
    },
    recommendation: 'Verify NFT ownership before allowing position operations.',
    references: ['https://sec3.dev/']
  },
  {
    id: 'SOL1240',
    name: 'Pool Authority Compromise',
    severity: 'critical',
    category: 'amm',
    description: 'Pool authority can drain funds.',
    detection: {
      patterns: [
        /pool_authority/i,
        /pool_signer/i,
        /vault_authority/i
      ]
    },
    recommendation: 'Use PDA as pool authority. Minimize authority privileges.',
    references: ['https://sec3.dev/']
  },
  // ========================================
  // LENDING PROTOCOL PATTERNS
  // ========================================
  {
    id: 'SOL1241',
    name: 'Health Factor Calculation Error',
    severity: 'critical',
    category: 'lending',
    description: 'Health factor calculation vulnerable to manipulation.',
    detection: {
      patterns: [
        /health_factor/i,
        /collateral_value.*\/.*borrow/i,
        /ltv.*ratio/i
      ]
    },
    recommendation: 'Use conservative rounding. Update all positions before check.',
    references: ['https://sec3.dev/']
  },
  {
    id: 'SOL1242',
    name: 'Liquidation Bonus Exploit',
    severity: 'high',
    category: 'lending',
    description: 'Liquidation bonus can be exploited for profit.',
    detection: {
      patterns: [
        /liquidation_bonus/i,
        /liquidation_incentive/i,
        /bonus_percent/i
      ]
    },
    recommendation: 'Cap liquidation bonus. Implement partial liquidation.',
    references: ['https://sec3.dev/']
  },
  {
    id: 'SOL1243',
    name: 'Collateral Factor Too High',
    severity: 'high',
    category: 'lending',
    description: 'Collateral factor allows excessive leverage.',
    detection: {
      patterns: [
        /collateral_factor/i,
        /loan_to_value/i,
        /max_ltv/i
      ]
    },
    recommendation: 'Set conservative collateral factors per asset risk.',
    references: ['https://sec3.dev/']
  },
  {
    id: 'SOL1244',
    name: 'Flash Loan Fee Bypass',
    severity: 'high',
    category: 'lending',
    description: 'Flash loan fee can be bypassed.',
    detection: {
      patterns: [
        /flash_loan/i,
        /flash_fee/i,
        /instant_loan/i
      ]
    },
    recommendation: 'Verify fee payment before completing flash loan.',
    references: ['https://sec3.dev/']
  },
  {
    id: 'SOL1245',
    name: 'Reserve Utilization Manipulation',
    severity: 'high',
    category: 'lending',
    description: 'Reserve utilization rate can be manipulated.',
    detection: {
      patterns: [
        /utilization_rate/i,
        /borrow.*supply/i,
        /available_liquidity/i
      ]
    },
    recommendation: 'Use time-weighted utilization. Add rate smoothing.',
    references: ['https://sec3.dev/']
  },
  {
    id: 'SOL1246',
    name: 'Borrow Index Stale',
    severity: 'high',
    category: 'lending',
    description: 'Borrow index not updated before operations.',
    detection: {
      patterns: [
        /borrow_index/i,
        /cumulative_borrow/i,
        /interest_index/i
      ]
    },
    recommendation: 'Update indexes before any borrow/repay operations.',
    references: ['https://sec3.dev/']
  },
  {
    id: 'SOL1247',
    name: 'Supply Cap Exceeded',
    severity: 'medium',
    category: 'lending',
    description: 'Supply caps not enforced properly.',
    detection: {
      patterns: [
        /supply_cap/i,
        /max_supply/i,
        /deposit_limit/i
      ]
    },
    recommendation: 'Check supply cap before allowing deposits.',
    references: ['https://sec3.dev/']
  },
  {
    id: 'SOL1248',
    name: 'Reserve Configuration Mismatch',
    severity: 'high',
    category: 'lending',
    description: 'Reserve configuration doesnt match asset risk.',
    detection: {
      patterns: [
        /reserve_config/i,
        /asset_config/i,
        /market_config/i
      ]
    },
    recommendation: 'Validate reserve configs match asset characteristics.',
    references: ['https://sec3.dev/']
  },
  {
    id: 'SOL1249',
    name: 'Isolated Asset Bypass',
    severity: 'high',
    category: 'lending',
    description: 'Isolated asset restrictions can be bypassed.',
    detection: {
      patterns: [
        /isolated/i,
        /siloed/i,
        /isolation_mode/i
      ]
    },
    recommendation: 'Enforce isolation mode across all operations.',
    references: ['https://sec3.dev/']
  },
  {
    id: 'SOL1250',
    name: 'E-Mode Configuration Risk',
    severity: 'medium',
    category: 'lending',
    description: 'Efficiency mode parameters too aggressive.',
    detection: {
      patterns: [
        /emode/i,
        /efficiency_mode/i,
        /high_efficiency/i
      ]
    },
    recommendation: 'Set conservative e-mode parameters for correlated assets.',
    references: ['https://sec3.dev/']
  },
  // ========================================
  // PERPETUALS PATTERNS
  // ========================================
  {
    id: 'SOL1251',
    name: 'Funding Rate Manipulation',
    severity: 'critical',
    category: 'perps',
    description: 'Funding rate can be manipulated for profit.',
    detection: {
      patterns: [
        /funding_rate/i,
        /funding_payment/i,
        /mark_price.*index_price/i
      ]
    },
    recommendation: 'Cap funding rate. Use TWAP for mark price.',
    references: ['https://sec3.dev/']
  },
  {
    id: 'SOL1252',
    name: 'Mark Price Deviation',
    severity: 'critical',
    category: 'perps',
    description: 'Mark price can deviate significantly from index.',
    detection: {
      patterns: [
        /mark_price/i,
        /fair_price/i,
        /oracle_price.*deviation/i
      ]
    },
    recommendation: 'Cap mark-index deviation. Use circuit breakers.',
    references: ['https://sec3.dev/']
  },
  {
    id: 'SOL1253',
    name: 'ADL Unfair Selection',
    severity: 'high',
    category: 'perps',
    description: 'Auto-deleveraging selection criteria unfair.',
    detection: {
      patterns: [
        /adl/i,
        /auto_deleverage/i,
        /socialized_loss/i
      ]
    },
    recommendation: 'Use fair ADL ranking (PnL-weighted, leverage-based).',
    references: ['https://sec3.dev/']
  },
  {
    id: 'SOL1254',
    name: 'Position Size Limit Bypass',
    severity: 'high',
    category: 'perps',
    description: 'Max position size can be bypassed.',
    detection: {
      patterns: [
        /max_position/i,
        /position_limit/i,
        /open_interest_cap/i
      ]
    },
    recommendation: 'Check position limits before increasing position.',
    references: ['https://sec3.dev/']
  },
  {
    id: 'SOL1255',
    name: 'Leverage Multiplier Exploit',
    severity: 'critical',
    category: 'perps',
    description: 'Max leverage allows risky positions.',
    detection: {
      patterns: [
        /max_leverage/i,
        /leverage_multiplier/i,
        /margin_requirement/i
      ]
    },
    recommendation: 'Set conservative max leverage. Implement position sizing.',
    references: ['https://sec3.dev/']
  },
  {
    id: 'SOL1256',
    name: 'Insurance Fund Depletion',
    severity: 'critical',
    category: 'perps',
    description: 'Insurance fund can be drained.',
    detection: {
      patterns: [
        /insurance_fund/i,
        /insurance_vault/i,
        /cover_loss/i
      ]
    },
    recommendation: 'Implement insurance fund caps. Add socialization threshold.',
    references: ['https://sec3.dev/']
  },
  {
    id: 'SOL1257',
    name: 'PnL Settlement Timing',
    severity: 'high',
    category: 'perps',
    description: 'PnL settlement can be timed for advantage.',
    detection: {
      patterns: [
        /settle_pnl/i,
        /realize_pnl/i,
        /settlement_price/i
      ]
    },
    recommendation: 'Use oracle price at settlement. Add settlement delay.',
    references: ['https://sec3.dev/']
  },
  {
    id: 'SOL1258',
    name: 'Cross-Margin Liquidation Cascade',
    severity: 'critical',
    category: 'perps',
    description: 'Cross-margin can cause liquidation cascade.',
    detection: {
      patterns: [
        /cross_margin/i,
        /account_margin/i,
        /portfolio_margin/i
      ]
    },
    recommendation: 'Implement position limits. Add liquidation buffers.',
    references: ['https://sec3.dev/']
  },
  {
    id: 'SOL1259',
    name: 'Order Type Manipulation',
    severity: 'medium',
    category: 'perps',
    description: 'Order types can be manipulated (limit, stop, etc).',
    detection: {
      patterns: [
        /limit_order/i,
        /stop_loss/i,
        /take_profit/i,
        /trigger_price/i
      ]
    },
    recommendation: 'Validate order parameters. Use oracle price for triggers.',
    references: ['https://sec3.dev/']
  },
  {
    id: 'SOL1260',
    name: 'Keeper Frontrunning',
    severity: 'high',
    category: 'perps',
    description: 'Keeper can frontrun liquidations or orders.',
    detection: {
      patterns: [
        /keeper/i,
        /executor/i,
        /resolver/i,
        /liquidation_bot/i
      ]
    },
    recommendation: 'Use commit-reveal. Add MEV protection.',
    references: ['https://sec3.dev/']
  },
  // ========================================
  // OPTIONS PATTERNS
  // ========================================
  {
    id: 'SOL1261',
    name: 'Option Premium Manipulation',
    severity: 'high',
    category: 'options',
    description: 'Option premium pricing vulnerable to manipulation.',
    detection: {
      patterns: [
        /premium/i,
        /option_price/i,
        /black_scholes/i,
        /implied_volatility/i
      ]
    },
    recommendation: 'Use market IV. Add premium bounds.',
    references: ['https://sec3.dev/']
  },
  {
    id: 'SOL1262',
    name: 'Exercise Window Manipulation',
    severity: 'high',
    category: 'options',
    description: 'Option exercise can be timed for advantage.',
    detection: {
      patterns: [
        /exercise/i,
        /expiry/i,
        /settlement_time/i,
        /expiration/i
      ]
    },
    recommendation: 'Use oracle price at fixed settlement time.',
    references: ['https://sec3.dev/']
  },
  {
    id: 'SOL1263',
    name: 'Collateral Shortfall',
    severity: 'critical',
    category: 'options',
    description: 'Option writer collateral insufficient.',
    detection: {
      patterns: [
        /writer_collateral/i,
        /margin_requirement/i,
        /covered/i,
        /naked/i
      ]
    },
    recommendation: 'Require full collateralization or adequate margin.',
    references: ['https://sec3.dev/']
  },
  {
    id: 'SOL1264',
    name: 'Greeks Calculation Error',
    severity: 'medium',
    category: 'options',
    description: 'Option greeks calculated incorrectly.',
    detection: {
      patterns: [
        /delta/i,
        /gamma/i,
        /theta/i,
        /vega/i
      ]
    },
    recommendation: 'Use standard option pricing models. Verify calculations.',
    references: ['https://sec3.dev/']
  },
  {
    id: 'SOL1265',
    name: 'Vault Epoch Manipulation',
    severity: 'high',
    category: 'options',
    description: 'Option vault epoch transitions exploitable.',
    detection: {
      patterns: [
        /epoch/i,
        /round/i,
        /vault.*deposit/i,
        /instant_deposit/i
      ]
    },
    recommendation: 'Queue deposits for next epoch. Use time-weighted shares.',
    references: ['https://sec3.dev/']
  },
  // ========================================
  // STAKING PATTERNS
  // ========================================
  {
    id: 'SOL1266',
    name: 'Staking Reward Manipulation',
    severity: 'high',
    category: 'staking',
    description: 'Staking rewards can be claimed unfairly.',
    detection: {
      patterns: [
        /reward.*per.*token/i,
        /reward_rate/i,
        /earned.*rewards/i
      ]
    },
    recommendation: 'Use reward per token pattern. Update on stake changes.',
    references: ['https://sec3.dev/']
  },
  {
    id: 'SOL1267',
    name: 'Unbonding Period Bypass',
    severity: 'high',
    category: 'staking',
    description: 'Unbonding/cooldown period can be bypassed.',
    detection: {
      patterns: [
        /unbonding/i,
        /cooldown/i,
        /unstake.*delay/i,
        /withdrawal_delay/i
      ]
    },
    recommendation: 'Enforce unbonding period on-chain.',
    references: ['https://sec3.dev/']
  },
  {
    id: 'SOL1268',
    name: 'Slashing Insufficient',
    severity: 'high',
    category: 'staking',
    description: 'Slashing penalty not proportional to violation.',
    detection: {
      patterns: [
        /slash/i,
        /penalty/i,
        /punishment/i,
        /slashing_rate/i
      ]
    },
    recommendation: 'Set appropriate slashing rates. Handle edge cases.',
    references: ['https://sec3.dev/']
  },
  {
    id: 'SOL1269',
    name: 'Validator Set Manipulation',
    severity: 'critical',
    category: 'staking',
    description: 'Validator set can be manipulated.',
    detection: {
      patterns: [
        /validator.*set/i,
        /active_validators/i,
        /validator_selection/i
      ]
    },
    recommendation: 'Use fair validator selection. Add churn limits.',
    references: ['https://sec3.dev/']
  },
  {
    id: 'SOL1270',
    name: 'Delegation Centralization',
    severity: 'medium',
    category: 'staking',
    description: 'Stake delegation too centralized.',
    detection: {
      patterns: [
        /delegation/i,
        /delegator/i,
        /stake_account/i,
        /delegation_cap/i
      ]
    },
    recommendation: 'Implement delegation caps. Incentivize decentralization.',
    references: ['https://sec3.dev/']
  },
  // ========================================
  // YIELD AGGREGATOR PATTERNS
  // ========================================
  {
    id: 'SOL1271',
    name: 'Strategy Griefing',
    severity: 'high',
    category: 'yield',
    description: 'Yield strategy can be griefed by small deposits.',
    detection: {
      patterns: [
        /strategy/i,
        /vault.*strategy/i,
        /harvest/i,
        /compound/i
      ]
    },
    recommendation: 'Set minimum deposit. Use batch harvesting.',
    references: ['https://sec3.dev/']
  },
  {
    id: 'SOL1272',
    name: 'Harvest Manipulation',
    severity: 'high',
    category: 'yield',
    description: 'Harvest timing can be manipulated for MEV.',
    detection: {
      patterns: [
        /harvest/i,
        /claim_rewards/i,
        /compound_rewards/i
      ]
    },
    recommendation: 'Use permissioned harvesters. Add harvest delay.',
    references: ['https://sec3.dev/']
  },
  {
    id: 'SOL1273',
    name: 'Strategy Migration Risk',
    severity: 'high',
    category: 'yield',
    description: 'Strategy migration can cause fund loss.',
    detection: {
      patterns: [
        /migrate/i,
        /set_strategy/i,
        /update_strategy/i
      ]
    },
    recommendation: 'Add migration timelock. Verify new strategy.',
    references: ['https://sec3.dev/']
  },
  {
    id: 'SOL1274',
    name: 'Withdrawal Fee Exploit',
    severity: 'medium',
    category: 'yield',
    description: 'Withdrawal fees can be bypassed or exploited.',
    detection: {
      patterns: [
        /withdrawal_fee/i,
        /exit_fee/i,
        /redemption_fee/i
      ]
    },
    recommendation: 'Apply fees consistently. Consider time-based fees.',
    references: ['https://sec3.dev/']
  },
  {
    id: 'SOL1275',
    name: 'Protocol Integration Risk',
    severity: 'high',
    category: 'yield',
    description: 'Underlying protocol integration vulnerable.',
    detection: {
      patterns: [
        /underlying_protocol/i,
        /external_call/i,
        /third_party/i
      ]
    },
    recommendation: 'Verify underlying protocol addresses. Add circuit breakers.',
    references: ['https://sec3.dev/']
  },
  // ========================================
  // BRIDGE PATTERNS
  // ========================================
  {
    id: 'SOL1276',
    name: 'Cross-Chain Message Replay',
    severity: 'critical',
    category: 'bridge',
    description: 'Cross-chain message can be replayed.',
    detection: {
      patterns: [
        /message.*nonce/i,
        /cross_chain.*replay/i,
        /bridge.*message/i
      ]
    },
    recommendation: 'Use unique nonces. Mark messages as processed.',
    references: ['https://sec3.dev/']
  },
  {
    id: 'SOL1277',
    name: 'Source Chain Verification',
    severity: 'critical',
    category: 'bridge',
    description: 'Source chain not properly verified.',
    detection: {
      patterns: [
        /source_chain/i,
        /origin_chain/i,
        /emitter_chain/i
      ]
    },
    recommendation: 'Verify source chain ID. Validate emitter address.',
    references: ['https://sec3.dev/']
  },
  {
    id: 'SOL1278',
    name: 'Guardian Threshold Too Low',
    severity: 'critical',
    category: 'bridge',
    description: 'Guardian/validator threshold insufficient.',
    detection: {
      patterns: [
        /guardian.*threshold/i,
        /validator.*threshold/i,
        /quorum.*\d/i
      ]
    },
    recommendation: 'Set threshold > 2/3 of guardians.',
    references: ['https://sec3.dev/']
  },
  {
    id: 'SOL1279',
    name: 'Finality Not Waited',
    severity: 'critical',
    category: 'bridge',
    description: 'Bridge doesnt wait for source chain finality.',
    detection: {
      patterns: [
        /finality/i,
        /confirmations/i,
        /block_height.*check/i
      ]
    },
    recommendation: 'Wait for sufficient confirmations on source chain.',
    references: ['https://sec3.dev/']
  },
  {
    id: 'SOL1280',
    name: 'Token Mapping Mismatch',
    severity: 'critical',
    category: 'bridge',
    description: 'Bridged token mapping incorrect.',
    detection: {
      patterns: [
        /token_mapping/i,
        /wrapped_token/i,
        /bridge_mint/i
      ]
    },
    recommendation: 'Verify token mappings. Use canonical token registry.',
    references: ['https://sec3.dev/']
  },
  // ========================================
  // NFT PATTERNS
  // ========================================
  {
    id: 'SOL1281',
    name: 'NFT Ownership Not Verified',
    severity: 'critical',
    category: 'nft',
    description: 'NFT ownership not checked before operation.',
    detection: {
      patterns: [
        /nft.*owner/i,
        /holder.*check/i,
        /token_account.*amount/i
      ]
    },
    recommendation: 'Verify NFT holder. Check token account amount == 1.',
    references: ['https://sec3.dev/']
  },
  {
    id: 'SOL1282',
    name: 'Royalty Enforcement Bypass',
    severity: 'medium',
    category: 'nft',
    description: 'NFT royalties not enforced.',
    detection: {
      patterns: [
        /royalty/i,
        /creator_fee/i,
        /seller_fee_basis_points/i
      ]
    },
    recommendation: 'Use Metaplex pNFT for enforced royalties.',
    references: ['https://sec3.dev/']
  },
  {
    id: 'SOL1283',
    name: 'Metadata URI Injection',
    severity: 'high',
    category: 'nft',
    description: 'Metadata URI not validated.',
    detection: {
      patterns: [
        /metadata.*uri/i,
        /token_uri/i,
        /update_metadata/i
      ]
    },
    recommendation: 'Validate URI format. Consider immutable metadata.',
    references: ['https://sec3.dev/']
  },
  {
    id: 'SOL1284',
    name: 'Collection Verification Missing',
    severity: 'high',
    category: 'nft',
    description: 'NFT collection not verified.',
    detection: {
      patterns: [
        /collection/i,
        /verified.*collection/i,
        /collection_mint/i
      ]
    },
    recommendation: 'Check collection.verified == true.',
    references: ['https://sec3.dev/']
  },
  {
    id: 'SOL1285',
    name: 'Edition Supply Manipulation',
    severity: 'high',
    category: 'nft',
    description: 'NFT edition supply can be manipulated.',
    detection: {
      patterns: [
        /edition/i,
        /max_supply/i,
        /print.*edition/i
      ]
    },
    recommendation: 'Verify edition master. Check max supply.',
    references: ['https://sec3.dev/']
  },
  // ========================================
  // GAMING PATTERNS
  // ========================================
  {
    id: 'SOL1286',
    name: 'Randomness Prediction',
    severity: 'critical',
    category: 'gaming',
    description: 'Game randomness is predictable.',
    detection: {
      patterns: [
        /random/i,
        /slot_hashes/i,
        /recent_slothashes/i,
        /pseudo_random/i
      ]
    },
    recommendation: 'Use VRF (Switchboard, Orao). Dont use slot hashes.',
    references: ['https://sec3.dev/']
  },
  {
    id: 'SOL1287',
    name: 'Game State Manipulation',
    severity: 'critical',
    category: 'gaming',
    description: 'Game state can be manipulated externally.',
    detection: {
      patterns: [
        /game_state/i,
        /player_state/i,
        /score.*update/i
      ]
    },
    recommendation: 'Verify game state transitions. Add server authority.',
    references: ['https://sec3.dev/']
  },
  {
    id: 'SOL1288',
    name: 'Reward Economy Exploit',
    severity: 'high',
    category: 'gaming',
    description: 'Game reward economy exploitable.',
    detection: {
      patterns: [
        /reward.*mint/i,
        /game.*reward/i,
        /token.*emission/i
      ]
    },
    recommendation: 'Rate limit rewards. Add anti-bot mechanisms.',
    references: ['https://sec3.dev/']
  },
  {
    id: 'SOL1289',
    name: 'Asset Duplication',
    severity: 'critical',
    category: 'gaming',
    description: 'Game assets can be duplicated.',
    detection: {
      patterns: [
        /item.*transfer/i,
        /asset.*clone/i,
        /inventory/i
      ]
    },
    recommendation: 'Use NFTs for unique items. Add supply checks.',
    references: ['https://sec3.dev/']
  },
  {
    id: 'SOL1290',
    name: 'Matchmaking Manipulation',
    severity: 'medium',
    category: 'gaming',
    description: 'Game matchmaking can be exploited.',
    detection: {
      patterns: [
        /matchmaking/i,
        /player_match/i,
        /opponent.*selection/i
      ]
    },
    recommendation: 'Use verifiable matchmaking. Add ELO system.',
    references: ['https://sec3.dev/']
  },
  // ========================================
  // MISC DEFI PATTERNS
  // ========================================
  {
    id: 'SOL1291',
    name: 'Price Impact Not Calculated',
    severity: 'high',
    category: 'defi',
    description: 'Trade price impact not shown/enforced.',
    detection: {
      patterns: [
        /price_impact/i,
        /slippage.*percentage/i,
        /execution_price/i
      ]
    },
    recommendation: 'Calculate and display price impact. Warn on high impact.',
    references: ['https://sec3.dev/']
  },
  {
    id: 'SOL1292',
    name: 'MEV Extraction Vulnerability',
    severity: 'high',
    category: 'defi',
    description: 'Transaction vulnerable to MEV extraction.',
    detection: {
      patterns: [
        /swap/i,
        /trade/i,
        /liquidate/i
      ]
    },
    recommendation: 'Use private transactions. Add MEV protection.',
    references: ['https://sec3.dev/']
  },
  {
    id: 'SOL1293',
    name: 'Protocol Fee Excessive',
    severity: 'low',
    category: 'defi',
    description: 'Protocol fees may be set too high.',
    detection: {
      patterns: [
        /protocol_fee/i,
        /fee_percentage/i,
        /fee_bps/i
      ]
    },
    recommendation: 'Cap protocol fees. Use governance for fee changes.',
    references: ['https://sec3.dev/']
  },
  {
    id: 'SOL1294',
    name: 'Emergency Withdrawal Missing',
    severity: 'medium',
    category: 'defi',
    description: 'No emergency withdrawal mechanism.',
    detection: {
      patterns: [
        /emergency/i,
        /rescue/i,
        /recover_funds/i
      ]
    },
    recommendation: 'Implement emergency withdrawal with timelock.',
    references: ['https://sec3.dev/']
  },
  {
    id: 'SOL1295',
    name: 'Rug Pull Indicators',
    severity: 'critical',
    category: 'defi',
    description: 'Code patterns indicating potential rug pull.',
    detection: {
      patterns: [
        /withdraw_all/i,
        /drain/i,
        /admin.*withdraw.*any/i,
        /hidden.*mint/i
      ]
    },
    recommendation: 'Review admin capabilities. Use multisig.',
    references: ['https://sec3.dev/']
  },
  {
    id: 'SOL1296',
    name: 'Token Approval Unlimited',
    severity: 'medium',
    category: 'defi',
    description: 'Unlimited token approvals requested.',
    detection: {
      patterns: [
        /u64::MAX/i,
        /approve.*unlimited/i,
        /infinite.*approval/i
      ]
    },
    recommendation: 'Request exact amount approval. Revoke after use.',
    references: ['https://sec3.dev/']
  },
  {
    id: 'SOL1297',
    name: 'Deadline Not Enforced',
    severity: 'high',
    category: 'defi',
    description: 'Transaction deadline not enforced.',
    detection: {
      patterns: [
        /deadline/i,
        /expiry/i,
        /valid_until/i
      ]
    },
    recommendation: 'Enforce deadline parameter. Reject stale transactions.',
    references: ['https://sec3.dev/']
  },
  {
    id: 'SOL1298',
    name: 'Referral Code Manipulation',
    severity: 'low',
    category: 'defi',
    description: 'Referral system can be gamed.',
    detection: {
      patterns: [
        /referral/i,
        /referrer/i,
        /affiliate/i
      ]
    },
    recommendation: 'Add referral validation. Cap referral rewards.',
    references: ['https://sec3.dev/']
  },
  {
    id: 'SOL1299',
    name: 'Rate Limit Not Implemented',
    severity: 'medium',
    category: 'defi',
    description: 'No rate limiting on critical operations.',
    detection: {
      patterns: [
        /rate_limit/i,
        /cooldown/i,
        /throttle/i
      ]
    },
    recommendation: 'Implement rate limits for sensitive operations.',
    references: ['https://sec3.dev/']
  },
  {
    id: 'SOL1300',
    name: 'Versioning Not Implemented',
    severity: 'low',
    category: 'defi',
    description: 'Protocol version not tracked.',
    detection: {
      patterns: [
        /version/i,
        /protocol_version/i,
        /schema_version/i
      ]
    },
    recommendation: 'Track protocol version. Handle upgrades gracefully.',
    references: ['https://sec3.dev/']
  }
];

// Export function to run all patterns in this batch
export function runBatchedPatterns42(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';
  
  if (!content) return findings;
  
  for (const pattern of batchedPatterns42) {
    for (const regex of pattern.detection.patterns) {
      if (regex.test(content)) {
        const match = content.match(regex);
        if (match) {
          findings.push({
            id: pattern.id,
            title: pattern.name,
            severity: pattern.severity,
            description: pattern.description,
            location: { file: input.path },
            recommendation: pattern.recommendation,
          });
          break;
        }
      }
    }
  }
  
  return findings;
}

export { batchedPatterns42 };
export const BATCH_42_COUNT = batchedPatterns42.length; // 70 patterns
