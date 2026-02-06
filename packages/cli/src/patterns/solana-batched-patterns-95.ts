/**
 * SolGuard Batch 95 Patterns
 * 
 * Source: OtterSec Audits + Neodyme Research + Sec3 Workshop + Zellic Deep Dive + Feb 2026 Final
 * Patterns: SOL5701-SOL5800
 * Added: Feb 6, 2026 7:30 AM
 */

import type { ParsedRust } from '../parsers/rust.js';

export const batch95Patterns = [
  // ===== OTTERSEC JET GOVERNANCE PATTERNS =====
  {
    id: 'SOL5701',
    name: 'governance-voter-weight-manipulation',
    severity: 'critical' as const,
    category: 'governance',
    description: 'Detection of voter weight manipulation in governance systems (Jet Governance audit)',
    pattern: /voter_weight|voting_power|stake_weight|governance_power/gi,
    detector: (content: string) => {
      const issues: string[] = [];
      
      if (/voter_weight|voting_power/i.test(content)) {
        if (!/snapshot|checkpoint|lock_time/i.test(content)) {
          issues.push('Voter weight without snapshot mechanism - vulnerable to flash loan vote manipulation');
        }
        if (!/decay|linear_vesting|time_lock/i.test(content)) {
          issues.push('Voter weight without time-based decay or vesting requirement');
        }
      }
      
      return issues;
    },
  },
  {
    id: 'SOL5702',
    name: 'governance-proposal-spam-protection',
    severity: 'medium' as const,
    category: 'governance',
    description: 'Detection of governance proposal spam vulnerabilities',
    pattern: /create_proposal|new_proposal|submit_proposal/gi,
    detector: (content: string) => {
      const issues: string[] = [];
      
      if (/create_proposal|submit_proposal/i.test(content)) {
        if (!/min_stake|proposal_deposit|bond/i.test(content)) {
          issues.push('Proposal creation without stake requirement - vulnerable to spam');
        }
        if (!/active_proposal_limit|max_proposals/i.test(content)) {
          issues.push('No limit on active proposals per user');
        }
      }
      
      return issues;
    },
  },

  // ===== OTTERSEC CEGA VAULT PATTERNS =====
  {
    id: 'SOL5703',
    name: 'structured-product-pricing-exploit',
    severity: 'high' as const,
    category: 'defi',
    description: 'Detection of structured product pricing vulnerabilities (Cega Vault audit)',
    pattern: /structured_product|option_vault|exotic_option|barrier_option/gi,
    detector: (content: string) => {
      const issues: string[] = [];
      
      if (/structured_product|option_vault/i.test(content)) {
        if (!/mark_to_market|fair_value|external_price/i.test(content)) {
          issues.push('Structured product without external price verification');
        }
        if (!/settlement_price|expiry_price/i.test(content)) {
          issues.push('Option vault without settlement price source');
        }
      }
      
      return issues;
    },
  },
  {
    id: 'SOL5704',
    name: 'vault-deposit-timing-attack',
    severity: 'high' as const,
    category: 'defi',
    description: 'Detection of vault deposit timing attacks',
    pattern: /deposit_window|epoch_deposit|round_deposit/gi,
    detector: (content: string) => {
      const issues: string[] = [];
      
      if (/deposit_window|epoch/i.test(content)) {
        if (!/close_window|deposit_lock|cut_off/i.test(content)) {
          issues.push('Vault deposit window without clear cutoff - timing attack possible');
        }
      }
      
      return issues;
    },
  },

  // ===== NEODYME POC FRAMEWORK PATTERNS =====
  {
    id: 'SOL5705',
    name: 'poc-framework-detectable-patterns',
    severity: 'high' as const,
    category: 'attack-surface',
    description: 'Detection of patterns that are testable via Neodyme PoC framework',
    pattern: /invoke_signed|cross_program|cpi.*invoke|program_invoke/gi,
    detector: (content: string) => {
      const issues: string[] = [];
      
      // Check for testable CPI patterns
      if (/invoke_signed|invoke/i.test(content)) {
        if (!/cpi.*check|program_id.*verify/i.test(content)) {
          issues.push('CPI invocation without program ID verification - add PoC test');
        }
      }
      
      // Check for state manipulation
      if (/set_state|update_state|modify/i.test(content)) {
        if (!/owner.*check|authority.*verify/i.test(content)) {
          issues.push('State modification without ownership check - add PoC test');
        }
      }
      
      return issues;
    },
  },
  {
    id: 'SOL5706',
    name: 'semantic-inconsistency-detection',
    severity: 'high' as const,
    category: 'logic',
    description: 'Detection of semantic inconsistencies between similar functions (Stake Pool audit)',
    pattern: /update_|set_|modify_|change_/gi,
    detector: (content: string) => {
      const issues: string[] = [];
      
      // Check for inconsistent validation patterns
      const updateFuncs = content.match(/fn\s+update_\w+|fn\s+set_\w+/gi) || [];
      if (updateFuncs.length > 1) {
        // Multiple update functions should have consistent validation
        if (!/common.*validation|shared.*check|validate_authority/i.test(content)) {
          issues.push('Multiple update functions may have inconsistent validation - review for semantic consistency');
        }
      }
      
      return issues;
    },
  },

  // ===== SEC3 WORKSHOP PATTERNS =====
  {
    id: 'SOL5707',
    name: 'workshop-level0-owner-check',
    severity: 'critical' as const,
    category: 'access-control',
    description: 'Sec3/Neodyme workshop Level 0 - missing owner check pattern',
    pattern: /AccountInfo|UncheckedAccount/gi,
    detector: (content: string) => {
      const issues: string[] = [];
      
      if (/AccountInfo.*<|UncheckedAccount/i.test(content)) {
        if (!/\.owner\s*==|owner\s*=\s*constraint/i.test(content)) {
          issues.push('AccountInfo/UncheckedAccount without owner check - Workshop Level 0 vulnerability');
        }
      }
      
      return issues;
    },
  },
  {
    id: 'SOL5708',
    name: 'workshop-signer-verification',
    severity: 'critical' as const,
    category: 'access-control',
    description: 'Sec3 workshop - missing signer verification pattern',
    pattern: /is_signer|Signer<|signer\s*:/gi,
    detector: (content: string) => {
      const issues: string[] = [];
      
      // Check for operations that need signer but might be missing
      if (/transfer|withdraw|mint|burn/i.test(content)) {
        if (!/is_signer|Signer<|#\[account\(.*signer/i.test(content)) {
          issues.push('Critical operation may be missing signer requirement');
        }
      }
      
      return issues;
    },
  },

  // ===== ZELLIC ANCHOR DEEP DIVE =====
  {
    id: 'SOL5709',
    name: 'zellic-init-if-needed-race',
    severity: 'high' as const,
    category: 'initialization',
    description: 'Zellic: init_if_needed race condition vulnerability',
    pattern: /init_if_needed|init\s*=\s*true/gi,
    detector: (content: string) => {
      const issues: string[] = [];
      
      if (/init_if_needed/i.test(content)) {
        issues.push('init_if_needed can allow attacker to front-run and initialize account with malicious data');
        
        if (!/realloc|space.*check/i.test(content)) {
          issues.push('init_if_needed without realloc safety checks');
        }
      }
      
      return issues;
    },
  },
  {
    id: 'SOL5710',
    name: 'zellic-account-reloading',
    severity: 'high' as const,
    category: 'data-integrity',
    description: 'Zellic: account data reload vulnerability after CPI',
    pattern: /invoke|cpi|cross_program.*call/gi,
    detector: (content: string) => {
      const issues: string[] = [];
      
      // Check if account data is used after CPI without reload
      if (/invoke.*\(|cpi.*\(/i.test(content)) {
        if (/\.data|account.*data/i.test(content)) {
          if (!/reload|refresh|try_borrow_mut_data/i.test(content)) {
            issues.push('Account data accessed after CPI without reload - may be stale');
          }
        }
      }
      
      return issues;
    },
  },
  {
    id: 'SOL5711',
    name: 'zellic-type-cosplay-advanced',
    severity: 'critical' as const,
    category: 'type-safety',
    description: 'Zellic: advanced type cosplay where accounts masquerade as different types',
    pattern: /try_from_slice|deserialize|from_account_info/gi,
    detector: (content: string) => {
      const issues: string[] = [];
      
      if (/try_from_slice|deserialize/i.test(content)) {
        if (!/discriminator|account_type|type_check/i.test(content)) {
          issues.push('Deserialization without type discriminator check - type cosplay possible');
        }
      }
      
      // Check for Account<T> without type verification
      if (/Account<.*>/i.test(content)) {
        if (!/discriminator|DISCRIMINATOR/i.test(content)) {
          issues.push('Account type may be spoofable without discriminator verification');
        }
      }
      
      return issues;
    },
  },

  // ===== DRIFT PROTOCOL PATTERNS (Zellic Audit) =====
  {
    id: 'SOL5712',
    name: 'drift-perp-market-manipulation',
    severity: 'critical' as const,
    category: 'defi',
    description: 'Detection of perpetual market manipulation patterns (Drift audit)',
    pattern: /perp.*market|perpetual|funding|mark_price|oracle_price/gi,
    detector: (content: string) => {
      const issues: string[] = [];
      
      if (/perp.*market|perpetual/i.test(content)) {
        // Oracle guardrails
        if (!/oracle.*guardrail|price.*band|deviation.*limit/i.test(content)) {
          issues.push('Perpetual market without oracle guardrails');
        }
        // Open interest limits
        if (!/open_interest.*limit|max_position/i.test(content)) {
          issues.push('Perpetual market without open interest limits');
        }
        // Funding rate caps
        if (!/funding.*cap|max_funding/i.test(content)) {
          issues.push('Perpetual market without funding rate caps');
        }
      }
      
      return issues;
    },
  },
  {
    id: 'SOL5713',
    name: 'drift-liquidation-engine-exploit',
    severity: 'high' as const,
    category: 'defi',
    description: 'Detection of liquidation engine exploits in perp protocols',
    pattern: /liquidat|margin_call|under_collateral|bankruptcy/gi,
    detector: (content: string) => {
      const issues: string[] = [];
      
      if (/liquidat/i.test(content)) {
        if (!/partial.*liquidat|full.*liquidat/i.test(content)) {
          issues.push('Liquidation without partial liquidation option');
        }
        if (!/liquidation.*fee|penalty/i.test(content)) {
          issues.push('Liquidation without fee mechanism');
        }
        if (!/insurance.*fund|backstop/i.test(content)) {
          issues.push('Liquidation without insurance fund backstop');
        }
      }
      
      return issues;
    },
  },

  // ===== PHOENIX DEX PATTERNS (MadShield + OtterSec) =====
  {
    id: 'SOL5714',
    name: 'phoenix-orderbook-manipulation',
    severity: 'high' as const,
    category: 'defi',
    description: 'Detection of orderbook manipulation vulnerabilities (Phoenix audit)',
    pattern: /orderbook|order_book|limit_order|market_order/gi,
    detector: (content: string) => {
      const issues: string[] = [];
      
      if (/orderbook|order_book/i.test(content)) {
        if (!/self_trade.*prevent|wash.*trade/i.test(content)) {
          issues.push('Orderbook without self-trade prevention');
        }
        if (!/order.*expiry|time_in_force/i.test(content)) {
          issues.push('Orderbook without order expiry mechanism');
        }
      }
      
      return issues;
    },
  },
  {
    id: 'SOL5715',
    name: 'phoenix-matching-engine-exploit',
    severity: 'high' as const,
    category: 'defi',
    description: 'Detection of matching engine exploits in CLOB DEXes',
    pattern: /match.*order|fill.*order|execute.*trade|matching.*engine/gi,
    detector: (content: string) => {
      const issues: string[] = [];
      
      if (/match.*order|matching.*engine/i.test(content)) {
        if (!/price.*time.*priority|fifo/i.test(content)) {
          issues.push('Matching engine without price-time priority');
        }
        if (!/atomic|all_or_none|fill_or_kill/i.test(content)) {
          issues.push('Consider adding atomic order types');
        }
      }
      
      return issues;
    },
  },

  // ===== ORCA WHIRLPOOLS PATTERNS (Kudelski + Neodyme) =====
  {
    id: 'SOL5716',
    name: 'whirlpool-tick-array-exploit',
    severity: 'critical' as const,
    category: 'defi',
    description: 'Detection of Whirlpool tick array manipulation vulnerabilities',
    pattern: /tick_array|tick_sequence|tick_spacing|current_tick/gi,
    detector: (content: string) => {
      const issues: string[] = [];
      
      if (/tick_array|tick_sequence/i.test(content)) {
        if (!/tick_array.*pda|seeds.*tick/i.test(content)) {
          issues.push('Tick array without PDA derivation verification');
        }
        if (!/tick_spacing.*check|valid.*tick/i.test(content)) {
          issues.push('Tick operations without spacing validation');
        }
      }
      
      return issues;
    },
  },
  {
    id: 'SOL5717',
    name: 'whirlpool-position-exploit',
    severity: 'high' as const,
    category: 'defi',
    description: 'Detection of Whirlpool position manipulation vulnerabilities',
    pattern: /position|liquidity_position|open_position|close_position/gi,
    detector: (content: string) => {
      const issues: string[] = [];
      
      if (/open_position|create_position/i.test(content)) {
        if (!/position_mint|position_token/i.test(content)) {
          issues.push('Position without position NFT mint');
        }
      }
      
      if (/close_position/i.test(content)) {
        if (!/collect_fee.*first|withdraw_rewards/i.test(content)) {
          issues.push('Position close may leave uncollected fees');
        }
      }
      
      return issues;
    },
  },

  // ===== MARINADE FINANCE PATTERNS (Kudelski + Ackee + Neodyme) =====
  {
    id: 'SOL5718',
    name: 'liquid-staking-exploit',
    severity: 'high' as const,
    category: 'staking',
    description: 'Detection of liquid staking vulnerabilities (Marinade audits)',
    pattern: /liquid_staking|stake_pool|msol|lst|staked_sol/gi,
    detector: (content: string) => {
      const issues: string[] = [];
      
      if (/liquid_staking|stake_pool/i.test(content)) {
        if (!/exchange_rate|price_per_share/i.test(content)) {
          issues.push('Liquid staking without exchange rate tracking');
        }
        if (!/delayed_unstake|unbonding/i.test(content)) {
          issues.push('Consider delayed unstake for large amounts');
        }
        if (!/validator_list|delegation_strategy/i.test(content)) {
          issues.push('Stake pool without validator delegation strategy');
        }
      }
      
      return issues;
    },
  },
  {
    id: 'SOL5719',
    name: 'stake-delegation-manipulation',
    severity: 'high' as const,
    category: 'staking',
    description: 'Detection of stake delegation manipulation vulnerabilities',
    pattern: /delegate_stake|redelegate|merge_stake|split_stake/gi,
    detector: (content: string) => {
      const issues: string[] = [];
      
      if (/delegate_stake|redelegate/i.test(content)) {
        if (!/cooldown|epoch.*boundary/i.test(content)) {
          issues.push('Stake operations without epoch boundary checks');
        }
        if (!/validator.*score|performance.*check/i.test(content)) {
          issues.push('Delegation without validator performance verification');
        }
      }
      
      return issues;
    },
  },

  // ===== MANGO MARKETS PATTERNS (Neodyme) =====
  {
    id: 'SOL5720',
    name: 'mango-perp-insurance-fund',
    severity: 'critical' as const,
    category: 'defi',
    description: 'Detection of insurance fund depletion vulnerabilities (Mango audit)',
    pattern: /insurance_fund|socialized_loss|bankruptcy_fund/gi,
    detector: (content: string) => {
      const issues: string[] = [];
      
      if (/insurance_fund|bankruptcy_fund/i.test(content)) {
        if (!/fund_balance.*check|sufficient.*fund/i.test(content)) {
          issues.push('Insurance fund usage without balance check');
        }
        if (!/replenish|contribute|fee.*to.*fund/i.test(content)) {
          issues.push('Insurance fund without replenishment mechanism');
        }
      }
      
      return issues;
    },
  },
  {
    id: 'SOL5721',
    name: 'mango-spot-margin-exploit',
    severity: 'high' as const,
    category: 'defi',
    description: 'Detection of spot margin trading exploits',
    pattern: /spot_margin|margin_trade|leverage_spot|borrow_spot/gi,
    detector: (content: string) => {
      const issues: string[] = [];
      
      if (/spot_margin|margin_trade/i.test(content)) {
        if (!/initial_margin|maintenance_margin/i.test(content)) {
          issues.push('Spot margin without initial/maintenance margin requirements');
        }
        if (!/borrow_limit|utilization_cap/i.test(content)) {
          issues.push('Margin trading without borrow limits');
        }
      }
      
      return issues;
    },
  },

  // ===== SOLIDO PATTERNS (Bramah + Neodyme) =====
  {
    id: 'SOL5722',
    name: 'solido-validator-management',
    severity: 'medium' as const,
    category: 'staking',
    description: 'Detection of validator management vulnerabilities (Solido audits)',
    pattern: /validator_list|add_validator|remove_validator|validator_score/gi,
    detector: (content: string) => {
      const issues: string[] = [];
      
      if (/add_validator|remove_validator/i.test(content)) {
        if (!/governance|multisig|admin/i.test(content)) {
          issues.push('Validator list changes without governance');
        }
        if (!/validator.*vote|committee/i.test(content)) {
          issues.push('Validator changes without committee approval');
        }
      }
      
      return issues;
    },
  },

  // ===== PYTH ORACLE PATTERNS (Zellic) =====
  {
    id: 'SOL5723',
    name: 'pyth-price-confidence-check',
    severity: 'high' as const,
    category: 'oracle',
    description: 'Detection of Pyth oracle usage without confidence interval checks',
    pattern: /pyth|price_feed|get_price|price_account/gi,
    detector: (content: string) => {
      const issues: string[] = [];
      
      if (/pyth.*price|price_feed/i.test(content)) {
        if (!/confidence|conf\b|uncertainty/i.test(content)) {
          issues.push('Pyth price used without confidence interval check');
        }
        if (!/expo|exponent|scale/i.test(content)) {
          issues.push('Pyth price used without exponent handling');
        }
        if (!/publish_time|price_age|stale/i.test(content)) {
          issues.push('Pyth price used without staleness check');
        }
      }
      
      return issues;
    },
  },
  {
    id: 'SOL5724',
    name: 'pyth-ema-price-usage',
    severity: 'medium' as const,
    category: 'oracle',
    description: 'Detection of Pyth EMA price usage patterns',
    pattern: /ema_price|twap_price|ema_conf/gi,
    detector: (content: string) => {
      const issues: string[] = [];
      
      if (/ema_price|twap/i.test(content)) {
        if (!/ema_conf|ema_confidence/i.test(content)) {
          issues.push('Pyth EMA price without EMA confidence check');
        }
      }
      
      return issues;
    },
  },

  // ===== QUARRY MINING PATTERNS (Quantstamp) =====
  {
    id: 'SOL5725',
    name: 'quarry-reward-manipulation',
    severity: 'high' as const,
    category: 'defi',
    description: 'Detection of quarry/mining reward manipulation vulnerabilities',
    pattern: /quarry|mining|reward_rate|emission_rate|staking_reward/gi,
    detector: (content: string) => {
      const issues: string[] = [];
      
      if (/quarry|mining.*reward/i.test(content)) {
        if (!/reward_per_token|accumulated_reward/i.test(content)) {
          issues.push('Mining rewards without per-token accumulator');
        }
        if (!/update_reward.*before|accrue.*first/i.test(content)) {
          issues.push('Reward claim may not accrue pending rewards first');
        }
      }
      
      return issues;
    },
  },

  // ===== SABER STABLE SWAP PATTERNS (Bramah) =====
  {
    id: 'SOL5726',
    name: 'stableswap-imbalance-exploit',
    severity: 'high' as const,
    category: 'defi',
    description: 'Detection of stableswap imbalance exploits (Saber audit)',
    pattern: /stable_swap|curve|amplification|a_factor/gi,
    detector: (content: string) => {
      const issues: string[] = [];
      
      if (/stable_swap|amplification/i.test(content)) {
        if (!/imbalance_fee|withdraw_imbalance/i.test(content)) {
          issues.push('Stableswap without imbalance fees');
        }
        if (!/amp.*ramp|a_factor.*change/i.test(content)) {
          issues.push('Amplification factor changes should be ramped over time');
        }
      }
      
      return issues;
    },
  },

  // ===== SOLEND LENDING PATTERNS (Kudelski) =====
  {
    id: 'SOL5727',
    name: 'solend-interest-model-exploit',
    severity: 'high' as const,
    category: 'defi',
    description: 'Detection of interest rate model exploits (Solend audit)',
    pattern: /interest_rate|utilization_rate|borrow_rate|supply_rate/gi,
    detector: (content: string) => {
      const issues: string[] = [];
      
      if (/interest_rate|utilization/i.test(content)) {
        if (!/optimal_utilization|kink/i.test(content)) {
          issues.push('Interest model without optimal utilization kink');
        }
        if (!/max_rate|rate_cap/i.test(content)) {
          issues.push('Interest rate without maximum cap');
        }
      }
      
      return issues;
    },
  },
  {
    id: 'SOL5728',
    name: 'solend-obligation-exploit',
    severity: 'high' as const,
    category: 'defi',
    description: 'Detection of obligation (borrow position) exploits',
    pattern: /obligation|borrow_position|user_position|collateral_deposit/gi,
    detector: (content: string) => {
      const issues: string[] = [];
      
      if (/obligation|borrow_position/i.test(content)) {
        if (!/refresh_obligation|update_obligation/i.test(content)) {
          issues.push('Obligation accessed without refresh - may use stale data');
        }
        if (!/max_obligation|position_limit/i.test(content)) {
          issues.push('No maximum obligation limit');
        }
      }
      
      return issues;
    },
  },

  // ===== SWIM PROTOCOL PATTERNS (Kudelski) =====
  {
    id: 'SOL5729',
    name: 'swim-cross-chain-message',
    severity: 'high' as const,
    category: 'cross-chain',
    description: 'Detection of cross-chain message handling vulnerabilities',
    pattern: /cross_chain.*message|bridge.*message|relay.*message/gi,
    detector: (content: string) => {
      const issues: string[] = [];
      
      if (/cross_chain.*message|bridge.*message/i.test(content)) {
        if (!/message_hash|hash_message/i.test(content)) {
          issues.push('Cross-chain message without hash verification');
        }
        if (!/sequence|nonce|message_id/i.test(content)) {
          issues.push('Cross-chain message without sequence/nonce for replay protection');
        }
      }
      
      return issues;
    },
  },

  // ===== FRIKTION VOLT PATTERNS (Kudelski) =====
  {
    id: 'SOL5730',
    name: 'volt-epoch-transition-exploit',
    severity: 'high' as const,
    category: 'defi',
    description: 'Detection of vault epoch transition exploits (Friktion audit)',
    pattern: /epoch_transition|round_transition|vault_epoch|epoch_end/gi,
    detector: (content: string) => {
      const issues: string[] = [];
      
      if (/epoch_transition|round_transition/i.test(content)) {
        if (!/pending_deposit|pending_withdraw/i.test(content)) {
          issues.push('Epoch transition without handling pending deposits/withdrawals');
        }
        if (!/settle.*before|finalize.*epoch/i.test(content)) {
          issues.push('Epoch transition without settlement');
        }
      }
      
      return issues;
    },
  },

  // ===== HUBBLE PROTOCOL PATTERNS (Kudelski) =====
  {
    id: 'SOL5731',
    name: 'hubble-collateral-ratio-exploit',
    severity: 'high' as const,
    category: 'defi',
    description: 'Detection of collateral ratio manipulation vulnerabilities (Hubble audit)',
    pattern: /collateral_ratio|cr\b|mcr|min_collateral/gi,
    detector: (content: string) => {
      const issues: string[] = [];
      
      if (/collateral_ratio|mcr\b/i.test(content)) {
        if (!/oracle.*price|external.*price/i.test(content)) {
          issues.push('Collateral ratio calculated without oracle price');
        }
        if (!/recovery_mode|global_cr/i.test(content)) {
          issues.push('No recovery mode for systemically low collateral');
        }
      }
      
      return issues;
    },
  },

  // ===== HEDGE PROTOCOL PATTERNS (Kudelski + OtterSec + Sec3) =====
  {
    id: 'SOL5732',
    name: 'hedge-cdp-exploit',
    severity: 'high' as const,
    category: 'defi',
    description: 'Detection of CDP (Collateralized Debt Position) exploits',
    pattern: /cdp|vault_position|debt_position|mint_stable/gi,
    detector: (content: string) => {
      const issues: string[] = [];
      
      if (/cdp|debt_position/i.test(content)) {
        if (!/liquidation_threshold|health_factor/i.test(content)) {
          issues.push('CDP without health factor tracking');
        }
        if (!/stability_fee|interest_accrual/i.test(content)) {
          issues.push('CDP without stability fee accrual');
        }
      }
      
      return issues;
    },
  },

  // ===== INVARIANT PATTERNS (Sec3) =====
  {
    id: 'SOL5733',
    name: 'invariant-clmm-position',
    severity: 'high' as const,
    category: 'defi',
    description: 'Detection of Invariant CLMM position vulnerabilities',
    pattern: /invariant|position_list|fee_tier|sqrt_price/gi,
    detector: (content: string) => {
      const issues: string[] = [];
      
      if (/invariant|sqrt_price/i.test(content)) {
        if (!/price_limit|sqrt_price_limit/i.test(content)) {
          issues.push('CLMM swap without price limit');
        }
        if (!/sqrt_price_x64|q64/i.test(content)) {
          issues.push('Consider using fixed-point sqrt price for precision');
        }
      }
      
      return issues;
    },
  },

  // ===== UXD PROTOCOL PATTERNS (Sec3) =====
  {
    id: 'SOL5734',
    name: 'uxd-redeemable-parity',
    severity: 'high' as const,
    category: 'defi',
    description: 'Detection of redeemable stablecoin parity vulnerabilities',
    pattern: /redeemable|redeem_stable|parity|backing_ratio/gi,
    detector: (content: string) => {
      const issues: string[] = [];
      
      if (/redeemable|redeem_stable/i.test(content)) {
        if (!/redemption_fee|exit_fee/i.test(content)) {
          issues.push('Redeemable stablecoin without redemption fee');
        }
        if (!/cooldown|redemption_delay/i.test(content)) {
          issues.push('Consider redemption cooldown to prevent runs');
        }
      }
      
      return issues;
    },
  },

  // ===== MEAN PROTOCOL PATTERNS (Sec3) =====
  {
    id: 'SOL5735',
    name: 'mean-dca-exploit',
    severity: 'medium' as const,
    category: 'defi',
    description: 'Detection of DCA (Dollar Cost Averaging) protocol vulnerabilities',
    pattern: /dca|dollar_cost|recurring_swap|scheduled_trade/gi,
    detector: (content: string) => {
      const issues: string[] = [];
      
      if (/dca|recurring_swap/i.test(content)) {
        if (!/slippage_per_trade|max_slippage/i.test(content)) {
          issues.push('DCA trades without per-trade slippage limits');
        }
        if (!/cancel_order|stop_dca/i.test(content)) {
          issues.push('DCA without cancellation mechanism');
        }
      }
      
      return issues;
    },
  },

  // ===== DEBRIDGE PATTERNS (Neodyme) =====
  {
    id: 'SOL5736',
    name: 'debridge-claim-validation',
    severity: 'critical' as const,
    category: 'cross-chain',
    description: 'Detection of cross-chain claim validation vulnerabilities',
    pattern: /claim|redeem.*bridge|unlock_asset|release_token/gi,
    detector: (content: string) => {
      const issues: string[] = [];
      
      if (/claim.*bridge|unlock_asset/i.test(content)) {
        if (!/proof.*verify|merkle.*proof|inclusion_proof/i.test(content)) {
          issues.push('Bridge claim without proof verification');
        }
        if (!/claim_hash|unique_claim/i.test(content)) {
          issues.push('Bridge claim without unique claim hash');
        }
      }
      
      return issues;
    },
  },

  // ===== PORT FINANCE PATTERNS (Kudelski + SlowMist) =====
  {
    id: 'SOL5737',
    name: 'port-max-withdraw-bug',
    severity: 'high' as const,
    category: 'defi',
    description: 'Detection of maximum withdraw calculation bugs (Port Finance PoC)',
    pattern: /max_withdraw|available_liquidity|withdrawable/gi,
    detector: (content: string) => {
      const issues: string[] = [];
      
      if (/max_withdraw|withdrawable/i.test(content)) {
        if (!/min\(|cmp::min|smaller/i.test(content)) {
          issues.push('Max withdraw calculation may not consider all constraints');
        }
        if (!/reserve_liquidity|available_tokens/i.test(content)) {
          issues.push('Withdraw calculation should consider reserve liquidity');
        }
      }
      
      return issues;
    },
  },

  // ===== STREAMFLOW PATTERNS (Opcodes) =====
  {
    id: 'SOL5738',
    name: 'streamflow-vesting-exploit',
    severity: 'medium' as const,
    category: 'defi',
    description: 'Detection of token vesting/streaming vulnerabilities',
    pattern: /vesting|stream|linear_unlock|cliff/gi,
    detector: (content: string) => {
      const issues: string[] = [];
      
      if (/vesting|stream/i.test(content)) {
        if (!/start_time|cliff_time/i.test(content)) {
          issues.push('Vesting without start time or cliff');
        }
        if (!/cancel_stream|pause_stream/i.test(content)) {
          issues.push('Consider stream cancellation/pause mechanism');
        }
        if (!/claimed|withdrawn_amount/i.test(content)) {
          issues.push('Vesting should track claimed amount');
        }
      }
      
      return issues;
    },
  },

  // ===== LIGHT PROTOCOL PATTERNS (HashCloak) =====
  {
    id: 'SOL5739',
    name: 'light-zk-proof-verification',
    severity: 'critical' as const,
    category: 'privacy',
    description: 'Detection of ZK proof verification vulnerabilities',
    pattern: /zk_proof|zero_knowledge|groth16|plonk|verify_proof/gi,
    detector: (content: string) => {
      const issues: string[] = [];
      
      if (/zk_proof|verify_proof/i.test(content)) {
        if (!/verification_key|vk\b/i.test(content)) {
          issues.push('ZK proof verification without verification key');
        }
        if (!/public_input|public_signal/i.test(content)) {
          issues.push('ZK proof without public input binding');
        }
      }
      
      return issues;
    },
  },

  // ===== MAPLE FINANCE PATTERNS (Bramah) =====
  {
    id: 'SOL5740',
    name: 'maple-pool-delegate-exploit',
    severity: 'high' as const,
    category: 'defi',
    description: 'Detection of pool delegate vulnerabilities in lending pools',
    pattern: /pool_delegate|loan_manager|fund_loan|default/gi,
    detector: (content: string) => {
      const issues: string[] = [];
      
      if (/pool_delegate|loan_manager/i.test(content)) {
        if (!/delegate_fee|management_fee/i.test(content)) {
          issues.push('Pool delegate without fee mechanism');
        }
        if (!/delegate_stake|skin_in_game/i.test(content)) {
          issues.push('Pool delegate without stake requirement');
        }
      }
      
      return issues;
    },
  },

  // ===== CASHMERE MULTISIG PATTERNS (OtterSec) =====
  {
    id: 'SOL5741',
    name: 'cashmere-multisig-exploit',
    severity: 'high' as const,
    category: 'access-control',
    description: 'Detection of multisig implementation vulnerabilities',
    pattern: /multisig|multi_sig|threshold_sig|m_of_n/gi,
    detector: (content: string) => {
      const issues: string[] = [];
      
      if (/multisig|multi_sig/i.test(content)) {
        if (!/unique.*signature|duplicate.*check/i.test(content)) {
          issues.push('Multisig without duplicate signature check');
        }
        if (!/signer.*order|canonical.*order/i.test(content)) {
          issues.push('Consider enforcing signer order for deterministic verification');
        }
        if (!/nonce|sequence/i.test(content)) {
          issues.push('Multisig transaction without nonce/sequence');
        }
      }
      
      return issues;
    },
  },

  // ===== SQUADS PROTOCOL PATTERNS (OtterSec) =====
  {
    id: 'SOL5742',
    name: 'squads-proposal-execution',
    severity: 'high' as const,
    category: 'governance',
    description: 'Detection of Squads-style proposal execution vulnerabilities',
    pattern: /proposal_execute|execute_instruction|batch_execute/gi,
    detector: (content: string) => {
      const issues: string[] = [];
      
      if (/proposal_execute|batch_execute/i.test(content)) {
        if (!/approved_by|threshold_met/i.test(content)) {
          issues.push('Proposal execution without threshold verification');
        }
        if (!/instruction.*verify|validate_instruction/i.test(content)) {
          issues.push('Batch execution without instruction validation');
        }
      }
      
      return issues;
    },
  },

  // ===== TRIDENT FUZZING PATTERNS (Ackee) =====
  {
    id: 'SOL5743',
    name: 'trident-fuzzable-vulnerabilities',
    severity: 'medium' as const,
    category: 'testing',
    description: 'Detection of patterns that should be fuzz-tested with Trident',
    pattern: /arithmetic|overflow|underflow|division|modulo/gi,
    detector: (content: string) => {
      const issues: string[] = [];
      
      // Check for fuzz-testable arithmetic
      if (/\+|\-|\*|\/|%/i.test(content) && /u64|u128|i64|i128/i.test(content)) {
        if (!/checked_|saturating_|wrapping_/i.test(content)) {
          issues.push('Arithmetic operation should be fuzz-tested for overflow/underflow');
        }
      }
      
      // Check for input-dependent paths
      if (/if.*amount|if.*value|match.*input/i.test(content)) {
        issues.push('Input-dependent branches should be fuzz-tested');
      }
      
      return issues;
    },
  },

  // ===== BLOCKWORKS CHECKED MATH PATTERNS =====
  {
    id: 'SOL5744',
    name: 'blockworks-checked-math-macro',
    severity: 'high' as const,
    category: 'arithmetic',
    description: 'Detection of unsafe arithmetic that should use Blockworks checked_math',
    pattern: /\+\s*=|\-\s*=|\*\s*=|\/\s*=/gi,
    detector: (content: string) => {
      const issues: string[] = [];
      
      // Check for compound arithmetic assignments
      if (/\+=|\-=|\*=|\/=/i.test(content)) {
        if (!/checked!|I80F48|require!/i.test(content)) {
          issues.push('Compound arithmetic assignment without checked! macro');
        }
      }
      
      return issues;
    },
  },

  // ===== ANCHOR TEST UI PATTERNS =====
  {
    id: 'SOL5745',
    name: 'test-coverage-gaps',
    severity: 'low' as const,
    category: 'testing',
    description: 'Detection of potential test coverage gaps',
    pattern: /pub\s+fn\s+\w+|instruction|handler/gi,
    detector: (content: string) => {
      const issues: string[] = [];
      
      // Check for instruction handlers
      const handlers = content.match(/pub\s+fn\s+\w+/gi) || [];
      if (handlers.length > 0) {
        if (!/\#\[test\]|test_/i.test(content)) {
          issues.push('Instruction handlers should have corresponding tests');
        }
      }
      
      return issues;
    },
  },

  // ===== ADDITIONAL SECURITY PATTERNS =====
  {
    id: 'SOL5746',
    name: 'rent-exemption-exploitation',
    severity: 'medium' as const,
    category: 'protocol',
    description: 'Detection of rent exemption exploitation vulnerabilities',
    pattern: /rent_exempt|minimum_balance|rent.*sysvar/gi,
    detector: (content: string) => {
      const issues: string[] = [];
      
      if (/rent_exempt|minimum_balance/i.test(content)) {
        if (!/lamports\s*>=|sufficient_lamports/i.test(content)) {
          issues.push('Account creation may not ensure rent exemption');
        }
      }
      
      return issues;
    },
  },
  {
    id: 'SOL5747',
    name: 'account-close-lamport-drain',
    severity: 'high' as const,
    category: 'token',
    description: 'Detection of account closure lamport drain vulnerabilities',
    pattern: /close\s*=|close_account|lamports.*=.*0/gi,
    detector: (content: string) => {
      const issues: string[] = [];
      
      if (/close\s*=|close_account/i.test(content)) {
        if (!/destination|recipient|refund_to/i.test(content)) {
          issues.push('Account close without specifying lamport destination');
        }
      }
      
      return issues;
    },
  },
  {
    id: 'SOL5748',
    name: 'pda-authority-escalation',
    severity: 'high' as const,
    category: 'access-control',
    description: 'Detection of PDA authority escalation vulnerabilities',
    pattern: /pda.*authority|authority.*pda|signer_seeds/gi,
    detector: (content: string) => {
      const issues: string[] = [];
      
      if (/pda.*authority|signer_seeds/i.test(content)) {
        if (!/bump.*verify|canonical_bump/i.test(content)) {
          issues.push('PDA authority without bump verification');
        }
        if (!/seeds.*check|derive.*verify/i.test(content)) {
          issues.push('PDA authority without seed verification');
        }
      }
      
      return issues;
    },
  },
  {
    id: 'SOL5749',
    name: 'cross-program-reentrancy',
    severity: 'critical' as const,
    category: 'reentrancy',
    description: 'Detection of cross-program reentrancy vulnerabilities',
    pattern: /invoke.*after|cpi.*then|callback.*invoke/gi,
    detector: (content: string) => {
      const issues: string[] = [];
      
      // Check for state access after CPI
      if (/invoke|cpi/i.test(content)) {
        if (/after.*invoke|post.*cpi/i.test(content)) {
          issues.push('State access after CPI - potential reentrancy');
        }
      }
      
      // Check for callback patterns
      if (/callback|on_return/i.test(content)) {
        if (!/reentrancy.*guard|lock/i.test(content)) {
          issues.push('Callback without reentrancy guard');
        }
      }
      
      return issues;
    },
  },
  {
    id: 'SOL5750',
    name: 'token-2022-hook-exploit',
    severity: 'high' as const,
    category: 'token',
    description: 'Detection of Token-2022 transfer hook exploitation',
    pattern: /transfer_hook|execute_transfer|hook_program/gi,
    detector: (content: string) => {
      const issues: string[] = [];
      
      if (/transfer_hook|hook_program/i.test(content)) {
        if (!/hook.*validate|verify.*hook/i.test(content)) {
          issues.push('Transfer hook without validation');
        }
        if (!/compute.*limit|hook.*gas/i.test(content)) {
          issues.push('Transfer hook without compute limit consideration');
        }
      }
      
      return issues;
    },
  },
];

export function checkBatch95Patterns(parsed: ParsedRust): Array<{id: string; name: string; severity: string; message: string; line?: number}> {
  const issues: Array<{id: string; name: string; severity: string; message: string; line?: number}> = [];
  const content = parsed.content;

  for (const pattern of batch95Patterns) {
    if (pattern.pattern.test(content)) {
      const detectedIssues = pattern.detector(content);
      for (const issue of detectedIssues) {
        issues.push({
          id: pattern.id,
          name: pattern.name,
          severity: pattern.severity,
          message: `${pattern.description}: ${issue}`,
        });
      }
    }
    // Reset regex lastIndex
    pattern.pattern.lastIndex = 0;
  }

  return issues;
}

export default batch95Patterns;
