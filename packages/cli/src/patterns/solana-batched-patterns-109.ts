/**
 * Batch 109: Helius Complete Exploit Mechanics Deep Dive
 * 
 * Sources:
 * 1. Helius "Solana Hacks, Bugs, and Exploits: A Complete History" (Jun 2025)
 *    - 38 verified incidents over 5 years (2020-Q1 2025)
 *    - ~$600M gross losses, ~$469M mitigated (~$131M net)
 * 2. Detailed mechanics from major exploits: Solend, Wormhole, Cashio, Crema, Mango, Slope
 * 3. 2024-2025 latest attacks: DEXX, Pump.fun, Banana Gun, Thunder, NoOnes
 * 
 * Pattern IDs: SOL7201-SOL7275
 */

import type { PatternInput, Finding } from './index.js';

interface PatternDef {
  id: string;
  name: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  pattern: RegExp;
  description: string;
  recommendation: string;
}

const BATCH_109_PATTERNS: PatternDef[] = [
  // ============================================
  // SOLEND AUTH BYPASS MECHANICS ($2M at risk, Aug 2021)
  // SOL7201-SOL7204
  // ============================================
  {
    id: 'SOL7201',
    name: 'Solend-Style Config Update Without Market Owner Check',
    severity: 'critical',
    pattern: /(?:update.*config|set.*parameter|modify.*reserve)[\s\S]{0,200}(?!lending_market\.owner|market\.authority|has_one.*market_owner)/i,
    description: 'Configuration update function does not verify the caller owns the lending market. Attacker can create fake market, pass it as account, and update reserve parameters.',
    recommendation: 'Verify lending_market.owner == authority.key() before any config updates. Use Anchor has_one constraint.'
  },
  {
    id: 'SOL7202',
    name: 'Liquidation Threshold Without Bounds Check',
    severity: 'high',
    pattern: /liquidation_threshold|loan_to_value|ltv_ratio[\s\S]{0,100}(?!>=\s*MIN|<=\s*MAX|require!.*\d)/i,
    description: 'Liquidation threshold can be set to arbitrary values, allowing attacker to make all positions liquidatable instantly.',
    recommendation: 'Enforce MIN_LIQUIDATION_THRESHOLD and MAX_LIQUIDATION_THRESHOLD bounds. Use checked_div for calculations.'
  },
  {
    id: 'SOL7203',
    name: 'Liquidation Bonus Without Maximum Cap',
    severity: 'high',
    pattern: /liquidation_bonus|liquidation_reward|penalty[\s\S]{0,100}(?!MAX_BONUS|<=\s*\d+\s*%)/i,
    description: 'Liquidation bonus can be set extremely high, allowing attackers who control liquidator bots to extract excessive value.',
    recommendation: 'Cap liquidation_bonus at reasonable level (e.g., 10-15%). Emit events on bonus changes.'
  },
  {
    id: 'SOL7204',
    name: 'Missing Rapid Detection Circuit Breaker',
    severity: 'medium',
    pattern: /pub\s+fn\s+\w+[\s\S]{0,500}(?!pause|circuit.*breaker|emergency.*stop|halt)/i,
    description: 'Protocol lacks circuit breaker mechanism for rapid exploit detection. Solend detected attack in 41 min and mitigated in 70 min.',
    recommendation: 'Implement emergency pause with multi-sig or time-delayed unpause. Set up monitoring alerts.'
  },
  
  // ============================================
  // WORMHOLE GUARDIAN MECHANICS ($326M, Feb 2022)
  // SOL7211-SOL7213
  // ============================================
  {
    id: 'SOL7211',
    name: 'Cross-Chain Guardian Signature Count Not Verified',
    severity: 'critical',
    pattern: /(?:guardian|validator.*signature|multi.*sig.*bridge|verify.*message)[\s\S]{0,200}(?!guardian_set.*len|signature_count\s*>=|require.*quorum)/i,
    description: 'Bridge does not verify minimum guardian signatures before processing cross-chain messages. Wormhole required 2/3 quorum.',
    recommendation: 'Verify signatures.len() >= guardian_set.len() * 2 / 3 + 1. Use verified guardian set account.'
  },
  {
    id: 'SOL7212',
    name: 'Using Deprecated Signature Verification',
    severity: 'critical',
    pattern: /verify_signatures|check_signatures|validate_sig[\s\S]{0,100}(?!ed25519_program_id|secp256k1_program_id|Instructions::verify)/i,
    description: 'Using deprecated signature verification function that may have bypasses. Wormhole used verify_signatures_address incorrectly.',
    recommendation: 'Use current signature verification methods. Validate against Instructions sysvar.'
  },
  {
    id: 'SOL7213',
    name: 'Wrapped Token Minted Without Collateral Verification',
    severity: 'critical',
    pattern: /(?:mint.*wrapped|wrapped.*mint|bridge.*mint)[\s\S]{0,200}(?!verify_deposit|check_locked|collateral_proof)/i,
    description: 'Wrapped tokens minted on destination chain without verifying locked collateral on source chain.',
    recommendation: 'Require cryptographic proof of locked collateral before minting wrapped tokens.'
  },
  
  // ============================================
  // CASHIO INFINITE MINT MECHANICS ($52.8M, Mar 2022)
  // SOL7221-SOL7223
  // ============================================
  {
    id: 'SOL7221',
    name: 'LP Token Collateral Without Authenticity Check',
    severity: 'critical',
    pattern: /(?:collateral.*lp|lp.*token.*deposit|accept.*lp)[\s\S]{0,200}(?!lp_mint\s*==|verify_lp_pool|pool_state\.lp_mint)/i,
    description: 'LP tokens accepted as collateral without verifying they come from legitimate liquidity pool.',
    recommendation: 'Verify LP token mint matches expected pool. Check pool.lp_mint == collateral.mint.'
  },
  {
    id: 'SOL7222',
    name: 'Nested Account Validation Without Full Chain Verification',
    severity: 'critical',
    pattern: /(?:collateral.*bank|validate.*arrow|saber_swap)[\s\S]{0,200}(?!arrow\.mint|bank\.crate_mint|full_chain)/i,
    description: 'Collateral validation checks immediate account but not nested/referenced accounts in trust chain.',
    recommendation: 'Validate entire trust chain: collateral → bank → swap → underlying tokens.'
  },
  {
    id: 'SOL7223',
    name: 'Missing Root of Trust in Collateral Chain',
    severity: 'critical',
    pattern: /(?:crate_token|crate_collateral|collateral_accounts)[\s\S]{0,200}(?!TRUSTED_MINTS|whitelist|allowed_collateral.*const)/i,
    description: 'Collateral system has no established root of trust. Any account matching structure can be used as fake collateral.',
    recommendation: 'Hardcode or PDA-derive trusted collateral sources. Never trust user-provided account structures.'
  },
  
  // ============================================
  // CREMA CLMM ATTACK MECHANICS ($8.8M, Jul 2022)
  // SOL7231-SOL7233
  // ============================================
  {
    id: 'SOL7231',
    name: 'CLMM Tick Account Without Owner Verification',
    severity: 'critical',
    pattern: /(?:tick_array|tick_state|tick_account)[\s\S]{0,200}(?!tick\.owner\s*==|program_id|has_one.*pool)/i,
    description: 'CLMM tick account accepted without verifying it belongs to the program. Attacker can create fake tick with manipulated fee data.',
    recommendation: 'Verify tick_account.owner == program_id. Use Anchor Account<TickArray> type.'
  },
  {
    id: 'SOL7232',
    name: 'Fee Accumulator Without Authenticity Check',
    severity: 'critical',
    pattern: /(?:fee_growth|accumulated_fees|fee_owed)[\s\S]{0,200}(?!fee_state\.owner|verified_fee_account)/i,
    description: 'Fee accumulator data read without verifying it was written by legitimate protocol operations.',
    recommendation: 'Store fees in program-owned PDAs. Verify fee account derivation.'
  },
  {
    id: 'SOL7233',
    name: 'Flash Loan Enables Fee Claim Amplification',
    severity: 'high',
    pattern: /(?:claim_fee|collect_fees|withdraw_fee)[\s\S]{0,200}(?!flash_loan_guard|single_claim_per_epoch)/i,
    description: 'Flash loans from external protocols can be used to amplify attack within single transaction.',
    recommendation: 'Implement per-epoch claim limits. Track cumulative claims per position.'
  },
  
  // ============================================
  // MANGO MARKETS ORACLE MANIPULATION ($116M, Oct 2022)
  // SOL7241-SOL7243
  // ============================================
  {
    id: 'SOL7241',
    name: 'Price Oracle Vulnerable to Self-Trading',
    severity: 'critical',
    pattern: /(?:perp.*price|oracle_price|mark_price)[\s\S]{0,200}(?!twap|time_weighted|min_liquidity_check)/i,
    description: 'Oracle price can be manipulated through self-trading in low-liquidity markets.',
    recommendation: 'Use TWAP oracles. Require minimum liquidity for price validity. Implement position limits.'
  },
  {
    id: 'SOL7242',
    name: 'Unrealized PnL Counted as Withdrawable Collateral',
    severity: 'critical',
    pattern: /(?:unrealized_pnl|paper_profit|equity.*unrealized)[\s\S]{0,200}(?!realized_only|settled_pnl|require_settlement)/i,
    description: 'Unrealized profits from manipulated positions counted as collateral for new borrows.',
    recommendation: 'Only count realized, settled PnL as collateral. Require position settlement before borrowing.'
  },
  {
    id: 'SOL7243',
    name: 'No Maximum Position Size Relative to Pool',
    severity: 'high',
    pattern: /(?:position_size|open_interest|position_notional)[\s\S]{0,200}(?!max_position|position_limit|<=.*MAX_SIZE)/i,
    description: 'Single user can accumulate position larger than protocol can safely liquidate.',
    recommendation: 'Limit max position to percentage of pool liquidity. Implement open interest caps.'
  },
  
  // ============================================
  // SLOPE WALLET KEY EXPOSURE ($8M, Aug 2022)
  // SOL7251-SOL7252
  // ============================================
  {
    id: 'SOL7251',
    name: 'Seed Phrase Sent to External Logging Service',
    severity: 'critical',
    pattern: /(?:telemetry|analytics|log.*seed|send.*mnemonic)[\s\S]{0,200}(?!redact.*seed|mask.*key|never_log_sensitive)/i,
    description: 'Wallet sends seed phrase or private key to external analytics or logging service.',
    recommendation: 'Never transmit seed phrases. Implement strict redaction for all sensitive data.'
  },
  {
    id: 'SOL7252',
    name: 'Private Keys Stored Without Encryption',
    severity: 'critical',
    pattern: /(?:store.*key|save.*seed|persist.*private)[\s\S]{0,200}(?!encrypt.*store|keychain|secure.*enclave)/i,
    description: 'Private keys or seed phrases stored in plaintext, accessible to anyone with storage access.',
    recommendation: 'Encrypt keys at rest using hardware security module or secure enclave.'
  },
  
  // ============================================
  // 2024-2025 LATEST ATTACK PATTERNS
  // SOL7261-SOL7275
  // ============================================
  {
    id: 'SOL7261',
    name: 'Trading Platform Hot Wallet Key Centralization',
    severity: 'critical',
    pattern: /(?:hot_wallet|custodial.*key|central.*key_store)[\s\S]{0,200}(?!user_controlled_key|non_custodial|mpc_wallet)/i,
    description: 'Trading platform stores user keys in centralized hot wallet, single point of failure.',
    recommendation: 'Use non-custodial architecture. Implement MPC wallets for institutional keys.'
  },
  {
    id: 'SOL7262',
    name: 'Privileged Employee Access Without Monitoring',
    severity: 'high',
    pattern: /(?:admin_key|operator_access|privileged_function)[\s\S]{0,200}(?!multi_sig|audit_log|access_monitoring)/i,
    description: 'Employees with system access can exploit privileged position without detection.',
    recommendation: 'Implement multi-sig for admin actions. Log all privileged operations. Background checks.'
  },
  {
    id: 'SOL7263',
    name: 'Trading Bot Stores Private Keys Insecurely',
    severity: 'critical',
    pattern: /(?:bot.*private_key|trading.*key|auto.*trader.*key)[\s\S]{0,200}(?!hardware_wallet|hsm|session_key.*limited)/i,
    description: 'Automated trading bot stores private keys in memory or config without proper isolation.',
    recommendation: 'Use session keys with limited permissions. Hardware wallet signing for large amounts.'
  },
  {
    id: 'SOL7264',
    name: 'NoSQL Injection in Session Management',
    severity: 'high',
    pattern: /(?:mongodb|nosql|session.*db)[\s\S]{0,200}(?!parameterized|sanitize.*input|prepared_statement)/i,
    description: 'MongoDB or other NoSQL database vulnerable to injection attacks on session data.',
    recommendation: 'Use parameterized queries. Sanitize all user input. Implement query validation.'
  },
  {
    id: 'SOL7265',
    name: 'NPM Package Without Integrity Verification',
    severity: 'high',
    pattern: /(?:npm\s+install|yarn\s+add|package\.json)[\s\S]{0,200}(?!integrity.*sha512|package-lock|npm\s+audit)/i,
    description: 'Dependencies installed without verifying package integrity or source.',
    recommendation: 'Lock dependencies with package-lock.json. Run npm audit. Use Subresource Integrity.'
  },
  {
    id: 'SOL7266',
    name: 'Governance Vote Without Token Lock Period',
    severity: 'high',
    pattern: /(?:vote.*governance|governance.*vote|dao.*proposal)[\s\S]{0,200}(?!vote_escrow|lock_period|snapshot_voting)/i,
    description: 'Governance tokens can be flash-borrowed to pass proposals in single block.',
    recommendation: 'Require vote escrow with lock period. Use snapshot-based voting power.'
  },
  {
    id: 'SOL7267',
    name: 'Bonding Curve Vulnerable to Flash Loan',
    severity: 'critical',
    pattern: /(?:bonding_curve|amm_price|curve_price)[\s\S]{0,200}(?!flash_guard|price_oracle|external_price)/i,
    description: 'Algorithmic bonding curve price can be manipulated with flash loan within single tx.',
    recommendation: 'Use external oracle for base price. Implement flash loan cooldown.'
  },
  {
    id: 'SOL7268',
    name: 'Bridge Message Replayable Across Chains',
    severity: 'critical',
    pattern: /(?:bridge.*message|cross_chain.*msg|relay.*message)[\s\S]{0,200}(?!nonce|sequence_number|chain_id.*check)/i,
    description: 'Cross-chain message can be replayed on different chain or replayed multiple times.',
    recommendation: 'Include chain_id and nonce in message hash. Track processed messages.'
  },
  {
    id: 'SOL7269',
    name: 'Program Closure Possible With Funds Still Locked',
    severity: 'critical',
    pattern: /(?:close_program|upgrade.*program|shutdown)[\s\S]{0,200}(?!require.*empty|all_funds_withdrawn|migration_complete)/i,
    description: 'Program can be closed or upgraded in way that permanently locks user funds.',
    recommendation: 'Prevent program closure if funds remain. Implement recoverable shutdown sequence.'
  },
  {
    id: 'SOL7270',
    name: 'Token With Asymmetric Transfer Restrictions',
    severity: 'high',
    pattern: /(?:transfer.*restrict|sell.*block|honeypot)[\s\S]{0,200}(?!symmetric_transfer|equal_restrictions)/i,
    description: 'Token allows buys but restricts sells, trapping user funds.',
    recommendation: 'Verify transfer function treats buy and sell symmetrically. Audit token contract.'
  },
  {
    id: 'SOL7271',
    name: 'DePIN Network Without Sybil Resistance',
    severity: 'high',
    pattern: /(?:node_register|provider_join|device_onboard)[\s\S]{0,200}(?!proof_of_device|hardware_attestation|stake_requirement)/i,
    description: 'Decentralized physical infrastructure network vulnerable to fake node registration.',
    recommendation: 'Require hardware attestation or significant stake for node registration.'
  },
  {
    id: 'SOL7272',
    name: 'DAO Proposal Without Visibility Period',
    severity: 'high',
    pattern: /(?:create.*proposal|submit.*proposal)[\s\S]{0,200}(?!min_delay|notice_period|announce.*proposal)/i,
    description: 'Governance proposal can be created and executed without community visibility.',
    recommendation: 'Require minimum visibility period before voting. Emit events on proposal creation.'
  },
  {
    id: 'SOL7273',
    name: 'Vault Share Calculation Exploitable by First Depositor',
    severity: 'high',
    pattern: /(?:shares\s*=.*deposit.*total_supply|calculate_shares)[\s\S]{0,200}(?!min_deposit|virtual_shares|initial_mint)/i,
    description: 'First depositor can donate to inflate share price and steal from subsequent depositors.',
    recommendation: 'Mint minimum initial shares to dead address. Implement virtual share offset.'
  },
  {
    id: 'SOL7274',
    name: 'PT Token Pricing Without Proper Oracle',
    severity: 'critical',
    pattern: /(?:pt_token|principal_token|fixed_yield)[\s\S]{0,200}(?!pt_oracle|yield_oracle|market_price_pt)/i,
    description: 'Principal token (PT) priced incorrectly, allowing arbitrage or under-collateralization.',
    recommendation: 'Use specialized oracle for PT tokens that accounts for yield and maturity.'
  },
  {
    id: 'SOL7275',
    name: 'No White Hat Recovery Mechanism',
    severity: 'medium',
    pattern: /(?:emergency|recovery|incident)[\s\S]{0,200}(?!bug_bounty|white_hat|recovery_address)/i,
    description: 'Protocol lacks mechanism to coordinate with white hat hackers for fund recovery.',
    recommendation: 'Establish bug bounty program. Publish recovery contacts. Prepare negotiation playbook.'
  },
];

export function checkBatch109Patterns(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';
  
  for (const pattern of BATCH_109_PATTERNS) {
    if (pattern.pattern.test(content)) {
      findings.push({
        id: pattern.id,
        title: pattern.name,
        severity: pattern.severity,
        description: pattern.description,
        location: { file: input.path },
        recommendation: pattern.recommendation,
      });
    }
  }
  
  return findings;
}

export { BATCH_109_PATTERNS };
