/**
 * SolGuard Batch 80 Security Patterns
 * Based on: arXiv Academic Research, Zellic Anchor Vulnerabilities, Protocol-Specific Deep Dive
 * 
 * Pattern IDs: SOL4076 - SOL4175 (100 patterns)
 * Created: Feb 6, 2026 1:30 AM CST
 * 
 * Sources:
 * - arXiv "Exploring Vulnerabilities in Solana Smart Contracts" (Apr 2025)
 * - Zellic "The Vulnerabilities You'll Write With Anchor"
 * - Neodyme "Common Pitfalls" and Security Workshop
 * - Kudelski Security Research on Solana
 * - Trail of Bits DeFi Security Best Practices
 */

import type { Finding, PatternInput } from './index.js';

// ============================================================================
// ZELLIC ANCHOR-SPECIFIC VULNERABILITIES
// ============================================================================

const ZELLIC_ANCHOR_PATTERNS: {
  id: string;
  name: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  pattern: RegExp;
  description: string;
  recommendation: string;
}[] = [
  {
    id: 'SOL4076',
    name: 'Zellic - Discriminator Collision Risk',
    severity: 'high',
    pattern: /(?:#\[account\])[\s\S]{0,200}(?:struct\s+\w+)[\s\S]{0,100}(?:struct\s+\w+)/i,
    description: 'Multiple account types may have colliding 8-byte discriminators. Anchor uses first 8 bytes of SHA256(namespace:name).',
    recommendation: 'Audit discriminator uniqueness across all account types. Consider using explicit discriminator values.'
  },
  {
    id: 'SOL4077',
    name: 'Zellic - init_if_needed Race Condition',
    severity: 'critical',
    pattern: /init_if_needed[\s\S]{0,100}(?!realloc|seeds_constraint)/i,
    description: 'init_if_needed can be exploited if attacker initializes account first. Race condition vulnerability.',
    recommendation: 'Avoid init_if_needed. Use separate init instruction with proper access control.'
  },
  {
    id: 'SOL4078',
    name: 'Zellic - UncheckedAccount Without Validation',
    severity: 'critical',
    pattern: /UncheckedAccount[\s\S]{0,50}(?!\/\/\/\s*CHECK|#\[doc)/i,
    description: 'UncheckedAccount used without documenting safety checks. Anchor requires CHECK comment.',
    recommendation: 'Add /// CHECK: comment explaining why account is safe, or use proper account types.'
  },
  {
    id: 'SOL4079',
    name: 'Zellic - Seeds Constraint Without Bump',
    severity: 'high',
    pattern: /seeds\s*=[\s\S]{0,50}(?!bump)/i,
    description: 'PDA seeds specified without bump constraint. May accept non-canonical PDA addresses.',
    recommendation: 'Always include bump constraint with seeds. Use canonical bump only.'
  },
  {
    id: 'SOL4080',
    name: 'Zellic - has_one Without Owner Check',
    severity: 'high',
    pattern: /has_one[\s\S]{0,50}(?!@.*owner|@.*program)/i,
    description: 'has_one constraint without additional owner verification. May trust attacker-controlled accounts.',
    recommendation: 'Combine has_one with owner constraint or explicit program ID check.'
  },
  {
    id: 'SOL4081',
    name: 'Zellic - Constraint Order Vulnerability',
    severity: 'medium',
    pattern: /(?:#\[account\([\s\S]*has_one[\s\S]*constraint)/i,
    description: 'Constraint ordering may affect validation. has_one should come before constraint.',
    recommendation: 'Order constraints: mut, init/seeds first, then has_one, then custom constraint.'
  },
  {
    id: 'SOL4082',
    name: 'Zellic - Missing close Constraint',
    severity: 'medium',
    pattern: /(?:close|zero)[\s\S]{0,80}(?:account)[\s\S]{0,50}(?!close\s*=)/i,
    description: 'Account closed without close constraint. May not properly transfer lamports.',
    recommendation: 'Use close = target_account constraint for proper account closure.'
  },
  {
    id: 'SOL4083',
    name: 'Zellic - realloc Without zero_init',
    severity: 'medium',
    pattern: /realloc[\s\S]{0,50}(?!realloc::zero\s*=\s*true)/i,
    description: 'Account reallocation without zeroing new space. May leak previous data.',
    recommendation: 'Use realloc::zero = true when expanding account size.'
  },
  {
    id: 'SOL4084',
    name: 'Zellic - Account Not mut When Modified',
    severity: 'high',
    pattern: /(?:\.key|\.to_account_info)[\s\S]{0,200}(?:serialize|borrow_mut)[\s\S]{0,50}(?!#\[account\(mut)/i,
    description: 'Account data modified but not marked mutable. Transaction will fail or behave unexpectedly.',
    recommendation: 'Mark all accounts that are modified with mut constraint.'
  },
  {
    id: 'SOL4085',
    name: 'Zellic - Signer Not Verified',
    severity: 'critical',
    pattern: /(?:authority|payer|user)[\s\S]{0,50}(?:AccountInfo|Account)[\s\S]{0,30}(?!Signer)/i,
    description: 'Authority account not verified as signer. Attacker can pass any account.',
    recommendation: 'Use Signer<\'info> type or add signer constraint for authority accounts.'
  },

  // ============================================================================
  // NEODYME COMMON PITFALLS
  // ============================================================================

  {
    id: 'SOL4086',
    name: 'Neodyme - Account Info Owner Not Checked',
    severity: 'critical',
    pattern: /AccountInfo[\s\S]{0,100}(?:data|lamports)[\s\S]{0,50}(?!owner.*==|\.owner)/i,
    description: 'AccountInfo used without owner verification. May accept accounts from wrong program.',
    recommendation: 'Verify account.owner == expected_program_id for all AccountInfo usage.'
  },
  {
    id: 'SOL4087',
    name: 'Neodyme - Data Not Validated Before Use',
    severity: 'high',
    pattern: /(?:borrow|data)[\s\S]{0,50}(?:deserialize|try_from)[\s\S]{0,50}(?!len.*check|size.*verify)/i,
    description: 'Account data deserialized without size validation. May panic or read garbage.',
    recommendation: 'Verify account data length before deserialization.'
  },
  {
    id: 'SOL4088',
    name: 'Neodyme - invoke_signed Without PDA Verification',
    severity: 'critical',
    pattern: /invoke_signed[\s\S]{0,100}(?:seeds)[\s\S]{0,50}(?!find_program_address|verify_pda)/i,
    description: 'invoke_signed used without verifying PDA matches expected. May sign for wrong account.',
    recommendation: 'Verify PDA address matches expected before invoke_signed.'
  },
  {
    id: 'SOL4089',
    name: 'Neodyme - Integer Overflow in Loop',
    severity: 'high',
    pattern: /(?:for|while)[\s\S]{0,80}(?:\+=|-=|\+\+|--|\*=)[\s\S]{0,30}(?!checked_|saturating_)/i,
    description: 'Loop counter arithmetic without overflow protection. May cause infinite loop.',
    recommendation: 'Use checked arithmetic in all loop operations.'
  },
  {
    id: 'SOL4090',
    name: 'Neodyme - Unvalidated Account Type',
    severity: 'high',
    pattern: /(?:Account|AccountInfo)[\s\S]{0,80}(?:key|address)[\s\S]{0,50}(?!discriminator|type_check)/i,
    description: 'Account type not validated. May accept different account type with matching fields.',
    recommendation: 'Always verify account discriminator or use Anchor typed accounts.'
  },

  // ============================================================================
  // KUDELSKI SECURITY PATTERNS
  // ============================================================================

  {
    id: 'SOL4091',
    name: 'Kudelski - Authority Key Without Scope Limit',
    severity: 'high',
    pattern: /(?:authority|admin)[\s\S]{0,100}(?:key|pubkey)[\s\S]{0,50}(?!scope|limited|specific)/i,
    description: 'Authority key can perform any operation. No scope limitations.',
    recommendation: 'Implement role-based access control. Limit authority actions by type.'
  },
  {
    id: 'SOL4092',
    name: 'Kudelski - State Update Without Invariant Check',
    severity: 'high',
    pattern: /(?:state|data)[\s\S]{0,80}(?:update|modify|set)[\s\S]{0,50}(?!invariant|verify|assert)/i,
    description: 'State updated without checking invariants. May violate protocol assumptions.',
    recommendation: 'Add invariant checks before and after state updates.'
  },
  {
    id: 'SOL4093',
    name: 'Kudelski - Token Transfer Without Balance Verification',
    severity: 'high',
    pattern: /(?:transfer|spl_token)[\s\S]{0,100}(?:invoke)[\s\S]{0,50}(?!balance.*check|sufficient)/i,
    description: 'Token transfer without pre-checking balance. May fail unexpectedly.',
    recommendation: 'Verify source has sufficient balance before transfer.'
  },
  {
    id: 'SOL4094',
    name: 'Kudelski - PDA Authority Without Program Check',
    severity: 'critical',
    pattern: /(?:pda|program_derived)[\s\S]{0,100}(?:authority|signer)[\s\S]{0,50}(?!program_id.*verify)/i,
    description: 'PDA used as authority without verifying derived from correct program.',
    recommendation: 'Verify PDA derivation uses expected program ID.'
  },
  {
    id: 'SOL4095',
    name: 'Kudelski - Cross-Reference Account Mismatch',
    severity: 'high',
    pattern: /(?:account_a|account_b)[\s\S]{0,100}(?:reference|points_to)[\s\S]{0,50}(?!verify_match|check_ref)/i,
    description: 'Account cross-references not validated. May link to wrong accounts.',
    recommendation: 'Verify all account cross-references match expected values.'
  },

  // ============================================================================
  // arXiv ACADEMIC RESEARCH PATTERNS
  // ============================================================================

  {
    id: 'SOL4096',
    name: 'arXiv - BPF Verifier Bypass Risk',
    severity: 'critical',
    pattern: /(?:unsafe|raw_pointer|transmute)[\s\S]{0,100}(?!justified|documented)/i,
    description: 'Unsafe Rust may bypass BPF verifier protections. Academic research identifies this as attack vector.',
    recommendation: 'Avoid unsafe code. If required, thoroughly document and audit justification.'
  },
  {
    id: 'SOL4097',
    name: 'arXiv - Stack Overflow in Recursive Call',
    severity: 'high',
    pattern: /(?:fn\s+\w+)[\s\S]{0,200}(?:self\.\w+\(|recursion|recursive)/i,
    description: 'Recursive function without depth limit. BPF has limited stack space.',
    recommendation: 'Convert recursion to iteration. If recursion needed, add depth limit.'
  },
  {
    id: 'SOL4098',
    name: 'arXiv - Compute Budget Exhaustion Attack',
    severity: 'medium',
    pattern: /(?:compute|cu)[\s\S]{0,80}(?:intensive|expensive)[\s\S]{0,50}(?!limit|check|budget)/i,
    description: 'Compute-intensive operation without budget management. May be used for DoS.',
    recommendation: 'Check remaining compute budget before expensive operations.'
  },
  {
    id: 'SOL4099',
    name: 'arXiv - Sysvar Account Spoofing',
    severity: 'critical',
    pattern: /(?:sysvar|clock|rent|epoch)[\s\S]{0,80}(?:account)[\s\S]{0,50}(?!sysvar::.*ID|verify_sysvar)/i,
    description: 'Sysvar account not verified against known sysvar addresses. May accept fake sysvar.',
    recommendation: 'Verify sysvar account keys match sysvar::*::ID constants.'
  },
  {
    id: 'SOL4100',
    name: 'arXiv - Parallel Execution Race Condition',
    severity: 'high',
    pattern: /(?:parallel|concurrent)[\s\S]{0,100}(?:access|modify)[\s\S]{0,50}(?!lock|mutex|atomic)/i,
    description: 'Parallel transaction execution may cause race conditions. Account locking needed.',
    recommendation: 'Ensure account write locks are properly acquired. Use atomic operations.'
  },

  // ============================================================================
  // LENDING PROTOCOL DEEP PATTERNS
  // ============================================================================

  {
    id: 'SOL4101',
    name: 'Lending - Interest Rate Model Kink Validation',
    severity: 'medium',
    pattern: /(?:interest_rate|utilization)[\s\S]{0,100}(?:kink|threshold)[\s\S]{0,50}(?!bounds|0\.\d|validate)/i,
    description: 'Interest rate kink points not validated. May cause rate discontinuities.',
    recommendation: 'Validate kink points are within [0, 1] and properly ordered.'
  },
  {
    id: 'SOL4102',
    name: 'Lending - Liquidation Bonus Bounds Missing',
    severity: 'high',
    pattern: /(?:liquidation_bonus|incentive)[\s\S]{0,80}(?:set|update)[\s\S]{0,50}(?!max_bonus|bounded)/i,
    description: 'Liquidation bonus unbounded. Excessive bonus drains protocol reserves.',
    recommendation: 'Cap liquidation bonus (typically 5-15%). Validate on configuration.'
  },
  {
    id: 'SOL4103',
    name: 'Lending - Close Factor Without Limit',
    severity: 'high',
    pattern: /(?:close_factor|liquidation_close)[\s\S]{0,80}(?!max|bounded|<\s*1|<=\s*100)/i,
    description: 'Close factor unbounded. May allow 100% liquidation in single transaction.',
    recommendation: 'Limit close factor (typically 50%). Implement gradual liquidation.'
  },
  {
    id: 'SOL4104',
    name: 'Lending - Borrow Cap Not Enforced',
    severity: 'high',
    pattern: /(?:borrow|loan)[\s\S]{0,100}(?:amount)[\s\S]{0,50}(?!cap|limit|max_borrow)/i,
    description: 'No borrow cap per asset. Single asset can dominate protocol risk.',
    recommendation: 'Implement per-asset borrow caps based on liquidity and risk profile.'
  },
  {
    id: 'SOL4105',
    name: 'Lending - Reserve Factor Drain',
    severity: 'high',
    pattern: /(?:reserve_factor|protocol_fee)[\s\S]{0,80}(?:withdraw|drain)[\s\S]{0,50}(?!timelock|governance)/i,
    description: 'Reserve funds withdrawable without governance. Protocol safety net at risk.',
    recommendation: 'Require governance approval for reserve withdrawals. Add timelock.'
  },

  // ============================================================================
  // AMM/DEX DEEP PATTERNS
  // ============================================================================

  {
    id: 'SOL4106',
    name: 'AMM - Invariant Violation in Swap',
    severity: 'critical',
    pattern: /(?:swap|exchange)[\s\S]{0,100}(?:k_value|constant_product)[\s\S]{0,50}(?!verify|assert|check)/i,
    description: 'AMM invariant (k = x * y) not verified after swap. May drain liquidity.',
    recommendation: 'Assert invariant maintained or improved after every swap operation.'
  },
  {
    id: 'SOL4107',
    name: 'AMM - LP Share Inflation Attack',
    severity: 'critical',
    pattern: /(?:lp_token|share)[\s\S]{0,100}(?:mint|issue)[\s\S]{0,50}(?:first|initial)[\s\S]{0,30}(?!minimum|dead_shares)/i,
    description: 'LP share minting vulnerable to inflation attack. First depositor can manipulate.',
    recommendation: 'Mint minimum LP shares to dead address on pool creation.'
  },
  {
    id: 'SOL4108',
    name: 'AMM - Virtual Reserve Manipulation',
    severity: 'high',
    pattern: /(?:virtual_reserve|amplification)[\s\S]{0,100}(?:set|change)[\s\S]{0,50}(?!gradual|timelock)/i,
    description: 'Virtual reserve changes immediate. Enables price manipulation.',
    recommendation: 'Implement gradual amplification changes over multiple blocks.'
  },
  {
    id: 'SOL4109',
    name: 'AMM - Concentrated Liquidity Range Validation',
    severity: 'high',
    pattern: /(?:tick|range|position)[\s\S]{0,100}(?:lower|upper)[\s\S]{0,50}(?!validate|lower\s*<\s*upper)/i,
    description: 'CLMM position range not validated. Invalid ranges may cause unexpected behavior.',
    recommendation: 'Validate tickLower < tickUpper and both within valid tick range.'
  },
  {
    id: 'SOL4110',
    name: 'AMM - Fee Tier Bypass in Routing',
    severity: 'medium',
    pattern: /(?:route|path)[\s\S]{0,100}(?:fee|tier)[\s\S]{0,50}(?!verify|match|expected)/i,
    description: 'Swap routing may bypass intended fee tier. Lower fee pools drain liquidity.',
    recommendation: 'Verify routed pools match expected fee tiers.'
  },

  // ============================================================================
  // STAKING PROTOCOL PATTERNS
  // ============================================================================

  {
    id: 'SOL4111',
    name: 'Staking - Validator Commission Manipulation',
    severity: 'high',
    pattern: /(?:commission|fee)[\s\S]{0,80}(?:rate|percent)[\s\S]{0,50}(?:change|update)[\s\S]{0,30}(?!bounded|max)/i,
    description: 'Validator commission changeable without bounds. May suddenly increase to 100%.',
    recommendation: 'Cap commission rate changes per epoch. Announce changes in advance.'
  },
  {
    id: 'SOL4112',
    name: 'Staking - Instant Unstake Without Cooldown',
    severity: 'high',
    pattern: /(?:unstake|withdraw)[\s\S]{0,100}(?:immediate|instant)[\s\S]{0,50}(?!cooldown|delay|epoch)/i,
    description: 'Instant unstaking without cooldown period. Enables rapid stake movement attacks.',
    recommendation: 'Implement minimum cooldown period (typically 1 epoch).'
  },
  {
    id: 'SOL4113',
    name: 'Staking - Reward Rate Manipulation',
    severity: 'high',
    pattern: /(?:reward_rate|apy|apr)[\s\S]{0,80}(?:set|update)[\s\S]{0,50}(?!governance|timelock|bounded)/i,
    description: 'Reward rate immediately changeable. Flash stake attacks possible.',
    recommendation: 'Apply reward rate changes gradually. Use time-weighted calculations.'
  },
  {
    id: 'SOL4114',
    name: 'Staking - Slashing Without Appeal',
    severity: 'medium',
    pattern: /(?:slash|penalty)[\s\S]{0,100}(?:apply|execute)[\s\S]{0,50}(?!appeal|dispute|timelock)/i,
    description: 'Slashing applied without appeal mechanism. May slash unfairly.',
    recommendation: 'Implement slashing appeal period before finalization.'
  },
  {
    id: 'SOL4115',
    name: 'Staking - Delegation Overflow',
    severity: 'high',
    pattern: /(?:delegate|stake)[\s\S]{0,80}(?:amount|lamports)[\s\S]{0,50}(?:add|\+=)[\s\S]{0,30}(?!checked_)/i,
    description: 'Delegation amount addition without overflow check. May wrap around.',
    recommendation: 'Use checked arithmetic for all stake calculations.'
  },

  // ============================================================================
  // GOVERNANCE PROTOCOL PATTERNS
  // ============================================================================

  {
    id: 'SOL4116',
    name: 'Governance - Proposal Without Minimum Threshold',
    severity: 'high',
    pattern: /(?:proposal|create_proposal)[\s\S]{0,100}(?!threshold|minimum_stake|required_tokens)/i,
    description: 'Anyone can create proposals. Spam and griefing risk.',
    recommendation: 'Require minimum token stake to create proposals.'
  },
  {
    id: 'SOL4117',
    name: 'Governance - Vote Without Snapshot',
    severity: 'critical',
    pattern: /(?:vote|voting_power)[\s\S]{0,100}(?:current_balance|live_balance)[\s\S]{0,50}(?!snapshot|checkpoint)/i,
    description: 'Voting power calculated from live balance. Flash loan vote attacks possible.',
    recommendation: 'Use snapshot-based voting power from before proposal creation.'
  },
  {
    id: 'SOL4118',
    name: 'Governance - Quorum Not Enforced',
    severity: 'high',
    pattern: /(?:proposal|execute)[\s\S]{0,100}(?:pass|approve)[\s\S]{0,50}(?!quorum|minimum_votes)/i,
    description: 'Proposals can pass without quorum. Low participation attacks.',
    recommendation: 'Enforce minimum participation quorum for proposal execution.'
  },
  {
    id: 'SOL4119',
    name: 'Governance - Execution Without Delay',
    severity: 'critical',
    pattern: /(?:proposal|execute)[\s\S]{0,100}(?:approved|passed)[\s\S]{0,50}(?!delay|timelock|queue)/i,
    description: 'Approved proposals execute immediately. No time for emergency response.',
    recommendation: 'Queue approved proposals with minimum execution delay (24-48h).'
  },
  {
    id: 'SOL4120',
    name: 'Governance - Delegate Vote Without Revocation',
    severity: 'medium',
    pattern: /(?:delegate|delegation)[\s\S]{0,100}(?:vote|power)[\s\S]{0,50}(?!revoke|undelegate|expires)/i,
    description: 'Vote delegation permanent without revocation mechanism.',
    recommendation: 'Implement vote delegation revocation. Consider auto-expiry.'
  },

  // ============================================================================
  // NFT/GAMING PROTOCOL PATTERNS
  // ============================================================================

  {
    id: 'SOL4121',
    name: 'NFT - Metadata URI Injection',
    severity: 'high',
    pattern: /(?:metadata|uri|json)[\s\S]{0,80}(?:update|set)[\s\S]{0,50}(?!sanitize|validate|whitelist)/i,
    description: 'Metadata URI can be set to malicious content. Phishing risk.',
    recommendation: 'Validate metadata URIs against whitelist. Sanitize content.'
  },
  {
    id: 'SOL4122',
    name: 'NFT - Royalty Enforcement Bypass',
    severity: 'medium',
    pattern: /(?:royalty|creator_fee)[\s\S]{0,100}(?:transfer|sale)[\s\S]{0,50}(?!enforce|check|required)/i,
    description: 'NFT transfers may bypass royalty payments. Creator revenue loss.',
    recommendation: 'Use Metaplex pNFT or similar enforced royalty standard.'
  },
  {
    id: 'SOL4123',
    name: 'NFT - Collection Verification Bypass',
    severity: 'high',
    pattern: /(?:collection|verified)[\s\S]{0,80}(?:check|assert)[\s\S]{0,50}(?!collection_key|verified.*true)/i,
    description: 'NFT collection membership not verified. Fake NFTs may pass.',
    recommendation: 'Verify collection key and verified flag for all collection NFTs.'
  },
  {
    id: 'SOL4124',
    name: 'Gaming - Randomness Predictable',
    severity: 'critical',
    pattern: /(?:random|rng|seed)[\s\S]{0,100}(?:blockhash|slot|timestamp)[\s\S]{0,50}(?!vrf|commit_reveal)/i,
    description: 'Game randomness derived from predictable on-chain values. Validators can manipulate.',
    recommendation: 'Use VRF (Switchboard/Chainlink) or commit-reveal for randomness.'
  },
  {
    id: 'SOL4125',
    name: 'Gaming - Item Duplication Risk',
    severity: 'critical',
    pattern: /(?:item|asset|inventory)[\s\S]{0,100}(?:transfer|move)[\s\S]{0,50}(?!atomic|lock|mutex)/i,
    description: 'Item transfers not atomic. Race conditions enable duplication.',
    recommendation: 'Implement atomic item transfers. Lock source before modification.'
  },

  // ============================================================================
  // TOKEN SECURITY PATTERNS
  // ============================================================================

  {
    id: 'SOL4126',
    name: 'Token - Mint Authority Not Revoked',
    severity: 'high',
    pattern: /(?:mint_authority|mint_to)[\s\S]{0,100}(?!revoke|set_authority.*None|immutable)/i,
    description: 'Mint authority retained post-launch. Infinite supply risk.',
    recommendation: 'Revoke mint authority after initial distribution for fixed-supply tokens.'
  },
  {
    id: 'SOL4127',
    name: 'Token - Freeze Authority Abuse Risk',
    severity: 'medium',
    pattern: /(?:freeze_authority|freeze_account)[\s\S]{0,80}(?!governance|multisig|revoked)/i,
    description: 'Freeze authority can lock user funds arbitrarily.',
    recommendation: 'Revoke freeze authority or place under governance control.'
  },
  {
    id: 'SOL4128',
    name: 'Token-2022 - Transfer Hook Validation',
    severity: 'high',
    pattern: /(?:transfer_hook|ExtraAccountMeta)[\s\S]{0,100}(?!validate|verify|check_program)/i,
    description: 'Token-2022 transfer hook not validated. Malicious hooks can steal funds.',
    recommendation: 'Validate transfer hook program ID and extra account metas.'
  },
  {
    id: 'SOL4129',
    name: 'Token-2022 - Confidential Transfer Leak',
    severity: 'high',
    pattern: /(?:confidential|encrypted)[\s\S]{0,100}(?:balance|amount)[\s\S]{0,50}(?:log|emit|expose)/i,
    description: 'Confidential transfer amounts may be leaked through side channels.',
    recommendation: 'Never log or expose confidential amounts. Audit all data flows.'
  },
  {
    id: 'SOL4130',
    name: 'Token-2022 - Permanent Delegate Risk',
    severity: 'critical',
    pattern: /(?:permanent_delegate|default_account_state)[\s\S]{0,80}(?!warning|documented)/i,
    description: 'Token-2022 permanent delegate can transfer user tokens anytime.',
    recommendation: 'Document permanent delegate clearly. Consider user consent mechanisms.'
  },

  // ============================================================================
  // BRIDGE PROTOCOL ADVANCED PATTERNS
  // ============================================================================

  {
    id: 'SOL4131',
    name: 'Bridge - Guardian Set Update Race',
    severity: 'critical',
    pattern: /(?:guardian_set|validator_set)[\s\S]{0,100}(?:update|change)[\s\S]{0,50}(?!pending|delay)/i,
    description: 'Guardian set updates immediate. May enable stale signature replay.',
    recommendation: 'Implement guardian set update delay. Track set index in messages.'
  },
  {
    id: 'SOL4132',
    name: 'Bridge - Cross-Chain Decimal Mismatch',
    severity: 'high',
    pattern: /(?:bridge|cross_chain)[\s\S]{0,100}(?:decimals|precision)[\s\S]{0,50}(?!normalize|convert|map)/i,
    description: 'Token decimals may differ across chains. Causes balance mismatches.',
    recommendation: 'Normalize decimals in bridge logic. Handle precision loss.'
  },
  {
    id: 'SOL4133',
    name: 'Bridge - Canonical Token Verification',
    severity: 'critical',
    pattern: /(?:wrapped|bridged)[\s\S]{0,100}(?:token|mint)[\s\S]{0,50}(?!canonical|verify_mint|whitelist)/i,
    description: 'Bridged token not verified as canonical. Multiple wrappers for same asset.',
    recommendation: 'Maintain canonical wrapped token registry. Verify on bridging.'
  },
  {
    id: 'SOL4134',
    name: 'Bridge - Message Sequence Gap',
    severity: 'high',
    pattern: /(?:sequence|nonce)[\s\S]{0,100}(?:process|handle)[\s\S]{0,50}(?!sequential|no_gap|ordered)/i,
    description: 'Bridge messages processed out of order. May cause state inconsistency.',
    recommendation: 'Process messages sequentially. Handle or reject gaps explicitly.'
  },
  {
    id: 'SOL4135',
    name: 'Bridge - Proof Verification Timeout',
    severity: 'medium',
    pattern: /(?:proof|attestation)[\s\S]{0,100}(?:verify|validate)[\s\S]{0,50}(?!timeout|expiry|max_age)/i,
    description: 'Bridge proofs valid indefinitely. Stale proofs may be replayed.',
    recommendation: 'Add proof expiry. Reject proofs older than threshold.'
  },

  // ============================================================================
  // PERPETUAL/DERIVATIVES PATTERNS
  // ============================================================================

  {
    id: 'SOL4136',
    name: 'Perp - Funding Rate Manipulation',
    severity: 'high',
    pattern: /(?:funding_rate|funding_payment)[\s\S]{0,100}(?:calculate|compute)[\s\S]{0,50}(?!twap|time_weighted|bounds)/i,
    description: 'Funding rate calculated from spot price. Manipulation enables funding extraction.',
    recommendation: 'Use TWAP for funding rate calculation. Add rate bounds.'
  },
  {
    id: 'SOL4137',
    name: 'Perp - ADL Priority Gaming',
    severity: 'high',
    pattern: /(?:adl|auto_deleverage)[\s\S]{0,100}(?:priority|rank)[\s\S]{0,50}(?!deterministic|transparent)/i,
    description: 'ADL priority opaque or manipulable. Users may be unfairly deleveraged.',
    recommendation: 'Use transparent, deterministic ADL ranking based on PnL and leverage.'
  },
  {
    id: 'SOL4138',
    name: 'Perp - Mark Price Manipulation',
    severity: 'critical',
    pattern: /(?:mark_price|index_price)[\s\S]{0,100}(?:calculate)[\s\S]{0,50}(?!multiple_sources|median|trimmed)/i,
    description: 'Mark price from single source. Manipulation causes mass liquidations.',
    recommendation: 'Use median of multiple oracle sources for mark price.'
  },
  {
    id: 'SOL4139',
    name: 'Perp - Liquidation Cascade Risk',
    severity: 'critical',
    pattern: /(?:liquidation|liquidate)[\s\S]{0,100}(?:batch|mass)[\s\S]{0,50}(?!circuit_breaker|pause)/i,
    description: 'Mass liquidations may cause cascade. Nov 2025 $258M incident pattern.',
    recommendation: 'Implement liquidation circuit breakers. Pause on abnormal activity.'
  },
  {
    id: 'SOL4140',
    name: 'Perp - Insurance Fund Depletion',
    severity: 'high',
    pattern: /(?:insurance_fund|deficit)[\s\S]{0,100}(?:use|withdraw)[\s\S]{0,50}(?!backstop|limit|reserve)/i,
    description: 'Insurance fund can be fully depleted. No backstop for socializing losses.',
    recommendation: 'Keep minimum insurance fund reserve. Implement loss socialization.'
  },

  // ============================================================================
  // OPTIONS PROTOCOL PATTERNS
  // ============================================================================

  {
    id: 'SOL4141',
    name: 'Options - Premium Mispricing',
    severity: 'high',
    pattern: /(?:premium|option_price)[\s\S]{0,100}(?:calculate)[\s\S]{0,50}(?!volatility|greeks|model)/i,
    description: 'Option premium not using proper pricing model. Arbitrage opportunity.',
    recommendation: 'Use Black-Scholes or equivalent. Update implied volatility regularly.'
  },
  {
    id: 'SOL4142',
    name: 'Options - Settlement Price Manipulation',
    severity: 'critical',
    pattern: /(?:settlement|expiry)[\s\S]{0,100}(?:price)[\s\S]{0,50}(?!twap|average|oracle)/i,
    description: 'Settlement price from single snapshot. Manipulation at expiry.',
    recommendation: 'Use TWAP around settlement time. Multiple oracle sources.'
  },
  {
    id: 'SOL4143',
    name: 'Options - Exercise Window Attack',
    severity: 'high',
    pattern: /(?:exercise|execute)[\s\S]{0,100}(?:option)[\s\S]{0,50}(?:window|period)[\s\S]{0,30}(?!documented)/i,
    description: 'Exercise window parameters exploitable. May prevent legitimate exercise.',
    recommendation: 'Document exercise windows clearly. Add buffer for execution.'
  },
  {
    id: 'SOL4144',
    name: 'Options - Collateral Ratio Stale',
    severity: 'high',
    pattern: /(?:collateral_ratio|margin)[\s\S]{0,100}(?:option|position)[\s\S]{0,50}(?!update|refresh|current)/i,
    description: 'Option collateral requirements not updated with price changes.',
    recommendation: 'Update collateral requirements on every price change.'
  },
  {
    id: 'SOL4145',
    name: 'Options - Greeks Calculation Error',
    severity: 'medium',
    pattern: /(?:delta|gamma|theta|vega)[\s\S]{0,80}(?:calculate)[\s\S]{0,50}(?!boundary|edge_case)/i,
    description: 'Greeks calculation may fail at boundary conditions (deep ITM/OTM).',
    recommendation: 'Handle edge cases in Greeks calculation. Add numerical stability.'
  },

  // ============================================================================
  // YIELD AGGREGATOR PATTERNS
  // ============================================================================

  {
    id: 'SOL4146',
    name: 'Yield - Strategy Approval Without Audit',
    severity: 'high',
    pattern: /(?:strategy|vault)[\s\S]{0,100}(?:add|register|approve)[\s\S]{0,50}(?!audit|review|governance)/i,
    description: 'New strategies added without security review. Malicious strategy risk.',
    recommendation: 'Require governance approval and audit for new strategies.'
  },
  {
    id: 'SOL4147',
    name: 'Yield - Emergency Withdrawal Path',
    severity: 'high',
    pattern: /(?:emergency|panic)[\s\S]{0,100}(?:withdraw|exit)[\s\S]{0,50}(?!guaranteed|fallback)/i,
    description: 'No emergency withdrawal path. Funds locked if strategy fails.',
    recommendation: 'Implement emergency withdrawal that bypasses strategy.'
  },
  {
    id: 'SOL4148',
    name: 'Yield - Harvest Sandwich Attack',
    severity: 'high',
    pattern: /(?:harvest|compound)[\s\S]{0,100}(?:reward|yield)[\s\S]{0,50}(?!private|protected|mev)/i,
    description: 'Harvest transactions public. MEV bots sandwich for profit.',
    recommendation: 'Use private mempool for harvests. Implement MEV protection.'
  },
  {
    id: 'SOL4149',
    name: 'Yield - Share Price Manipulation',
    severity: 'critical',
    pattern: /(?:share_price|exchange_rate)[\s\S]{0,100}(?:vault)[\s\S]{0,50}(?!protected|twap|bounded)/i,
    description: 'Vault share price manipulable via donations. Inflation attack.',
    recommendation: 'Use virtual shares or donation protection. Bound price changes.'
  },
  {
    id: 'SOL4150',
    name: 'Yield - Underlying Protocol Risk',
    severity: 'medium',
    pattern: /(?:underlying|external)[\s\S]{0,100}(?:protocol|contract)[\s\S]{0,50}(?!monitor|health_check)/i,
    description: 'Yield source protocol may fail. No monitoring of underlying health.',
    recommendation: 'Monitor underlying protocol metrics. Implement automatic pausing.'
  },

  // ============================================================================
  // FINAL COMPREHENSIVE PATTERNS
  // ============================================================================

  {
    id: 'SOL4151',
    name: 'Account Revival After Close',
    severity: 'high',
    pattern: /(?:close|zero_account)[\s\S]{0,100}(?!rent_exempt.*check|revival.*protect)/i,
    description: 'Closed accounts can be revived by sending lamports. State resurrection.',
    recommendation: 'Zero all data before close. Check for revival in instruction guards.'
  },
  {
    id: 'SOL4152',
    name: 'Instruction Data Size Unchecked',
    severity: 'medium',
    pattern: /(?:instruction|ix)[\s\S]{0,80}(?:data)[\s\S]{0,50}(?!len.*check|size.*verify|bounded)/i,
    description: 'Instruction data size not validated. May panic on deserialize.',
    recommendation: 'Verify instruction data size before processing.'
  },
  {
    id: 'SOL4153',
    name: 'Missing Rent Exemption Check',
    severity: 'medium',
    pattern: /(?:account|create)[\s\S]{0,100}(?:lamports)[\s\S]{0,50}(?!rent.*exempt|minimum_balance)/i,
    description: 'Account may not be rent exempt. Will be garbage collected.',
    recommendation: 'Ensure accounts have minimum balance for rent exemption.'
  },
  {
    id: 'SOL4154',
    name: 'Event Ordering Assumption',
    severity: 'low',
    pattern: /(?:event|log|emit)[\s\S]{0,100}(?:order|sequence)[\s\S]{0,50}(?!guaranteed|documented)/i,
    description: 'Event ordering not guaranteed in parallel execution. Indexer issues.',
    recommendation: 'Include sequence numbers in events. Don\'t rely on emission order.'
  },
  {
    id: 'SOL4155',
    name: 'Program ID Hardcoded',
    severity: 'low',
    pattern: /(?:program_id|pubkey)[\s\S]{0,50}(?:=|:)[\s\S]{0,30}(?:"[1-9A-HJ-NP-Za-km-z]{32,44}")/i,
    description: 'Program IDs hardcoded. May conflict with deployments on different networks.',
    recommendation: 'Use declare_id! macro. Support configurable program IDs for testing.'
  },
  {
    id: 'SOL4156',
    name: 'Version Mismatch Risk',
    severity: 'medium',
    pattern: /(?:version|upgrade)[\s\S]{0,100}(?:migration|compatibility)[\s\S]{0,50}(?!check|verify)/i,
    description: 'Account version not verified during upgrade. Data corruption risk.',
    recommendation: 'Include version field in accounts. Verify and migrate on access.'
  },
  {
    id: 'SOL4157',
    name: 'Borsh Deserialization Panic',
    severity: 'high',
    pattern: /(?:borsh|deserialize)[\s\S]{0,80}(?:unwrap|expect)[\s\S]{0,30}(?!\?|match|if let)/i,
    description: 'Borsh deserialization failure causes panic. DoS vector.',
    recommendation: 'Handle deserialization errors gracefully. Return proper error codes.'
  },
  {
    id: 'SOL4158',
    name: 'Clock Sysvar Manipulation',
    severity: 'medium',
    pattern: /(?:Clock|slot|timestamp)[\s\S]{0,100}(?:assume|expect)[\s\S]{0,50}(?:accurate|precise)/i,
    description: 'Clock sysvar values can be slightly manipulated by validators.',
    recommendation: 'Allow tolerance in time-sensitive operations. Don\'t rely on exact timing.'
  },
  {
    id: 'SOL4159',
    name: 'Native SOL Handling Error',
    severity: 'high',
    pattern: /(?:native_sol|system_program)[\s\S]{0,100}(?:transfer|lamport)[\s\S]{0,50}(?!wrap|wsol|handle)/i,
    description: 'Native SOL vs wrapped SOL handling inconsistent. Transfer failures.',
    recommendation: 'Handle native SOL separately or auto-wrap. Document token behavior.'
  },
  {
    id: 'SOL4160',
    name: 'Compute Unit Estimation',
    severity: 'low',
    pattern: /(?:compute|cu)[\s\S]{0,80}(?:budget|units)[\s\S]{0,50}(?!dynamic|estimate|measure)/i,
    description: 'Compute budget static. May fail on variable-cost operations.',
    recommendation: 'Estimate compute dynamically. Add buffer for safety.'
  },

  // ============================================================================
  // ADDITIONAL EDGE CASE PATTERNS
  // ============================================================================

  {
    id: 'SOL4161',
    name: 'Seed Injection Attack',
    severity: 'critical',
    pattern: /(?:seeds|pda)[\s\S]{0,100}(?:user_input|param)[\s\S]{0,50}(?!sanitize|validate|bounded)/i,
    description: 'User input used directly in PDA seeds. May collide with other PDAs.',
    recommendation: 'Sanitize and bound user input in seeds. Use fixed-length fields.'
  },
  {
    id: 'SOL4162',
    name: 'Duplicate Account Parameter',
    severity: 'high',
    pattern: /(?:accounts|ctx)[\s\S]{0,100}(?:same|duplicate|equal)[\s\S]{0,50}(?!check|verify|!=)/i,
    description: 'Same account passed for multiple parameters. Logic bypass.',
    recommendation: 'Verify distinct accounts where required. Check key inequality.'
  },
  {
    id: 'SOL4163',
    name: 'Empty Account Data Assumption',
    severity: 'medium',
    pattern: /(?:account|data)[\s\S]{0,80}(?:new|create|init)[\s\S]{0,50}(?!zeroed|empty_check)/i,
    description: 'New account data assumed to be zero. May contain previous data.',
    recommendation: 'Explicitly zero account data on creation. Don\'t assume empty.'
  },
  {
    id: 'SOL4164',
    name: 'Program Upgrade Authority Leak',
    severity: 'high',
    pattern: /(?:upgrade_authority|BpfUpgradeableLoader)[\s\S]{0,100}(?!verified|checked|set_to_none)/i,
    description: 'Upgrade authority not verified or restricted. Unauthorized upgrades possible.',
    recommendation: 'Verify upgrade authority in sensitive operations. Consider making immutable.'
  },
  {
    id: 'SOL4165',
    name: 'External CPI Return Data',
    severity: 'medium',
    pattern: /(?:get_return_data|return_data)[\s\S]{0,100}(?!program_id.*verify|trusted)/i,
    description: 'CPI return data not verified for source. May trust wrong program.',
    recommendation: 'Verify return data came from expected program ID.'
  },
  {
    id: 'SOL4166',
    name: 'Anchor Context Lifetime',
    severity: 'medium',
    pattern: /(?:Context|ctx)[\s\S]{0,80}(?:borrow|reference)[\s\S]{0,50}(?:lifetime|\')/i,
    description: 'Anchor context lifetime issues can cause unexpected behavior.',
    recommendation: 'Be careful with context borrows. Clone data if needed beyond scope.'
  },
  {
    id: 'SOL4167',
    name: 'Zero-Copy Account Aliasing',
    severity: 'high',
    pattern: /(?:zero_copy|AccountLoader)[\s\S]{0,100}(?:borrow_mut)[\s\S]{0,50}(?:multiple|twice)/i,
    description: 'Multiple mutable borrows of zero-copy account. Aliasing UB risk.',
    recommendation: 'Never hold multiple mutable references. Reborrow after scope end.'
  },
  {
    id: 'SOL4168',
    name: 'Lookup Table Entry Validation',
    severity: 'high',
    pattern: /(?:address_lookup|ALT)[\s\S]{0,100}(?:table)[\s\S]{0,50}(?!verify|validate|trusted)/i,
    description: 'Address lookup table entries not validated. May resolve to wrong addresses.',
    recommendation: 'Verify lookup table authority. Validate resolved addresses.'
  },
  {
    id: 'SOL4169',
    name: 'Blockhash Expiry Risk',
    severity: 'medium',
    pattern: /(?:blockhash|recent_blockhash)[\s\S]{0,100}(?:cache|store)[\s\S]{0,50}(?!refresh|expiry)/i,
    description: 'Cached blockhash may expire. Transaction will fail after ~60 seconds.',
    recommendation: 'Refresh blockhash before transaction submission. Handle expiry.'
  },
  {
    id: 'SOL4170',
    name: 'Priority Fee Griefing',
    severity: 'medium',
    pattern: /(?:priority_fee|compute_budget)[\s\S]{0,100}(?:user_supplied|param)[\s\S]{0,50}(?!bounded|max)/i,
    description: 'User-controlled priority fee unbounded. May cause fee spikes.',
    recommendation: 'Bound priority fees. Implement fee estimation with caps.'
  },
  {
    id: 'SOL4171',
    name: 'CPI Guard State Manipulation',
    severity: 'high',
    pattern: /(?:cpi_guard|transfer_hook)[\s\S]{0,100}(?:state|enabled)[\s\S]{0,50}(?:toggle|change)/i,
    description: 'CPI guard state can be toggled. May enable unauthorized CPIs.',
    recommendation: 'Make CPI guard state immutable after initialization.'
  },
  {
    id: 'SOL4172',
    name: 'Associated Token Account Race',
    severity: 'medium',
    pattern: /(?:associated_token|get_associated_token|ATA)[\s\S]{0,100}(?:create)[\s\S]{0,50}(?!idempotent|exists_check)/i,
    description: 'ATA creation may race with other transactions. Multiple creations fail.',
    recommendation: 'Use create_idempotent for ATA creation. Handle already exists.'
  },
  {
    id: 'SOL4173',
    name: 'Token Account Closure Timing',
    severity: 'medium',
    pattern: /(?:token_account|close_account)[\s\S]{0,100}(?:balance.*zero)[\s\S]{0,50}(?!verify|assert)/i,
    description: 'Token account closed without verifying zero balance. Token loss.',
    recommendation: 'Verify token balance is zero before closing account.'
  },
  {
    id: 'SOL4174',
    name: 'Metaplex Edition Validation',
    severity: 'high',
    pattern: /(?:edition|master_edition)[\s\S]{0,100}(?:mint|create)[\s\S]{0,50}(?!supply_check|max_supply)/i,
    description: 'NFT edition supply not validated. May exceed max supply.',
    recommendation: 'Verify edition number against max supply before minting.'
  },
  {
    id: 'SOL4175',
    name: 'SPL Governance Proposal Injection',
    severity: 'critical',
    pattern: /(?:governance|proposal)[\s\S]{0,100}(?:instruction|execute)[\s\S]{0,50}(?!whitelist|validate)/i,
    description: 'Governance proposals can execute arbitrary instructions. Full control risk.',
    recommendation: 'Whitelist allowed proposal instructions. Validate targets.'
  }
];

// Export all patterns
export const BATCH_80_PATTERNS = [...ZELLIC_ANCHOR_PATTERNS];

// Pattern scanner function
export function scanBatch80(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const lines = input.content.split('\n');

  for (const pattern of BATCH_80_PATTERNS) {
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const context = lines.slice(i, Math.min(i + 4, lines.length)).join('\n');
      
      if (pattern.pattern.test(context)) {
        findings.push({
          id: pattern.id,
          name: pattern.name,
          severity: pattern.severity,
          file: input.file,
          line: i + 1,
          column: 1,
          description: pattern.description,
          snippet: line.substring(0, 100),
          recommendation: pattern.recommendation
        });
        break;
      }
    }
  }

  return findings;
}

export default BATCH_80_PATTERNS;
