/**
 * SolGuard Batch 76 Security Patterns
 * Based on: DEV.to Feb 2026 Critical Vulns + sannykim/solsec + Latest Phishing Research
 * 
 * Pattern IDs: SOL3676 - SOL3775 (100 patterns)
 * Created: Feb 6, 2026 12:00 AM CST
 * 
 * Sources:
 * - DEV.to "Solana Vulnerabilities Every Developer Should Know" (Feb 2026)
 * - sannykim/solsec GitHub collection
 * - SlowMist Phishing Analysis (Dec 2025)
 * - Helius Complete Exploit History
 * - Sec3 2025 Security Ecosystem Review
 */

import type { Finding, PatternInput } from './index.js';

// ============================================================================
// DEV.TO FEB 2026: 15 CRITICAL VULNERABILITY DEEP DIVE
// ============================================================================

const DEVTO_CRITICAL_VULNS: {
  id: string;
  name: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  pattern: RegExp;
  description: string;
  recommendation: string;
}[] = [
  // 1. Missing Signer Check - Solend $2M Pattern
  {
    id: 'SOL3676',
    name: 'Missing Signer Check - AccountInfo Without Verification',
    severity: 'critical',
    pattern: /AccountInfo[^}]{0,100}(?!is_signer|Signer)/,
    description: 'AccountInfo used without signer verification. Solend Aug 2021 attempted $2M exploit pattern.',
    recommendation: 'Use Signer<\'info> in Anchor or manually check authority.is_signer() in native.'
  },
  {
    id: 'SOL3677',
    name: 'Missing Signer - Key Comparison Without Signature',
    severity: 'critical',
    pattern: /\.key\(\)\s*==\s*[^;]+(?!\.is_signer)/,
    description: 'Comparing keys without verifying signature allows attacker to pass any pubkey.',
    recommendation: 'Always combine key comparison with is_signer check.'
  },
  {
    id: 'SOL3678',
    name: 'Authority Pattern Without Signer Type',
    severity: 'critical',
    pattern: /authority:\s*AccountInfo/,
    description: 'Authority defined as AccountInfo instead of Signer allows unsigned authority bypass.',
    recommendation: 'Change authority type to Signer<\'info> in Anchor structs.'
  },
  {
    id: 'SOL3679',
    name: 'Admin Function Missing Signer Validation',
    severity: 'critical',
    pattern: /(?:admin|owner|authority)[\s\S]{0,50}(?:update|modify|set|change)[\s\S]{0,100}(?!is_signer)/,
    description: 'Admin function modifies state without verifying signer.',
    recommendation: 'Require signer verification for all privileged operations.'
  },

  // 2. Missing Owner Check - Crema $8.8M Pattern
  {
    id: 'SOL3680',
    name: 'Missing Owner Check - Account Data Read',
    severity: 'critical',
    pattern: /\.data\.borrow\(\)[\s\S]{0,50}(?!owner\(\)|\.owner)/,
    description: 'Reading account data without owner verification. Crema Finance $8.8M exploit pattern.',
    recommendation: 'Verify account.owner() == program_id before reading data.'
  },
  {
    id: 'SOL3681',
    name: 'UncheckedAccount Without Owner Validation',
    severity: 'high',
    pattern: /UncheckedAccount[^}]{0,200}(?!owner|CHECK)/,
    description: 'UncheckedAccount usage without documented owner validation.',
    recommendation: 'Add /// CHECK comment explaining validation or use Account<T>.'
  },
  {
    id: 'SOL3682',
    name: 'Fake Account Injection - Tick/Price Data',
    severity: 'critical',
    pattern: /(?:tick|price|oracle|feed)[\s\S]{0,100}AccountInfo[\s\S]{0,100}(?!owner)/,
    description: 'Price/tick data account without owner check allows fake data injection.',
    recommendation: 'Verify account ownership before trusting price/tick data.'
  },
  {
    id: 'SOL3683',
    name: 'Token Account Owner Field Confusion',
    severity: 'high',
    pattern: /token_account\.owner[\s\S]{0,50}(?!==\s*(?:user|authority|expected))/,
    description: 'Token account owner field checked incorrectly (account owner vs token owner).',
    recommendation: 'Distinguish between SPL token owner (in data) and account owner (program).'
  },

  // 3. Account Data Matching - Solend Oracle $1.26M Pattern
  {
    id: 'SOL3684',
    name: 'Account Data Mismatch - Token/Mint Constraint',
    severity: 'high',
    pattern: /token_account[\s\S]{0,100}(?!constraint.*mint|mint\s*==)/,
    description: 'Token account accepted without mint constraint. Solend oracle $1.26M pattern.',
    recommendation: 'Add constraint = token_account.mint == expected_mint.'
  },
  {
    id: 'SOL3685',
    name: 'Oracle Single Source Dependency',
    severity: 'high',
    pattern: /(?:price|oracle)[\s\S]{0,100}(?:get_price|read)[\s\S]{0,200}(?!fallback|secondary|aggregate)/,
    description: 'Single oracle source without fallback enables price manipulation.',
    recommendation: 'Use multiple oracle sources with aggregation and fallback.'
  },
  {
    id: 'SOL3686',
    name: 'Pool-Token Relationship Not Verified',
    severity: 'high',
    pattern: /pool[\s\S]{0,50}token[\s\S]{0,100}(?!constraint|verify_relationship)/,
    description: 'Pool and token account relationship not verified.',
    recommendation: 'Verify pool.token_account == passed token account.'
  },

  // 4. Type Cosplay - Discriminator Bypass
  {
    id: 'SOL3687',
    name: 'Type Cosplay - Manual Deserialization Without Discriminator',
    severity: 'critical',
    pattern: /(?:deserialize|from_bytes|unpack)[\s\S]{0,100}(?!discriminator|disc_check)/,
    description: 'Manual deserialization without discriminator check allows type confusion.',
    recommendation: 'Verify 8-byte discriminator before deserializing account data.'
  },
  {
    id: 'SOL3688',
    name: 'AccountInfo Casting Without Type Verification',
    severity: 'high',
    pattern: /as\s+&(?:mut\s+)?\[u8\][\s\S]{0,50}(?!discriminator)/,
    description: 'Unsafe casting of account data without type verification.',
    recommendation: 'Use Account<T> or verify discriminator before casting.'
  },
  {
    id: 'SOL3689',
    name: 'Similar Data Layout Risk - Cosplay Vulnerable',
    severity: 'medium',
    pattern: /struct\s+\w+[\s\S]{0,50}authority:\s*Pubkey[\s\S]{0,50}balance:\s*u64/,
    description: 'Account struct has common layout vulnerable to type cosplay.',
    recommendation: 'Ensure unique discriminator and validate account type on every access.'
  },

  // 5. PDA Bump Canonicalization
  {
    id: 'SOL3690',
    name: 'Non-Canonical PDA Bump - User Provided',
    severity: 'high',
    pattern: /bump:\s*(?:u8|ctx\.accounts\.\w+\.bump)[\s\S]{0,100}create_program_address/,
    description: 'User-provided bump seed allows shadow PDA creation.',
    recommendation: 'Use find_program_address and store canonical bump.'
  },
  {
    id: 'SOL3691',
    name: 'PDA Bump Not Stored for Verification',
    severity: 'medium',
    pattern: /find_program_address[\s\S]{0,200}(?!\.bump\s*=|store.*bump)/,
    description: 'PDA canonical bump not stored, preventing future verification.',
    recommendation: 'Store bump in account data and verify on subsequent accesses.'
  },
  {
    id: 'SOL3692',
    name: 'create_program_address Without find_program_address',
    severity: 'high',
    pattern: /create_program_address[\s\S]{0,100}(?!find_program_address)/,
    description: 'Direct create_program_address usage without finding canonical bump.',
    recommendation: 'Always use find_program_address to get canonical bump first.'
  },

  // 6. Account Reinitialization
  {
    id: 'SOL3693',
    name: 'Initialize Without Existence Check',
    severity: 'critical',
    pattern: /(?:initialize|init)[\s\S]{0,200}(?!is_initialized|already_exists|discriminator)/,
    description: 'Initialize function without checking if account already exists.',
    recommendation: 'Check is_initialized flag or discriminator before initializing.'
  },
  {
    id: 'SOL3694',
    name: 'init_if_needed Race Condition',
    severity: 'high',
    pattern: /init_if_needed/,
    description: 'init_if_needed can cause race conditions in multi-instruction transactions.',
    recommendation: 'Use explicit init with existence check instead of init_if_needed.'
  },
  {
    id: 'SOL3695',
    name: 'Close and Reinitialize Attack Vector',
    severity: 'high',
    pattern: /close[\s\S]{0,100}(?!zero|clear|wipe)[\s\S]{0,100}init/,
    description: 'Close without zeroing data allows reinitialization with stale data.',
    recommendation: 'Zero all account data before transferring lamports.'
  },

  // 7. Arbitrary CPI
  {
    id: 'SOL3696',
    name: 'Arbitrary CPI - User Controlled Program ID',
    severity: 'critical',
    pattern: /invoke(?:_signed)?[\s\S]{0,50}program_id[\s\S]{0,100}(?!==|!=|TOKEN_PROGRAM|SYSTEM_PROGRAM)/,
    description: 'CPI target program ID from user input without validation.',
    recommendation: 'Hardcode program IDs or use Program<\'info, T> for CPI targets.'
  },
  {
    id: 'SOL3697',
    name: 'CPI Program Account Not Type Verified',
    severity: 'high',
    pattern: /cpi_program:\s*AccountInfo/,
    description: 'CPI program passed as AccountInfo allows arbitrary program invocation.',
    recommendation: 'Use Program<\'info, Token> or similar typed program account.'
  },
  {
    id: 'SOL3698',
    name: 'Token Transfer CPI Without SPL Verification',
    severity: 'critical',
    pattern: /(?:transfer|Transfer)[\s\S]{0,100}invoke[\s\S]{0,100}(?!spl_token|TOKEN_PROGRAM)/,
    description: 'Token transfer CPI without verifying SPL Token program.',
    recommendation: 'Hardcode TOKEN_PROGRAM_ID for token operations.'
  },

  // 8. Integer Overflow - Nirvana $3.5M Pattern
  {
    id: 'SOL3699',
    name: 'Unchecked Arithmetic - Financial Calculation',
    severity: 'high',
    pattern: /(?:balance|amount|fee|reward)[\s\S]{0,30}(?:\+|\-|\*|\/)[\s\S]{0,30}(?!checked_|saturating_)/,
    description: 'Unchecked arithmetic on financial values. Nirvana $3.5M exploit pattern.',
    recommendation: 'Use checked_add/sub/mul/div for all financial calculations.'
  },
  {
    id: 'SOL3700',
    name: 'u128 to u64 Truncation Risk',
    severity: 'high',
    pattern: /as\s+u64[\s\S]{0,30}(?!try_into|checked)/,
    description: 'Casting larger integer to u64 can silently truncate.',
    recommendation: 'Use try_into() with error handling for type conversions.'
  },
  {
    id: 'SOL3701',
    name: 'Division Before Multiplication - Precision Loss',
    severity: 'medium',
    pattern: /\/[\s\S]{0,20}\*[\s\S]{0,30}(?!precision|scale)/,
    description: 'Division before multiplication causes precision loss in integer math.',
    recommendation: 'Multiply first, then divide. Use fixed-point math for precision.'
  },

  // 9. Account Closure - Resurrection Attack
  {
    id: 'SOL3702',
    name: 'Account Close Without Data Zero',
    severity: 'high',
    pattern: /close[\s\S]{0,100}lamports[\s\S]{0,100}(?!\.fill\(0\)|\.zero\(\)|clear_data)/,
    description: 'Closing account without zeroing data allows resurrection attack.',
    recommendation: 'Zero all account data before transferring lamports.'
  },
  {
    id: 'SOL3703',
    name: 'Rent Siphoning - Refund Calculation',
    severity: 'medium',
    pattern: /lamports\.borrow_mut\(\)[\s\S]{0,50}(?!rent_exempt|minimum_balance)/,
    description: 'Account closure may leave insufficient lamports for rent.',
    recommendation: 'Calculate rent-exempt minimum before closing.'
  },

  // 10. Duplicate Mutable Accounts
  {
    id: 'SOL3704',
    name: 'Duplicate Mutable Accounts - No Uniqueness Check',
    severity: 'high',
    pattern: /(?:source|from)[\s\S]{0,50}mut[\s\S]{0,50}(?:dest|to)[\s\S]{0,50}mut[\s\S]{0,100}(?!!=|ne|different)/,
    description: 'Two mutable accounts without uniqueness verification.',
    recommendation: 'Verify source.key() != destination.key() before operations.'
  },
  {
    id: 'SOL3705',
    name: 'Self-Transfer Balance Doubling',
    severity: 'high',
    pattern: /transfer[\s\S]{0,100}(?!source.*!=.*dest|from.*!=.*to)/,
    description: 'Transfer without checking source != destination allows balance manipulation.',
    recommendation: 'Add explicit check: require!(from.key() != to.key()).'
  },
];

// ============================================================================
// SANNYKIM/SOLSEC: POC EXPLOIT PATTERNS
// ============================================================================

const SOLSEC_POC_PATTERNS: typeof DEVTO_CRITICAL_VULNS = [
  // Port Max Withdraw Bug
  {
    id: 'SOL3706',
    name: 'Port Finance - Max Withdraw Calculation Bug',
    severity: 'high',
    pattern: /max_withdraw[\s\S]{0,100}(?!health_factor|collateral_check)/,
    description: 'Max withdraw calculation without health factor verification.',
    recommendation: 'Always verify position health after calculating max withdrawal.'
  },

  // Jet Governance Token Lock
  {
    id: 'SOL3707',
    name: 'Jet Governance - Token Lock Bypass',
    severity: 'high',
    pattern: /governance[\s\S]{0,100}lock[\s\S]{0,100}(?!time_check|unlock_time)/,
    description: 'Governance token lock without proper time verification.',
    recommendation: 'Verify lock period has elapsed before allowing unlocks.'
  },

  // Cashio Infinite Mint
  {
    id: 'SOL3708',
    name: 'Cashio - Root of Trust Missing ($52M)',
    severity: 'critical',
    pattern: /collateral[\s\S]{0,100}mint[\s\S]{0,100}(?!verify_chain|root_trust)/,
    description: 'Collateral validation without root of trust verification. Cashio $52M pattern.',
    recommendation: 'Establish and verify root of trust for all collateral chains.'
  },

  // SPL Token-Lending Rounding
  {
    id: 'SOL3709',
    name: 'Neodyme Rounding Attack ($2.6B at Risk)',
    severity: 'critical',
    pattern: /(?:round|ceil|floor)[\s\S]{0,50}(?:deposit|withdraw|redeem)/,
    description: 'Rounding in deposit/withdraw calculation exploitable. $2.6B at risk pattern.',
    recommendation: 'Round against user for deposits (floor), against protocol for withdrawals (ceil).'
  },

  // Cope Roulette Revert
  {
    id: 'SOL3710',
    name: 'Cope Roulette - Transaction Revert Exploit',
    severity: 'medium',
    pattern: /(?:random|rng|lottery)[\s\S]{0,100}(?!commit_reveal|vrf)/,
    description: 'Randomness without commit-reveal allows revert exploitation.',
    recommendation: 'Use VRF or commit-reveal scheme for on-chain randomness.'
  },

  // LP Token Manipulation
  {
    id: 'SOL3711',
    name: 'OtterSec LP Oracle Manipulation ($200M Risk)',
    severity: 'critical',
    pattern: /lp_token[\s\S]{0,100}(?:price|value)[\s\S]{0,100}(?!fair_price|virtual_price)/,
    description: 'LP token pricing vulnerable to manipulation. $200M at risk pattern.',
    recommendation: 'Use fair/virtual pricing for LP tokens, not spot reserves.'
  },

  // Wormhole Guardian Bypass
  {
    id: 'SOL3712',
    name: 'Wormhole - Guardian Quorum Bypass ($326M)',
    severity: 'critical',
    pattern: /(?:guardian|validator)[\s\S]{0,100}(?:verify|check)[\s\S]{0,100}(?!quorum|threshold|count)/,
    description: 'Guardian/validator verification without quorum check. Wormhole $326M pattern.',
    recommendation: 'Verify minimum guardian quorum before accepting signatures.'
  },

  // Crema CLMM Tick Manipulation
  {
    id: 'SOL3713',
    name: 'Crema CLMM - Fake Tick Account ($8.8M)',
    severity: 'critical',
    pattern: /tick[\s\S]{0,100}(?:account|data)[\s\S]{0,100}(?!owner_check|verify_program)/,
    description: 'CLMM tick account without program ownership verification. Crema $8.8M pattern.',
    recommendation: 'Verify tick account is owned by CLMM program before reading.'
  },

  // Nirvana Bonding Curve
  {
    id: 'SOL3714',
    name: 'Nirvana - Bonding Curve Flash Loan ($3.5M)',
    severity: 'critical',
    pattern: /bonding_curve[\s\S]{0,100}(?!flash_loan_guard|atomic_check)/,
    description: 'Bonding curve vulnerable to flash loan manipulation. Nirvana $3.5M pattern.',
    recommendation: 'Add flash loan guards or atomic transaction checks.'
  },
];

// ============================================================================
// SLOWMIST PHISHING PATTERNS (DEC 2025) - $3M+ INCIDENTS
// ============================================================================

const SLOWMIST_PHISHING: typeof DEVTO_CRITICAL_VULNS = [
  {
    id: 'SOL3715',
    name: 'SetAuthority Phishing - Silent Owner Transfer',
    severity: 'critical',
    pattern: /SetAuthority[\s\S]{0,100}(?!two_step|timelock|confirmation)/,
    description: 'SetAuthority without two-step confirmation enables phishing. SlowMist $3M+ pattern.',
    recommendation: 'Implement two-step authority transfer with timelock.'
  },
  {
    id: 'SOL3716',
    name: 'Owner Permission Exploitation',
    severity: 'critical',
    pattern: /(?:owner|authority)[\s\S]{0,50}(?:change|transfer|set)[\s\S]{0,100}(?!event|emit|log)/,
    description: 'Authority changes without event emission hide malicious transfers.',
    recommendation: 'Emit events for all authority changes and critical operations.'
  },
  {
    id: 'SOL3717',
    name: 'Transaction Simulation Bypass',
    severity: 'high',
    pattern: /(?:simulate|preflight)[\s\S]{0,100}(?:skip|bypass)/,
    description: 'Skipping transaction simulation hides malicious intent.',
    recommendation: 'Never skip simulation; ensure users see accurate previews.'
  },
  {
    id: 'SOL3718',
    name: 'Delegate Authority Abuse - No Expiry',
    severity: 'high',
    pattern: /delegate[\s\S]{0,100}(?!expiry|revoke|time_limit)/,
    description: 'Token delegation without expiry allows indefinite access.',
    recommendation: 'Add expiry timestamps and revocation to all delegations.'
  },
  {
    id: 'SOL3719',
    name: 'Unlimited Token Approval Phishing',
    severity: 'high',
    pattern: /approve[\s\S]{0,50}(?:u64::MAX|MAX_AMOUNT|unlimited)/,
    description: 'Unlimited token approval creates phishing vector.',
    recommendation: 'Approve only required amounts, implement approval limits.'
  },
  {
    id: 'SOL3720',
    name: 'Memo-Based Phishing Vector',
    severity: 'medium',
    pattern: /memo[\s\S]{0,100}(?:url|http|link)/,
    description: 'Transaction memo containing URLs may be phishing vector.',
    recommendation: 'Sanitize memo fields, warn users about embedded links.'
  },
  {
    id: 'SOL3721',
    name: 'Fake Airdrop Claim Pattern',
    severity: 'high',
    pattern: /airdrop[\s\S]{0,100}claim[\s\S]{0,100}(?!merkle_proof|whitelist_check)/,
    description: 'Airdrop claim without proper verification enables phishing.',
    recommendation: 'Use merkle proofs and whitelists for airdrop claims.'
  },
  {
    id: 'SOL3722',
    name: 'Blind Signing Risk',
    severity: 'high',
    pattern: /sign[\s\S]{0,50}(?:message|transaction)[\s\S]{0,100}(?!preview|display|show_user)/,
    description: 'Signing without clear preview enables blind signing attacks.',
    recommendation: 'Always show human-readable transaction preview before signing.'
  },
  {
    id: 'SOL3723',
    name: 'Session Key Without Expiry',
    severity: 'medium',
    pattern: /session[\s\S]{0,50}key[\s\S]{0,100}(?!expiry|ttl|timeout)/,
    description: 'Session keys without expiry create persistent access risk.',
    recommendation: 'Add TTL and scope limits to all session keys.'
  },
];

// ============================================================================
// HELIUS COMPLETE HISTORY - 2024-2025 PATTERNS
// ============================================================================

const HELIUS_RECENT_EXPLOITS: typeof DEVTO_CRITICAL_VULNS = [
  // DEXX Hot Wallet ($30M)
  {
    id: 'SOL3724',
    name: 'DEXX - Hot Wallet Key Exposure ($30M)',
    severity: 'critical',
    pattern: /(?:hot_wallet|private_key)[\s\S]{0,100}(?:store|log|expose)/,
    description: 'Hot wallet private key exposure. DEXX $30M pattern.',
    recommendation: 'Use HSM, multi-sig, and never log private keys.'
  },
  {
    id: 'SOL3725',
    name: 'DEXX - Commingled User Funds',
    severity: 'critical',
    pattern: /(?:user_funds|deposit)[\s\S]{0,100}(?:pool|shared)[\s\S]{0,100}(?!segregated|isolated)/,
    description: 'User funds commingled in shared wallet.',
    recommendation: 'Segregate user funds with individual custody accounts.'
  },

  // Pump.fun Insider ($1.9M)
  {
    id: 'SOL3726',
    name: 'Pump.fun - Insider Employee Exploit ($1.9M)',
    severity: 'critical',
    pattern: /(?:employee|admin|internal)[\s\S]{0,100}(?:access|privilege)[\s\S]{0,100}(?!audit|monitor)/,
    description: 'Insider access without monitoring. Pump.fun $1.9M pattern.',
    recommendation: 'Implement privileged access monitoring and audit trails.'
  },
  {
    id: 'SOL3727',
    name: 'Pump.fun - Bonding Curve Flash Loan',
    severity: 'high',
    pattern: /bonding[\s\S]{0,50}curve[\s\S]{0,100}(?:buy|sell)[\s\S]{0,100}(?!same_block_check)/,
    description: 'Bonding curve vulnerable to same-block flash loan manipulation.',
    recommendation: 'Add same-block detection for bonding curve operations.'
  },

  // Banana Gun ($1.4M)
  {
    id: 'SOL3728',
    name: 'Banana Gun - Trading Bot Key Storage ($1.4M)',
    severity: 'critical',
    pattern: /(?:bot|trading)[\s\S]{0,100}(?:key|secret)[\s\S]{0,100}(?:backend|server)/,
    description: 'Trading bot private keys stored on backend. Banana Gun $1.4M pattern.',
    recommendation: 'Use client-side key management, never store user keys server-side.'
  },

  // Thunder Terminal ($240K)
  {
    id: 'SOL3729',
    name: 'Thunder Terminal - MongoDB Injection ($240K)',
    severity: 'high',
    pattern: /(?:mongo|database)[\s\S]{0,100}(?:query|find)[\s\S]{0,100}(?!sanitize|validate)/,
    description: 'Database query without input sanitization. Thunder Terminal $240K pattern.',
    recommendation: 'Sanitize all database inputs, use parameterized queries.'
  },
  {
    id: 'SOL3730',
    name: 'Thunder Terminal - Session Token Leak',
    severity: 'high',
    pattern: /session[\s\S]{0,50}(?:token|jwt)[\s\S]{0,100}(?:log|expose|store)/,
    description: 'Session tokens exposed in logs or storage.',
    recommendation: 'Never log session tokens, use secure httpOnly cookies.'
  },

  // Loopscale ($5.8M)
  {
    id: 'SOL3731',
    name: 'Loopscale - PT Token Pricing Flaw ($5.8M)',
    severity: 'critical',
    pattern: /(?:pt_token|principal)[\s\S]{0,100}(?:price|value)[\s\S]{0,100}(?!maturity|discount)/,
    description: 'Principal token pricing without maturity consideration. Loopscale $5.8M pattern.',
    recommendation: 'Include maturity and discount factors in PT token pricing.'
  },
  {
    id: 'SOL3732',
    name: 'Loopscale - Flash Loan Collateralization Bypass',
    severity: 'critical',
    pattern: /collateral[\s\S]{0,100}flash[\s\S]{0,100}(?!pre_check|post_check)/,
    description: 'Collateralization check bypassable with flash loans.',
    recommendation: 'Check collateralization before and after flash loan execution.'
  },

  // NoOnes ($4M+)
  {
    id: 'SOL3733',
    name: 'NoOnes - P2P Hot Wallet Compromise ($4M)',
    severity: 'critical',
    pattern: /p2p[\s\S]{0,100}(?:wallet|fund)[\s\S]{0,100}(?:hot|online)/,
    description: 'P2P platform using hot wallets. NoOnes $4M pattern.',
    recommendation: 'Use cold storage and multi-sig for P2P escrow funds.'
  },

  // Cypher Protocol ($1.35M)
  {
    id: 'SOL3734',
    name: 'Cypher - Sub-Account Isolation Failure ($1.35M)',
    severity: 'high',
    pattern: /sub_account[\s\S]{0,100}(?!isolated|separate|boundary)/,
    description: 'Sub-accounts not properly isolated. Cypher $1.35M pattern.',
    recommendation: 'Enforce strict isolation between sub-accounts.'
  },

  // io.net Sybil
  {
    id: 'SOL3735',
    name: 'io.net - Sybil Attack on GPU Network',
    severity: 'high',
    pattern: /(?:node|provider|validator)[\s\S]{0,100}(?:register|join)[\s\S]{0,100}(?!sybil|identity_check)/,
    description: 'Network registration without Sybil protection.',
    recommendation: 'Implement identity verification and stake requirements.'
  },

  // SVT Token Honeypot
  {
    id: 'SOL3736',
    name: 'SVT Token - Honeypot Pattern',
    severity: 'high',
    pattern: /transfer[\s\S]{0,100}(?:restrict|block|pause)[\s\S]{0,100}(?:sell|out)/,
    description: 'Token with asymmetric transfer restrictions (buy ok, sell blocked).',
    recommendation: 'Detect and warn about honeypot transfer patterns.'
  },

  // Saga DAO ($230K)
  {
    id: 'SOL3737',
    name: 'Saga DAO - Governance Attack ($230K)',
    severity: 'high',
    pattern: /proposal[\s\S]{0,100}(?:execute|pass)[\s\S]{0,100}(?!notice_period|timelock)/,
    description: 'DAO proposal without notice period. Saga DAO $230K pattern.',
    recommendation: 'Require minimum notice period before proposal execution.'
  },

  // Web3.js Supply Chain ($164K)
  {
    id: 'SOL3738',
    name: 'Web3.js - NPM Supply Chain Attack ($164K)',
    severity: 'critical',
    pattern: /(?:npm|package)[\s\S]{0,100}(?:install|require)[\s\S]{0,100}(?!lockfile|integrity)/,
    description: 'Dependency without integrity verification. Web3.js $164K pattern.',
    recommendation: 'Use lockfiles, verify package integrity, audit dependencies.'
  },
];

// ============================================================================
// SEC3 2025 CATEGORY PATTERNS
// ============================================================================

const SEC3_2025_CATEGORIES: typeof DEVTO_CRITICAL_VULNS = [
  // Business Logic (38.5%)
  {
    id: 'SOL3739',
    name: 'Business Logic - State Machine Violation',
    severity: 'high',
    pattern: /state[\s\S]{0,100}(?:transition|change)[\s\S]{0,100}(?!valid_state|allowed_transition)/,
    description: 'State machine transition without validation (38.5% of all vulns).',
    recommendation: 'Define and enforce explicit state transition rules.'
  },
  {
    id: 'SOL3740',
    name: 'Business Logic - Economic Invariant',
    severity: 'critical',
    pattern: /(?:total|sum|balance)[\s\S]{0,100}(?!invariant_check|verify_sum)/,
    description: 'Missing economic invariant check allows fund manipulation.',
    recommendation: 'Verify total balance invariants after every operation.'
  },

  // Input Validation (25%)
  {
    id: 'SOL3741',
    name: 'Input Validation - Instruction Data',
    severity: 'high',
    pattern: /instruction_data[\s\S]{0,100}(?:deserialize|parse)[\s\S]{0,100}(?!validate|bounds_check)/,
    description: 'Instruction data deserialized without validation (25% of vulns).',
    recommendation: 'Validate all instruction data bounds and formats.'
  },
  {
    id: 'SOL3742',
    name: 'Input Validation - Numeric Range',
    severity: 'medium',
    pattern: /(?:amount|value|quantity)[\s\S]{0,50}:\s*u64[\s\S]{0,100}(?!min_check|max_check|range)/,
    description: 'Numeric input without range validation.',
    recommendation: 'Add minimum and maximum bounds checks for all numeric inputs.'
  },

  // Access Control (19%)
  {
    id: 'SOL3743',
    name: 'Access Control - Role Revocation Missing',
    severity: 'high',
    pattern: /role[\s\S]{0,100}(?:grant|assign)[\s\S]{0,100}(?!revoke|remove)/,
    description: 'Role assignment without revocation mechanism (19% of vulns).',
    recommendation: 'Implement role revocation for all grantable permissions.'
  },
  {
    id: 'SOL3744',
    name: 'Access Control - Time-Based Bypass',
    severity: 'medium',
    pattern: /(?:unlock|release|vest)[\s\S]{0,100}(?:time|timestamp)[\s\S]{0,100}(?!clock_check|slot_check)/,
    description: 'Time-based access control using manipulable timestamp.',
    recommendation: 'Use on-chain clock and slot for time-based controls.'
  },

  // Data Integrity (8.9%)
  {
    id: 'SOL3745',
    name: 'Data Integrity - Hash Collision',
    severity: 'medium',
    pattern: /hash[\s\S]{0,50}(?:\[0\.\.\d\]|\[\.\.8\])[\s\S]{0,100}/,
    description: 'Truncated hash increases collision risk (8.9% of vulns).',
    recommendation: 'Use full hash output for security-critical comparisons.'
  },
  {
    id: 'SOL3746',
    name: 'Data Integrity - Merkle Proof Verification',
    severity: 'high',
    pattern: /merkle[\s\S]{0,100}(?:proof|verify)[\s\S]{0,100}(?!root_check|depth_check)/,
    description: 'Merkle proof verification without root/depth validation.',
    recommendation: 'Verify proof against known root and expected depth.'
  },

  // DoS/Liveness (8.5%)
  {
    id: 'SOL3747',
    name: 'DoS - Unbounded Iteration',
    severity: 'high',
    pattern: /for[\s\S]{0,30}\.iter\(\)[\s\S]{0,100}(?!\.take\(|limit|MAX_)/,
    description: 'Unbounded iteration causes compute exhaustion (8.5% of vulns).',
    recommendation: 'Add iteration limits and pagination for all loops.'
  },
  {
    id: 'SOL3748',
    name: 'DoS - Account Spam Vector',
    severity: 'medium',
    pattern: /(?:create|init)[\s\S]{0,100}(?:account|pda)[\s\S]{0,100}(?!rate_limit|fee)/,
    description: 'Account creation without cost/rate limiting enables spam.',
    recommendation: 'Require minimum fee or rate limit account creation.'
  },
];

// ============================================================================
// ADVANCED DEFI PATTERNS
// ============================================================================

const ADVANCED_DEFI_PATTERNS: typeof DEVTO_CRITICAL_VULNS = [
  // AMM Security
  {
    id: 'SOL3749',
    name: 'AMM - Constant Product Violation',
    severity: 'critical',
    pattern: /(?:swap|trade)[\s\S]{0,100}(?!k_invariant|x_y_check|product_check)/,
    description: 'AMM swap without constant product invariant verification.',
    recommendation: 'Verify x*y=k before and after every swap.'
  },
  {
    id: 'SOL3750',
    name: 'AMM - LP Token Inflation Attack',
    severity: 'critical',
    pattern: /lp[\s\S]{0,50}mint[\s\S]{0,100}(?!deposit_check|share_calculation)/,
    description: 'LP token minting without proper share calculation.',
    recommendation: 'Calculate LP shares based on proportional deposit value.'
  },
  {
    id: 'SOL3751',
    name: 'AMM - Sandwich Attack Vector',
    severity: 'high',
    pattern: /swap[\s\S]{0,100}(?!slippage|min_out|deadline)/,
    description: 'Swap without slippage protection enables sandwich attacks.',
    recommendation: 'Require slippage tolerance and deadline for all swaps.'
  },

  // Lending Security
  {
    id: 'SOL3752',
    name: 'Lending - Health Factor Bypass',
    severity: 'critical',
    pattern: /(?:borrow|withdraw)[\s\S]{0,100}(?!health_factor|collateral_ratio)/,
    description: 'Borrow/withdraw without health factor check.',
    recommendation: 'Verify health factor remains above threshold after operation.'
  },
  {
    id: 'SOL3753',
    name: 'Lending - Liquidation Bonus Exploit',
    severity: 'high',
    pattern: /liquidation[\s\S]{0,50}bonus[\s\S]{0,100}(?!max_bonus|cap)/,
    description: 'Liquidation bonus without maximum cap.',
    recommendation: 'Cap liquidation bonus to prevent excessive extraction.'
  },
  {
    id: 'SOL3754',
    name: 'Lending - Interest Rate Manipulation',
    severity: 'high',
    pattern: /interest[\s\S]{0,50}rate[\s\S]{0,100}(?!utilization|curve|bounds)/,
    description: 'Interest rate calculation without bounds.',
    recommendation: 'Use bounded interest rate curve based on utilization.'
  },

  // Oracle Security
  {
    id: 'SOL3755',
    name: 'Oracle - Staleness Window',
    severity: 'high',
    pattern: /(?:price|oracle)[\s\S]{0,100}(?:get|read)[\s\S]{0,100}(?!staleness|timestamp|age)/,
    description: 'Oracle price read without staleness check.',
    recommendation: 'Reject oracle data older than staleness threshold.'
  },
  {
    id: 'SOL3756',
    name: 'Oracle - Confidence Interval',
    severity: 'medium',
    pattern: /(?:pyth|oracle)[\s\S]{0,100}(?:price)[\s\S]{0,100}(?!confidence|conf_interval)/,
    description: 'Oracle price without confidence interval check.',
    recommendation: 'Verify price confidence is within acceptable range.'
  },
  {
    id: 'SOL3757',
    name: 'Oracle - TWAP Window Manipulation',
    severity: 'high',
    pattern: /twap[\s\S]{0,100}(?:window|period)[\s\S]{0,100}(?!min_samples|sufficient_history)/,
    description: 'TWAP with insufficient sample window.',
    recommendation: 'Require minimum samples and time window for TWAP.'
  },

  // Governance Security
  {
    id: 'SOL3758',
    name: 'Governance - Flash Vote Attack',
    severity: 'critical',
    pattern: /(?:vote|voting)[\s\S]{0,100}(?!snapshot|lock_period|checkpoint)/,
    description: 'Voting without snapshot enables flash loan voting.',
    recommendation: 'Use token snapshots for voting weight calculation.'
  },
  {
    id: 'SOL3759',
    name: 'Governance - Execution Delay Missing',
    severity: 'high',
    pattern: /proposal[\s\S]{0,100}execute[\s\S]{0,100}(?!timelock|delay|wait_period)/,
    description: 'Proposal execution without timelock delay.',
    recommendation: 'Add mandatory delay between proposal passing and execution.'
  },
  {
    id: 'SOL3760',
    name: 'Governance - Quorum Manipulation',
    severity: 'high',
    pattern: /quorum[\s\S]{0,100}(?!percentage|dynamic|adjusted)/,
    description: 'Static quorum vulnerable to supply manipulation.',
    recommendation: 'Use dynamic quorum based on participation rate.'
  },

  // Staking Security
  {
    id: 'SOL3761',
    name: 'Staking - Reward Dilution Attack',
    severity: 'high',
    pattern: /reward[\s\S]{0,100}(?:distribute|claim)[\s\S]{0,100}(?!per_share|checkpoint)/,
    description: 'Reward distribution without per-share tracking.',
    recommendation: 'Use accumulated rewards per share for fair distribution.'
  },
  {
    id: 'SOL3762',
    name: 'Staking - Unbonding Period Bypass',
    severity: 'high',
    pattern: /unstake[\s\S]{0,100}(?!unbonding|cooldown|wait_period)/,
    description: 'Unstaking without unbonding period.',
    recommendation: 'Enforce minimum unbonding period for stake withdrawals.'
  },

  // Bridge Security
  {
    id: 'SOL3763',
    name: 'Bridge - Message Replay Attack',
    severity: 'critical',
    pattern: /bridge[\s\S]{0,100}(?:message|payload)[\s\S]{0,100}(?!nonce|replay_check|used_message)/,
    description: 'Bridge message without replay protection.',
    recommendation: 'Track used message nonces and reject replays.'
  },
  {
    id: 'SOL3764',
    name: 'Bridge - Source Chain Finality',
    severity: 'critical',
    pattern: /bridge[\s\S]{0,100}(?:confirm|verify)[\s\S]{0,100}(?!finality|confirmations)/,
    description: 'Bridge message accepted without finality confirmation.',
    recommendation: 'Wait for source chain finality before processing.'
  },
];

// ============================================================================
// TOKEN-2022 ADVANCED PATTERNS
// ============================================================================

const TOKEN_2022_ADVANCED: typeof DEVTO_CRITICAL_VULNS = [
  {
    id: 'SOL3765',
    name: 'Token-2022 - Transfer Hook Reentrancy',
    severity: 'critical',
    pattern: /transfer_hook[\s\S]{0,100}(?!reentrancy_guard|state_check)/,
    description: 'Transfer hook callback vulnerable to reentrancy.',
    recommendation: 'Add reentrancy guard for all transfer hook callbacks.'
  },
  {
    id: 'SOL3766',
    name: 'Token-2022 - Confidential Transfer Decryption',
    severity: 'high',
    pattern: /confidential[\s\S]{0,100}(?:decrypt|reveal)[\s\S]{0,100}(?!authorized|proof)/,
    description: 'Confidential transfer decryption without authorization.',
    recommendation: 'Require authorization proof for balance decryption.'
  },
  {
    id: 'SOL3767',
    name: 'Token-2022 - Transfer Fee Bypass',
    severity: 'high',
    pattern: /transfer[\s\S]{0,100}(?!fee_check|collect_fee)[\s\S]{0,50}token_2022/,
    description: 'Token-2022 transfer without fee collection.',
    recommendation: 'Ensure transfer fees are collected on every transfer.'
  },
  {
    id: 'SOL3768',
    name: 'Token-2022 - Interest Bearing Manipulation',
    severity: 'high',
    pattern: /interest[\s\S]{0,100}(?:accrue|compound)[\s\S]{0,100}(?!rate_limit|max_rate)/,
    description: 'Interest bearing token without rate limits.',
    recommendation: 'Cap interest rate and accrual frequency.'
  },
  {
    id: 'SOL3769',
    name: 'Token-2022 - Permanent Delegate Abuse',
    severity: 'critical',
    pattern: /permanent[\s\S]{0,50}delegate[\s\S]{0,100}(?!revocable|user_consent)/,
    description: 'Permanent delegate without revocation mechanism.',
    recommendation: 'Allow users to revoke permanent delegates.'
  },
  {
    id: 'SOL3770',
    name: 'Token-2022 - Metadata Pointer Spoofing',
    severity: 'medium',
    pattern: /metadata[\s\S]{0,50}pointer[\s\S]{0,100}(?!verify|validate)/,
    description: 'Metadata pointer accepted without verification.',
    recommendation: 'Verify metadata pointer points to valid, owned account.'
  },
];

// ============================================================================
// VALIDATOR/INFRASTRUCTURE PATTERNS
// ============================================================================

const INFRASTRUCTURE_PATTERNS: typeof DEVTO_CRITICAL_VULNS = [
  {
    id: 'SOL3771',
    name: 'Validator - Jito Client Concentration (88%)',
    severity: 'medium',
    pattern: /(?:validator|client)[\s\S]{0,100}(?:jito|mev)[\s\S]{0,100}(?!diversity|fallback)/,
    description: 'Jito client 88% concentration creates systemic risk.',
    recommendation: 'Support multiple validator clients for resilience.'
  },
  {
    id: 'SOL3772',
    name: 'RPC - Provider Manipulation',
    severity: 'high',
    pattern: /rpc[\s\S]{0,100}(?:url|endpoint)[\s\S]{0,100}(?!trusted|verified|multi_provider)/,
    description: 'Single RPC provider dependency enables manipulation.',
    recommendation: 'Use multiple trusted RPC providers with verification.'
  },
  {
    id: 'SOL3773',
    name: 'Address Lookup Table - Poisoning',
    severity: 'high',
    pattern: /lookup_table[\s\S]{0,100}(?:use|extend)[\s\S]{0,100}(?!verify|trusted)/,
    description: 'Address lookup table used without verification.',
    recommendation: 'Verify lookup table ownership and contents.'
  },
  {
    id: 'SOL3774',
    name: 'Priority Fee - Front-Running Vector',
    severity: 'medium',
    pattern: /priority[\s\S]{0,50}fee[\s\S]{0,100}(?!private|jito_bundle)/,
    description: 'Public priority fee enables front-running.',
    recommendation: 'Use private transactions or Jito bundles for MEV protection.'
  },
  {
    id: 'SOL3775',
    name: 'Durable Nonce - Replay Attack',
    severity: 'high',
    pattern: /durable[\s\S]{0,50}nonce[\s\S]{0,100}(?!advance|consumed)/,
    description: 'Durable nonce not advanced after use enables replay.',
    recommendation: 'Always advance nonce after transaction execution.'
  },
];

// ============================================================================
// EXPORT ALL PATTERNS
// ============================================================================

export const BATCH_76_PATTERNS = [
  ...DEVTO_CRITICAL_VULNS,
  ...SOLSEC_POC_PATTERNS,
  ...SLOWMIST_PHISHING,
  ...HELIUS_RECENT_EXPLOITS,
  ...SEC3_2025_CATEGORIES,
  ...ADVANCED_DEFI_PATTERNS,
  ...TOKEN_2022_ADVANCED,
  ...INFRASTRUCTURE_PATTERNS,
];

export function scanBatch76(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.content;
  const filePath = input.filePath || 'unknown';

  for (const pattern of BATCH_76_PATTERNS) {
    const match = pattern.pattern.exec(content);
    if (match) {
      const lines = content.substring(0, match.index).split('\n');
      const line = lines.length;
      
      findings.push({
        id: pattern.id,
        name: pattern.name,
        severity: pattern.severity,
        description: pattern.description,
        recommendation: pattern.recommendation,
        file: filePath,
        line,
        snippet: match[0].substring(0, 200),
      });
    }
  }

  return findings;
}

// Pattern count: 100 patterns (SOL3676 - SOL3775)
export const BATCH_76_COUNT = BATCH_76_PATTERNS.length;
