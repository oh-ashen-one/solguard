/**
 * Batch 108: Sec3 2025 Report + arXiv:2504.07419 Academic Research
 * 
 * Sources:
 * 1. Sec3 2025 Report: 163 audits, 1,669 vulnerabilities analyzed
 *    - Business Logic: 38.5% | Input Validation: 25% | Access Control: 19%
 *    - Data Integrity: 8.9% | DoS/Liveness: 8.5%
 * 2. arXiv:2504.07419 - "Exploring Vulnerabilities in Solana Smart Contracts"
 *    - Lack of Signer/Owner Check, Rent-Exemption, Account Confusion, Re-initialization
 * 3. Academic security analysis tool comparison (113 Ethereum vs 12 Solana tools)
 * 
 * Pattern IDs: SOL7051-SOL7200
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

const BATCH_108_PATTERNS: PatternDef[] = [
  // ============================================
  // SEC3 2025: BUSINESS LOGIC (38.5% of all vulns)
  // SOL7051-SOL7080
  // ============================================
  {
    id: 'SOL7051',
    name: 'Sec3: State Transition Logic Flaw',
    severity: 'high',
    pattern: /(?:state|status)\s*=\s*\w+(?![\s\S]{0,100}(?:require!|assert!|match))/i,
    description: 'State transition without validation. Business logic flaws are 38.5% of all Sec3 findings.',
    recommendation: 'Validate state transitions: require!(valid_transition(old_state, new_state))'
  },
  {
    id: 'SOL7052',
    name: 'Sec3: Invariant Violation Risk',
    severity: 'critical',
    pattern: /(?:fn\s+\w+)[\s\S]{0,500}(?:balance|amount)[\s\S]{0,100}(?!invariant|assert_eq)/i,
    description: 'Function modifying balances without invariant check. Top business logic vuln in Sec3 report.',
    recommendation: 'Add invariant checks: assert!(total_before == total_after)'
  },
  {
    id: 'SOL7053',
    name: 'Sec3: Protocol Logic Assumption',
    severity: 'high',
    pattern: /(?:if|require!)[\s\S]{0,50}(?:>|<|==)\s*0(?![\s\S]{0,50}edge_case)/i,
    description: 'Boundary condition check may miss edge cases. Business logic category.',
    recommendation: 'Test all boundary conditions: 0, 1, max-1, max values.'
  },
  {
    id: 'SOL7054',
    name: 'Sec3: Fee Calculation Logic',
    severity: 'high',
    pattern: /fee[\s\S]{0,50}(?:\*|\/|\%)(?![\s\S]{0,100}(?:checked|saturating|round))/i,
    description: 'Fee calculation without proper arithmetic handling. Rounding errors in fees.',
    recommendation: 'Use checked arithmetic and explicit rounding for fee calculations.'
  },
  {
    id: 'SOL7055',
    name: 'Sec3: Reward Distribution Logic',
    severity: 'high',
    pattern: /reward[\s\S]{0,100}(?:distribute|claim)(?![\s\S]{0,100}(?:epoch|period|total))/i,
    description: 'Reward distribution without epoch/period tracking. Double-claim possible.',
    recommendation: 'Track reward epochs and validate claim eligibility per period.'
  },
  {
    id: 'SOL7056',
    name: 'Sec3: Auction Logic Vulnerability',
    severity: 'high',
    pattern: /(?:bid|auction)[\s\S]{0,100}(?:end|close)(?![\s\S]{0,100}(?:timestamp|slot|block))/i,
    description: 'Auction logic without time validation. Last-second manipulation possible.',
    recommendation: 'Use on-chain time (Clock::get) for auction deadlines.'
  },
  {
    id: 'SOL7057',
    name: 'Sec3: Voting Logic Flaw',
    severity: 'high',
    pattern: /(?:vote|proposal)[\s\S]{0,100}(?:count|tally)(?![\s\S]{0,100}weight)/i,
    description: 'Voting without weight consideration. Token-weighted votes ignored.',
    recommendation: 'Implement weighted voting based on token holdings.'
  },
  {
    id: 'SOL7058',
    name: 'Sec3: Escrow Release Logic',
    severity: 'critical',
    pattern: /escrow[\s\S]{0,100}release(?![\s\S]{0,150}(?:condition|require!|assert!))/i,
    description: 'Escrow release without condition verification. Premature release possible.',
    recommendation: 'Validate all escrow conditions before release.'
  },
  {
    id: 'SOL7059',
    name: 'Sec3: Vesting Schedule Logic',
    severity: 'high',
    pattern: /(?:vesting|unlock)[\s\S]{0,100}(?:claim|withdraw)(?![\s\S]{0,100}schedule)/i,
    description: 'Vesting claim without schedule validation. Cliff/linear vesting bypassed.',
    recommendation: 'Verify vesting schedule and cliff period before claims.'
  },
  {
    id: 'SOL7060',
    name: 'Sec3: Staking Compound Logic',
    severity: 'medium',
    pattern: /(?:stake|compound)[\s\S]{0,100}(?:reward|interest)(?![\s\S]{0,100}(?:last_|previous_))/i,
    description: 'Staking rewards without tracking last claim time. Exploitation possible.',
    recommendation: 'Track last_reward_claim timestamp per user.'
  },

  // ============================================
  // SEC3 2025: INPUT VALIDATION (25% of all vulns)
  // SOL7061-SOL7085
  // ============================================
  {
    id: 'SOL7061',
    name: 'Sec3: Missing Amount Validation',
    severity: 'high',
    pattern: /amount[\s\S]{0,30}:\s*u64(?![\s\S]{0,100}(?:require!|>|<|!=\s*0))/i,
    description: 'Amount parameter without validation. Zero amounts or overflow not checked.',
    recommendation: 'Validate: require!(amount > 0 && amount <= MAX_AMOUNT)'
  },
  {
    id: 'SOL7062',
    name: 'Sec3: Unchecked User Input Length',
    severity: 'medium',
    pattern: /(?:String|Vec<u8>|str)[\s\S]{0,50}(?![\s\S]{0,100}(?:len\(\)|max_len|limit))/i,
    description: 'Variable-length input without size check. DoS via large inputs.',
    recommendation: 'Add length limits: require!(input.len() <= MAX_LENGTH)'
  },
  {
    id: 'SOL7063',
    name: 'Sec3: Numeric Range Not Validated',
    severity: 'high',
    pattern: /(?:rate|percentage|basis_points)[\s\S]{0,50}(?![\s\S]{0,100}(?:<=\s*\d|bounds))/i,
    description: 'Rate/percentage without bounds check. 100% or 10000bps exceeded.',
    recommendation: 'Validate: require!(rate <= 10000) // 100% in basis points'
  },
  {
    id: 'SOL7064',
    name: 'Sec3: Slippage Tolerance Missing',
    severity: 'high',
    pattern: /(?:swap|trade|exchange)[\s\S]{0,200}(?!slippage|min_amount_out|max_amount_in)/i,
    description: 'Trade operation without slippage protection. Front-running vulnerable.',
    recommendation: 'Add slippage check: require!(amount_out >= min_amount_out)'
  },
  {
    id: 'SOL7065',
    name: 'Sec3: Deadline Not Enforced',
    severity: 'medium',
    pattern: /(?:swap|trade|order)[\s\S]{0,200}(?!deadline|expires|valid_until)/i,
    description: 'Transaction without deadline. Stale transactions executed.',
    recommendation: 'Add deadline: require!(Clock::get()?.unix_timestamp <= deadline)'
  },
  {
    id: 'SOL7066',
    name: 'Sec3: Array Index Unchecked',
    severity: 'high',
    pattern: /\[\s*\w+\s*\](?![\s\S]{0,30}(?:get\(|\.len\(\)|bounds))/i,
    description: 'Array access without bounds check. Panic on out-of-bounds.',
    recommendation: 'Use .get(index) instead of [index] for safe access.'
  },
  {
    id: 'SOL7067',
    name: 'Sec3: Pubkey Zero Check Missing',
    severity: 'high',
    pattern: /(?:authority|owner|admin)[\s\S]{0,50}Pubkey(?![\s\S]{0,100}(?:!=\s*Pubkey::default|!= default))/i,
    description: 'Pubkey not checked for zero/default. Can set to invalid authority.',
    recommendation: 'Validate: require!(pubkey != Pubkey::default())'
  },
  {
    id: 'SOL7068',
    name: 'Sec3: Timestamp Future Check Missing',
    severity: 'medium',
    pattern: /timestamp[\s\S]{0,50}(?![\s\S]{0,100}(?:<=\s*Clock|future|now))/i,
    description: 'User-provided timestamp not validated against current time.',
    recommendation: 'Validate: require!(timestamp <= Clock::get()?.unix_timestamp)'
  },
  {
    id: 'SOL7069',
    name: 'Sec3: Price Impact Not Validated',
    severity: 'high',
    pattern: /(?:price|rate)[\s\S]{0,100}(?:impact|change)(?![\s\S]{0,100}(?:max|limit|threshold))/i,
    description: 'Price impact not limited. Large trades cause excessive slippage.',
    recommendation: 'Enforce max price impact: require!(impact <= MAX_IMPACT)'
  },
  {
    id: 'SOL7070',
    name: 'Sec3: Seed Input Validation',
    severity: 'high',
    pattern: /seeds\s*=\s*\[[\s\S]{0,100}(?:user_input|param)(?![\s\S]{0,50}validate)/i,
    description: 'User input used in PDA seeds without validation. Seed injection possible.',
    recommendation: 'Sanitize all user inputs used in PDA seed derivation.'
  },

  // ============================================
  // SEC3 2025: ACCESS CONTROL (19% of all vulns)
  // SOL7071-SOL7090
  // ============================================
  {
    id: 'SOL7071',
    name: 'Sec3: Admin Function Exposed',
    severity: 'critical',
    pattern: /(?:pub\s+fn|fn)\s+(?:admin|update_config|set_authority)(?![\s\S]{0,100}(?:has_one|constraint))/i,
    description: 'Admin function without access constraint. 19% of Sec3 findings are access control.',
    recommendation: 'Add: #[account(has_one = admin)]'
  },
  {
    id: 'SOL7072',
    name: 'Sec3: Role-Based Access Missing',
    severity: 'high',
    pattern: /(?:minter|operator|manager)[\s\S]{0,100}(?!role|permission|authorized)/i,
    description: 'Privileged operation without role verification.',
    recommendation: 'Implement role-based access: require!(has_role(MINTER_ROLE))'
  },
  {
    id: 'SOL7073',
    name: 'Sec3: Upgrade Authority Not Protected',
    severity: 'critical',
    pattern: /(?:upgrade|migrate)[\s\S]{0,100}authority(?![\s\S]{0,100}(?:multisig|timelock|governance))/i,
    description: 'Upgrade authority without additional protection. Single key can upgrade.',
    recommendation: 'Use multisig + timelock for upgrade authority.'
  },
  {
    id: 'SOL7074',
    name: 'Sec3: Pause Function Unprotected',
    severity: 'high',
    pattern: /(?:pause|unpause|emergency)[\s\S]{0,100}(?!authority|admin|guardian)/i,
    description: 'Emergency pause without guardian check. Anyone can pause/unpause.',
    recommendation: 'Restrict pause to guardian: require!(signer == guardian)'
  },
  {
    id: 'SOL7075',
    name: 'Sec3: Token Mint Authority Check',
    severity: 'critical',
    pattern: /mint_to|MintTo(?![\s\S]{0,100}mint_authority)/i,
    description: 'Minting without mint authority verification.',
    recommendation: 'Verify: require!(signer == mint.mint_authority)'
  },
  {
    id: 'SOL7076',
    name: 'Sec3: Freeze Authority Exposure',
    severity: 'high',
    pattern: /freeze|FreezeAccount(?![\s\S]{0,100}(?:authority|constraint))/i,
    description: 'Freeze operation without authority check.',
    recommendation: 'Verify freeze authority before freeze operations.'
  },
  {
    id: 'SOL7077',
    name: 'Sec3: Close Authority Missing',
    severity: 'high',
    pattern: /close[\s\S]{0,50}account(?![\s\S]{0,100}close_authority)/i,
    description: 'Account close without close_authority verification.',
    recommendation: 'Check close authority: require!(signer == close_authority)'
  },
  {
    id: 'SOL7078',
    name: 'Sec3: Delegate Authority Check',
    severity: 'high',
    pattern: /delegate[\s\S]{0,100}(?:amount|approve)(?![\s\S]{0,100}(?:owner|authority))/i,
    description: 'Token delegation without owner check.',
    recommendation: 'Verify token owner before delegating.'
  },
  {
    id: 'SOL7079',
    name: 'Sec3: Whitelist Not Enforced',
    severity: 'medium',
    pattern: /whitelist(?![\s\S]{0,100}(?:contains|include|require!))/i,
    description: 'Whitelist defined but not enforced in operations.',
    recommendation: 'Enforce: require!(whitelist.contains(&user))'
  },
  {
    id: 'SOL7080',
    name: 'Sec3: Blacklist Bypass Possible',
    severity: 'medium',
    pattern: /blacklist(?![\s\S]{0,100}(?:!contains|exclude|require!))/i,
    description: 'Blacklist check can be bypassed.',
    recommendation: 'Enforce: require!(!blacklist.contains(&user))'
  },

  // ============================================
  // SEC3 2025: DATA INTEGRITY & ARITHMETIC (8.9%)
  // SOL7081-SOL7100
  // ============================================
  {
    id: 'SOL7081',
    name: 'Sec3: Division Before Multiplication',
    severity: 'high',
    pattern: /\/[\s\S]{0,20}\*(?![\s\S]{0,30}(?:u128|checked))/i,
    description: 'Division before multiplication causes precision loss.',
    recommendation: 'Multiply first, then divide: (a * b) / c'
  },
  {
    id: 'SOL7082',
    name: 'Sec3: Precision Loss in Conversion',
    severity: 'medium',
    pattern: /as\s+u(?:8|16|32)(?![\s\S]{0,30}try_into)/i,
    description: 'Unsafe downcast loses precision. u64 to u32 can truncate.',
    recommendation: 'Use try_into() for safe conversion.'
  },
  {
    id: 'SOL7083',
    name: 'Sec3: Rounding Direction Not Specified',
    severity: 'medium',
    pattern: /\/\s*\w+(?![\s\S]{0,50}(?:ceil|floor|round))/i,
    description: 'Division without explicit rounding direction.',
    recommendation: 'Specify rounding: use div_ceil() or div_floor() as appropriate.'
  },
  {
    id: 'SOL7084',
    name: 'Sec3: Share Calculation Precision',
    severity: 'high',
    pattern: /(?:share|portion|ratio)[\s\S]{0,50}(?:\*|\/|\%)(?![\s\S]{0,50}(?:u128|PRECISION))/i,
    description: 'Share calculation without precision scaling.',
    recommendation: 'Scale with PRECISION: (amount * PRECISION) / total_shares'
  },
  {
    id: 'SOL7085',
    name: 'Sec3: LP Token Math',
    severity: 'critical',
    pattern: /(?:lp_token|liquidity)[\s\S]{0,100}(?:mint|burn)[\s\S]{0,100}(?!sqrt|geometric)/i,
    description: 'LP token calculation without proper AMM math.',
    recommendation: 'Use sqrt for initial LP: sqrt(amount0 * amount1)'
  },
  {
    id: 'SOL7086',
    name: 'Sec3: Interest Compound Error',
    severity: 'high',
    pattern: /interest[\s\S]{0,100}(?:rate|compound)(?![\s\S]{0,100}(?:exp|power|accumulator))/i,
    description: 'Interest calculation without proper compounding.',
    recommendation: 'Use exponential for compound interest.'
  },
  {
    id: 'SOL7087',
    name: 'Sec3: Fee Rounding Favor',
    severity: 'medium',
    pattern: /fee[\s\S]{0,50}(?:\/|div)(?![\s\S]{0,50}(?:ceil|protocol_favor))/i,
    description: 'Fee rounding may favor user over protocol.',
    recommendation: 'Round fees UP (ceil) to favor protocol.'
  },
  {
    id: 'SOL7088',
    name: 'Sec3: Oracle Price Decimal Mismatch',
    severity: 'critical',
    pattern: /(?:price|oracle)[\s\S]{0,100}(?:decimal|exponent)(?![\s\S]{0,100}normalize)/i,
    description: 'Oracle price not normalized for token decimals.',
    recommendation: 'Normalize prices: price * 10^(target_decimals - oracle_decimals)'
  },
  {
    id: 'SOL7089',
    name: 'Sec3: Accumulator Overflow Risk',
    severity: 'high',
    pattern: /accumulator[\s\S]{0,50}(?:\+=|\+\s*=)(?![\s\S]{0,30}checked)/i,
    description: 'Accumulator addition without overflow check.',
    recommendation: 'Use checked arithmetic for accumulators.'
  },
  {
    id: 'SOL7090',
    name: 'Sec3: Timestamp Arithmetic Unsafe',
    severity: 'medium',
    pattern: /(?:unix_timestamp|slot)[\s\S]{0,50}(?:-|\+)[\s\S]{0,50}(?!checked)/i,
    description: 'Timestamp arithmetic can underflow (negative time).',
    recommendation: 'Use checked_sub for timestamp differences.'
  },

  // ============================================
  // SEC3 2025: DOS & LIVENESS (8.5%)
  // SOL7091-SOL7110
  // ============================================
  {
    id: 'SOL7091',
    name: 'Sec3: Unbounded Loop DoS',
    severity: 'high',
    pattern: /(?:for|while|loop)[\s\S]{0,50}(?:\.iter\(\)|\.len\(\))(?![\s\S]{0,100}(?:limit|MAX_|take\())/i,
    description: 'Loop over unbounded collection. DoS via large array.',
    recommendation: 'Add iteration limit: .take(MAX_ITERATIONS)'
  },
  {
    id: 'SOL7092',
    name: 'Sec3: Compute Unit Exhaustion',
    severity: 'high',
    pattern: /(?:for|loop)[\s\S]{0,200}(?:invoke|cpi|transfer)(?![\s\S]{0,100}batch)/i,
    description: 'Multiple CPIs in loop can exhaust compute units.',
    recommendation: 'Batch operations or limit per-transaction count.'
  },
  {
    id: 'SOL7093',
    name: 'Sec3: Account Resize DoS',
    severity: 'medium',
    pattern: /realloc(?![\s\S]{0,100}(?:MAX_SIZE|limit))/i,
    description: 'Account realloc without size limit. Rent attack possible.',
    recommendation: 'Set maximum account size limit.'
  },
  {
    id: 'SOL7094',
    name: 'Sec3: Vector Push DoS',
    severity: 'medium',
    pattern: /\.push\((?![\s\S]{0,100}(?:capacity|MAX_))/i,
    description: 'Unbounded vector growth. Memory exhaustion possible.',
    recommendation: 'Limit vector capacity: require!(vec.len() < MAX_LEN)'
  },
  {
    id: 'SOL7095',
    name: 'Sec3: HashMap DoS Attack',
    severity: 'medium',
    pattern: /HashMap[\s\S]{0,100}insert(?![\s\S]{0,100}(?:capacity|MAX_))/i,
    description: 'Unbounded HashMap insertion. Memory and compute DoS.',
    recommendation: 'Limit map size and use efficient key patterns.'
  },
  {
    id: 'SOL7096',
    name: 'Sec3: Recursive Call Stack',
    severity: 'high',
    pattern: /fn\s+(\w+)[\s\S]{0,200}\1\s*\(/i,
    description: 'Recursive function call. Stack overflow on deep recursion.',
    recommendation: 'Limit recursion depth or use iterative approach.'
  },
  {
    id: 'SOL7097',
    name: 'Sec3: String Concatenation DoS',
    severity: 'low',
    pattern: /format!\s*\([\s\S]{0,100}\{\}[\s\S]{0,100}(?:user|input)/i,
    description: 'String formatting with user input. Memory allocation attack.',
    recommendation: 'Validate and limit string input lengths.'
  },
  {
    id: 'SOL7098',
    name: 'Sec3: CPI Return Data Overflow',
    severity: 'medium',
    pattern: /set_return_data(?![\s\S]{0,50}(?:MAX_|limit))/i,
    description: 'CPI return data without size limit (1024 bytes max).',
    recommendation: 'Limit return data: require!(data.len() <= MAX_RETURN_DATA)'
  },
  {
    id: 'SOL7099',
    name: 'Sec3: Serialization Size Attack',
    severity: 'medium',
    pattern: /(?:serialize|try_to_vec)(?![\s\S]{0,100}(?:MAX_|limit))/i,
    description: 'Serialization without size validation.',
    recommendation: 'Check serialized size before writing.'
  },
  {
    id: 'SOL7100',
    name: 'Sec3: Log Spam Attack',
    severity: 'low',
    pattern: /msg!\s*\([\s\S]{0,50}(?:for|loop|while)/i,
    description: 'Logging in loop. Log buffer exhaustion.',
    recommendation: 'Limit logging in loops or use aggregate logs.'
  },

  // ============================================
  // ARXIV: LACK OF CHECK PATTERNS (SOL7101-SOL7120)
  // From arXiv:2504.07419 Section 3.1
  // ============================================
  {
    id: 'SOL7101',
    name: 'arXiv 3.1.1: Signer Check Pattern',
    severity: 'critical',
    pattern: /(?:config|state)\.(?:admin|authority)\s*==[\s\S]{0,50}(?!is_signer)/i,
    description: 'arXiv Listing 1 pattern: Admin check without signature verification.',
    recommendation: 'Add: if !admin.is_signer { return Err(MissingRequiredSignature) }'
  },
  {
    id: 'SOL7102',
    name: 'arXiv 3.1.1: Update Admin Vulnerability',
    severity: 'critical',
    pattern: /(?:update|set)_admin[\s\S]{0,200}(?:new_admin|admin)[\s\S]{0,100}(?!is_signer)/i,
    description: 'arXiv: Admin update function accepting pubkey without signature proof.',
    recommendation: 'Verify current admin signed the transaction.'
  },
  {
    id: 'SOL7103',
    name: 'arXiv 3.1.2: Owner Check Pattern',
    severity: 'critical',
    pattern: /AccountInfo[\s\S]{0,100}(?:config|vault|state)(?![\s\S]{0,100}\.owner)/i,
    description: 'arXiv 3.1.2: Reading account data without owner verification.',
    recommendation: 'Add: if account.owner != program_id { return Err(IllegalOwner) }'
  },
  {
    id: 'SOL7104',
    name: 'arXiv 3.1.2: Forged Account Attack',
    severity: 'critical',
    pattern: /(?:unpack|deserialize)[\s\S]{0,100}(?:AccountInfo|account)(?![\s\S]{0,100}owner)/i,
    description: 'arXiv: Deserializing account without ownership check. Fake account injection.',
    recommendation: 'Verify owner before unpacking account data.'
  },
  {
    id: 'SOL7105',
    name: 'arXiv 3.1.3: Rent Exemption Check',
    severity: 'medium',
    pattern: /(?:Account|Mint|Multisig)(?![\s\S]{0,100}(?:rent_exempt|minimum_balance))/i,
    description: 'arXiv 3.1.3: Token account without rent-exemption verification.',
    recommendation: 'Verify: lamports >= Rent::get()?.minimum_balance(data_len)'
  },
  {
    id: 'SOL7106',
    name: 'arXiv 3.1.3: Low Balance Eviction Risk',
    severity: 'medium',
    pattern: /lamports[\s\S]{0,50}(?:sub|transfer)(?![\s\S]{0,100}rent_exempt)/i,
    description: 'arXiv: Lamport reduction without rent-exemption check. Account eviction.',
    recommendation: 'Ensure remaining lamports >= rent-exempt minimum.'
  },

  // ============================================
  // ARXIV: CONFLATION PATTERNS (SOL7111-SOL7130)
  // From arXiv:2504.07419 Section 3.2
  // ============================================
  {
    id: 'SOL7111',
    name: 'arXiv 3.2.1: Account Type Confusion',
    severity: 'critical',
    pattern: /(?:Account|State)[\s\S]{0,100}(?:unpack|from_slice)(?![\s\S]{0,100}(?:tag|discriminator|type))/i,
    description: 'arXiv 3.2.1: Account type not validated. Different account types conflated.',
    recommendation: 'Validate account type tag before deserialization.'
  },
  {
    id: 'SOL7112',
    name: 'arXiv 3.2.1: Data Format Version',
    severity: 'high',
    pattern: /(?:upgrade|migrate)[\s\S]{0,100}(?:data|account)(?![\s\S]{0,100}version)/i,
    description: 'arXiv: Account data format upgrade without version tracking.',
    recommendation: 'Add version field and check on deserialization.'
  },
  {
    id: 'SOL7113',
    name: 'arXiv 3.2.2: Cross-Instance Confusion',
    severity: 'critical',
    pattern: /(?:init|initialize)[\s\S]{0,200}(?!is_initialized|state\s*==)/i,
    description: 'arXiv 3.2.2: Initialization without state check. Re-initialization attack.',
    recommendation: 'Check: require!(!account.is_initialized)'
  },
  {
    id: 'SOL7114',
    name: 'arXiv 3.2.2: Shared State Vulnerability',
    severity: 'critical',
    pattern: /(?:global|shared)[\s\S]{0,50}(?:state|config)(?![\s\S]{0,100}(?:instance|unique))/i,
    description: 'arXiv: Multiple instances sharing state. Cross-instance attack.',
    recommendation: 'Use unique PDA seeds per instance.'
  },
  {
    id: 'SOL7115',
    name: 'arXiv: Re-initialization Attack',
    severity: 'critical',
    pattern: /fn\s+initialize[\s\S]{0,300}(?!require!\s*\(!|if\s+!|is_initialized)/i,
    description: 'arXiv: Initialize function callable multiple times.',
    recommendation: 'Add: require!(!account.is_initialized, AlreadyInitialized)'
  },

  // ============================================
  // ARXIV: TOOL-BASED DETECTION PATTERNS (SOL7121-SOL7140)
  // Based on tool capabilities from arXiv Section 2
  // ============================================
  {
    id: 'SOL7121',
    name: 'arXiv Tools: Checked Math Detection',
    severity: 'high',
    pattern: /(?:\+|-|\*)\s*(?:\d+|amount|value)(?![\s\S]{0,30}(?:checked_|saturating_|wrapping_))/i,
    description: 'Pattern detectable by Blockworks Checked Math tool.',
    recommendation: 'Use checked_add(), checked_sub(), checked_mul().'
  },
  {
    id: 'SOL7122',
    name: 'arXiv Tools: Unsafe Dependency',
    severity: 'medium',
    pattern: /(?:solana-sdk|anchor-lang)\s*=\s*"[<>=]*\d+\.\d+(?![\s\S]{0,30}locked)/i,
    description: 'Pattern detectable by cargo-audit tool. Unpinned dependency.',
    recommendation: 'Use exact version pins or lock file.'
  },
  {
    id: 'SOL7123',
    name: 'arXiv Tools: Semgrep Pattern',
    severity: 'high',
    pattern: /\.unwrap\(\)|\.expect\([\s\S]{0,50}(?:should|will|must)/i,
    description: 'Pattern detectable by Kudelski Semgrep. Panic on error.',
    recommendation: 'Use ? operator or match for error handling.'
  },
  {
    id: 'SOL7124',
    name: 'arXiv Tools: Trdelnik Fuzzing Target',
    severity: 'medium',
    pattern: /(?:pub|fn)\s+\w+[\s\S]{0,100}(?:amount|value)[\s\S]{0,50}u64/i,
    description: 'Function should be fuzz tested (Trdelnik pattern).',
    recommendation: 'Add fuzz tests for functions with numeric inputs.'
  },
  {
    id: 'SOL7125',
    name: 'arXiv Tools: PoC Framework Target',
    severity: 'info',
    pattern: /(?:transfer|withdraw|deposit|swap)[\s\S]{0,200}invoke/i,
    description: 'High-value operation should have PoC test (sol-ctf-framework).',
    recommendation: 'Write proof-of-concept exploit tests.'
  },

  // ============================================
  // ARXIV: SOLANA-SPECIFIC PATTERNS (SOL7131-SOL7150)
  // From arXiv comparison with Ethereum
  // ============================================
  {
    id: 'SOL7131',
    name: 'arXiv: Decoupled Code-Data Risk',
    severity: 'high',
    pattern: /AccountInfo[\s\S]{0,100}(?:try_borrow_data|data\.borrow)(?![\s\S]{0,100}owner)/i,
    description: 'arXiv: Solana decouples code and data. Account data read without validation.',
    recommendation: 'Always verify account owner and type before data access.'
  },
  {
    id: 'SOL7132',
    name: 'arXiv: Anyone Can Call Pattern',
    severity: 'high',
    pattern: /pub\s+fn\s+process[\s\S]{0,100}accounts[\s\S]{0,200}(?!authority|signer)/i,
    description: 'arXiv: Solana programs accept calls from anyone. No implicit auth.',
    recommendation: 'Explicitly check callers have appropriate permissions.'
  },
  {
    id: 'SOL7133',
    name: 'arXiv: Input Parameters Untrusted',
    severity: 'high',
    pattern: /instruction_data[\s\S]{0,50}(?:deserialize|unpack)(?![\s\S]{0,100}validate)/i,
    description: 'arXiv: User provides all input parameters. Must validate everything.',
    recommendation: 'Validate all deserialized instruction data.'
  },
  {
    id: 'SOL7134',
    name: 'arXiv: Account Array Trust',
    severity: 'high',
    pattern: /accounts\[\s*\d+\s*\](?![\s\S]{0,100}(?:verify|check|require!))/i,
    description: 'arXiv: Accounts array provided by user. Each account must be validated.',
    recommendation: 'Verify each account before use.'
  },
  {
    id: 'SOL7135',
    name: 'arXiv: SBF/BPF Specific',
    severity: 'medium',
    pattern: /(?:compute_budget|sol_log_|syscall)(?![\s\S]{0,100}check)/i,
    description: 'arXiv: SBF runtime specific operation. May have unique constraints.',
    recommendation: 'Review SBF-specific behavior and limitations.'
  },

  // ============================================
  // ARXIV: ATTACK TABLE PATTERNS (SOL7141-SOL7150)
  // From arXiv Table 1 - Major Attacks
  // ============================================
  {
    id: 'SOL7141',
    name: 'arXiv Table 1: Solend Oracle Pattern',
    severity: 'critical',
    pattern: /(?:price|oracle)[\s\S]{0,100}(?:get|fetch)(?![\s\S]{0,100}(?:aggregate|multiple|twap))/i,
    description: 'arXiv Table 1: Solend $1.26M oracle attack pattern.',
    recommendation: 'Use aggregated prices from multiple oracles.'
  },
  {
    id: 'SOL7142',
    name: 'arXiv Table 1: Mango Flash Loan',
    severity: 'critical',
    pattern: /(?:flash_loan|borrow)[\s\S]{0,200}(?:price|collateral)(?![\s\S]{0,100}twap)/i,
    description: 'arXiv Table 1: Mango $100M flash loan price manipulation.',
    recommendation: 'Use TWAP for flash-loan-sensitive operations.'
  },
  {
    id: 'SOL7143',
    name: 'arXiv Table 1: Cashio Unverified Account',
    severity: 'critical',
    pattern: /(?:collateral|backing)[\s\S]{0,100}(?![\s\S]{0,100}(?:whitelist|verify|trusted))/i,
    description: 'arXiv Table 1: Cashio $52M unverified account bypass.',
    recommendation: 'Maintain whitelist of trusted collateral mints.'
  },
  {
    id: 'SOL7144',
    name: 'arXiv Table 1: Wormhole Deprecated Function',
    severity: 'critical',
    pattern: /(?:deprecated|legacy|old)[\s\S]{0,50}(?:function|method|api)/i,
    description: 'arXiv Table 1: Wormhole 120k ETH via deprecated function.',
    recommendation: 'Remove or secure all deprecated functions.'
  },
  {
    id: 'SOL7145',
    name: 'arXiv Table 1: OptiFi Operational Error',
    severity: 'high',
    pattern: /(?:program|contract)[\s\S]{0,50}(?:close|terminate)(?![\s\S]{0,100}multisig)/i,
    description: 'arXiv Table 1: OptiFi 661k USDC operational error.',
    recommendation: 'Require multisig for program closure.'
  },
  {
    id: 'SOL7146',
    name: 'arXiv Table 1: Nirvana Flash Loan Curve',
    severity: 'critical',
    pattern: /(?:bonding|curve)[\s\S]{0,100}(?:flash|instant)(?![\s\S]{0,100}protection)/i,
    description: 'arXiv Table 1: Nirvana $3.5M flash loan curve manipulation.',
    recommendation: 'Add flash loan protection to bonding curves.'
  },
  {
    id: 'SOL7147',
    name: 'arXiv Table 1: Crema CLMM Flash',
    severity: 'critical',
    pattern: /(?:clmm|concentrated|tick)[\s\S]{0,100}(?:flash|loan)(?![\s\S]{0,100}owner)/i,
    description: 'arXiv Table 1: Crema $1.68M CLMM flash loan exploit.',
    recommendation: 'Verify tick account ownership in flash loan context.'
  },
  {
    id: 'SOL7148',
    name: 'arXiv Table 1: UXD/Tulip Exposure',
    severity: 'high',
    pattern: /(?:deposit|lend)[\s\S]{0,100}(?:external|third_party)(?![\s\S]{0,100}limit)/i,
    description: 'arXiv Table 1: UXD $20M/Tulip $2.5M exposure to Mango.',
    recommendation: 'Limit exposure to any single external protocol.'
  },
  {
    id: 'SOL7149',
    name: 'arXiv Table 1: Jet Protocol Unknown',
    severity: 'medium',
    pattern: /(?:jet|protocol)[\s\S]{0,100}(?:position|margin)(?![\s\S]{0,100}verify)/i,
    description: 'arXiv Table 1: Jet Protocol vulnerability pattern.',
    recommendation: 'Verify all position accounts and states.'
  },
  {
    id: 'SOL7150',
    name: 'arXiv: 113 vs 12 Tool Gap',
    severity: 'info',
    pattern: /(?:#\[test\]|test_)[\s\S]{0,100}(?:pub\s+fn|fn)(?![\s\S]{0,200}fuzz)/i,
    description: 'arXiv: Solana has fewer security tools (12 vs 113 for Ethereum).',
    recommendation: 'Add fuzz testing and symbolic analysis to test suite.'
  },
];

/**
 * Run Batch 108 patterns
 */
export function checkBatch108Patterns(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';
  const fileName = input.path || input.rust?.filePath || 'unknown';
  
  if (!content) return findings;
  
  const lines = content.split('\n');
  
  for (const pattern of BATCH_108_PATTERNS) {
    try {
      const flags = pattern.pattern.flags.includes('g') ? pattern.pattern.flags : pattern.pattern.flags + 'g';
      const regex = new RegExp(pattern.pattern.source, flags);
      const matches = [...content.matchAll(regex)];
      
      for (const match of matches) {
        const matchIndex = match.index || 0;
        let lineNum = 1;
        let charCount = 0;
        for (let i = 0; i < lines.length; i++) {
          charCount += lines[i].length + 1;
          if (charCount > matchIndex) {
            lineNum = i + 1;
            break;
          }
        }
        
        const startLine = Math.max(0, lineNum - 2);
        const endLine = Math.min(lines.length, lineNum + 2);
        const snippet = lines.slice(startLine, endLine).join('\n');
        
        findings.push({
          id: pattern.id,
          title: pattern.name,
          severity: pattern.severity,
          description: pattern.description,
          location: { file: fileName, line: lineNum },
          recommendation: pattern.recommendation,
          code: snippet.substring(0, 200),
        });
      }
    } catch (error) {
      // Skip pattern on error
    }
  }
  
  return findings;
}

export { BATCH_108_PATTERNS };
