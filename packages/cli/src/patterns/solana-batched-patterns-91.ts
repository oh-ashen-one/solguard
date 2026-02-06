/**
 * SolGuard Security Patterns - Batch 91
 * 
 * Feb 6, 2026 5:30 AM - Fresh Research from Latest Sources
 * Sources:
 * - arXiv:2504.07419 "Exploring Vulnerabilities in Solana Smart Contracts" (Apr 2025) - Deep Dive
 * - Sec3 2025 Security Ecosystem Review FINAL (163 audits, 1,669 vulnerabilities, 76% Medium+)
 * - Helius Complete Solana Hacks History (38 verified incidents, ~$600M gross, $131M net losses)
 * - BlockHacks "How Solana Smart Contracts Get Hacked" Analysis
 * - ThreeSigma "Rust Memory Safety on Solana" (Loopscale $5.8M Apr 2025)
 * - Certora Lulo Smart Contract Security Assessment
 * - Solsec GitHub - Curated Audit Resources
 * 
 * Patterns: SOL5101-SOL5200
 */

import type { Finding, PatternInput } from './index.js';

interface PatternDef {
  id: string;
  name: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  pattern: RegExp;
  description: string;
  recommendation: string;
}

const BATCH_91_PATTERNS: PatternDef[] = [
  // ============================================
  // arXiv:2504.07419 Deep Dive Patterns
  // "Exploring Vulnerabilities in Solana Smart Contracts"
  // Table 1: Major Attacks on Solana Since Feb 2022
  // ============================================
  {
    id: 'SOL5101',
    name: 'arXiv: Missing Signer Check (Listing 1)',
    severity: 'critical',
    pattern: /fn\s+update_admin[\s\S]*?accounts\s*\[[\s\S]*?(?!is_signer|Signer)/i,
    description: 'arXiv Listing 1: Admin update function without signer verification. Attacker can pass admin account as parameter and set their own account as new admin.',
    recommendation: 'Always verify is_signer for authority operations: require!(admin.is_signer, ErrorCode::Unauthorized);'
  },
  {
    id: 'SOL5102',
    name: 'arXiv: Solend Oracle Attack Pattern ($1.26M)',
    severity: 'critical',
    pattern: /oracle[\s\S]{0,100}price[\s\S]{0,100}(?!staleness|confidence|twap|window)/i,
    description: 'arXiv Table 1: Solend lost $1.26M to oracle manipulation (Nov 2022). Price feeds without staleness/confidence checks.',
    recommendation: 'Validate oracle staleness (< 60s), confidence intervals, and use TWAP for large operations.'
  },
  {
    id: 'SOL5103',
    name: 'arXiv: Mango Flash Loan Attack ($100M)',
    severity: 'critical',
    pattern: /flash_loan|borrow[\s\S]{0,100}(?:perp|spot|collateral)(?![\s\S]{0,100}same_tx_repay|[\s\S]{0,100}atomic)/i,
    description: 'arXiv Table 1: Mango Markets lost $100M to flash loan price manipulation (Oct 2022). Borrowed against artificially inflated collateral.',
    recommendation: 'Use TWAP for collateral valuation. Add flash loan guards and same-transaction repayment verification.'
  },
  {
    id: 'SOL5104',
    name: 'arXiv: Tulip/UXD Protocol Cascade ($22.5M)',
    severity: 'critical',
    pattern: /mango[\s\S]{0,50}(?:market|position|collateral)(?![\s\S]{0,100}isolation|[\s\S]{0,100}risk_tier)/i,
    description: 'arXiv Table 1: Tulip ($2.5M) and UXD ($20M) lost funds due to Mango Markets cascade. External protocol dependency without isolation.',
    recommendation: 'Isolate external protocol dependencies. Implement circuit breakers for cross-protocol exposure.'
  },
  {
    id: 'SOL5105',
    name: 'arXiv: OptiFi Operational Error Pattern',
    severity: 'high',
    pattern: /solana\s+program\s+close|close_program|program_close/i,
    description: 'arXiv Table 1: OptiFi accidentally closed mainnet program, locking $661K USDC permanently. Irreversible operation.',
    recommendation: 'Implement peer review (3+ team members) for deployment commands. Never use program close in production.'
  },
  {
    id: 'SOL5106',
    name: 'arXiv: Nirvana Bonding Curve Flash Loan ($3.5M)',
    severity: 'critical',
    pattern: /bonding_curve|price_curve[\s\S]{0,100}flash(?![\s\S]{0,100}guard|[\s\S]{0,100}lock|[\s\S]{0,100}block)/i,
    description: 'arXiv Table 1: Nirvana Finance drained $3.5M via flash loan bonding curve manipulation (Jul 2022).',
    recommendation: 'Add flash loan detection. Use time-weighted pricing for bonding curves.'
  },
  {
    id: 'SOL5107',
    name: 'arXiv: Crema Finance CLMM Flash Loan ($1.68M)',
    severity: 'critical',
    pattern: /tick[\s\S]{0,50}account[\s\S]{0,100}(?!owner|constraint|has_one)/i,
    description: 'arXiv Table 1: Crema Finance lost $1.68M when attacker created fake tick accounts (Jul 2022). Flash loan amplified the attack.',
    recommendation: 'Verify tick account ownership via PDA derivation. Never trust user-provided tick data.'
  },
  {
    id: 'SOL5108',
    name: 'arXiv: Cashio Unverified Account Attack ($52M)',
    severity: 'critical',
    pattern: /collateral[\s\S]{0,100}mint[\s\S]{0,100}(?!verify|whitelist|check|constraint)/i,
    description: 'arXiv Table 1: Cashio lost $52M when attacker bypassed unverified collateral accounts (Mar 2022). Infinite mint glitch.',
    recommendation: 'Whitelist valid collateral mints. Verify mint field in all collateral validation.'
  },
  {
    id: 'SOL5109',
    name: 'arXiv: Wormhole Deprecated Function ($326M)',
    severity: 'critical',
    pattern: /verify_signature[\s\S]{0,100}(?:deprecated|legacy|old)(?![\s\S]{0,100}remove|[\s\S]{0,100}disable)/i,
    description: 'arXiv Table 1: Wormhole lost 120K ETH ($326M) via forged signatures using deprecated function (Feb 2022).',
    recommendation: 'Remove deprecated functions immediately. Use current verification methods only.'
  },
  {
    id: 'SOL5110',
    name: 'arXiv: Jet Protocol Unknown Vulnerability',
    severity: 'high',
    pattern: /jet[\s\S]{0,30}(?:protocol|lending|governance)(?![\s\S]{0,100}audit|[\s\S]{0,100}verified)/i,
    description: 'arXiv Table 1: Jet Protocol suffered unknown attack (Mar 2022). Demonstrates need for comprehensive auditing.',
    recommendation: 'Conduct thorough audits before mainnet. Implement monitoring and incident response.'
  },
  
  // ============================================
  // Sec3 2025 Report: Business Logic (38.5% of vulns)
  // Most severe category - 36.9% of High+Critical
  // ============================================
  {
    id: 'SOL5111',
    name: 'Sec3-2025: State Machine Violation',
    severity: 'high',
    pattern: /state\s*=|status\s*=[\s\S]{0,50}(?!require!|assert!|match)/i,
    description: 'Sec3 2025 Report: Business logic flaws from improper state transitions. 38.5% of all vulnerabilities.',
    recommendation: 'Implement state machine with explicit transitions and invariant checks.'
  },
  {
    id: 'SOL5112',
    name: 'Sec3-2025: Invariant Violation',
    severity: 'critical',
    pattern: /swap|exchange|trade(?![\s\S]{0,100}invariant|[\s\S]{0,100}k_constant|[\s\S]{0,100}assert)/i,
    description: 'Sec3 2025 Report: Protocol invariants not enforced in critical operations.',
    recommendation: 'Verify invariants (e.g., xy=k for AMMs) after every state-changing operation.'
  },
  {
    id: 'SOL5113',
    name: 'Sec3-2025: Economic Model Flaw',
    severity: 'high',
    pattern: /reward|yield|interest[\s\S]{0,100}(?:rate|amount)(?![\s\S]{0,100}cap|[\s\S]{0,100}limit|[\s\S]{0,100}max)/i,
    description: 'Sec3 2025 Report: Unbounded rewards/yields can drain protocol.',
    recommendation: 'Cap reward rates. Implement economic invariants and emission schedules.'
  },
  {
    id: 'SOL5114',
    name: 'Sec3-2025: Order of Operations',
    severity: 'high',
    pattern: /transfer[\s\S]{0,50}(?:before|then)[\s\S]{0,50}(?:check|verify)/i,
    description: 'Sec3 2025 Report: Incorrect operation ordering leads to exploits.',
    recommendation: 'Follow checks-effects-interactions pattern. Verify before modifying state.'
  },
  {
    id: 'SOL5115',
    name: 'Sec3-2025: Edge Case Logic',
    severity: 'medium',
    pattern: /amount\s*==\s*0|balance\s*==\s*0(?![\s\S]{0,50}return|[\s\S]{0,50}err)/i,
    description: 'Sec3 2025 Report: Zero-amount edge cases not handled correctly.',
    recommendation: 'Handle all edge cases: zero amounts, empty arrays, boundary values.'
  },
  
  // ============================================
  // Sec3 2025 Report: Input Validation (25% of vulns)
  // 27.9% of High+Critical findings
  // ============================================
  {
    id: 'SOL5116',
    name: 'Sec3-2025: Missing Account Type Check',
    severity: 'critical',
    pattern: /AccountInfo[\s\S]{0,100}(?!discriminator|try_from|deserialize_with_type)/i,
    description: 'Sec3 2025 Report: Account type not verified, allowing type confusion. 25% of vulnerabilities.',
    recommendation: 'Always verify account discriminator. Use Anchor #[account] for automatic checks.'
  },
  {
    id: 'SOL5117',
    name: 'Sec3-2025: Insufficient Input Bounds',
    severity: 'high',
    pattern: /amount|quantity|size[\s\S]{0,30}:\s*u\d+(?![\s\S]{0,50}require!|[\s\S]{0,50}<=|[\s\S]{0,50}>=)/i,
    description: 'Sec3 2025 Report: Numeric inputs without bounds validation.',
    recommendation: 'Validate all numeric inputs: require!(amount <= MAX_AMOUNT && amount >= MIN_AMOUNT);'
  },
  {
    id: 'SOL5118',
    name: 'Sec3-2025: PDA Seed Injection',
    severity: 'critical',
    pattern: /seeds\s*=\s*\[[\s\S]*?\w+\.as_bytes\(\)[\s\S]*?\](?![\s\S]{0,50}validate|[\s\S]{0,50}check)/i,
    description: 'Sec3 2025 Report: User-controlled PDA seeds without validation enable spoofing.',
    recommendation: 'Validate all user-provided seed components. Use fixed prefixes for PDAs.'
  },
  {
    id: 'SOL5119',
    name: 'Sec3-2025: Array Length Mismatch',
    severity: 'high',
    pattern: /\[[\s\S]*?\][\s\S]{0,50}len\(\)[\s\S]{0,50}(?!==|!=|require!)/i,
    description: 'Sec3 2025 Report: Related arrays without length consistency checks.',
    recommendation: 'Verify related arrays have matching lengths before processing.'
  },
  {
    id: 'SOL5120',
    name: 'Sec3-2025: String Length Overflow',
    severity: 'medium',
    pattern: /String|&str[\s\S]{0,50}(?!\.len\(\)\s*<=|max_len|truncate)/i,
    description: 'Sec3 2025 Report: Unbounded strings can overflow account space.',
    recommendation: 'Enforce maximum string lengths: require!(name.len() <= MAX_NAME_LEN);'
  },
  
  // ============================================
  // Sec3 2025 Report: Access Control (19% of vulns)
  // 20.7% of High+Critical findings
  // ============================================
  {
    id: 'SOL5121',
    name: 'Sec3-2025: Missing Authority Constraint',
    severity: 'critical',
    pattern: /authority|admin|owner[\s\S]{0,50}AccountInfo(?![\s\S]{0,100}Signer|[\s\S]{0,100}has_one|[\s\S]{0,100}constraint)/i,
    description: 'Sec3 2025 Report: Authority accounts without proper constraints. 19% of vulnerabilities.',
    recommendation: 'Add #[account(signer, constraint = authority.key() == expected_authority)]'
  },
  {
    id: 'SOL5122',
    name: 'Sec3-2025: Privilege Escalation',
    severity: 'critical',
    pattern: /set_authority|update_authority|change_admin(?![\s\S]{0,100}multisig|[\s\S]{0,100}timelock)/i,
    description: 'Sec3 2025 Report: Authority changes without governance controls.',
    recommendation: 'Require multisig or timelock for authority changes. Emit events.'
  },
  {
    id: 'SOL5123',
    name: 'Sec3-2025: Role Confusion',
    severity: 'high',
    pattern: /role|permission[\s\S]{0,50}(?:=|check)(?![\s\S]{0,100}match|[\s\S]{0,100}enum)/i,
    description: 'Sec3 2025 Report: Ambiguous role definitions enable privilege abuse.',
    recommendation: 'Use explicit role enums. Verify role requirements for each function.'
  },
  {
    id: 'SOL5124',
    name: 'Sec3-2025: Pausable Without Guard',
    severity: 'high',
    pattern: /pause|emergency[\s\S]{0,50}(?!check_paused|require!.*paused|is_paused)/i,
    description: 'Sec3 2025 Report: Emergency functions without pause state verification.',
    recommendation: 'Implement consistent pause checks: require!(!state.is_paused, ErrorCode::Paused);'
  },
  {
    id: 'SOL5125',
    name: 'Sec3-2025: Initialization Race',
    severity: 'critical',
    pattern: /initialize|init(?![\s\S]{0,50}is_initialized|[\s\S]{0,50}constraint|[\s\S]{0,50}#\[account\(init)/i,
    description: 'Sec3 2025 Report: Initialization without protection against double-init or frontrunning.',
    recommendation: 'Use Anchor init with payer and space. Check is_initialized flag.'
  },
  
  // ============================================
  // Sec3 2025 Report: Data Integrity & Arithmetic (8.9%)
  // ============================================
  {
    id: 'SOL5126',
    name: 'Sec3-2025: Precision Loss in Division',
    severity: 'high',
    pattern: /\/\s*\d+[\s\S]{0,30}\*(?![\s\S]{0,50}checked_|[\s\S]{0,50}\.0)/i,
    description: 'Sec3 2025 Report: Division before multiplication loses precision. 8.9% of vulnerabilities.',
    recommendation: 'Multiply before dividing. Use fixed-point math or higher precision types.'
  },
  {
    id: 'SOL5127',
    name: 'Sec3-2025: Unsafe Rounding Direction',
    severity: 'high',
    pattern: /amount[\s\S]{0,30}\/[\s\S]{0,30}(?!floor|ceil|round_up|round_down)/i,
    description: 'Sec3 2025 Report: Rounding direction not explicit, can favor attacker.',
    recommendation: 'Use explicit rounding: round down for withdrawals, round up for deposits.'
  },
  {
    id: 'SOL5128',
    name: 'Sec3-2025: Cross-Instruction State',
    severity: 'high',
    pattern: /invoke[\s\S]{0,100}account[\s\S]{0,100}(?!reload|refresh|re-read)/i,
    description: 'Sec3 2025 Report: Account state not refreshed after CPI, reading stale data.',
    recommendation: 'Reload account data after cross-program invocations.'
  },
  {
    id: 'SOL5129',
    name: 'Sec3-2025: Timestamp Manipulation',
    severity: 'medium',
    pattern: /clock\.unix_timestamp(?![\s\S]{0,50}tolerance|[\s\S]{0,50}slot)/i,
    description: 'Sec3 2025 Report: Relying solely on timestamp without slot validation.',
    recommendation: 'Use slot numbers for sequencing. Allow timestamp tolerance for time-based logic.'
  },
  {
    id: 'SOL5130',
    name: 'Sec3-2025: Account Data Overwrite',
    severity: 'critical',
    pattern: /data\.borrow_mut\(\)[\s\S]{0,50}(?!copy_from_slice.*\[0\.\.8\])/i,
    description: 'Sec3 2025 Report: Account data overwritten without preserving discriminator.',
    recommendation: 'Always preserve the first 8 bytes (discriminator) when writing account data.'
  },
  
  // ============================================
  // Sec3 2025 Report: DoS & Liveness (8.5%)
  // ============================================
  {
    id: 'SOL5131',
    name: 'Sec3-2025: Unbounded Loop Iteration',
    severity: 'high',
    pattern: /for\s+\w+\s+in[\s\S]{0,30}\.iter\(\)(?![\s\S]{0,50}take\(|[\s\S]{0,50}\.len\(\)\s*<)/i,
    description: 'Sec3 2025 Report: Unbounded loops can exceed compute limits. 8.5% of vulnerabilities.',
    recommendation: 'Bound all loops: for item in items.iter().take(MAX_ITEMS)'
  },
  {
    id: 'SOL5132',
    name: 'Sec3-2025: Storage Bloat Attack',
    severity: 'medium',
    pattern: /Vec::new\(\)|Vec::with_capacity(?![\s\S]{0,50}MAX_|[\s\S]{0,50}CAP_)/i,
    description: 'Sec3 2025 Report: Unbounded storage can be filled by attacker.',
    recommendation: 'Cap all dynamic storage. Use rent-aware data structures.'
  },
  {
    id: 'SOL5133',
    name: 'Sec3-2025: External Call Dependency',
    severity: 'high',
    pattern: /invoke(?:_signed)?[\s\S]{0,50}(?:oracle|external|third_party)(?![\s\S]{0,100}fallback|[\s\S]{0,100}timeout)/i,
    description: 'Sec3 2025 Report: External dependencies without fallback can halt protocol.',
    recommendation: 'Implement fallback mechanisms for external dependencies.'
  },
  {
    id: 'SOL5134',
    name: 'Sec3-2025: Withdrawal Lock',
    severity: 'critical',
    pattern: /withdraw[\s\S]{0,100}lock[\s\S]{0,50}(?!emergency|bypass|override)/i,
    description: 'Sec3 2025 Report: Funds can be permanently locked without emergency escape.',
    recommendation: 'Implement emergency withdrawal mechanism with timelock.'
  },
  {
    id: 'SOL5135',
    name: 'Sec3-2025: Queue Griefing',
    severity: 'medium',
    pattern: /queue|fifo|pending[\s\S]{0,50}push(?![\s\S]{0,50}cap|[\s\S]{0,50}limit|[\s\S]{0,50}max)/i,
    description: 'Sec3 2025 Report: Unbounded queues can be filled to block legitimate users.',
    recommendation: 'Cap queue sizes. Implement priority or stake-weighted access.'
  },
  
  // ============================================
  // Helius 38 Incidents: Deep Patterns
  // $600M+ gross losses, $131M net
  // ============================================
  {
    id: 'SOL5136',
    name: 'Helius: Jump Crypto Reimbursement Pattern',
    severity: 'info',
    pattern: /reimburse|refund|compensate(?![\s\S]{0,100}insurance|[\s\S]{0,100}fund)/i,
    description: 'Helius History: Jump Crypto reimbursed $326M for Wormhole. Protocol should have insurance funds.',
    recommendation: 'Maintain insurance/treasury fund for potential reimbursements.'
  },
  {
    id: 'SOL5137',
    name: 'Helius: Slope Wallet Seed Logging',
    severity: 'critical',
    pattern: /seed|mnemonic|private_key[\s\S]{0,50}(?:log|print|send|transmit|server)/i,
    description: 'Helius History: Slope Wallet logged seed phrases to central server, losing $8M across 9K wallets.',
    recommendation: 'NEVER log or transmit seed phrases. Keep secrets in secure enclave only.'
  },
  {
    id: 'SOL5138',
    name: 'Helius: Raydium Admin Key Compromise ($4.4M)',
    severity: 'critical',
    pattern: /admin_key|pool_authority[\s\S]{0,50}(?!multisig|threshold|governance)/i,
    description: 'Helius History: Raydium lost $4.4M when admin keys were compromised (Dec 2022).',
    recommendation: 'Use multisig (3-of-5 minimum) for all admin operations.'
  },
  {
    id: 'SOL5139',
    name: 'Helius: Pump.fun Insider Exploit ($1.9M)',
    severity: 'high',
    pattern: /launch|bonding[\s\S]{0,50}early_access|privileged(?![\s\S]{0,100}lock|[\s\S]{0,100}delay)/i,
    description: 'Helius History: Pump.fun employee used privileged access to extract $1.9M (May 2024).',
    recommendation: 'Implement time delays and transparency for privileged operations.'
  },
  {
    id: 'SOL5140',
    name: 'Helius: Banana Gun Bot Compromise ($1.4M)',
    severity: 'high',
    pattern: /bot|trading_bot[\s\S]{0,50}(?:key|wallet|authority)(?![\s\S]{0,100}rotate|[\s\S]{0,100}limit)/i,
    description: 'Helius History: Banana Gun trading bot keys compromised, draining $1.4M (Oct 2024).',
    recommendation: 'Rotate bot keys regularly. Implement per-transaction limits.'
  },
  {
    id: 'SOL5141',
    name: 'Helius: Thunder Terminal MongoDB Flaw',
    severity: 'critical',
    pattern: /mongodb|database[\s\S]{0,50}(?:session|token|auth)(?![\s\S]{0,100}encrypt|[\s\S]{0,100}hash)/i,
    description: 'Helius History: Thunder Terminal lost $240K via MongoDB session key vulnerability (Dec 2024).',
    recommendation: 'Encrypt all session data. Use proper authentication mechanisms.'
  },
  {
    id: 'SOL5142',
    name: 'Helius: DEXX Private Key Leak ($30M)',
    severity: 'critical',
    pattern: /private_key[\s\S]{0,50}(?:store|save|database|server)(?![\s\S]{0,100}encrypt|[\s\S]{0,100}hsm)/i,
    description: 'Helius History: DEXX leaked user private keys from infrastructure (Nov 2024), losing $30M.',
    recommendation: 'Use HSM for key storage. Never store raw private keys.'
  },
  {
    id: 'SOL5143',
    name: 'Helius: Saga DAO Insider Theft ($10M)',
    severity: 'high',
    pattern: /dao[\s\S]{0,50}(?:treasury|funds)[\s\S]{0,50}(?!multisig|governance|vote)/i,
    description: 'Helius History: Saga DAO treasury drained by insiders ($10M, Jan 2024).',
    recommendation: 'Require governance votes for treasury access. Use multisig.'
  },
  {
    id: 'SOL5144',
    name: 'Helius: Web3.js Supply Chain Attack',
    severity: 'critical',
    pattern: /@solana\/web3\.js[\s\S]{0,30}(?:1\.95\.5|1\.95\.6|1\.95\.7)/i,
    description: 'Helius History: Web3.js versions 1.95.5-1.95.7 compromised with malicious code (Dec 2024).',
    recommendation: 'Pin dependencies. Verify package checksums. Monitor for supply chain attacks.'
  },
  {
    id: 'SOL5145',
    name: 'Helius: Solareum Exit Scam',
    severity: 'info',
    pattern: /trading_bot[\s\S]{0,50}(?:rug|exit|shutdown)(?![\s\S]{0,100}audit|[\s\S]{0,100}verified)/i,
    description: 'Helius History: Solareum trading bot exit scammed users (Mar 2024).',
    recommendation: 'Use only audited and reputable trading services.'
  },
  
  // ============================================
  // ThreeSigma: Rust Memory Safety on Solana
  // Loopscale $5.8M (Apr 2025)
  // ============================================
  {
    id: 'SOL5146',
    name: 'ThreeSigma: Loopscale RateX PT Token ($5.8M)',
    severity: 'critical',
    pattern: /pt_token|rate_x|principal_token[\s\S]{0,100}(?:value|calculate)(?![\s\S]{0,100}oracle|[\s\S]{0,100}price_feed)/i,
    description: 'ThreeSigma Apr 2025: Loopscale lost $5.8M due to RateX PT token valuation flaw.',
    recommendation: 'Use reliable price feeds for token valuation. Verify calculation logic thoroughly.'
  },
  {
    id: 'SOL5147',
    name: 'ThreeSigma: Logical Vulnerability in 2025',
    severity: 'high',
    pattern: /calculate[\s\S]{0,50}value[\s\S]{0,50}(?!validate|verify|check)/i,
    description: 'ThreeSigma: Even in 2025, logical vulnerabilities in smart contracts remain the primary attack vector.',
    recommendation: 'Focus audits on business logic. Formal verification for critical calculations.'
  },
  {
    id: 'SOL5148',
    name: 'ThreeSigma: Collateral Valuation Flaw',
    severity: 'critical',
    pattern: /collateral[\s\S]{0,100}(?:value|worth|price)[\s\S]{0,50}(?!oracle|feed|twap)/i,
    description: 'ThreeSigma: Collateral valuation without oracle can be manipulated.',
    recommendation: 'Use oracle price feeds for all collateral valuations.'
  },
  
  // ============================================
  // Certora Lulo Audit Patterns
  // Oracle Failures, Referral Fee Exploits, Withdrawal Manipulation
  // ============================================
  {
    id: 'SOL5149',
    name: 'Certora-Lulo: Oracle Update Failure',
    severity: 'critical',
    pattern: /oracle[\s\S]{0,50}update[\s\S]{0,50}(?!require!|assert!|check|verify)/i,
    description: 'Certora Lulo Audit: Oracle update failures not handled, can cause incorrect pricing.',
    recommendation: 'Handle oracle update failures gracefully. Implement fallback pricing.'
  },
  {
    id: 'SOL5150',
    name: 'Certora-Lulo: Referral Fee Exploit',
    severity: 'high',
    pattern: /referral[\s\S]{0,50}(?:fee|reward|bonus)(?![\s\S]{0,100}cap|[\s\S]{0,100}limit|[\s\S]{0,100}max)/i,
    description: 'Certora Lulo Audit: Uncapped referral fees can be exploited for excessive rewards.',
    recommendation: 'Cap referral fees. Prevent self-referral.'
  },
  {
    id: 'SOL5151',
    name: 'Certora-Lulo: Withdrawal Manipulation',
    severity: 'critical',
    pattern: /withdraw[\s\S]{0,100}(?:rate|amount)[\s\S]{0,50}(?!rate_limit|delay|queue)/i,
    description: 'Certora Lulo Audit: Withdrawal rate manipulation can drain protocol.',
    recommendation: 'Implement withdrawal rate limits and delays for large amounts.'
  },
  
  // ============================================
  // BlockHacks: $600M+ Loss Analysis
  // Top Attack Patterns from Major Exploits
  // ============================================
  {
    id: 'SOL5152',
    name: 'BlockHacks: Wormhole Signature Verification ($326M)',
    severity: 'critical',
    pattern: /verify_signatures|guardian[\s\S]{0,100}(?!threshold|quorum|count)/i,
    description: 'BlockHacks: Wormhole lost $326M due to signature verification bypass. Largest Solana exploit.',
    recommendation: 'Verify guardian signatures with proper threshold. Use latest verification methods.'
  },
  {
    id: 'SOL5153',
    name: 'BlockHacks: Mango Markets Oracle ($116M)',
    severity: 'critical',
    pattern: /spot_price|mark_price[\s\S]{0,50}(?!twap|window|average)/i,
    description: 'BlockHacks: Mango Markets lost $116M to spot price oracle manipulation.',
    recommendation: 'Use TWAP for all price-sensitive operations. Add oracle guards.'
  },
  {
    id: 'SOL5154',
    name: 'BlockHacks: Cashio Root of Trust ($52M)',
    severity: 'critical',
    pattern: /mint[\s\S]{0,50}validation[\s\S]{0,50}(?!require!|assert!|check)/i,
    description: 'BlockHacks: Cashio lost $52M by not validating collateral mint. Infinite mint glitch.',
    recommendation: 'Establish and verify root of trust for all collateral accounts.'
  },
  {
    id: 'SOL5155',
    name: 'BlockHacks: Cumulative Loss Pattern',
    severity: 'info',
    pattern: /(?:bridge|lending|dex|amm)[\s\S]{0,100}(?!audit|verified|secure)/i,
    description: 'BlockHacks: Bridges, lending, and DEXs account for majority of $600M+ losses.',
    recommendation: 'Prioritize security audits for bridges, lending protocols, and DEXs.'
  },
  
  // ============================================
  // Solsec GitHub: Audit Findings Compilation
  // Neodyme, OtterSec, Kudelski, Halborn, Bramah
  // ============================================
  {
    id: 'SOL5156',
    name: 'Solsec-Neodyme: Rounding Error Pattern',
    severity: 'high',
    pattern: /division[\s\S]{0,30}(?:floor|ceil|round)(?![\s\S]{0,50}direction|[\s\S]{0,50}favor)/i,
    description: 'Solsec/Neodyme: Rounding errors put $2.6B at risk in SPL lending (from Neodyme disclosure).',
    recommendation: 'Explicit rounding direction. Floor for user-favorable, ceil for protocol-favorable.'
  },
  {
    id: 'SOL5157',
    name: 'Solsec-OtterSec: LP Token Oracle ($200M)',
    severity: 'critical',
    pattern: /lp_token[\s\S]{0,50}(?:price|value|oracle)(?![\s\S]{0,100}fair_pricing|[\s\S]{0,100}sqrt)/i,
    description: 'Solsec/OtterSec: LP token oracle manipulation can drain lending protocols ($200M+ at risk).',
    recommendation: 'Use fair LP pricing formula: 2 * sqrt(reserve0 * reserve1) / totalSupply.'
  },
  {
    id: 'SOL5158',
    name: 'Solsec-Kudelski: Ownership Validation',
    severity: 'critical',
    pattern: /AccountInfo[\s\S]{0,100}(?!owner\s*==|owner\.key\(\)|#\[account\(owner)/i,
    description: 'Solsec/Kudelski: Missing ownership validation is top vulnerability from audits.',
    recommendation: 'Always verify account ownership: require!(account.owner == &program_id);'
  },
  {
    id: 'SOL5159',
    name: 'Solsec-Halborn: CPI Guard Bypass',
    severity: 'high',
    pattern: /cpi_guard[\s\S]{0,50}(?:approve|delegate)(?![\s\S]{0,100}check|[\s\S]{0,100}verify)/i,
    description: 'Solsec/Halborn: CPI guard can be bypassed with certain approval patterns.',
    recommendation: 'Verify CPI guard state. Use approve_checked for token operations.'
  },
  {
    id: 'SOL5160',
    name: 'Solsec-Bramah: Flash Loan Detection',
    severity: 'high',
    pattern: /flash_loan(?![\s\S]{0,100}same_block|[\s\S]{0,100}same_tx|[\s\S]{0,100}detect)/i,
    description: 'Solsec/Bramah: Flash loans used in multiple major exploits (Nirvana, Crema, Mango).',
    recommendation: 'Detect flash loans by checking if same transaction borrows and repays.'
  },
  
  // ============================================
  // Advanced DeFi Attack Vectors (2025-2026)
  // ============================================
  {
    id: 'SOL5161',
    name: 'Advanced: MEV Sandwich Detection',
    severity: 'high',
    pattern: /swap[\s\S]{0,100}slippage[\s\S]{0,50}(?!protection|tolerance|max)/i,
    description: 'Advanced 2025-2026: MEV sandwich attacks exploit swaps without slippage protection.',
    recommendation: 'Implement slippage protection. Use private mempools or Jito bundles.'
  },
  {
    id: 'SOL5162',
    name: 'Advanced: JIT Liquidity Attack',
    severity: 'high',
    pattern: /liquidity[\s\S]{0,50}(?:add|remove)[\s\S]{0,50}(?!lock|cooldown|delay)/i,
    description: 'Advanced: JIT (Just-In-Time) liquidity can extract value from traders.',
    recommendation: 'Add liquidity cooldowns. Use time-weighted positions.'
  },
  {
    id: 'SOL5163',
    name: 'Advanced: Cross-Margin Cascade',
    severity: 'critical',
    pattern: /cross_margin|portfolio_margin[\s\S]{0,100}(?!isolation|risk_tier)/i,
    description: 'Advanced: Cross-margin positions can cascade liquidations.',
    recommendation: 'Implement position isolation. Add circuit breakers for cascade prevention.'
  },
  {
    id: 'SOL5164',
    name: 'Advanced: Concentrated Liquidity Manipulation',
    severity: 'high',
    pattern: /tick[\s\S]{0,30}(?:lower|upper)[\s\S]{0,50}(?!validate|check|verify)/i,
    description: 'Advanced: CLMM tick manipulation can skew prices in concentrated ranges.',
    recommendation: 'Validate tick positions. Use TWAP for CLMM-based pricing.'
  },
  {
    id: 'SOL5165',
    name: 'Advanced: Perpetual Funding Rate Attack',
    severity: 'high',
    pattern: /funding_rate[\s\S]{0,50}(?!cap|limit|max|min)/i,
    description: 'Advanced: Extreme funding rates can be manipulated to extract value.',
    recommendation: 'Cap funding rates. Implement funding rate velocity limits.'
  },
  
  // ============================================
  // Token-2022 Specific Patterns
  // ============================================
  {
    id: 'SOL5166',
    name: 'Token-2022: Transfer Hook Reentrancy',
    severity: 'critical',
    pattern: /transfer_hook[\s\S]{0,100}(?:invoke|call)(?![\s\S]{0,100}guard|[\s\S]{0,100}flag)/i,
    description: 'Token-2022: Transfer hooks can enable reentrancy via custom program execution.',
    recommendation: 'Use reentrancy guards when handling tokens with transfer hooks.'
  },
  {
    id: 'SOL5167',
    name: 'Token-2022: Fee Configuration Exploit',
    severity: 'high',
    pattern: /transfer_fee[\s\S]{0,50}(?:rate|basis_points)(?![\s\S]{0,100}max|[\s\S]{0,100}cap)/i,
    description: 'Token-2022: Uncapped transfer fees can be set to 100%, locking tokens.',
    recommendation: 'Validate transfer fee configurations. Handle fee-on-transfer tokens specially.'
  },
  {
    id: 'SOL5168',
    name: 'Token-2022: Permanent Delegate Risk',
    severity: 'critical',
    pattern: /permanent_delegate[\s\S]{0,50}(?!audit|verify|check)/i,
    description: 'Token-2022: Permanent delegate can transfer or burn tokens without holder consent.',
    recommendation: 'Warn users about permanent delegate tokens. Treat as high-risk assets.'
  },
  {
    id: 'SOL5169',
    name: 'Token-2022: Non-Transferable Token Logic',
    severity: 'medium',
    pattern: /non_transferable[\s\S]{0,50}(?:token|mint)(?![\s\S]{0,100}check|[\s\S]{0,100}verify)/i,
    description: 'Token-2022: Non-transferable tokens require special handling in protocols.',
    recommendation: 'Check transfer restrictions before accepting tokens.'
  },
  {
    id: 'SOL5170',
    name: 'Token-2022: Interest Bearing Calculation',
    severity: 'high',
    pattern: /interest_bearing[\s\S]{0,50}(?:rate|amount)(?![\s\S]{0,100}ui_amount|[\s\S]{0,100}real_amount)/i,
    description: 'Token-2022: Interest-bearing tokens have different UI and real amounts.',
    recommendation: 'Use amount_to_ui_amount() for display. Store real amounts.'
  },
  
  // ============================================
  // Compressed NFT (cNFT) Patterns
  // ============================================
  {
    id: 'SOL5171',
    name: 'cNFT: Merkle Proof Verification',
    severity: 'critical',
    pattern: /merkle[\s\S]{0,50}(?:proof|tree)[\s\S]{0,50}(?!verify|validate|check)/i,
    description: 'cNFT: Compressed NFTs require merkle proof verification for ownership.',
    recommendation: 'Always verify merkle proofs when handling cNFTs.'
  },
  {
    id: 'SOL5172',
    name: 'cNFT: Concurrent Merkle Tree Update',
    severity: 'high',
    pattern: /concurrent_merkle_tree[\s\S]{0,50}(?!changelog|canopy)/i,
    description: 'cNFT: Concurrent updates to merkle tree can cause conflicts.',
    recommendation: 'Use changelog for concurrent updates. Implement proper canopy depth.'
  },
  {
    id: 'SOL5173',
    name: 'cNFT: Leaf Data Integrity',
    severity: 'high',
    pattern: /leaf[\s\S]{0,30}(?:data|hash)[\s\S]{0,50}(?!verify|validate)/i,
    description: 'cNFT: Leaf data must be verified against expected structure.',
    recommendation: 'Validate leaf data schema and ownership before processing.'
  },
  
  // ============================================
  // Governance Attack Patterns
  // ============================================
  {
    id: 'SOL5174',
    name: 'Governance: Flash Loan Voting',
    severity: 'critical',
    pattern: /vote[\s\S]{0,50}(?:power|weight)[\s\S]{0,50}(?!snapshot|checkpoint)/i,
    description: 'Governance: Flash loans can be used to acquire voting power temporarily.',
    recommendation: 'Use vote snapshots at proposal creation time.'
  },
  {
    id: 'SOL5175',
    name: 'Governance: Proposal Frontrunning',
    severity: 'high',
    pattern: /proposal[\s\S]{0,50}create[\s\S]{0,50}(?!delay|queue|timelock)/i,
    description: 'Governance: Proposals without delay can be frontrun by attackers.',
    recommendation: 'Add delay between proposal and voting. Implement timelock for execution.'
  },
  {
    id: 'SOL5176',
    name: 'Governance: Quorum Manipulation',
    severity: 'high',
    pattern: /quorum[\s\S]{0,50}(?:percentage|threshold)(?![\s\S]{0,100}minimum|[\s\S]{0,100}floor)/i,
    description: 'Governance: Low quorum thresholds enable minority control.',
    recommendation: 'Set appropriate quorum thresholds (typically 4-10% of supply).'
  },
  
  // ============================================
  // Bridge Security Patterns
  // ============================================
  {
    id: 'SOL5177',
    name: 'Bridge: Message Verification',
    severity: 'critical',
    pattern: /bridge[\s\S]{0,50}message[\s\S]{0,50}(?!verify|validate|signatures)/i,
    description: 'Bridge: Cross-chain messages must have cryptographic verification.',
    recommendation: 'Verify all bridge messages with proper signature threshold.'
  },
  {
    id: 'SOL5178',
    name: 'Bridge: Finality Assumption',
    severity: 'critical',
    pattern: /bridge[\s\S]{0,50}(?:confirm|finality)[\s\S]{0,50}(?!block_number|confirmations)/i,
    description: 'Bridge: Insufficient finality confirmation leads to reorg attacks.',
    recommendation: 'Wait for sufficient confirmations on source chain before minting.'
  },
  {
    id: 'SOL5179',
    name: 'Bridge: Nonce Management',
    severity: 'high',
    pattern: /bridge[\s\S]{0,50}nonce[\s\S]{0,50}(?!increment|unique|replay)/i,
    description: 'Bridge: Improper nonce management enables replay attacks.',
    recommendation: 'Use incrementing nonces. Mark processed messages as used.'
  },
  {
    id: 'SOL5180',
    name: 'Bridge: Rate Limiting',
    severity: 'high',
    pattern: /bridge[\s\S]{0,50}(?:mint|transfer)[\s\S]{0,50}(?!rate_limit|cap|threshold)/i,
    description: 'Bridge: Unbounded minting on destination chain if bridge is compromised.',
    recommendation: 'Implement rate limits and circuit breakers for bridge operations.'
  },
  
  // ============================================
  // Wallet/Key Management Patterns
  // ============================================
  {
    id: 'SOL5181',
    name: 'Wallet: Seed Phrase Exposure',
    severity: 'critical',
    pattern: /(?:seed|mnemonic|secret)_phrase[\s\S]{0,50}(?:display|show|log|print)/i,
    description: 'Wallet: Seed phrases must never be logged or displayed insecurely.',
    recommendation: 'Use secure display methods. Clear memory after use.'
  },
  {
    id: 'SOL5182',
    name: 'Wallet: Key Derivation Path',
    severity: 'high',
    pattern: /derivation_path[\s\S]{0,50}(?!bip44|ed25519|standard)/i,
    description: 'Wallet: Non-standard derivation paths can lead to key recovery issues.',
    recommendation: 'Use standard BIP44 derivation paths for Solana.'
  },
  {
    id: 'SOL5183',
    name: 'Wallet: Transaction Signing Blind',
    severity: 'high',
    pattern: /sign[\s\S]{0,30}transaction[\s\S]{0,50}(?!simulate|preview|verify)/i,
    description: 'Wallet: Blind signing without simulation can approve malicious transactions.',
    recommendation: 'Always simulate transactions before signing. Show human-readable summary.'
  },
  
  // ============================================
  // Protocol-Specific Deep Patterns
  // ============================================
  {
    id: 'SOL5184',
    name: 'Lending: Interest Rate Model',
    severity: 'high',
    pattern: /interest_rate[\s\S]{0,50}(?:model|curve)[\s\S]{0,50}(?!kink|optimal)/i,
    description: 'Lending: Interest rate models without kink can lead to extreme rates.',
    recommendation: 'Implement kinked interest rate model with optimal utilization.'
  },
  {
    id: 'SOL5185',
    name: 'Lending: Bad Debt Socialization',
    severity: 'high',
    pattern: /bad_debt[\s\S]{0,50}(?!socialize|distribute|insurance)/i,
    description: 'Lending: Bad debt handling strategy affects all depositors.',
    recommendation: 'Implement insurance fund. Socialize bad debt fairly across depositors.'
  },
  {
    id: 'SOL5186',
    name: 'AMM: Impermanent Loss Calculation',
    severity: 'medium',
    pattern: /impermanent_loss[\s\S]{0,50}(?!calculate|estimate|warn)/i,
    description: 'AMM: LPs should be warned about impermanent loss risk.',
    recommendation: 'Calculate and display impermanent loss estimates to LPs.'
  },
  {
    id: 'SOL5187',
    name: 'Staking: Delegation Security',
    severity: 'high',
    pattern: /delegate[\s\S]{0,30}(?:stake|token)[\s\S]{0,50}(?!whitelist|approved|verify)/i,
    description: 'Staking: Delegation to malicious validators can slash funds.',
    recommendation: 'Implement validator whitelist or reputation system.'
  },
  {
    id: 'SOL5188',
    name: 'Vault: Share Inflation Attack',
    severity: 'critical',
    pattern: /vault[\s\S]{0,50}(?:share|deposit)[\s\S]{0,50}(?!initial_shares|first_deposit)/i,
    description: 'Vault: First depositor can inflate share value to steal from others.',
    recommendation: 'Mint initial shares to dead address or use virtual shares.'
  },
  {
    id: 'SOL5189',
    name: 'Options: Settlement Price Manipulation',
    severity: 'critical',
    pattern: /settlement[\s\S]{0,50}price[\s\S]{0,50}(?!twap|window|average)/i,
    description: 'Options: Settlement prices can be manipulated near expiry.',
    recommendation: 'Use TWAP for settlement prices over extended window.'
  },
  {
    id: 'SOL5190',
    name: 'Perps: Funding Payment Timing',
    severity: 'high',
    pattern: /funding[\s\S]{0,50}payment[\s\S]{0,50}(?!interval|checkpoint)/i,
    description: 'Perps: Funding payments at predictable times enable gaming.',
    recommendation: 'Use continuous funding or randomize payment intervals.'
  },
  
  // ============================================
  // Infrastructure Security Patterns
  // ============================================
  {
    id: 'SOL5191',
    name: 'Infra: RPC Endpoint Trust',
    severity: 'high',
    pattern: /rpc[\s\S]{0,30}(?:endpoint|url)[\s\S]{0,50}(?!verify|trusted|known)/i,
    description: 'Infrastructure: Untrusted RPC endpoints can return false data.',
    recommendation: 'Use multiple RPC providers. Verify critical data on-chain.'
  },
  {
    id: 'SOL5192',
    name: 'Infra: Websocket Reconnection',
    severity: 'medium',
    pattern: /websocket[\s\S]{0,50}(?:connect|subscribe)[\s\S]{0,50}(?!reconnect|retry)/i,
    description: 'Infrastructure: Websocket disconnections can cause missed events.',
    recommendation: 'Implement automatic reconnection with exponential backoff.'
  },
  {
    id: 'SOL5193',
    name: 'Infra: Transaction Retry Logic',
    severity: 'medium',
    pattern: /send_transaction[\s\S]{0,50}(?!retry|confirm|poll)/i,
    description: 'Infrastructure: Transactions may not land without proper retry logic.',
    recommendation: 'Implement transaction retry with confirmation polling.'
  },
  
  // ============================================
  // Emergency Response Patterns
  // ============================================
  {
    id: 'SOL5194',
    name: 'Emergency: Pause Mechanism',
    severity: 'high',
    pattern: /emergency[\s\S]{0,50}(?!pause|stop|halt|freeze)/i,
    description: 'Emergency: Protocols need pause mechanisms for incident response.',
    recommendation: 'Implement pausable pattern with guardian/multisig control.'
  },
  {
    id: 'SOL5195',
    name: 'Emergency: Fund Recovery',
    severity: 'high',
    pattern: /stuck_funds|locked_funds(?![\s\S]{0,100}recover|[\s\S]{0,100}rescue)/i,
    description: 'Emergency: No mechanism to recover accidentally stuck funds.',
    recommendation: 'Implement fund recovery with timelock and governance approval.'
  },
  {
    id: 'SOL5196',
    name: 'Emergency: Upgrade Path',
    severity: 'medium',
    pattern: /upgrade[\s\S]{0,30}(?:program|contract)[\s\S]{0,50}(?!authority|multisig|timelock)/i,
    description: 'Emergency: Program upgrades need proper authorization.',
    recommendation: 'Use multisig + timelock for program upgrades.'
  },
  
  // ============================================
  // Monitoring & Detection Patterns
  // ============================================
  {
    id: 'SOL5197',
    name: 'Monitor: Event Emission',
    severity: 'low',
    pattern: /(?:transfer|withdraw|deposit|swap)[\s\S]{0,100}(?!emit!|log|event)/i,
    description: 'Monitoring: Critical operations should emit events for off-chain monitoring.',
    recommendation: 'Emit events for all state-changing operations.'
  },
  {
    id: 'SOL5198',
    name: 'Monitor: Anomaly Detection Data',
    severity: 'low',
    pattern: /amount[\s\S]{0,30}>\s*\d+(?![\s\S]{0,50}alert|[\s\S]{0,50}flag|[\s\S]{0,50}monitor)/i,
    description: 'Monitoring: Large transactions should trigger monitoring alerts.',
    recommendation: 'Implement anomaly detection for unusual transaction patterns.'
  },
  {
    id: 'SOL5199',
    name: 'Monitor: Invariant Assertion',
    severity: 'medium',
    pattern: /invariant(?![\s\S]{0,50}check|[\s\S]{0,50}assert|[\s\S]{0,50}verify)/i,
    description: 'Monitoring: Protocol invariants should be checked and logged.',
    recommendation: 'Add invariant checks with logging for debugging.'
  },
  {
    id: 'SOL5200',
    name: 'Monitor: Circuit Breaker Trigger',
    severity: 'high',
    pattern: /circuit_breaker(?![\s\S]{0,100}trigger|[\s\S]{0,100}threshold|[\s\S]{0,100}trip)/i,
    description: 'Monitoring: Circuit breakers should automatically trigger on anomalies.',
    recommendation: 'Implement automatic circuit breakers with configurable thresholds.'
  },
];

/**
 * Run Batch 91 patterns against the input
 */
export function checkBatch91Patterns(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';
  const fileName = input.path || input.rust?.filePath || 'unknown';
  
  if (!content) {
    return findings;
  }
  
  const lines = content.split('\n');
  
  for (const pattern of BATCH_91_PATTERNS) {
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
      // Skip pattern if regex fails
    }
  }
  
  return findings;
}

export default BATCH_91_PATTERNS;
