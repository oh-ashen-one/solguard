/**
 * SolGuard Batch 77 Security Patterns
 * Based on: arXiv:2504.07419 Academic Research + Armani Sealevel + Audit Firm Reports
 * 
 * Pattern IDs: SOL3776 - SOL3875 (100 patterns)
 * Created: Feb 6, 2026 12:05 AM CST
 * 
 * Sources:
 * - arXiv:2504.07419 "Exploring Vulnerabilities in Solana Smart Contracts"
 * - Armani Sealevel Attacks GitHub
 * - Neodyme Common Pitfalls + Workshop
 * - OtterSec Auditor's Perspective
 * - Kudelski Solana Program Security
 * - Zellic Anchor Vulnerabilities
 * - Trail of Bits DeFi Security
 * - Sec3 How to Audit Series
 */

import type { Finding, PatternInput } from './index.js';

// ============================================================================
// ARXIV ACADEMIC: SYSTEMATIC VULNERABILITY CLASSIFICATION
// ============================================================================

const ARXIV_ACADEMIC_PATTERNS: {
  id: string;
  name: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  pattern: RegExp;
  description: string;
  recommendation: string;
}[] = [
  // 3.1.1 Missing Signer Check (arXiv)
  {
    id: 'SOL3776',
    name: 'arXiv 3.1.1 - Missing Signer Verification (Solend Pattern)',
    severity: 'critical',
    pattern: /(?:authority|admin|owner)[\s\S]{0,50}AccountInfo[\s\S]{0,100}(?!\.is_signer)/,
    description: 'Authority account without signer verification. Solend $2M pattern documented in arXiv.',
    recommendation: 'Always verify authority.is_signer() before privileged operations.'
  },
  {
    id: 'SOL3777',
    name: 'arXiv 3.1.1 - Key Match Without Signature',
    severity: 'critical',
    pattern: /\.key\s*==[\s\S]{0,30}\.key[\s\S]{0,100}(?!is_signer)/,
    description: 'Key comparison without signer check allows spoofing.',
    recommendation: 'Combine key comparison with is_signer verification.'
  },

  // 3.1.2 Missing Ownership Check (arXiv)
  {
    id: 'SOL3778',
    name: 'arXiv 3.1.2 - Missing Account Ownership Verification',
    severity: 'critical',
    pattern: /AccountInfo[\s\S]{0,100}\.data[\s\S]{0,100}(?!owner\s*==|owner\(\))/,
    description: 'Account data access without ownership check. arXiv documented vulnerability.',
    recommendation: 'Verify account.owner() == expected_program_id before data access.'
  },
  {
    id: 'SOL3779',
    name: 'arXiv 3.1.2 - Forged Account Injection',
    severity: 'critical',
    pattern: /try_borrow_data[\s\S]{0,100}(?!owner_check|verify_owner)/,
    description: 'Borrowing account data without ownership verification allows forged accounts.',
    recommendation: 'Check account ownership before borrowing data.'
  },

  // 3.1.3 Missing Rent Exemption Check
  {
    id: 'SOL3780',
    name: 'arXiv 3.1.3 - Missing Rent Exemption Check',
    severity: 'medium',
    pattern: /(?:create|init)[\s\S]{0,100}(?:account|pda)[\s\S]{0,100}(?!rent_exempt|minimum_balance)/,
    description: 'Account creation without rent exemption verification.',
    recommendation: 'Verify account has rent-exempt minimum balance.'
  },

  // Account Type Confusion (arXiv)
  {
    id: 'SOL3781',
    name: 'arXiv - Account Type Confusion Attack',
    severity: 'critical',
    pattern: /try_from_slice[\s\S]{0,100}(?!discriminator|type_check)/,
    description: 'Deserialization without type verification enables confusion attacks.',
    recommendation: 'Verify 8-byte discriminator before deserialization.'
  },

  // Cross-Instance Reinitialization (arXiv)
  {
    id: 'SOL3782',
    name: 'arXiv - Cross-Instance Reinitialization Attack',
    severity: 'high',
    pattern: /initialize[\s\S]{0,100}(?:program_id|cross_program)[\s\S]{0,100}(?!instance_check)/,
    description: 'Initialization vulnerable to cross-program instance attacks.',
    recommendation: 'Verify program instance matches expected deployment.'
  },

  // Oracle Manipulation (Solend $1.26M - arXiv Table 1)
  {
    id: 'SOL3783',
    name: 'arXiv Table 1 - Oracle Attack Pattern (Solend)',
    severity: 'critical',
    pattern: /oracle[\s\S]{0,100}(?:price|feed)[\s\S]{0,100}(?!aggregate|multi_source)/,
    description: 'Single oracle source vulnerable to manipulation. Solend $1.26M (arXiv Table 1).',
    recommendation: 'Use multiple oracle sources with aggregation.'
  },

  // Flash Loan Attack (Mango $100M, Nirvana $3.5M - arXiv Table 1)
  {
    id: 'SOL3784',
    name: 'arXiv Table 1 - Flash Loan Attack (Mango/Nirvana)',
    severity: 'critical',
    pattern: /(?:flash_loan|borrow)[\s\S]{0,100}(?!same_block|atomic_check)/,
    description: 'Flash loan without same-block detection. Mango $100M, Nirvana $3.5M (arXiv).',
    recommendation: 'Add same-block/same-slot detection for flash loan protection.'
  },

  // Cascade Attack (Tulip/UXD via Mango - arXiv Table 1)
  {
    id: 'SOL3785',
    name: 'arXiv Table 1 - Cascade Attack (Tulip/UXD)',
    severity: 'high',
    pattern: /(?:integrated|connected)[\s\S]{0,100}(?:protocol|pool)[\s\S]{0,100}(?!isolation|circuit_breaker)/,
    description: 'Cross-protocol integration without isolation. Tulip $2.5M, UXD $20M via Mango.',
    recommendation: 'Implement circuit breakers and protocol isolation.'
  },

  // Operational Error (OptiFi $661K - arXiv Table 1)
  {
    id: 'SOL3786',
    name: 'arXiv Table 1 - Operational Error (OptiFi)',
    severity: 'high',
    pattern: /(?:close|shutdown)[\s\S]{0,100}program[\s\S]{0,100}(?!funds_check|balance_check)/,
    description: 'Program close without checking locked funds. OptiFi $661K (arXiv).',
    recommendation: 'Verify no funds locked before program closure.'
  },

  // Unverified Accounts (Cashio $52M - arXiv Table 1)
  {
    id: 'SOL3787',
    name: 'arXiv Table 1 - Unverified Account Bypass (Cashio)',
    severity: 'critical',
    pattern: /(?:collateral|mint)[\s\S]{0,100}(?:verify|validate)[\s\S]{0,100}(?!chain_of_trust)/,
    description: 'Collateral verification without chain of trust. Cashio $52M (arXiv).',
    recommendation: 'Establish and verify complete chain of trust for accounts.'
  },

  // Deprecated Function (Wormhole 120K ETH - arXiv Table 1)
  {
    id: 'SOL3788',
    name: 'arXiv Table 1 - Deprecated Function Exploit (Wormhole)',
    severity: 'critical',
    pattern: /verify_signatures_address|deprecated|unsafe_function/,
    description: 'Use of deprecated security function. Wormhole 120K ETH (arXiv).',
    recommendation: 'Audit for deprecated functions, use current security APIs.'
  },

  // eBPF/SBF Specific Issues (arXiv)
  {
    id: 'SOL3789',
    name: 'arXiv - eBPF Syscall Abuse',
    severity: 'high',
    pattern: /syscall[\s\S]{0,50}(?:invoke|sol_)[\s\S]{0,100}(?!validate_input)/,
    description: 'Direct syscall usage without input validation.',
    recommendation: 'Validate all inputs before syscall invocation.'
  },
  {
    id: 'SOL3790',
    name: 'arXiv - LLVM Compilation Vulnerability',
    severity: 'medium',
    pattern: /(?:#\[repr|#\[inline)[\s\S]{0,50}(?:never|always)/,
    description: 'Compiler directives may affect security properties.',
    recommendation: 'Audit compiler directives for security implications.'
  },
];

// ============================================================================
// ARMANI SEALEVEL ATTACKS (CLASSIC COLLECTION)
// ============================================================================

const SEALEVEL_ATTACKS: typeof ARXIV_ACADEMIC_PATTERNS = [
  {
    id: 'SOL3791',
    name: 'Sealevel - Duplicate Mutable Accounts',
    severity: 'high',
    pattern: /(?:account_a|source)[\s\S]{0,30}mut[\s\S]{0,30}(?:account_b|dest)[\s\S]{0,30}mut[\s\S]{0,100}(?!key.*!=)/,
    description: 'Same account passed as multiple mutable arguments.',
    recommendation: 'Verify all mutable accounts are distinct: a.key() != b.key().'
  },
  {
    id: 'SOL3792',
    name: 'Sealevel - Account Type Confusion',
    severity: 'critical',
    pattern: /(?:cast|transmute)[\s\S]{0,50}(?:AccountInfo|&\[u8\])[\s\S]{0,100}(?!discriminator)/,
    description: 'Unsafe account type casting without discriminator check.',
    recommendation: 'Always verify discriminator before type casting.'
  },
  {
    id: 'SOL3793',
    name: 'Sealevel - Sysvar Address Spoofing',
    severity: 'high',
    pattern: /sysvar[\s\S]{0,100}(?:clock|rent|slot)[\s\S]{0,100}(?!check_id|is_sysvar)/,
    description: 'Sysvar account without address verification.',
    recommendation: 'Verify sysvar addresses match expected IDs.'
  },
  {
    id: 'SOL3794',
    name: 'Sealevel - Arbitrary Program CPI',
    severity: 'critical',
    pattern: /invoke(?:_signed)?[\s\S]{0,100}(?:program|cpi_program)[\s\S]{0,100}(?!==\s*(?:TOKEN|SYSTEM|ASSOCIATED))/,
    description: 'CPI to arbitrary program without ID verification.',
    recommendation: 'Hardcode or verify program IDs for all CPI calls.'
  },
  {
    id: 'SOL3795',
    name: 'Sealevel - PDA Not Verified',
    severity: 'high',
    pattern: /create_program_address[\s\S]{0,100}(?!==|verify|check)/,
    description: 'PDA address created but not verified.',
    recommendation: 'Verify PDA address matches expected derivation.'
  },
  {
    id: 'SOL3796',
    name: 'Sealevel - Bump Seed Canonicalization',
    severity: 'high',
    pattern: /bump[\s\S]{0,50}(?:u8|param)[\s\S]{0,100}(?!canonical|find_program)/,
    description: 'User-provided bump seed allows shadow PDAs.',
    recommendation: 'Use find_program_address for canonical bump.'
  },
  {
    id: 'SOL3797',
    name: 'Sealevel - Closing Account Without Zeroing',
    severity: 'high',
    pattern: /close[\s\S]{0,100}lamports[\s\S]{0,100}(?!\.fill\(0\)|zero|clear)/,
    description: 'Account closure without data zeroing enables resurrection.',
    recommendation: 'Zero all data before transferring lamports.'
  },
  {
    id: 'SOL3798',
    name: 'Sealevel - Missing Owner Check on Read',
    severity: 'critical',
    pattern: /\.try_borrow_data\(\)[\s\S]{0,50}(?!owner|program_id)/,
    description: 'Reading account data without verifying owner.',
    recommendation: 'Check account.owner == program_id before reading.'
  },
  {
    id: 'SOL3799',
    name: 'Sealevel - init_if_needed Race',
    severity: 'high',
    pattern: /init_if_needed/,
    description: 'init_if_needed creates race condition vulnerability.',
    recommendation: 'Use explicit initialization with existence check.'
  },
  {
    id: 'SOL3800',
    name: 'Sealevel - Reallocation Vulnerability',
    severity: 'medium',
    pattern: /realloc[\s\S]{0,100}(?!bounds_check|max_size)/,
    description: 'Account reallocation without size bounds.',
    recommendation: 'Validate reallocation size against maximum.'
  },
];

// ============================================================================
// NEODYME COMMON PITFALLS + WORKSHOP
// ============================================================================

const NEODYME_PATTERNS: typeof ARXIV_ACADEMIC_PATTERNS = [
  {
    id: 'SOL3801',
    name: 'Neodyme - Rounding Error ($2.6B Risk)',
    severity: 'critical',
    pattern: /(?:round|as\s+u64)[\s\S]{0,50}(?:amount|value)[\s\S]{0,100}(?!floor_for_deposit|ceil_for_withdraw)/,
    description: 'Rounding error in financial calculation. $2.6B at risk pattern.',
    recommendation: 'Use floor for deposits (favor protocol), ceil for withdrawals (favor protocol).'
  },
  {
    id: 'SOL3802',
    name: 'Neodyme - Integer Overflow in Checked Mode',
    severity: 'high',
    pattern: /\+|\-|\*|\/[\s\S]{0,30}(?:amount|balance|fee)[\s\S]{0,50}(?!checked_|saturating_)/,
    description: 'Arithmetic operation without overflow protection.',
    recommendation: 'Use checked_add/sub/mul/div for all arithmetic.'
  },
  {
    id: 'SOL3803',
    name: 'Neodyme - Verify invoke_signed Properly',
    severity: 'critical',
    pattern: /invoke_signed[\s\S]{0,100}(?!seeds_check|signer_seeds)/,
    description: 'invoke_signed without proper seeds verification.',
    recommendation: 'Verify signer seeds match expected PDA derivation.'
  },
  {
    id: 'SOL3804',
    name: 'Neodyme - Account Confusions Without Anchor',
    severity: 'high',
    pattern: /pub\s+struct[\s\S]{0,100}AccountInfo[\s\S]{0,100}(?!#\[account\])/,
    description: 'Manual account handling without Anchor type safety.',
    recommendation: 'Use Anchor #[account] for type-safe account handling.'
  },
  {
    id: 'SOL3805',
    name: 'Neodyme - Unvalidated Reference Account',
    severity: 'high',
    pattern: /(?:reference|ref)[\s\S]{0,50}(?:account|info)[\s\S]{0,100}(?!verify|validate|check)/,
    description: 'Reference account passed without validation.',
    recommendation: 'Validate all reference accounts, even read-only ones.'
  },
];

// ============================================================================
// OTTERSEC AUDITOR PERSPECTIVE
// ============================================================================

const OTTERSEC_PATTERNS: typeof ARXIV_ACADEMIC_PATTERNS = [
  {
    id: 'SOL3806',
    name: 'OtterSec - LP Token Oracle Manipulation ($200M)',
    severity: 'critical',
    pattern: /lp[\s\S]{0,50}(?:price|value)[\s\S]{0,100}(?:reserve|balance)[\s\S]{0,100}(?!fair_price|virtual)/,
    description: 'LP token pricing using spot reserves. $200M at risk pattern.',
    recommendation: 'Use fair/virtual pricing for LP tokens.'
  },
  {
    id: 'SOL3807',
    name: 'OtterSec - AMM Price Manipulation for Oracle',
    severity: 'critical',
    pattern: /(?:amm|dex)[\s\S]{0,100}(?:price|quote)[\s\S]{0,100}(?:oracle|feed)/,
    description: 'Using AMM spot price as oracle enables manipulation.',
    recommendation: 'Use TWAP or external oracles, not AMM spot prices.'
  },
  {
    id: 'SOL3808',
    name: 'OtterSec - Lending Protocol via LP Attack',
    severity: 'critical',
    pattern: /(?:lending|borrow)[\s\S]{0,100}lp[\s\S]{0,100}(?:collateral|deposit)/,
    description: 'LP tokens as lending collateral without manipulation protection.',
    recommendation: 'Use manipulation-resistant LP valuation for collateral.'
  },
  {
    id: 'SOL3809',
    name: 'OtterSec - Drift Oracle Guardrails Pattern',
    severity: 'medium',
    pattern: /oracle[\s\S]{0,100}(?!guardrail|bound|limit|max_deviation)/,
    description: 'Oracle without guardrails allows extreme price movements.',
    recommendation: 'Implement oracle guardrails (max deviation, staleness, confidence).'
  },
];

// ============================================================================
// KUDELSKI SOLANA PROGRAM SECURITY
// ============================================================================

const KUDELSKI_PATTERNS: typeof ARXIV_ACADEMIC_PATTERNS = [
  {
    id: 'SOL3810',
    name: 'Kudelski - Ownership Validation Missing',
    severity: 'critical',
    pattern: /(?:program|account)[\s\S]{0,50}(?:data|info)[\s\S]{0,100}(?!owner\s*==|verify_owner)/,
    description: 'Account ownership not validated (Kudelski).',
    recommendation: 'Verify account ownership before trusting data.'
  },
  {
    id: 'SOL3811',
    name: 'Kudelski - Data Validation Missing',
    severity: 'high',
    pattern: /try_borrow_data[\s\S]{0,100}(?!validate|check|verify)/,
    description: 'Account data read without validation (Kudelski).',
    recommendation: 'Validate account data format and constraints.'
  },
  {
    id: 'SOL3812',
    name: 'Kudelski - Unmodified Reference Accounts',
    severity: 'medium',
    pattern: /(?:reference|readonly)[\s\S]{0,50}account[\s\S]{0,100}(?!verify_validity)/,
    description: 'Reference-only accounts not validated (Kudelski).',
    recommendation: 'Verify validity of unmodified reference accounts.'
  },
  {
    id: 'SOL3813',
    name: 'Kudelski - Wormhole Signature Delegation Chain',
    severity: 'critical',
    pattern: /(?:signature|verify)[\s\S]{0,100}(?:delegate|chain)[\s\S]{0,100}(?!complete_verification)/,
    description: 'Signature verification delegation without complete chain.',
    recommendation: 'Ensure complete verification chain for delegated signatures.'
  },
];

// ============================================================================
// ZELLIC ANCHOR VULNERABILITIES
// ============================================================================

const ZELLIC_ANCHOR_PATTERNS: typeof ARXIV_ACADEMIC_PATTERNS = [
  {
    id: 'SOL3814',
    name: 'Zellic - Anchor Seeds Constraint Mismatch',
    severity: 'high',
    pattern: /seeds\s*=\s*\[[\s\S]{0,100}\][\s\S]{0,50}(?!bump)/,
    description: 'PDA seeds defined without bump constraint.',
    recommendation: 'Always include bump constraint with seeds.'
  },
  {
    id: 'SOL3815',
    name: 'Zellic - Anchor has_one Without Constraint',
    severity: 'medium',
    pattern: /has_one[\s\S]{0,50}(?!constraint|@)/,
    description: 'has_one attribute without additional constraint.',
    recommendation: 'Combine has_one with constraint for full validation.'
  },
  {
    id: 'SOL3816',
    name: 'Zellic - Anchor close Without Balance Check',
    severity: 'high',
    pattern: /#\[account\([\s\S]{0,100}close[\s\S]{0,100}\)][\s\S]{0,200}(?!balance_check)/,
    description: 'Anchor close attribute without verifying zero balance.',
    recommendation: 'Verify account has expected balance before closing.'
  },
  {
    id: 'SOL3817',
    name: 'Zellic - Anchor Realloc Without Zero Init',
    severity: 'medium',
    pattern: /realloc[\s\S]{0,50}(?!zero\s*=\s*true)/,
    description: 'Anchor realloc without zero initialization.',
    recommendation: 'Use realloc::zero = true to zero new bytes.'
  },
  {
    id: 'SOL3818',
    name: 'Zellic - UncheckedAccount Without CHECK',
    severity: 'high',
    pattern: /UncheckedAccount[\s\S]{0,100}(?!\/\/\/\s*CHECK)/,
    description: 'UncheckedAccount without /// CHECK documentation.',
    recommendation: 'Document security justification with /// CHECK comment.'
  },
  {
    id: 'SOL3819',
    name: 'Zellic - AccountInfo in Anchor (Should Use Typed)',
    severity: 'medium',
    pattern: /(?:pub\s+)?(?:\w+):\s*AccountInfo[\s\S]{0,50}(?!\/\/\/\s*CHECK)/,
    description: 'Raw AccountInfo usage in Anchor instead of typed account.',
    recommendation: 'Use Account<\'info, T>, Signer, or Program types.'
  },
];

// ============================================================================
// SEC3 HOW TO AUDIT SERIES
// ============================================================================

const SEC3_AUDIT_PATTERNS: typeof ARXIV_ACADEMIC_PATTERNS = [
  {
    id: 'SOL3820',
    name: 'Sec3 Part 1 - Common Attack Surface: Entry Point',
    severity: 'high',
    pattern: /(?:process|handle)_instruction[\s\S]{0,100}(?!validate_accounts|check_program_id)/,
    description: 'Instruction entry point without account validation.',
    recommendation: 'Validate all accounts at instruction entry.'
  },
  {
    id: 'SOL3821',
    name: 'Sec3 Part 1 - State Transition Analysis',
    severity: 'high',
    pattern: /state[\s\S]{0,50}(?:=|:=)[\s\S]{0,100}(?!match|enum|verify_transition)/,
    description: 'State modification without transition verification.',
    recommendation: 'Define and verify valid state transitions.'
  },
  {
    id: 'SOL3822',
    name: 'Sec3 Part 2 - Automated Scanning Gap',
    severity: 'medium',
    pattern: /unsafe[\s\S]{0,30}(?:code|fn|impl)/,
    description: 'Unsafe Rust code requires manual security review.',
    recommendation: 'Minimize unsafe code, audit thoroughly when required.'
  },
  {
    id: 'SOL3823',
    name: 'Sec3 Part 3 - PoC Framework Integration',
    severity: 'info',
    pattern: /(?:test|spec)[\s\S]{0,100}(?!exploit|attack|malicious)/,
    description: 'Tests may not include adversarial scenarios.',
    recommendation: 'Include exploit PoC tests using Neodyme framework.'
  },
  {
    id: 'SOL3824',
    name: 'Sec3 Part 4 - Anchor #[program] Handler',
    severity: 'medium',
    pattern: /#\[program\][\s\S]{0,200}pub\s+fn[\s\S]{0,100}(?!ctx\.accounts)/,
    description: 'Anchor handler not using ctx.accounts pattern.',
    recommendation: 'Use ctx.accounts for validated account access.'
  },
  {
    id: 'SOL3825',
    name: 'Sec3 - Unsafe Library Reference',
    severity: 'medium',
    pattern: /use\s+(?:unsafe_|deprecated_)/,
    description: 'Importing unsafe or deprecated library.',
    recommendation: 'Audit dependencies with cargo audit, update unsafe refs.'
  },
];

// ============================================================================
// TRAIL OF BITS DEFI SECURITY
// ============================================================================

const TRAIL_OF_BITS_PATTERNS: typeof ARXIV_ACADEMIC_PATTERNS = [
  {
    id: 'SOL3826',
    name: 'ToB - DeFi Composability Risk',
    severity: 'high',
    pattern: /(?:composed|integrated)[\s\S]{0,100}(?:protocol|defi)[\s\S]{0,100}(?!risk_assessment)/,
    description: 'DeFi protocol composition without risk assessment.',
    recommendation: 'Assess risks of composed protocol interactions.'
  },
  {
    id: 'SOL3827',
    name: 'ToB - Price Oracle Dependency',
    severity: 'high',
    pattern: /(?:price|oracle)[\s\S]{0,100}(?:single|one)[\s\S]{0,100}(?!fallback|backup)/,
    description: 'Single price oracle dependency creates failure point.',
    recommendation: 'Implement oracle fallback mechanisms.'
  },
  {
    id: 'SOL3828',
    name: 'ToB - Liquidation Path Analysis',
    severity: 'high',
    pattern: /liquidat(?:e|ion)[\s\S]{0,100}(?!path_analysis|cascade_check)/,
    description: 'Liquidation without cascade analysis.',
    recommendation: 'Analyze liquidation paths for cascade risks.'
  },
  {
    id: 'SOL3829',
    name: 'ToB - Emergency Mechanism',
    severity: 'medium',
    pattern: /(?:pause|emergency|shutdown)[\s\S]{0,100}(?!admin_only|multisig)/,
    description: 'Emergency mechanism without proper access control.',
    recommendation: 'Require multisig for emergency operations.'
  },
  {
    id: 'SOL3830',
    name: 'ToB - Upgrade Path Security',
    severity: 'high',
    pattern: /upgrade[\s\S]{0,100}(?:authority|admin)[\s\S]{0,100}(?!timelock|governance)/,
    description: 'Program upgrade without timelock or governance.',
    recommendation: 'Add timelock or governance for upgrades.'
  },
];

// ============================================================================
// REAL-WORLD EXPLOIT DEEP PATTERNS
// ============================================================================

const EXPLOIT_DEEP_PATTERNS: typeof ARXIV_ACADEMIC_PATTERNS = [
  // Wormhole Deep Dive
  {
    id: 'SOL3831',
    name: 'Wormhole - SignatureSet Account Spoofing',
    severity: 'critical',
    pattern: /(?:signature|guardian)[\s\S]{0,100}(?:set|verify)[\s\S]{0,100}(?!account_owner_check)/,
    description: 'Signature verification accepting fake SignatureSet. Wormhole $326M.',
    recommendation: 'Verify SignatureSet account owned by expected program.'
  },
  {
    id: 'SOL3832',
    name: 'Wormhole - VAA Verification Bypass',
    severity: 'critical',
    pattern: /vaa[\s\S]{0,100}(?:verify|validate)[\s\S]{0,100}(?!guardian_set|quorum)/,
    description: 'VAA verification without guardian set validation.',
    recommendation: 'Verify VAA against current guardian set with quorum.'
  },

  // Mango Markets Deep Dive
  {
    id: 'SOL3833',
    name: 'Mango - Self-Trading Oracle Manipulation',
    severity: 'critical',
    pattern: /(?:perp|trade)[\s\S]{0,100}(?:oracle|mark_price)[\s\S]{0,100}(?!self_trade_check)/,
    description: 'Perp trading allows self-trades affecting oracle. Mango $116M.',
    recommendation: 'Detect and prevent self-trades affecting price.'
  },
  {
    id: 'SOL3834',
    name: 'Mango - Unrealized PnL as Collateral',
    severity: 'critical',
    pattern: /(?:pnl|profit)[\s\S]{0,100}(?:unrealized|open)[\s\S]{0,100}(?:collateral|margin)/,
    description: 'Unrealized PnL counted as collateral before settlement.',
    recommendation: 'Only count settled PnL as collateral.'
  },
  {
    id: 'SOL3835',
    name: 'Mango - Position Concentration Missing',
    severity: 'high',
    pattern: /position[\s\S]{0,100}(?:size|value)[\s\S]{0,100}(?!concentration_limit|max_position)/,
    description: 'No position concentration limits.',
    recommendation: 'Implement position size limits relative to market.'
  },

  // Cashio Deep Dive
  {
    id: 'SOL3836',
    name: 'Cashio - Root of Trust Chain Bypass',
    severity: 'critical',
    pattern: /collateral[\s\S]{0,100}(?:chain|nested)[\s\S]{0,100}(?!root_of_trust)/,
    description: 'Collateral chain without root of trust. Cashio $52M.',
    recommendation: 'Verify complete chain to trusted root account.'
  },
  {
    id: 'SOL3837',
    name: 'Cashio - Saber LP Token Authenticity',
    severity: 'critical',
    pattern: /lp[\s\S]{0,50}token[\s\S]{0,100}(?:mint|verify)[\s\S]{0,100}(?!pool_owner_check)/,
    description: 'LP token accepted without pool ownership verification.',
    recommendation: 'Verify LP token mint owned by expected pool program.'
  },

  // Crema CLMM Deep Dive
  {
    id: 'SOL3838',
    name: 'Crema - Fake Tick Account Creation',
    severity: 'critical',
    pattern: /tick[\s\S]{0,100}(?:account|create)[\s\S]{0,100}(?!program_owner)/,
    description: 'Tick account created without program ownership. Crema $8.8M.',
    recommendation: 'Verify tick accounts owned by CLMM program.'
  },
  {
    id: 'SOL3839',
    name: 'Crema - Fee Accumulator Manipulation',
    severity: 'critical',
    pattern: /fee[\s\S]{0,100}(?:accumulator|collected)[\s\S]{0,100}(?!authentic_source)/,
    description: 'Fee data from unverified source.',
    recommendation: 'Verify fee accumulator from authenticated source.'
  },
  {
    id: 'SOL3840',
    name: 'Crema - Flash Loan Fee Claim Amplification',
    severity: 'critical',
    pattern: /(?:flash_loan|claim)[\s\S]{0,100}fee[\s\S]{0,100}(?!position_check)/,
    description: 'Fee claim without position verification.',
    recommendation: 'Verify position ownership and duration before fee claim.'
  },

  // Slope Wallet Deep Dive
  {
    id: 'SOL3841',
    name: 'Slope - Seed Phrase Logging to Telemetry',
    severity: 'critical',
    pattern: /(?:seed|mnemonic|phrase)[\s\S]{0,100}(?:log|send|transmit)/,
    description: 'Seed phrase sent to telemetry. Slope $8M.',
    recommendation: 'Never log or transmit seed phrases.'
  },
  {
    id: 'SOL3842',
    name: 'Slope - Unencrypted Key Storage',
    severity: 'critical',
    pattern: /(?:key|secret)[\s\S]{0,100}(?:store|save)[\s\S]{0,100}(?!encrypt|secure)/,
    description: 'Private keys stored without encryption.',
    recommendation: 'Always encrypt private keys at rest.'
  },
  {
    id: 'SOL3843',
    name: 'Slope - Sensitive Data in Telemetry',
    severity: 'critical',
    pattern: /telemetry[\s\S]{0,100}(?:send|track)[\s\S]{0,100}(?!sanitize|filter_sensitive)/,
    description: 'Telemetry may include sensitive data.',
    recommendation: 'Sanitize all telemetry to remove sensitive data.'
  },

  // Audius Governance Deep Dive
  {
    id: 'SOL3844',
    name: 'Audius - Malicious Proposal Acceptance',
    severity: 'critical',
    pattern: /proposal[\s\S]{0,100}(?:submit|create)[\s\S]{0,100}(?!validation|review)/,
    description: 'Governance proposal accepted without validation. Audius $6.1M.',
    recommendation: 'Validate proposal content and submitter permissions.'
  },
  {
    id: 'SOL3845',
    name: 'Audius - Treasury Permission Reconfiguration',
    severity: 'critical',
    pattern: /treasury[\s\S]{0,100}(?:permission|authority)[\s\S]{0,100}(?!timelock|delay)/,
    description: 'Treasury permissions changeable without delay.',
    recommendation: 'Add timelock for treasury permission changes.'
  },

  // Nirvana Finance Deep Dive
  {
    id: 'SOL3846',
    name: 'Nirvana - Bonding Curve Flash Loan',
    severity: 'critical',
    pattern: /bonding[\s\S]{0,100}(?:curve|price)[\s\S]{0,100}(?!flash_guard|atomic)/,
    description: 'Bonding curve exploitable via flash loan. Nirvana $3.5M.',
    recommendation: 'Add flash loan protection to bonding curves.'
  },
  {
    id: 'SOL3847',
    name: 'Nirvana - Instant Price Impact',
    severity: 'high',
    pattern: /(?:buy|sell)[\s\S]{0,100}(?:price|impact)[\s\S]{0,100}(?!slippage_limit)/,
    description: 'Trade without slippage limit allows manipulation.',
    recommendation: 'Enforce slippage limits on all trades.'
  },
];

// ============================================================================
// PROTOCOL-SPECIFIC PATTERNS
// ============================================================================

const PROTOCOL_SPECIFIC: typeof ARXIV_ACADEMIC_PATTERNS = [
  // Pyth Oracle
  {
    id: 'SOL3848',
    name: 'Pyth - Confidence Interval Not Checked',
    severity: 'high',
    pattern: /pyth[\s\S]{0,100}(?:price|get)[\s\S]{0,100}(?!conf|confidence)/,
    description: 'Pyth price used without confidence interval check.',
    recommendation: 'Verify Pyth confidence interval is acceptable.'
  },
  {
    id: 'SOL3849',
    name: 'Pyth - Expo Scaling Error',
    severity: 'high',
    pattern: /pyth[\s\S]{0,100}(?:price|expo)[\s\S]{0,100}(?!scale|adjust_expo)/,
    description: 'Pyth price not scaled by expo.',
    recommendation: 'Always scale Pyth price by 10^expo.'
  },

  // Switchboard Oracle
  {
    id: 'SOL3850',
    name: 'Switchboard - Aggregator Staleness',
    severity: 'high',
    pattern: /switchboard[\s\S]{0,100}(?:result|value)[\s\S]{0,100}(?!staleness|timestamp)/,
    description: 'Switchboard result used without staleness check.',
    recommendation: 'Check aggregator timestamp freshness.'
  },

  // Marinade Finance
  {
    id: 'SOL3851',
    name: 'Marinade - mSOL Pricing Attack',
    severity: 'high',
    pattern: /msol[\s\S]{0,100}(?:price|rate)[\s\S]{0,100}(?!verify_rate)/,
    description: 'mSOL exchange rate not verified.',
    recommendation: 'Verify mSOL rate from Marinade program.'
  },
  {
    id: 'SOL3852',
    name: 'Marinade - Delayed Unstake Ticket',
    severity: 'medium',
    pattern: /marinade[\s\S]{0,100}(?:unstake|ticket)[\s\S]{0,100}(?!epoch_check)/,
    description: 'Marinade unstake ticket epoch not verified.',
    recommendation: 'Verify ticket epoch matches current epoch.'
  },

  // Jupiter Aggregator
  {
    id: 'SOL3853',
    name: 'Jupiter - Route Manipulation',
    severity: 'high',
    pattern: /jupiter[\s\S]{0,100}(?:route|swap)[\s\S]{0,100}(?!min_out|slippage)/,
    description: 'Jupiter route without slippage protection.',
    recommendation: 'Always set min_out for Jupiter swaps.'
  },

  // Drift Protocol
  {
    id: 'SOL3854',
    name: 'Drift - Oracle Guard Rails',
    severity: 'high',
    pattern: /drift[\s\S]{0,100}(?:oracle|price)[\s\S]{0,100}(?!guard|limit)/,
    description: 'Drift oracle without guard rails.',
    recommendation: 'Use Drift oracle guard rails for price bounds.'
  },

  // Solend Protocol
  {
    id: 'SOL3855',
    name: 'Solend - Reserve Refresh Required',
    severity: 'high',
    pattern: /solend[\s\S]{0,100}(?:reserve|rate)[\s\S]{0,100}(?!refresh)/,
    description: 'Solend reserve not refreshed before use.',
    recommendation: 'Refresh reserve before reading rates.'
  },

  // Orca Whirlpool
  {
    id: 'SOL3856',
    name: 'Orca - Tick Array Bounds',
    severity: 'high',
    pattern: /whirlpool[\s\S]{0,100}(?:tick|array)[\s\S]{0,100}(?!bounds_check)/,
    description: 'Orca tick array access without bounds check.',
    recommendation: 'Verify tick index within array bounds.'
  },

  // Raydium
  {
    id: 'SOL3857',
    name: 'Raydium - Pool Authority Leak',
    severity: 'critical',
    pattern: /raydium[\s\S]{0,100}(?:pool|authority)[\s\S]{0,100}(?!admin_only)/,
    description: 'Raydium pool authority access pattern.',
    recommendation: 'Verify admin permissions for pool operations.'
  },

  // Metaplex
  {
    id: 'SOL3858',
    name: 'Metaplex - Collection Authority',
    severity: 'high',
    pattern: /metaplex[\s\S]{0,100}(?:collection|authority)[\s\S]{0,100}(?!verify)/,
    description: 'Collection authority not verified.',
    recommendation: 'Verify collection authority for NFT operations.'
  },

  // Phoenix
  {
    id: 'SOL3859',
    name: 'Phoenix - Order Book Crossing',
    severity: 'high',
    pattern: /phoenix[\s\S]{0,100}(?:order|book)[\s\S]{0,100}(?!cross_check)/,
    description: 'Phoenix order without crossing check.',
    recommendation: 'Handle order book crossing conditions.'
  },
];

// ============================================================================
// ADVANCED MEV & INFRASTRUCTURE
// ============================================================================

const MEV_INFRASTRUCTURE_PATTERNS: typeof ARXIV_ACADEMIC_PATTERNS = [
  {
    id: 'SOL3860',
    name: 'MEV - JIT Liquidity Attack',
    severity: 'high',
    pattern: /(?:liquidity|provision)[\s\S]{0,100}(?:add|remove)[\s\S]{0,100}(?!sandwich_protection)/,
    description: 'Liquidity operation vulnerable to JIT sandwich.',
    recommendation: 'Use private transactions or MEV protection.'
  },
  {
    id: 'SOL3861',
    name: 'MEV - Order Flow Extraction',
    severity: 'medium',
    pattern: /(?:order|trade)[\s\S]{0,100}(?:submit|send)[\s\S]{0,100}(?!private|protected)/,
    description: 'Trade order visible in mempool for front-running.',
    recommendation: 'Use Jito bundles or private transaction submission.'
  },
  {
    id: 'SOL3862',
    name: 'MEV - Time-Bandit Reorganization',
    severity: 'high',
    pattern: /(?:finality|confirm)[\s\S]{0,100}(?!sufficient_slots)/,
    description: 'Insufficient confirmation slots for finality.',
    recommendation: 'Wait for sufficient slot confirmations.'
  },
  {
    id: 'SOL3863',
    name: 'Infra - Validator Stake Concentration',
    severity: 'medium',
    pattern: /validator[\s\S]{0,100}(?:stake|delegation)[\s\S]{0,100}(?!diversity)/,
    description: 'Stake concentration risk in validator selection.',
    recommendation: 'Diversify stake across multiple validators.'
  },
  {
    id: 'SOL3864',
    name: 'Infra - Hosting Provider Concentration',
    severity: 'medium',
    pattern: /(?:deploy|host)[\s\S]{0,100}(?:aws|gcp|azure)[\s\S]{0,100}(?!multi_provider)/,
    description: 'Single cloud provider concentration risk.',
    recommendation: 'Distribute infrastructure across providers.'
  },
  {
    id: 'SOL3865',
    name: 'Infra - RPC Provider Manipulation',
    severity: 'high',
    pattern: /rpc[\s\S]{0,100}(?:endpoint|url)[\s\S]{0,100}(?!fallback|multi)/,
    description: 'Single RPC provider enables manipulation.',
    recommendation: 'Use multiple RPC providers with fallback.'
  },
];

// ============================================================================
// TESTING & DEPLOYMENT PATTERNS
// ============================================================================

const TESTING_DEPLOYMENT_PATTERNS: typeof ARXIV_ACADEMIC_PATTERNS = [
  {
    id: 'SOL3866',
    name: 'Testing - Devnet Address in Mainnet',
    severity: 'critical',
    pattern: /(?:devnet|testnet)[\s\S]{0,50}(?:address|pubkey|endpoint)/,
    description: 'Devnet/testnet reference in mainnet code.',
    recommendation: 'Remove all devnet/testnet references before mainnet.'
  },
  {
    id: 'SOL3867',
    name: 'Testing - Debug Code in Production',
    severity: 'high',
    pattern: /(?:debug|console\.log|println!)[\s\S]{0,50}(?!#\[cfg\(test\)\])/,
    description: 'Debug code in production build.',
    recommendation: 'Remove debug code or gate with cfg(test).'
  },
  {
    id: 'SOL3868',
    name: 'Testing - Missing Fuzzing',
    severity: 'medium',
    pattern: /(?:test|spec)[\s\S]{0,100}(?!fuzz|arbitrary|quickcheck)/,
    description: 'Test suite without fuzzing.',
    recommendation: 'Add fuzz testing for input validation.'
  },
  {
    id: 'SOL3869',
    name: 'Deployment - Upgrade Authority Active',
    severity: 'medium',
    pattern: /upgrade[\s\S]{0,50}authority[\s\S]{0,100}(?!revoked|none)/,
    description: 'Upgrade authority still active.',
    recommendation: 'Consider revoking upgrade authority after deployment.'
  },
  {
    id: 'SOL3870',
    name: 'Deployment - Mainnet Without Audit',
    severity: 'high',
    pattern: /mainnet[\s\S]{0,100}(?:deploy|launch)[\s\S]{0,100}(?!audit|reviewed)/,
    description: 'Mainnet deployment without audit reference.',
    recommendation: 'Complete security audit before mainnet launch.'
  },
];

// ============================================================================
// MISCELLANEOUS ADVANCED PATTERNS
// ============================================================================

const MISC_ADVANCED_PATTERNS: typeof ARXIV_ACADEMIC_PATTERNS = [
  {
    id: 'SOL3871',
    name: 'Misc - Timestamp Manipulation',
    severity: 'medium',
    pattern: /(?:clock|unix_timestamp)[\s\S]{0,100}(?!slot_based|tolerance)/,
    description: 'Timestamp used without manipulation protection.',
    recommendation: 'Use slot-based timing or add timestamp tolerance.'
  },
  {
    id: 'SOL3872',
    name: 'Misc - Slot-Based Randomness (Predictable)',
    severity: 'high',
    pattern: /(?:random|seed)[\s\S]{0,50}(?:slot|hash)[\s\S]{0,100}(?!vrf|commit_reveal)/,
    description: 'Slot-based randomness is predictable.',
    recommendation: 'Use VRF or commit-reveal for randomness.'
  },
  {
    id: 'SOL3873',
    name: 'Misc - CPI Return Data Spoofing',
    severity: 'high',
    pattern: /(?:cpi|invoke)[\s\S]{0,100}(?:return|result)[\s\S]{0,100}(?!verify_program)/,
    description: 'CPI return data accepted without program verification.',
    recommendation: 'Verify program ID before trusting return data.'
  },
  {
    id: 'SOL3874',
    name: 'Misc - Close Account Balance Drain',
    severity: 'high',
    pattern: /close[\s\S]{0,100}(?:account|pda)[\s\S]{0,100}(?!destination_check)/,
    description: 'Account close without destination verification.',
    recommendation: 'Verify close destination is expected recipient.'
  },
  {
    id: 'SOL3875',
    name: 'Misc - Rent Exemption Threshold',
    severity: 'medium',
    pattern: /(?:lamports|balance)[\s\S]{0,100}(?!>=.*rent_exempt|minimum_balance)/,
    description: 'Balance check without rent exemption consideration.',
    recommendation: 'Account for rent-exempt minimum in balance checks.'
  },
];

// ============================================================================
// EXPORT ALL PATTERNS
// ============================================================================

export const BATCH_77_PATTERNS = [
  ...ARXIV_ACADEMIC_PATTERNS,
  ...SEALEVEL_ATTACKS,
  ...NEODYME_PATTERNS,
  ...OTTERSEC_PATTERNS,
  ...KUDELSKI_PATTERNS,
  ...ZELLIC_ANCHOR_PATTERNS,
  ...SEC3_AUDIT_PATTERNS,
  ...TRAIL_OF_BITS_PATTERNS,
  ...EXPLOIT_DEEP_PATTERNS,
  ...PROTOCOL_SPECIFIC,
  ...MEV_INFRASTRUCTURE_PATTERNS,
  ...TESTING_DEPLOYMENT_PATTERNS,
  ...MISC_ADVANCED_PATTERNS,
];

export function scanBatch77(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.content;
  const filePath = input.filePath || 'unknown';

  for (const pattern of BATCH_77_PATTERNS) {
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

// Pattern count: 100 patterns (SOL3776 - SOL3875)
export const BATCH_77_COUNT = BATCH_77_PATTERNS.length;
