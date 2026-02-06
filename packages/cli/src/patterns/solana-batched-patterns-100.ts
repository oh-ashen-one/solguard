/**
 * SolGuard Security Patterns - Batch 100 🎉
 * 
 * Feb 6, 2026 9:30 AM - 100th Batch Milestone!
 * 
 * Sources:
 * - Sec3 2025 Report: 163 audits, 1,669 vulnerabilities (Business Logic 38.5%, Input 25%, Access 19%)
 * - Chrome Extension Malware (Crypto Copilot): Hidden SOL fee injection
 * - Helius Complete History: 38 verified incidents (Dec 2025 - Q1 2026 updates)
 * - Socket Security Research: Browser extension attack vectors
 * - Post-Quantum Security Research: 2026 future-proofing
 * 
 * Pattern IDs: SOL6201-SOL6300
 */

import type { PatternInput, Finding } from './index.js';

interface Pattern {
  id: string;
  name: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  pattern: RegExp;
  description: string;
  recommendation: string;
  category: string;
  source?: string;
}

// ===== Chrome Extension Malware Patterns (Crypto Copilot Attack) =====
const CHROME_EXTENSION_PATTERNS: Pattern[] = [
  {
    id: 'SOL6201',
    name: 'Hidden Fee Injection in Transaction',
    severity: 'critical',
    pattern: /SystemProgram\.transfer[\s\S]{0,200}(?:fee|platform|hidden|extra)[\s\S]{0,100}(?!.*user_consent|.*display_fee)/i,
    description: 'Transaction contains hidden fee transfer instructions that users may not see. Similar to Crypto Copilot extension attack.',
    recommendation: 'Always display all transfer instructions to users. Require explicit consent for any fees.',
    category: 'Browser Extension Security',
    source: 'Socket Security: Crypto Copilot Chrome Extension Malware (Nov 2025)'
  },
  {
    id: 'SOL6202',
    name: 'Atomic Transaction Fee Bundling',
    severity: 'high',
    pattern: /transaction[\s\S]{0,100}(?:append|add|push)[\s\S]{0,100}(?:transfer|fee)[\s\S]{0,100}(?!.*separate|.*transparent)/i,
    description: 'Fee instructions bundled atomically with legitimate operations can hide malicious transfers.',
    recommendation: 'Separate fee instructions from main operations. Display each instruction clearly in wallet UI.',
    category: 'Browser Extension Security',
    source: 'Crypto Copilot attack pattern analysis'
  },
  {
    id: 'SOL6203',
    name: 'Hardcoded Fee Recipient Address',
    severity: 'critical',
    pattern: /(?:fee|platform|recipient)[\s\S]{0,50}(?:address|pubkey)[\s\S]{0,20}[=:][\s\S]{0,10}["'][1-9A-HJ-NP-Za-km-z]{32,44}["']/i,
    description: 'Hardcoded fee recipient addresses can indicate malicious fee extraction like Crypto Copilot (Bjeida13AjgPaUEU9xrh1iQMwxZC7QDdvSfg73oxQff7).',
    recommendation: 'Verify fee recipient addresses against known malicious addresses. Use configurable, transparent fee settings.',
    category: 'Browser Extension Security',
    source: 'Socket Security: Identified attacker wallet Bjeida13...'
  },
  {
    id: 'SOL6204',
    name: 'Percentage-Based Hidden Fee Calculation',
    severity: 'high',
    pattern: /(?:fee|charge)[\s\S]{0,50}(?:0\.0\d+|percent|\*)[\s\S]{0,100}(?:swap|amount|trade)[\s\S]{0,100}(?!.*disclosed|.*shown)/i,
    description: 'Undisclosed percentage-based fees (e.g., 0.05% of swap) extracted from transactions.',
    recommendation: 'Always disclose fee percentages upfront. Display actual fee amount before signing.',
    category: 'Browser Extension Security',
    source: 'Crypto Copilot: 0.05% or 0.0013 SOL minimum'
  },
  {
    id: 'SOL6205',
    name: 'Wallet Permission Abuse for Fee Injection',
    severity: 'critical',
    pattern: /(?:phantom|solflare|wallet)[\s\S]{0,100}(?:connect|sign)[\s\S]{0,200}(?:inject|append|modify)[\s\S]{0,100}(?:transfer|fee)/i,
    description: 'Extensions abusing wallet connection permissions to inject unauthorized transfers.',
    recommendation: 'Audit all wallet integrations. Use minimal permission scopes. Display full transaction details.',
    category: 'Browser Extension Security',
    source: 'Crypto Copilot integrated with Phantom/Solflare'
  },
];

// ===== Sec3 2025 Business Logic Patterns (38.5% of vulnerabilities) =====
const SEC3_BUSINESS_LOGIC_PATTERNS: Pattern[] = [
  {
    id: 'SOL6206',
    name: 'Protocol State Machine Violation',
    severity: 'critical',
    pattern: /(?:state|status)[\s\S]{0,50}(?:transition|change|update)[\s\S]{0,200}(?!.*valid_transition|.*state_machine|.*require.*current_state)/i,
    description: 'State transitions without validation can allow skipping required protocol phases.',
    recommendation: 'Implement explicit state machine with validated transitions. Check current state before any update.',
    category: 'Business Logic',
    source: 'Sec3 2025: Business Logic 38.5% of severe vulnerabilities'
  },
  {
    id: 'SOL6207',
    name: 'Economic Invariant Violation',
    severity: 'critical',
    pattern: /(?:deposit|withdraw|mint|burn)[\s\S]{0,200}(?!.*invariant_check|.*balance_eq|.*total_supply.*==)/i,
    description: 'Token operations without economic invariant checks can break protocol math.',
    recommendation: 'Assert economic invariants after every operation: total_supply == sum(balances), etc.',
    category: 'Business Logic',
    source: 'Sec3 2025 Report: Economic invariant failures'
  },
  {
    id: 'SOL6208',
    name: 'Redemption Logic Bypass',
    severity: 'critical',
    pattern: /redeem[\s\S]{0,200}(?!.*cooldown|.*timelock|.*rate_limit|.*max_per_epoch)/i,
    description: 'Redemption without rate limits allows draining pools in single transaction.',
    recommendation: 'Add redemption cooldowns, per-epoch limits, and timelocked redemptions for large amounts.',
    category: 'Business Logic',
    source: 'Sec3 2025: Common redemption logic flaws'
  },
  {
    id: 'SOL6209',
    name: 'Fee Calculation Order Manipulation',
    severity: 'high',
    pattern: /fee[\s\S]{0,50}(?:calc|compute)[\s\S]{0,100}(?:before|after)[\s\S]{0,100}(?:swap|trade|transfer)/i,
    description: 'Fee calculation order can be manipulated to reduce fees paid or extract extra fees.',
    recommendation: 'Standardize fee calculation order. Calculate fees before state changes. Lock fee parameters.',
    category: 'Business Logic',
    source: 'Sec3 2025: Fee manipulation patterns'
  },
  {
    id: 'SOL6210',
    name: 'Reward Distribution Logic Flaw',
    severity: 'high',
    pattern: /(?:reward|yield|interest)[\s\S]{0,100}(?:distribut|claim|harvest)[\s\S]{0,200}(?!.*pro_rata|.*time_weighted|.*snapshot)/i,
    description: 'Reward distribution without time-weighting allows gaming via deposit/claim timing.',
    recommendation: 'Use time-weighted rewards. Take snapshots at distribution time. Prevent same-block claims.',
    category: 'Business Logic',
    source: 'Sec3 2025: Reward gaming vulnerabilities'
  },
  {
    id: 'SOL6211',
    name: 'Collateral Value Calculation Race',
    severity: 'critical',
    pattern: /collateral[\s\S]{0,100}(?:value|worth|price)[\s\S]{0,200}(?!.*atomic|.*same_slot|.*locked_price)/i,
    description: 'Collateral value calculated at different points can be manipulated between checks.',
    recommendation: 'Lock collateral price at operation start. Use atomic price checks. Prevent flash loan attacks.',
    category: 'Business Logic',
    source: 'Sec3 2025: Collateral manipulation patterns'
  },
  {
    id: 'SOL6212',
    name: 'Liquidation Profit Maximization Exploit',
    severity: 'high',
    pattern: /liquidat[\s\S]{0,200}(?:bonus|profit|incentive)[\s\S]{0,100}(?!.*cap|.*max_bonus|.*reasonable_range)/i,
    description: 'Unbounded liquidation bonuses can be exploited to drain excess collateral.',
    recommendation: 'Cap liquidation bonuses. Implement gradual liquidation. Return excess to borrower.',
    category: 'Business Logic',
    source: 'Sec3 2025: Liquidation mechanism flaws'
  },
];

// ===== Sec3 2025 Input Validation Patterns (25% of vulnerabilities) =====
const SEC3_INPUT_VALIDATION_PATTERNS: Pattern[] = [
  {
    id: 'SOL6213',
    name: 'Unbounded Array Input DoS',
    severity: 'high',
    pattern: /(?:Vec|array|list)[\s\S]{0,50}(?:input|param|arg)[\s\S]{0,100}(?!.*max_len|.*limit|.*\.len\(\)\s*[<>]=)/i,
    description: 'Unbounded array inputs can cause compute exhaustion or memory issues.',
    recommendation: 'Limit array lengths. Check .len() <= MAX before processing. Use pagination for large datasets.',
    category: 'Input Validation',
    source: 'Sec3 2025: Input Validation 25% of vulnerabilities'
  },
  {
    id: 'SOL6214',
    name: 'String Input Length Overflow',
    severity: 'medium',
    pattern: /String[\s\S]{0,50}(?:input|name|symbol|uri)[\s\S]{0,100}(?!.*max_len|.*truncate|.*\.len\(\)\s*<=)/i,
    description: 'Unbounded string inputs can exceed account space or cause serialization issues.',
    recommendation: 'Define max string lengths. Validate before storage. Use fixed-size arrays where possible.',
    category: 'Input Validation',
    source: 'Sec3 2025: String handling vulnerabilities'
  },
  {
    id: 'SOL6215',
    name: 'Numeric Range Violation',
    severity: 'high',
    pattern: /(?:amount|value|quantity|price)[\s\S]{0,50}(?:u64|u128|i64)[\s\S]{0,100}(?!.*require.*>.*0|.*min_|.*max_|.*range_check)/i,
    description: 'Numeric inputs without range validation can cause underflow, overflow, or invalid states.',
    recommendation: 'Validate numeric ranges. Check > 0 for amounts. Define min/max bounds for all inputs.',
    category: 'Input Validation',
    source: 'Sec3 2025: Numeric validation patterns'
  },
  {
    id: 'SOL6216',
    name: 'Enum Variant Out of Range',
    severity: 'medium',
    pattern: /enum[\s\S]{0,200}(?:from_u8|try_from|deserialize)[\s\S]{0,100}(?!.*match|.*invalid|.*err)/i,
    description: 'Enum deserialization without variant validation can cause undefined behavior.',
    recommendation: 'Use exhaustive match statements. Return error for invalid enum variants. Never use unsafe transmute.',
    category: 'Input Validation',
    source: 'Sec3 2025: Enum handling vulnerabilities'
  },
  {
    id: 'SOL6217',
    name: 'Timestamp Future/Past Manipulation',
    severity: 'high',
    pattern: /(?:timestamp|time|clock)[\s\S]{0,100}(?:input|param)[\s\S]{0,100}(?!.*sysvar::clock|.*Clock::get|.*reasonable_range)/i,
    description: 'User-provided timestamps without validation against Clock sysvar enable time manipulation.',
    recommendation: 'Always use Clock sysvar for time. If user input needed, validate within reasonable range of current time.',
    category: 'Input Validation',
    source: 'Sec3 2025: Timestamp manipulation patterns'
  },
  {
    id: 'SOL6218',
    name: 'Instruction Data Bounds Check Missing',
    severity: 'high',
    pattern: /instruction_data[\s\S]{0,100}(?:slice|index|\[)[\s\S]{0,50}(?!.*len|.*bounds|.*get\()/i,
    description: 'Direct indexing into instruction data without bounds checking can panic or read garbage.',
    recommendation: 'Use .get() with bounds checking. Validate instruction data length before parsing.',
    category: 'Input Validation',
    source: 'Sec3 2025: Instruction parsing vulnerabilities'
  },
];

// ===== Sec3 2025 Access Control Patterns (19% of vulnerabilities) =====
const SEC3_ACCESS_CONTROL_PATTERNS: Pattern[] = [
  {
    id: 'SOL6219',
    name: 'Admin Function Without Role Check',
    severity: 'critical',
    pattern: /(?:admin|owner|authority)[\s\S]{0,50}(?:function|instruction|handler)[\s\S]{0,200}(?!.*require.*is_signer|.*has_one|.*constraint)/i,
    description: 'Administrative functions without proper role verification allow unauthorized access.',
    recommendation: 'Verify admin signer on all privileged operations. Use has_one constraints in Anchor.',
    category: 'Access Control',
    source: 'Sec3 2025: Access Control 19% of vulnerabilities'
  },
  {
    id: 'SOL6220',
    name: 'Privileged Operation Missing Multi-Sig',
    severity: 'high',
    pattern: /(?:upgrade|migrate|pause|emergency)[\s\S]{0,200}(?!.*multisig|.*threshold|.*quorum|.*m_of_n)/i,
    description: 'Critical operations controlled by single key are vulnerable to key compromise.',
    recommendation: 'Use multi-sig for upgrades, pauses, and emergency functions. Implement time-locks.',
    category: 'Access Control',
    source: 'Sec3 2025: Single-key risks'
  },
  {
    id: 'SOL6221',
    name: 'Role Delegation Without Revocation',
    severity: 'medium',
    pattern: /(?:delegate|assign|grant)[\s\S]{0,100}(?:role|permission|authority)[\s\S]{0,200}(?!.*revoke|.*expir|.*timeout)/i,
    description: 'Delegated roles without revocation mechanism persist indefinitely.',
    recommendation: 'Implement role revocation. Add expiration timestamps. Allow admin to revoke any delegation.',
    category: 'Access Control',
    source: 'Sec3 2025: Role management vulnerabilities'
  },
  {
    id: 'SOL6222',
    name: 'Cross-Program Authority Confusion',
    severity: 'critical',
    pattern: /invoke[\s\S]{0,100}(?:authority|signer)[\s\S]{0,100}(?!.*ctx\.accounts|.*verified|.*program_id\s*==)/i,
    description: 'Authority accounts passed to CPI without verification can be spoofed.',
    recommendation: 'Verify authority accounts belong to expected programs. Check program_id ownership.',
    category: 'Access Control',
    source: 'Sec3 2025: CPI authority confusion'
  },
  {
    id: 'SOL6223',
    name: 'Initialization Authority Capture',
    severity: 'critical',
    pattern: /init[\s\S]{0,100}(?:authority|admin|owner)[\s\S]{0,100}(?!.*require.*known|.*hardcode|.*expected_authority)/i,
    description: 'First-caller becomes admin without verification, enabling authority capture by attackers.',
    recommendation: 'Set initial authority to known address. Use PDAs with seeds for deterministic authority.',
    category: 'Access Control',
    source: 'Sec3 2025: Initialization capture attacks'
  },
];

// ===== Sec3 2025 Data Integrity & Arithmetic Patterns (8.9% of vulnerabilities) =====
const SEC3_DATA_INTEGRITY_PATTERNS: Pattern[] = [
  {
    id: 'SOL6224',
    name: 'Cross-Account Data Consistency',
    severity: 'high',
    pattern: /(?:account_a|account_b)[\s\S]{0,100}(?:update|modify)[\s\S]{0,200}(?!.*atomic|.*same_tx|.*consistency_check)/i,
    description: 'Related accounts updated non-atomically can become inconsistent if transaction fails midway.',
    recommendation: 'Update related accounts atomically. Add consistency checks after updates. Use CPIs carefully.',
    category: 'Data Integrity',
    source: 'Sec3 2025: Data Integrity 8.9% of vulnerabilities'
  },
  {
    id: 'SOL6225',
    name: 'Precision Loss in Token Conversion',
    severity: 'high',
    pattern: /(?:convert|exchange|swap)[\s\S]{0,100}(?:decimal|precision)[\s\S]{0,100}(?!.*scale_|.*normalize|.*checked)/i,
    description: 'Token conversions between different decimal precision can lose value due to rounding.',
    recommendation: 'Scale to highest precision before math. Use fixed-point libraries. Round in favor of protocol.',
    category: 'Data Integrity',
    source: 'Sec3 2025: Precision loss patterns'
  },
  {
    id: 'SOL6226',
    name: 'Intermediate Overflow in Multi-Step Calculation',
    severity: 'high',
    pattern: /(?:u64|u128)[\s\S]{0,50}(?:\*|\+|-)[\s\S]{0,30}(?:\*|\+|-)[\s\S]{0,50}(?!.*checked|.*u128|.*overflow)/i,
    description: 'Multi-step calculations can overflow at intermediate steps even if final result fits.',
    recommendation: 'Use u128 for intermediate calculations. Apply checked_* for each operation.',
    category: 'Data Integrity',
    source: 'Sec3 2025: Arithmetic overflow patterns'
  },
  {
    id: 'SOL6227',
    name: 'Division Truncation Exploitation',
    severity: 'medium',
    pattern: /\/[\s\S]{0,30}(?:as u64|as u128)[\s\S]{0,50}(?!.*ceil|.*round|.*remainder)/i,
    description: 'Integer division always truncates, which can be exploited with small amounts.',
    recommendation: 'Use ceiling division when appropriate. Check for zero remainder. Add minimum thresholds.',
    category: 'Data Integrity',
    source: 'Sec3 2025: Division exploitation patterns'
  },
];

// ===== Sec3 2025 DoS & Liveness Patterns (8.5% of vulnerabilities) =====
const SEC3_DOS_PATTERNS: Pattern[] = [
  {
    id: 'SOL6228',
    name: 'Unbounded Loop Compute Exhaustion',
    severity: 'high',
    pattern: /(?:for|while|loop)[\s\S]{0,100}(?:iter|len)[\s\S]{0,100}(?!.*limit|.*max_iter|.*compute_budget)/i,
    description: 'Loops over unbounded data can exhaust compute units, causing transaction failure.',
    recommendation: 'Limit loop iterations. Use pagination. Check compute budget before heavy operations.',
    category: 'DoS & Liveness',
    source: 'Sec3 2025: DoS 8.5% of vulnerabilities'
  },
  {
    id: 'SOL6229',
    name: 'Account Closure Blocking',
    severity: 'medium',
    pattern: /close[\s\S]{0,100}(?:account|vault|position)[\s\S]{0,200}(?!.*force_close|.*admin_close|.*timeout)/i,
    description: 'Account closure can be blocked by attackers preventing state cleanup.',
    recommendation: 'Add admin force-close capability. Implement closure timeouts. Allow partial closures.',
    category: 'DoS & Liveness',
    source: 'Sec3 2025: Closure blocking patterns'
  },
  {
    id: 'SOL6230',
    name: 'Dependent Instruction Blocking',
    severity: 'medium',
    pattern: /require[\s\S]{0,50}(?:other|previous|dependent)[\s\S]{0,100}(?:instruction|tx)[\s\S]{0,100}(?!.*fallback|.*timeout)/i,
    description: 'Instructions dependent on external state can be blocked by attackers controlling that state.',
    recommendation: 'Minimize external dependencies. Add fallback mechanisms. Implement timeout-based recovery.',
    category: 'DoS & Liveness',
    source: 'Sec3 2025: Dependency blocking patterns'
  },
];

// ===== Helius 2026 Latest Exploit Patterns =====
const HELIUS_2026_PATTERNS: Pattern[] = [
  {
    id: 'SOL6231',
    name: 'Loopscale RateX Oracle Manipulation',
    severity: 'critical',
    pattern: /(?:rate|price|value)[\s\S]{0,50}(?:oracle|feed)[\s\S]{0,200}(?!.*twap|.*multi_source|.*manipulation_check)/i,
    description: 'Single-source rate oracles can be manipulated. Loopscale lost $5.8M to oracle manipulation.',
    recommendation: 'Use TWAP oracles. Aggregate multiple price sources. Implement deviation checks.',
    category: 'Oracle Security',
    source: 'Helius: Loopscale $5.8M Recovery (April 2025)'
  },
  {
    id: 'SOL6232',
    name: 'DEXX Private Key Server-Side Storage',
    severity: 'critical',
    pattern: /(?:private_key|secret_key|seed_phrase)[\s\S]{0,100}(?:server|backend|database|storage)/i,
    description: 'Server-side private key storage leads to catastrophic loss. DEXX lost $30M from key leak.',
    recommendation: 'Never store private keys server-side. Use client-side custody. Implement MPC if needed.',
    category: 'Key Management',
    source: 'Helius: DEXX $30M Private Key Leak (Nov 2024)'
  },
  {
    id: 'SOL6233',
    name: 'NoOnes Bridge Validation Bypass',
    severity: 'critical',
    pattern: /bridge[\s\S]{0,100}(?:transfer|mint|unlock)[\s\S]{0,200}(?!.*proof_verify|.*guardian_check|.*merkle)/i,
    description: 'Bridge operations without proper validation allow unauthorized minting. NoOnes lost $8M.',
    recommendation: 'Verify proofs for all bridge operations. Use guardian quorum. Implement rate limits.',
    category: 'Bridge Security',
    source: 'Helius: NoOnes $8M Bridge Exploit (Dec 2024)'
  },
  {
    id: 'SOL6234',
    name: 'Thunder Terminal MongoDB Injection',
    severity: 'critical',
    pattern: /(?:mongodb|database|query)[\s\S]{0,100}(?:session|token|auth)[\s\S]{0,100}(?!.*sanitize|.*parameterize|.*escape)/i,
    description: 'Database injection in off-chain services compromises user sessions. Thunder Terminal lost $240K.',
    recommendation: 'Use parameterized queries. Sanitize all inputs. Implement session rotation and 2FA.',
    category: 'Off-Chain Security',
    source: 'Helius: Thunder Terminal $240K (Dec 2024)'
  },
  {
    id: 'SOL6235',
    name: 'Banana Gun Bot Key Compromise',
    severity: 'critical',
    pattern: /(?:bot|automated)[\s\S]{0,100}(?:private_key|wallet|signer)[\s\S]{0,100}(?!.*hsm|.*enclave|.*mpc)/i,
    description: 'Trading bot key storage without HSM/enclave protection. Banana Gun lost $3M from key compromise.',
    recommendation: 'Use HSM or secure enclaves for bot keys. Implement key rotation. Add spending limits.',
    category: 'Bot Security',
    source: 'Helius: Banana Gun $3M Refunded (Sept 2024)'
  },
  {
    id: 'SOL6236',
    name: 'Pump.fun Employee Insider Exploit',
    severity: 'critical',
    pattern: /(?:employee|internal|staff)[\s\S]{0,100}(?:access|permission|key)[\s\S]{0,100}(?!.*audit_log|.*separation|.*principle_of_least)/i,
    description: 'Employee access without proper controls enables insider attacks. Pump.fun lost $1.9M to insider.',
    recommendation: 'Implement principle of least privilege. Audit all access. Use multi-sig for sensitive operations.',
    category: 'Insider Threat',
    source: 'Helius: Pump.fun $1.9M Employee Exploit (May 2024)'
  },
  {
    id: 'SOL6237',
    name: 'Web3.js Supply Chain npm Attack',
    severity: 'critical',
    pattern: /(?:npm|package|dependency)[\s\S]{0,100}(?:install|require|import)[\s\S]{0,100}(?!.*lock|.*hash|.*verify)/i,
    description: 'NPM package compromise can inject malicious code. Web3.js v1.95.5-8 was compromised.',
    recommendation: 'Pin dependency versions. Verify package hashes. Use lockfiles. Audit dependencies regularly.',
    category: 'Supply Chain',
    source: 'Helius: Web3.js NPM Backdoor (Dec 2024)'
  },
  {
    id: 'SOL6238',
    name: 'Solareum Wallet Drain via Fake App',
    severity: 'critical',
    pattern: /(?:mobile|app|download)[\s\S]{0,100}(?:wallet|key|seed)[\s\S]{0,100}(?!.*official|.*verified|.*store_check)/i,
    description: 'Fake mobile apps drain wallets by stealing keys. Solareum users lost $850K to fake app.',
    recommendation: 'Only use official app stores. Verify publisher identity. Never enter seeds in unofficial apps.',
    category: 'Phishing & Fake Apps',
    source: 'Helius: Solareum $850K Fake App (Sept 2024)'
  },
];

// ===== Post-Quantum & Future Security Patterns =====
const FUTURE_SECURITY_PATTERNS: Pattern[] = [
  {
    id: 'SOL6239',
    name: 'Quantum-Vulnerable Signature Scheme',
    severity: 'info',
    pattern: /ed25519|secp256k1|ecdsa[\s\S]{0,100}(?!.*post_quantum|.*pqc|.*dilithium|.*sphincs)/i,
    description: 'Current signature schemes may be vulnerable to quantum computers. Plan for migration.',
    recommendation: 'Monitor post-quantum cryptography developments. Plan signature scheme migration path.',
    category: 'Future Security',
    source: 'Medium: Solana Post-Quantum Research 2025-2026'
  },
  {
    id: 'SOL6240',
    name: 'AI Agent Wallet Control Without Limits',
    severity: 'high',
    pattern: /(?:ai|agent|automated)[\s\S]{0,100}(?:wallet|sign|transact)[\s\S]{0,100}(?!.*limit|.*approve|.*human_review)/i,
    description: 'AI agents with unlimited wallet control can drain funds if compromised or manipulated.',
    recommendation: 'Implement spending limits for AI agents. Require human approval above thresholds.',
    category: 'AI Security',
    source: 'Emerging 2026 AI Agent Security Concerns'
  },
  {
    id: 'SOL6241',
    name: 'Validator Concentration Risk',
    severity: 'medium',
    pattern: /(?:validator|stake)[\s\S]{0,100}(?:single|centralized|concentrated)[\s\S]{0,100}(?!.*distributed|.*decentralized)/i,
    description: 'Validator concentration (43% on Teraswitch/Latitude.sh) creates systemic risks.',
    recommendation: 'Monitor validator distribution. Encourage stake decentralization. Implement geographic diversity.',
    category: 'Network Security',
    source: 'CyberDaily: Validator Concentration Analysis (Nov 2025)'
  },
  {
    id: 'SOL6242',
    name: 'Jito Client Dominance Dependency',
    severity: 'medium',
    pattern: /(?:jito|mev)[\s\S]{0,100}(?:client|validator)[\s\S]{0,100}(?!.*fallback|.*alternative|.*diverse)/i,
    description: 'Jito client 88% dominance creates single point of failure for MEV infrastructure.',
    recommendation: 'Support client diversity. Implement fallback mechanisms. Monitor for Jito-specific vulnerabilities.',
    category: 'Network Security',
    source: 'CyberDaily: Jito 88% Client Dominance Risk'
  },
];

// ===== Advanced 2026 Attack Vector Patterns =====
const ADVANCED_2026_PATTERNS: Pattern[] = [
  {
    id: 'SOL6243',
    name: 'Referral Fee Bypass via Self-Referral',
    severity: 'medium',
    pattern: /referr(?:al|er)[\s\S]{0,100}(?:fee|reward|bonus)[\s\S]{0,200}(?!.*self_check|.*different_owner|.*cooldown)/i,
    description: 'Self-referral allows users to claim their own referral bonuses, draining funds.',
    recommendation: 'Block self-referrals. Add cooldowns between referrer signup and referral. Verify distinct wallets.',
    category: 'Economic Security',
    source: 'Sec3 2025: Referral system exploits'
  },
  {
    id: 'SOL6244',
    name: 'Flashbot Bundle Frontrunning',
    severity: 'high',
    pattern: /(?:bundle|jito|flashbot)[\s\S]{0,100}(?:submit|send)[\s\S]{0,100}(?!.*private|.*encrypted|.*commit_reveal)/i,
    description: 'Unprotected bundle submissions can be frontrun by validators or MEV searchers.',
    recommendation: 'Use commit-reveal for sensitive transactions. Encrypt bundle contents. Use trusted relayers.',
    category: 'MEV Protection',
    source: 'Advanced MEV Attack Research 2026'
  },
  {
    id: 'SOL6245',
    name: 'Governance Proposal Flash Attack',
    severity: 'critical',
    pattern: /(?:governance|proposal|vote)[\s\S]{0,100}(?:flash_loan|borrow)[\s\S]{0,100}(?!.*snapshot|.*timelock|.*voting_period)/i,
    description: 'Flash loans to temporarily gain voting power and pass malicious proposals.',
    recommendation: 'Snapshot voting power before proposals. Add voting delays. Implement timelocks on execution.',
    category: 'Governance Security',
    source: 'Helius: Governance attack patterns analysis'
  },
  {
    id: 'SOL6246',
    name: 'Token-2022 Transfer Hook Reentrancy',
    severity: 'critical',
    pattern: /transfer_hook[\s\S]{0,200}(?:invoke|call|execute)[\s\S]{0,100}(?!.*reentrancy_guard|.*lock|.*flag)/i,
    description: 'Token-2022 transfer hooks can enable reentrancy if not properly guarded.',
    recommendation: 'Add reentrancy guards to transfer hooks. Update state before external calls.',
    category: 'Token-2022 Security',
    source: 'Token-2022 Advanced Security Research'
  },
  {
    id: 'SOL6247',
    name: 'Compressed NFT Proof Replay',
    severity: 'high',
    pattern: /(?:cnft|compressed)[\s\S]{0,100}(?:proof|merkle)[\s\S]{0,100}(?!.*nonce|.*used_proof|.*invalidate)/i,
    description: 'cNFT merkle proofs can be replayed if not properly invalidated after use.',
    recommendation: 'Invalidate proofs after use. Add nonces to proof verification. Update merkle root atomically.',
    category: 'cNFT Security',
    source: 'Compressed NFT Security Research 2026'
  },
  {
    id: 'SOL6248',
    name: 'Blink Action Parameter Tampering',
    severity: 'high',
    pattern: /(?:blink|action)[\s\S]{0,100}(?:param|input|query)[\s\S]{0,100}(?!.*signature|.*hash|.*verify)/i,
    description: 'Blink action parameters can be tampered with if not cryptographically signed.',
    recommendation: 'Sign action parameters. Verify signatures server-side. Use content hashes.',
    category: 'Blink Security',
    source: 'Solana Actions/Blinks Security Analysis'
  },
  {
    id: 'SOL6249',
    name: 'Lookup Table Poisoning',
    severity: 'high',
    pattern: /(?:lookup_table|alt|address_lookup)[\s\S]{0,100}(?:add|extend|create)[\s\S]{0,100}(?!.*owner_check|.*authority)/i,
    description: 'Malicious addresses added to lookup tables can redirect funds or confuse users.',
    recommendation: 'Verify lookup table ownership. Validate all addresses before adding. Implement freezing.',
    category: 'Address Lookup Table Security',
    source: 'ALT Security Research 2026'
  },
  {
    id: 'SOL6250',
    name: 'Program Upgrade Backdoor Installation',
    severity: 'critical',
    pattern: /(?:upgrade|deploy)[\s\S]{0,100}(?:authority|program)[\s\S]{0,100}(?!.*timelock|.*multisig|.*announce)/i,
    description: 'Program upgrades without announcement period can silently install backdoors.',
    recommendation: 'Announce upgrades before execution. Use timelocks. Require multisig for upgrades.',
    category: 'Upgrade Security',
    source: 'Helius: Response Evolution Analysis'
  },
];

// Combine all patterns
const ALL_BATCH_100_PATTERNS = [
  ...CHROME_EXTENSION_PATTERNS,
  ...SEC3_BUSINESS_LOGIC_PATTERNS,
  ...SEC3_INPUT_VALIDATION_PATTERNS,
  ...SEC3_ACCESS_CONTROL_PATTERNS,
  ...SEC3_DATA_INTEGRITY_PATTERNS,
  ...SEC3_DOS_PATTERNS,
  ...HELIUS_2026_PATTERNS,
  ...FUTURE_SECURITY_PATTERNS,
  ...ADVANCED_2026_PATTERNS,
];

/**
 * Run Batch 100 patterns against input
 */
export function checkBatch100Patterns(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';
  const fileName = input.path || 'unknown';
  
  if (!content) return findings;
  
  const lines = content.split('\n');
  
  for (const pattern of ALL_BATCH_100_PATTERNS) {
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
          description: pattern.description + (pattern.source ? ` [Source: ${pattern.source}]` : ''),
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

// Export pattern count for documentation
export const BATCH_100_PATTERN_COUNT = ALL_BATCH_100_PATTERNS.length;

// Pattern categories for Batch 100
export const BATCH_100_CATEGORIES = {
  'Chrome Extension Security': CHROME_EXTENSION_PATTERNS.length,
  'Business Logic (Sec3 2025)': SEC3_BUSINESS_LOGIC_PATTERNS.length,
  'Input Validation (Sec3 2025)': SEC3_INPUT_VALIDATION_PATTERNS.length,
  'Access Control (Sec3 2025)': SEC3_ACCESS_CONTROL_PATTERNS.length,
  'Data Integrity (Sec3 2025)': SEC3_DATA_INTEGRITY_PATTERNS.length,
  'DoS & Liveness (Sec3 2025)': SEC3_DOS_PATTERNS.length,
  'Helius 2026 Exploits': HELIUS_2026_PATTERNS.length,
  'Future Security': FUTURE_SECURITY_PATTERNS.length,
  'Advanced 2026 Attack Vectors': ADVANCED_2026_PATTERNS.length,
};
