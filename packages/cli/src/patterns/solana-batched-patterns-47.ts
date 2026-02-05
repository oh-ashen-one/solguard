/**
 * Batch 47: Upbit Hack Patterns + Lulo Audit + CPI Deep Dive
 * IDs: SOL1581-SOL1650
 * 
 * Based on:
 * - Upbit $36M hack (Nov 2025) - Weak digital signatures, predictable nonces
 * - Lulo Certora audit (Jan 2025) - Oracle failures, referral exploits, withdrawal manipulation
 * - Three Sigma CPI research - CPI injection, privilege leaks, reentry flows
 * - ArXiv Solana vulnerability research paper
 */

import { SecurityPattern } from './types';

export const batchedPatterns47: SecurityPattern[] = [
  // === UPBIT HACK PATTERNS (Nov 2025 - $36M) ===
  {
    id: 'SOL1581',
    name: 'Weak Digital Signature Infrastructure',
    description: 'Detects weak or predictable digital signature generation that could allow private key derivation from transaction history. Based on Upbit $36M hack (Nov 2025).',
    severity: 'critical',
    category: 'cryptographic',
    detector: (code: string) => {
      const patterns = [
        /random\s*=\s*\d+/i,
        /nonce\s*=\s*timestamp/i,
        /signature.*hardcoded/i,
        /sign.*without.*random/i,
        /deterministic.*nonce/i,
        /predictable.*k.*value/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Use cryptographically secure random number generation (CSPRNG) for all signature nonces. Never use predictable values like timestamps or counters.',
  },
  {
    id: 'SOL1582',
    name: 'Hot Wallet Key Exposure Risk',
    description: 'Identifies hot wallet configurations that may expose private keys through weak signing or logging. Related to Upbit breach pattern.',
    severity: 'critical',
    category: 'key-management',
    detector: (code: string) => {
      const patterns = [
        /private.*key.*log/i,
        /secret.*key.*print/i,
        /keypair.*to_string/i,
        /export.*private/i,
        /serialize.*keypair/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Never log or serialize private keys. Use HSMs or secure enclaves for hot wallet operations.',
  },
  {
    id: 'SOL1583',
    name: 'Transaction Signature Nonce Reuse',
    description: 'Detects potential nonce reuse in ECDSA signatures which can lead to private key recovery.',
    severity: 'critical',
    category: 'cryptographic',
    detector: (code: string) => {
      const patterns = [
        /nonce.*=.*nonce/i,
        /same.*nonce/i,
        /reuse.*k.*value/i,
        /static.*nonce/i,
        /fixed.*random/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Ensure unique nonce for every signature. Use RFC 6979 deterministic nonce generation or CSPRNG.',
  },
  {
    id: 'SOL1584',
    name: 'Centralized Hot Wallet Single Point of Failure',
    description: 'Identifies centralized hot wallet architectures without multisig or threshold signatures.',
    severity: 'high',
    category: 'architecture',
    detector: (code: string) => {
      const patterns = [
        /single.*signer.*withdraw/i,
        /one.*key.*treasury/i,
        /admin.*only.*transfer/i,
        /owner.*withdraw.*all/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Implement multisig or threshold signatures for hot wallets. Use time-locked withdrawals for large amounts.',
  },

  // === LULO AUDIT PATTERNS (Certora Jan 2025) ===
  {
    id: 'SOL1585',
    name: 'Oracle Update Failure Not Handled',
    description: 'Detects missing handling for oracle update failures. Based on Lulo audit critical finding.',
    severity: 'critical',
    category: 'oracle',
    detector: (code: string) => {
      const patterns = [
        /oracle.*update.*unwrap\(\)/i,
        /price.*feed.*expect\(/i,
        /get_price.*\?(?!.*fallback)/i,
        /oracle.*result.*ok\(\)/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Implement fallback oracles and graceful degradation when oracle updates fail. Never panic on oracle failures.',
  },
  {
    id: 'SOL1586',
    name: 'Referral Fee Exploitation',
    description: 'Identifies referral fee logic that can be exploited for unauthorized fee extraction. Based on Lulo audit.',
    severity: 'high',
    category: 'business-logic',
    detector: (code: string) => {
      const patterns = [
        /referral.*fee.*unchecked/i,
        /referrer.*=.*signer/i,
        /fee.*to.*referral.*no.*verify/i,
        /referral.*self.*refer/i,
        /commission.*without.*validation/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Prevent self-referral and validate referral addresses against allowlist. Cap referral fees and verify referrer authenticity.',
  },
  {
    id: 'SOL1587',
    name: 'Withdrawal Manipulation',
    description: 'Detects withdrawal logic vulnerable to manipulation attacks. Based on Lulo audit critical finding.',
    severity: 'critical',
    category: 'business-logic',
    detector: (code: string) => {
      const patterns = [
        /withdraw.*amount.*user_input/i,
        /withdrawal.*no.*balance.*check/i,
        /claim.*without.*verify.*deposit/i,
        /withdraw.*before.*update.*state/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Verify balances before withdrawal. Update state before transfers. Implement withdrawal rate limits.',
  },
  {
    id: 'SOL1588',
    name: 'Oracle Price Staleness in Lulo Pattern',
    description: 'Detects missing staleness checks for oracle prices in lending/yield contexts.',
    severity: 'high',
    category: 'oracle',
    detector: (code: string) => {
      const patterns = [
        /price.*timestamp.*not.*checked/i,
        /oracle.*no.*freshness/i,
        /get_price.*without.*age/i,
        /pyth.*price.*\?(?!.*publish_time)/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Check price staleness using publish_time. Reject prices older than acceptable threshold (e.g., 60 seconds).',
  },

  // === CPI DEEP DIVE PATTERNS (Three Sigma Research) ===
  {
    id: 'SOL1589',
    name: 'CPI Injection Attack Vector',
    description: 'Detects CPI calls where the target program is derived from untrusted input, enabling injection attacks.',
    severity: 'critical',
    category: 'cpi',
    detector: (code: string) => {
      const patterns = [
        /invoke.*program_id.*from.*account/i,
        /cpi.*target.*user.*input/i,
        /invoke_signed.*\[.*accounts\[/i,
        /program.*id.*=.*ctx\.accounts/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Hardcode CPI target program IDs. Never derive program ID from user-supplied account data.',
  },
  {
    id: 'SOL1590',
    name: 'CPI Privilege Leak',
    description: 'Identifies CPI calls that may leak signer privileges to unintended programs.',
    severity: 'critical',
    category: 'cpi',
    detector: (code: string) => {
      const patterns = [
        /invoke.*is_signer.*true/i,
        /cpi.*pass.*signer.*seeds/i,
        /invoke_signed.*all.*accounts/i,
        /forward.*signer.*authority/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Only pass signer privileges to trusted programs. Minimize accounts passed to CPI calls.',
  },
  {
    id: 'SOL1591',
    name: 'CPI Reentry-Like Flow',
    description: 'Detects CPI patterns that could lead to reentry-like state inconsistencies.',
    severity: 'high',
    category: 'cpi',
    detector: (code: string) => {
      const patterns = [
        /state.*after.*invoke/i,
        /cpi.*then.*update.*balance/i,
        /invoke.*before.*state.*update/i,
        /external.*call.*then.*write/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Follow checks-effects-interactions pattern. Update all state before making CPI calls.',
  },
  {
    id: 'SOL1592',
    name: 'CPI Writable Account Overexposure',
    description: 'Identifies CPI calls passing writable accounts that could be modified by target program.',
    severity: 'high',
    category: 'cpi',
    detector: (code: string) => {
      const patterns = [
        /AccountMeta::new\(.*true\).*invoke/i,
        /cpi.*all.*writable/i,
        /pass.*mutable.*to.*external/i,
        /invoke.*treasury.*writable/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Only mark accounts as writable if the target program needs to modify them. Review CPI account mutability.',
  },

  // === PDA DERIVATION PATTERNS ===
  {
    id: 'SOL1593',
    name: 'PDA Seed Spoofing Vulnerability',
    description: 'Detects PDA derivation with user-controlled seeds that could be spoofed.',
    severity: 'critical',
    category: 'pda',
    detector: (code: string) => {
      const patterns = [
        /find_program_address.*user_input/i,
        /seeds.*=.*\[.*account\.key/i,
        /pda.*arbitrary.*seed/i,
        /derive.*address.*untrusted/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Use deterministic seeds derived from trusted sources. Validate PDA bump is canonical.',
  },
  {
    id: 'SOL1594',
    name: 'Non-Canonical PDA Bump Usage',
    description: 'Identifies PDA usage without canonical bump verification, allowing multiple valid PDAs.',
    severity: 'high',
    category: 'pda',
    detector: (code: string) => {
      const patterns = [
        /bump.*=.*\d+(?!.*canonical)/i,
        /find_program_address.*ignore.*bump/i,
        /pda.*without.*bump.*check/i,
        /seeds.*bump.*user.*provided/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Always store and verify the canonical bump. Use Anchor\'s bump constraint.',
  },
  {
    id: 'SOL1595',
    name: 'Orphaned PDA Account Risk',
    description: 'Detects PDA accounts that can become orphaned without proper lifecycle management.',
    severity: 'medium',
    category: 'pda',
    detector: (code: string) => {
      const patterns = [
        /init.*pda.*no.*close/i,
        /create.*account.*no.*cleanup/i,
        /pda.*permanent.*allocation/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Implement close instructions for PDAs when they are no longer needed to recover rent.',
  },

  // === RESOURCE LIMITS AND COMPUTE PATTERNS ===
  {
    id: 'SOL1596',
    name: 'Compute Unit Budget Exhaustion',
    description: 'Identifies operations that could exhaust compute units leading to DoS.',
    severity: 'high',
    category: 'dos',
    detector: (code: string) => {
      const patterns = [
        /for.*in.*0\.\.accounts\.len/i,
        /loop.*unbounded/i,
        /recursive.*call.*no.*limit/i,
        /iterate.*all.*users/i,
        /while.*true/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Implement pagination for large datasets. Add iteration limits. Use request_units wisely.',
  },
  {
    id: 'SOL1597',
    name: 'Account Lock Ordering Deadlock',
    description: 'Detects potential deadlock scenarios from inconsistent account locking order.',
    severity: 'medium',
    category: 'concurrency',
    detector: (code: string) => {
      const patterns = [
        /lock.*a.*then.*b/i,
        /borrow_mut.*multiple/i,
        /try_borrow.*loop/i,
        /concurrent.*account.*access/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Always acquire account locks in consistent order (e.g., by pubkey sort). Avoid holding locks during CPI.',
  },
  {
    id: 'SOL1598',
    name: 'Parallel Execution Hazard',
    description: 'Identifies transaction patterns that may fail under Solana\'s parallel execution model.',
    severity: 'medium',
    category: 'concurrency',
    detector: (code: string) => {
      const patterns = [
        /global.*state.*no.*sync/i,
        /shared.*counter.*increment/i,
        /race.*condition.*account/i,
        /concurrent.*modify.*same/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Design for concurrent execution. Use PDAs for isolation. Consider account-level locking strategies.',
  },

  // === MEMORY SAFETY PATTERNS (Despite Rust) ===
  {
    id: 'SOL1599',
    name: 'Unsafe Rust Block in Critical Path',
    description: 'Detects unsafe Rust code in security-critical functions.',
    severity: 'high',
    category: 'memory',
    detector: (code: string) => {
      const patterns = [
        /unsafe\s*\{[^}]*transfer/i,
        /unsafe\s*\{[^}]*withdraw/i,
        /unsafe\s*\{[^}]*authority/i,
        /unsafe\s*\{[^}]*signer/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Minimize unsafe blocks. Audit all unsafe code thoroughly. Consider safe alternatives.',
  },
  {
    id: 'SOL1600',
    name: 'Zero-Copy Deserialization Aliasing',
    description: 'Identifies zero-copy deserialization that could lead to aliasing issues.',
    severity: 'high',
    category: 'memory',
    detector: (code: string) => {
      const patterns = [
        /zero_copy.*mut.*reference/i,
        /from_bytes.*unchecked/i,
        /transmute.*account.*data/i,
        /cast.*slice.*to.*struct/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Use safe deserialization methods. Validate data bounds before zero-copy operations.',
  },

  // === HISTORICAL EXPLOIT PATTERNS (ArXiv Research) ===
  {
    id: 'SOL1601',
    name: 'Solend Oracle Attack Pattern',
    description: 'Detects oracle manipulation vulnerability similar to Solend $1.26M exploit.',
    severity: 'critical',
    category: 'oracle',
    detector: (code: string) => {
      const patterns = [
        /oracle.*price.*single.*source/i,
        /liquidation.*threshold.*oracle/i,
        /borrow.*limit.*price.*dependent/i,
        /collateral.*value.*one.*oracle/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Use multiple oracle sources with TWAP. Implement circuit breakers for sudden price movements.',
  },
  {
    id: 'SOL1602',
    name: 'Mango Flash Loan Attack Pattern',
    description: 'Identifies vulnerability to Mango-style $100M flash loan manipulation.',
    severity: 'critical',
    category: 'defi',
    detector: (code: string) => {
      const patterns = [
        /perp.*position.*same.*tx/i,
        /spot.*and.*perp.*manipulation/i,
        /self.*trade.*price.*impact/i,
        /flash.*loan.*oracle.*update/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Implement oracle manipulation resistance. Use TWAP for pricing. Add position limits.',
  },
  {
    id: 'SOL1603',
    name: 'Nirvana Flash Loan Pattern',
    description: 'Detects flash loan vulnerability in stablecoin/AMM contexts like Nirvana $3.5M exploit.',
    severity: 'critical',
    category: 'defi',
    detector: (code: string) => {
      const patterns = [
        /mint.*based.*on.*pool.*ratio/i,
        /stablecoin.*flash.*mint/i,
        /backing.*ratio.*manipulatable/i,
        /virtual.*price.*attack/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Implement flash loan guards. Use time-weighted averages for critical calculations.',
  },
  {
    id: 'SOL1604',
    name: 'Crema Finance Price Manipulation',
    description: 'Identifies CLMM price manipulation vectors similar to Crema Finance exploit.',
    severity: 'high',
    category: 'defi',
    detector: (code: string) => {
      const patterns = [
        /concentrated.*liquidity.*no.*check/i,
        /tick.*manipulation/i,
        /price.*range.*abuse/i,
        /clmm.*single.*side/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Implement tick and price range validation. Add slippage protection for CLMM operations.',
  },
  {
    id: 'SOL1605',
    name: 'Cashio Root of Trust Bypass',
    description: 'Detects missing validation in collateral verification chains like Cashio $52M exploit.',
    severity: 'critical',
    category: 'validation',
    detector: (code: string) => {
      const patterns = [
        /collateral.*account.*no.*verify/i,
        /trust.*chain.*broken/i,
        /nested.*account.*unchecked/i,
        /bank.*crate.*unverified/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Verify complete trust chains. Validate all nested account relationships. Never trust unverified accounts.',
  },
  {
    id: 'SOL1606',
    name: 'Wormhole Signature Verification Bypass',
    description: 'Identifies deprecated or weak signature verification similar to Wormhole 120K ETH exploit.',
    severity: 'critical',
    category: 'cryptographic',
    detector: (code: string) => {
      const patterns = [
        /verify_signatures.*deprecated/i,
        /guardian.*set.*bypass/i,
        /signature.*count.*insufficient/i,
        /secp256k1.*recover.*unchecked/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Use current verification methods. Require sufficient guardian signatures. Validate all signature components.',
  },
  {
    id: 'SOL1607',
    name: 'OptiFi Program Close Lockup',
    description: 'Detects program close operations that could lock user funds like OptiFi $661K incident.',
    severity: 'high',
    category: 'business-logic',
    detector: (code: string) => {
      const patterns = [
        /close.*program.*no.*withdraw/i,
        /shutdown.*without.*user.*exit/i,
        /admin.*close.*funds.*locked/i,
        /terminate.*pool.*assets.*trapped/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Implement graceful shutdown with user withdrawal period. Never allow closing with user funds locked.',
  },

  // === ADVANCED ANCHOR PATTERNS ===
  {
    id: 'SOL1608',
    name: 'Anchor Account Discriminator Collision',
    description: 'Detects potential account discriminator collisions in Anchor programs.',
    severity: 'high',
    category: 'anchor',
    detector: (code: string) => {
      const patterns = [
        /\#\[account\].*similar.*name/i,
        /discriminator.*manually.*set/i,
        /account.*type.*cast/i,
        /skip.*discriminator.*check/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Let Anchor auto-generate discriminators. Avoid manual discriminator manipulation.',
  },
  {
    id: 'SOL1609',
    name: 'Anchor Init If Needed Race',
    description: 'Identifies init_if_needed patterns that could be exploited in race conditions.',
    severity: 'high',
    category: 'anchor',
    detector: (code: string) => {
      const patterns = [
        /init_if_needed.*no.*constraint/i,
        /init_if_needed.*reinitialization/i,
        /conditional.*init.*race/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Avoid init_if_needed. Use explicit init with proper constraints. Add reinitialization guards.',
  },
  {
    id: 'SOL1610',
    name: 'Anchor Seeds Constraint Missing',
    description: 'Detects missing seeds constraints in Anchor PDA derivation.',
    severity: 'high',
    category: 'anchor',
    detector: (code: string) => {
      const patterns = [
        /\#\[account\(.*seeds.*\]\)(?!.*constraint)/i,
        /pda.*no.*seeds.*validation/i,
        /derive.*without.*seeds.*check/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Always use seeds constraint with bump. Validate PDA derivation in instruction.',
  },

  // === SERIALIZATION PATTERNS ===
  {
    id: 'SOL1611',
    name: 'Borsh Deserialization Overflow',
    description: 'Identifies potential overflow in Borsh deserialization of variable-length data.',
    severity: 'high',
    category: 'serialization',
    detector: (code: string) => {
      const patterns = [
        /BorshDeserialize.*Vec.*no.*limit/i,
        /deserialize.*unbounded.*string/i,
        /borsh.*from_slice.*large/i,
        /try_from_slice.*no.*size.*check/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Set maximum sizes for variable-length fields. Validate data size before deserialization.',
  },
  {
    id: 'SOL1612',
    name: 'Account Data Size Mismatch',
    description: 'Detects account data size mismatches that could cause serialization issues.',
    severity: 'medium',
    category: 'serialization',
    detector: (code: string) => {
      const patterns = [
        /realloc.*smaller.*size/i,
        /account.*space.*mismatch/i,
        /data.*len.*!=.*expected/i,
        /resize.*account.*truncate/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Validate account size matches expected struct size. Handle reallocation carefully.',
  },

  // === TOKEN-2022 ADVANCED PATTERNS ===
  {
    id: 'SOL1613',
    name: 'Token-2022 Transfer Hook Manipulation',
    description: 'Identifies vulnerabilities in Token-2022 transfer hook implementations.',
    severity: 'high',
    category: 'token-2022',
    detector: (code: string) => {
      const patterns = [
        /transfer_hook.*no.*verify/i,
        /hook.*program.*arbitrary/i,
        /execute_transfer_hook.*bypass/i,
        /transfer.*skip.*hook/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Validate transfer hook program. Ensure hooks cannot be bypassed. Audit hook logic thoroughly.',
  },
  {
    id: 'SOL1614',
    name: 'Token-2022 Confidential Transfer Leak',
    description: 'Detects potential information leaks in confidential transfer implementations.',
    severity: 'high',
    category: 'token-2022',
    detector: (code: string) => {
      const patterns = [
        /confidential.*amount.*log/i,
        /decrypt.*balance.*emit/i,
        /pending.*balance.*expose/i,
        /elgamal.*key.*public/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Never log decrypted amounts. Protect ElGamal keys. Audit confidential transfer flows.',
  },
  {
    id: 'SOL1615',
    name: 'Token-2022 Permanent Delegate Abuse',
    description: 'Identifies permanent delegate configurations that could enable token theft.',
    severity: 'critical',
    category: 'token-2022',
    detector: (code: string) => {
      const patterns = [
        /permanent_delegate.*untrusted/i,
        /delegate.*all.*tokens/i,
        /freeze.*authority.*delegate/i,
        /mint.*with.*permanent.*delegate/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Use permanent delegate only with trusted, audited addresses. Warn users of permanent delegate mints.',
  },

  // === BLINKS AND ACTIONS SECURITY ===
  {
    id: 'SOL1616',
    name: 'Blinks Action URL Manipulation',
    description: 'Detects Solana Actions/Blinks vulnerable to URL parameter manipulation.',
    severity: 'high',
    category: 'blinks',
    detector: (code: string) => {
      const patterns = [
        /action.*url.*user.*input/i,
        /blink.*parameter.*injection/i,
        /solana.*action.*no.*validate/i,
        /actions\.json.*dynamic/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Validate all Blinks parameters server-side. Use allowlists for action URLs.',
  },
  {
    id: 'SOL1617',
    name: 'Blinks Transaction Preview Mismatch',
    description: 'Identifies Blinks where preview transaction differs from executed transaction.',
    severity: 'critical',
    category: 'blinks',
    detector: (code: string) => {
      const patterns = [
        /preview.*tx.*different/i,
        /simulate.*then.*change/i,
        /action.*response.*modify/i,
        /blink.*bait.*switch/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Ensure transaction previews match actual execution. Sign transaction content not just hash.',
  },

  // === GOVERNANCE AND DAO PATTERNS ===
  {
    id: 'SOL1618',
    name: 'Governance Flash Loan Voting',
    description: 'Detects governance systems vulnerable to flash loan voting attacks.',
    severity: 'critical',
    category: 'governance',
    detector: (code: string) => {
      const patterns = [
        /vote.*power.*current.*balance/i,
        /snapshot.*same.*block/i,
        /governance.*no.*lock.*period/i,
        /proposal.*instant.*execution/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Use time-weighted voting power. Implement vote escrow. Add timelock for execution.',
  },
  {
    id: 'SOL1619',
    name: 'DAO Treasury Single Signer',
    description: 'Identifies DAO treasuries controlled by single signer instead of multisig.',
    severity: 'critical',
    category: 'governance',
    detector: (code: string) => {
      const patterns = [
        /treasury.*owner.*single/i,
        /dao.*funds.*one.*key/i,
        /vault.*authority.*admin/i,
        /governance.*no.*multisig/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Use Squads or SPL Governance multisig for treasury. Require multiple signers for withdrawals.',
  },
  {
    id: 'SOL1620',
    name: 'Proposal Spam Griefing',
    description: 'Detects governance systems vulnerable to proposal spam attacks.',
    severity: 'medium',
    category: 'governance',
    detector: (code: string) => {
      const patterns = [
        /create.*proposal.*no.*cost/i,
        /governance.*no.*deposit/i,
        /unlimited.*proposals/i,
        /proposal.*spam.*possible/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Require proposal deposit. Limit active proposals per user. Implement proposal thresholds.',
  },

  // === MEV AND FRONTRUNNING PATTERNS ===
  {
    id: 'SOL1621',
    name: 'Jito Bundle Sandwich Attack',
    description: 'Identifies transactions vulnerable to Jito bundle sandwich attacks.',
    severity: 'high',
    category: 'mev',
    detector: (code: string) => {
      const patterns = [
        /swap.*no.*slippage/i,
        /large.*trade.*single.*tx/i,
        /amm.*trade.*no.*protection/i,
        /market.*order.*no.*limit/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Implement slippage protection. Use private mempools. Consider Jito bundles for MEV protection.',
  },
  {
    id: 'SOL1622',
    name: 'Priority Fee Manipulation',
    description: 'Detects patterns where priority fee can be manipulated for MEV extraction.',
    severity: 'medium',
    category: 'mev',
    detector: (code: string) => {
      const patterns = [
        /priority.*fee.*dynamic/i,
        /compute.*price.*external/i,
        /fee.*bidding.*war/i,
        /transaction.*ordering.*abuse/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Set reasonable priority fee caps. Consider batch processing to reduce MEV exposure.',
  },

  // === STAKING AND VALIDATOR PATTERNS ===
  {
    id: 'SOL1623',
    name: 'Stake Pool Rate Manipulation',
    description: 'Identifies stake pool vulnerable to rate manipulation attacks.',
    severity: 'high',
    category: 'staking',
    detector: (code: string) => {
      const patterns = [
        /stake.*pool.*rate.*instant/i,
        /validator.*yield.*manipulation/i,
        /epoch.*boundary.*attack/i,
        /stake.*first.*depositor/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Use time-weighted rates. Implement minimum stake amounts. Add epoch boundary protections.',
  },
  {
    id: 'SOL1624',
    name: 'Validator Commission Manipulation',
    description: 'Detects validator commission changes that could affect staker yields.',
    severity: 'medium',
    category: 'staking',
    detector: (code: string) => {
      const patterns = [
        /commission.*change.*instant/i,
        /validator.*fee.*no.*notice/i,
        /stake.*no.*commission.*check/i,
        /yield.*commission.*hidden/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Implement commission change notice periods. Display validator commission clearly.',
  },

  // === BRIDGE AND CROSS-CHAIN PATTERNS ===
  {
    id: 'SOL1625',
    name: 'Bridge Message Replay Attack',
    description: 'Detects cross-chain bridge patterns vulnerable to message replay.',
    severity: 'critical',
    category: 'bridge',
    detector: (code: string) => {
      const patterns = [
        /bridge.*message.*no.*nonce/i,
        /cross_chain.*replay.*possible/i,
        /relay.*without.*sequence/i,
        /wormhole.*vaa.*reuse/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Use unique nonces for bridge messages. Track processed messages. Verify sequence numbers.',
  },
  {
    id: 'SOL1626',
    name: 'Bridge Finality Assumption',
    description: 'Identifies bridge reliance on incorrect finality assumptions.',
    severity: 'high',
    category: 'bridge',
    detector: (code: string) => {
      const patterns = [
        /finality.*1.*confirmation/i,
        /bridge.*instant.*finality/i,
        /cross_chain.*no.*wait/i,
        /relay.*before.*finalized/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Wait for appropriate finality on source chain. Implement challenge periods for large transfers.',
  },

  // === NFT AND GAMING PATTERNS ===
  {
    id: 'SOL1627',
    name: 'NFT Metadata Injection',
    description: 'Detects NFT metadata fields vulnerable to injection attacks.',
    severity: 'high',
    category: 'nft',
    detector: (code: string) => {
      const patterns = [
        /metadata.*uri.*user.*input/i,
        /nft.*name.*no.*sanitize/i,
        /symbol.*injection/i,
        /attribute.*script.*inject/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Sanitize all metadata fields. Validate URIs. Escape special characters.',
  },
  {
    id: 'SOL1628',
    name: 'Gaming Randomness Predictability',
    description: 'Identifies gaming contracts using predictable randomness.',
    severity: 'critical',
    category: 'gaming',
    detector: (code: string) => {
      const patterns = [
        /random.*=.*slot/i,
        /randomness.*blockhash/i,
        /game.*outcome.*timestamp/i,
        /rng.*from.*clock/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Use Switchboard VRF or similar verifiable randomness. Never use on-chain data for randomness.',
  },
  {
    id: 'SOL1629',
    name: 'Gaming Item Duplication',
    description: 'Detects gaming logic vulnerable to item duplication exploits.',
    severity: 'high',
    category: 'gaming',
    detector: (code: string) => {
      const patterns = [
        /item.*transfer.*no.*lock/i,
        /duplicate.*item.*race/i,
        /inventory.*concurrent.*modify/i,
        /trade.*during.*use/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Lock items during operations. Use atomic transfers. Implement proper state machine.',
  },
  {
    id: 'SOL1630',
    name: 'P2E Token Inflation Attack',
    description: 'Identifies play-to-earn systems vulnerable to token inflation.',
    severity: 'high',
    category: 'gaming',
    detector: (code: string) => {
      const patterns = [
        /reward.*no.*cap/i,
        /mint.*game.*token.*unlimited/i,
        /earn.*rate.*exploitable/i,
        /p2e.*emission.*unchecked/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Implement emission caps. Use halving schedules. Monitor reward rates.',
  },

  // === SUPPLY CHAIN PATTERNS ===
  {
    id: 'SOL1631',
    name: 'NPM Dependency Backdoor',
    description: 'Detects patterns indicating potential NPM supply chain attack vectors.',
    severity: 'critical',
    category: 'supply-chain',
    detector: (code: string) => {
      const patterns = [
        /require.*untrusted.*package/i,
        /postinstall.*script.*exec/i,
        /dependency.*version.*\*/i,
        /import.*from.*npm.*no.*lock/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Pin dependency versions. Audit postinstall scripts. Use lockfiles. Verify package integrity.',
  },
  {
    id: 'SOL1632',
    name: 'Build Pipeline Compromise',
    description: 'Identifies build configurations vulnerable to compromise.',
    severity: 'high',
    category: 'supply-chain',
    detector: (code: string) => {
      const patterns = [
        /build.*script.*remote.*exec/i,
        /ci.*cd.*no.*verify/i,
        /deploy.*unsigned.*artifact/i,
        /cargo.*build.*untrusted/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Verify all build artifacts. Use reproducible builds. Sign releases.',
  },

  // === LENDING PROTOCOL PATTERNS ===
  {
    id: 'SOL1633',
    name: 'Lending First Depositor Attack',
    description: 'Detects lending vaults vulnerable to first depositor share manipulation.',
    severity: 'critical',
    category: 'lending',
    detector: (code: string) => {
      const patterns = [
        /shares.*=.*0.*first/i,
        /vault.*initial.*deposit.*small/i,
        /mint.*shares.*\s*\/\s*total/i,
        /donation.*attack.*vulnerable/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Use virtual shares/assets. Require minimum initial deposit. Implement dead shares.',
  },
  {
    id: 'SOL1634',
    name: 'Liquidation Threshold Manipulation',
    description: 'Identifies liquidation mechanisms that can be manipulated.',
    severity: 'high',
    category: 'lending',
    detector: (code: string) => {
      const patterns = [
        /liquidation.*threshold.*dynamic/i,
        /health.*factor.*manipulation/i,
        /collateral.*factor.*exploit/i,
        /liquidate.*before.*price.*update/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Use time-weighted oracle prices. Implement liquidation delays. Add price deviation checks.',
  },
  {
    id: 'SOL1635',
    name: 'Bad Debt Accumulation',
    description: 'Detects lending protocols without proper bad debt handling.',
    severity: 'high',
    category: 'lending',
    detector: (code: string) => {
      const patterns = [
        /underwater.*position.*no.*handle/i,
        /bad.*debt.*accumulate/i,
        /insolvent.*borrow.*continue/i,
        /no.*socialized.*loss/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Implement bad debt socialization. Add insurance funds. Track protocol solvency.',
  },

  // === PERPETUAL DEX PATTERNS ===
  {
    id: 'SOL1636',
    name: 'Perp Funding Rate Manipulation',
    description: 'Identifies perpetual DEX funding rate manipulation vectors.',
    severity: 'high',
    category: 'perps',
    detector: (code: string) => {
      const patterns = [
        /funding.*rate.*instant/i,
        /mark.*price.*manipulate/i,
        /index.*price.*single.*source/i,
        /funding.*payment.*exploit/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Use TWAP for funding rate calculation. Implement funding rate caps. Use multiple price sources.',
  },
  {
    id: 'SOL1637',
    name: 'Perp ADL Gaming',
    description: 'Detects auto-deleveraging mechanisms that can be gamed.',
    severity: 'high',
    category: 'perps',
    detector: (code: string) => {
      const patterns = [
        /adl.*ranking.*predictable/i,
        /deleverage.*profit.*target/i,
        /auto.*liquidate.*gaming/i,
        /adl.*front.*run/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Randomize ADL selection within tiers. Add ADL protection mechanisms.',
  },

  // === OPTIONS PROTOCOL PATTERNS ===
  {
    id: 'SOL1638',
    name: 'Options Premium Mispricing',
    description: 'Identifies options pricing vulnerable to manipulation.',
    severity: 'high',
    category: 'options',
    detector: (code: string) => {
      const patterns = [
        /premium.*spot.*price.*only/i,
        /iv.*from.*single.*source/i,
        /black.*scholes.*no.*adjust/i,
        /option.*price.*stale.*vol/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Use proper volatility surfaces. Implement IV bounds. Add premium slippage protection.',
  },
  {
    id: 'SOL1639',
    name: 'Options Settlement Manipulation',
    description: 'Detects options settlement vulnerable to price manipulation at expiry.',
    severity: 'high',
    category: 'options',
    detector: (code: string) => {
      const patterns = [
        /settle.*price.*instant/i,
        /expiry.*price.*single.*point/i,
        /exercise.*no.*twap/i,
        /settlement.*manipulatable/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Use TWAP for settlement prices. Implement settlement windows. Add price deviation protection.',
  },

  // === RWA PATTERNS ===
  {
    id: 'SOL1640',
    name: 'RWA Oracle Centralization',
    description: 'Identifies real-world asset tokens with centralized oracle risk.',
    severity: 'high',
    category: 'rwa',
    detector: (code: string) => {
      const patterns = [
        /rwa.*price.*single.*authority/i,
        /asset.*valuation.*centralized/i,
        /real.*world.*oracle.*trusted/i,
        /custody.*attestation.*single/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Use multiple attestation sources. Implement oracle redundancy. Add dispute mechanisms.',
  },
  {
    id: 'SOL1641',
    name: 'RWA Custody Verification Missing',
    description: 'Detects RWA tokens without proper custody verification.',
    severity: 'critical',
    category: 'rwa',
    detector: (code: string) => {
      const patterns = [
        /mint.*rwa.*no.*proof/i,
        /custody.*not.*verified/i,
        /backing.*assumed/i,
        /real.*asset.*unverified/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Require proof of custody for minting. Implement regular attestation. Add reserve audits.',
  },

  // === YIELD AGGREGATOR PATTERNS ===
  {
    id: 'SOL1642',
    name: 'Yield Strategy Manipulation',
    description: 'Identifies yield aggregator strategies vulnerable to manipulation.',
    severity: 'high',
    category: 'yield',
    detector: (code: string) => {
      const patterns = [
        /strategy.*harvest.*frontrun/i,
        /yield.*report.*manipulate/i,
        /vault.*strategy.*untrusted/i,
        /harvest.*timing.*exploit/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Implement harvest guards. Use private harvests. Add yield smoothing.',
  },
  {
    id: 'SOL1643',
    name: 'Yield Aggregator Rug Risk',
    description: 'Detects yield vaults with rug pull risk from strategy changes.',
    severity: 'critical',
    category: 'yield',
    detector: (code: string) => {
      const patterns = [
        /strategy.*change.*instant/i,
        /vault.*migrate.*no.*timelock/i,
        /admin.*withdraw.*all/i,
        /strategy.*queue.*bypass/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Implement strategy timelock. Add withdrawal queue. Limit strategy migration powers.',
  },

  // === ADDITIONAL PATTERNS ===
  {
    id: 'SOL1644',
    name: 'Account Close Destination Wrong',
    description: 'Detects account closure sending funds to wrong destination.',
    severity: 'high',
    category: 'account',
    detector: (code: string) => {
      const patterns = [
        /close.*destination.*not.*owner/i,
        /account.*lamports.*wrong.*dest/i,
        /close_account.*arbitrary/i,
        /rent.*refund.*attacker/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Always close accounts to the original owner or verified destination.',
  },
  {
    id: 'SOL1645',
    name: 'Account Revival After Close',
    description: 'Identifies patterns allowing account revival after closure.',
    severity: 'high',
    category: 'account',
    detector: (code: string) => {
      const patterns = [
        /close.*then.*init/i,
        /account.*revive/i,
        /reopen.*closed.*account/i,
        /reinit.*after.*close/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Use account discriminators. Track closed accounts. Prevent reinitialization.',
  },
  {
    id: 'SOL1646',
    name: 'Missing Emergency Pause',
    description: 'Detects protocols without emergency pause functionality.',
    severity: 'medium',
    category: 'safety',
    detector: (code: string) => {
      const patterns = [
        /no.*pause.*function/i,
        /emergency.*stop.*missing/i,
        /circuit.*breaker.*absent/i,
        /cannot.*halt.*protocol/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Implement emergency pause with multisig control. Add circuit breakers for critical functions.',
  },
  {
    id: 'SOL1647',
    name: 'Insufficient Event Logging',
    description: 'Identifies critical operations without proper event emission.',
    severity: 'low',
    category: 'logging',
    detector: (code: string) => {
      const patterns = [
        /transfer.*no.*emit/i,
        /withdraw.*no.*log/i,
        /critical.*action.*silent/i,
        /state.*change.*no.*event/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Emit events for all state-changing operations. Include relevant data for off-chain indexing.',
  },
  {
    id: 'SOL1648',
    name: 'Timelock Bypass Vulnerability',
    description: 'Detects timelock mechanisms that can be bypassed.',
    severity: 'critical',
    category: 'access-control',
    detector: (code: string) => {
      const patterns = [
        /timelock.*admin.*override/i,
        /delay.*skip.*emergency/i,
        /bypass.*waiting.*period/i,
        /timelock.*cancel.*execute/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Remove timelock bypass capabilities. Require multisig for emergency actions.',
  },
  {
    id: 'SOL1649',
    name: 'Rate Limit Missing for Sensitive Operations',
    description: 'Identifies sensitive operations without rate limiting.',
    severity: 'medium',
    category: 'dos',
    detector: (code: string) => {
      const patterns = [
        /withdraw.*unlimited.*frequency/i,
        /mint.*no.*cooldown/i,
        /sensitive.*op.*no.*rate.*limit/i,
        /spam.*protection.*missing/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Implement rate limits for sensitive operations. Add cooldown periods.',
  },
  {
    id: 'SOL1650',
    name: 'Cross-Program Reentrancy',
    description: 'Detects cross-program invocation patterns vulnerable to reentrancy.',
    severity: 'critical',
    category: 'reentrancy',
    detector: (code: string) => {
      const patterns = [
        /invoke.*callback.*self/i,
        /cpi.*then.*self.*call/i,
        /reentrant.*via.*cpi/i,
        /nested.*invoke.*state/i,
      ];
      return patterns.some(p => p.test(code));
    },
    recommendation: 'Use reentrancy guards. Update state before CPI. Avoid callbacks to self.',
  },
];

export default batchedPatterns47;
