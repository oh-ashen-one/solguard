/**
 * SolGuard Pattern Batch 43
 * Real-World Exploit Patterns from 2024-2025
 * Patterns SOL1301-SOL1370
 * 
 * Based on: Sec3 2025 Security Review, Helius Exploit History
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

const batchedPatterns43: BatchPattern[] = [
  // ========================================
  // REAL EXPLOIT PATTERNS 2024-2025
  // ========================================
  {
    id: 'SOL1301',
    name: 'Loopscale RateX Attack Vector',
    severity: 'critical',
    category: 'exploit',
    description: 'PT token pricing vulnerability similar to Loopscale $5.8M exploit (April 2025).',
    detection: {
      patterns: [
        /pt_token/i,
        /pendle/i,
        /yield_token/i,
        /principal_token/i
      ]
    },
    recommendation: 'Validate PT token prices independently. Use TWAP for pricing.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL1302',
    name: 'Employee/Insider Key Access',
    severity: 'critical',
    category: 'exploit',
    description: 'Private key accessible to employees (Pump.fun $1.9M exploit pattern).',
    detection: {
      patterns: [
        /employee/i,
        /internal.*key/i,
        /bonding.*withdraw/i,
        /team.*wallet/i
      ]
    },
    recommendation: 'Use multisig for all treasury operations. Rotate keys regularly.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL1303',
    name: 'Hot Wallet Exposure',
    severity: 'critical',
    category: 'exploit',
    description: 'Hot wallet private key exposure (DEXX $30M pattern).',
    detection: {
      patterns: [
        /hot_wallet/i,
        /custodial.*key/i,
        /wallet.*server/i,
        /trading_bot.*key/i
      ]
    },
    recommendation: 'Use hardware security modules. Implement withdrawal limits.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL1304',
    name: 'Trading Bot Vulnerability',
    severity: 'high',
    category: 'exploit',
    description: 'Trading bot security flaw (Banana Gun $1.4M, Solareum $500K pattern).',
    detection: {
      patterns: [
        /trading_bot/i,
        /sniper.*bot/i,
        /auto_trade/i,
        /bot.*wallet/i
      ]
    },
    recommendation: 'Isolate bot funds. Use time-locked withdrawals.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL1305',
    name: 'Database Injection Attack',
    severity: 'critical',
    category: 'exploit',
    description: 'MongoDB injection vulnerability (Thunder Terminal $240K pattern).',
    detection: {
      patterns: [
        /mongodb/i,
        /database.*query/i,
        /nosql/i,
        /db\.find/i
      ]
    },
    recommendation: 'Sanitize all database queries. Use parameterized queries.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL1306',
    name: 'Cypher-Style Insider Theft',
    severity: 'critical',
    category: 'exploit',
    description: 'Insider with privileged access stealing funds (Cypher $1.35M pattern).',
    detection: {
      patterns: [
        /admin.*transfer/i,
        /owner.*withdraw/i,
        /privileged.*access/i
      ]
    },
    recommendation: 'Use multisig for all fund movements. Implement withdrawal cooldowns.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL1307',
    name: 'P2P Platform Hot Wallet',
    severity: 'critical',
    category: 'exploit',
    description: 'P2P exchange hot wallet compromise (NoOnes $4M pattern).',
    detection: {
      patterns: [
        /p2p.*exchange/i,
        /escrow.*hot/i,
        /otc.*wallet/i
      ]
    },
    recommendation: 'Use cold storage for majority of funds. Limit hot wallet exposure.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL1308',
    name: 'Sybil Attack Susceptibility',
    severity: 'high',
    category: 'exploit',
    description: 'System vulnerable to sybil attacks (io.net fake GPU pattern).',
    detection: {
      patterns: [
        /node.*registration/i,
        /validator.*join/i,
        /provider.*signup/i,
        /identity.*verification/i
      ]
    },
    recommendation: 'Require proof of resources. Implement stake-based admission.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL1309',
    name: 'Honeypot Token Pattern',
    severity: 'critical',
    category: 'exploit',
    description: 'Token designed to trap buyers (SVT honeypot pattern).',
    detection: {
      patterns: [
        /sell.*disabled/i,
        /transfer.*blocked/i,
        /whale.*only/i,
        /hidden.*fee/i
      ]
    },
    recommendation: 'Check for hidden transfer restrictions. Verify selling works.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL1310',
    name: 'DAO Governance Attack',
    severity: 'critical',
    category: 'exploit',
    description: 'DAO governance manipulation (Saga DAO $230K pattern).',
    detection: {
      patterns: [
        /dao.*proposal/i,
        /vote.*execution/i,
        /governance.*attack/i
      ]
    },
    recommendation: 'Add proposal review period. Use vote escrow.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL1311',
    name: 'Gaming SyncSpace Exploit',
    severity: 'high',
    category: 'exploit',
    description: 'Gaming platform synchronization exploit (Aurory pattern).',
    detection: {
      patterns: [
        /sync.*state/i,
        /game.*session/i,
        /player.*data.*sync/i
      ]
    },
    recommendation: 'Verify state transitions server-side. Add replay protection.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL1312',
    name: 'Protocol Crank Manipulation',
    severity: 'high',
    category: 'exploit',
    description: 'Protocol crank timing manipulation (Tulip pattern).',
    detection: {
      patterns: [
        /crank/i,
        /keeper.*timing/i,
        /automated.*execution/i
      ]
    },
    recommendation: 'Randomize crank timing. Add keeper incentives.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL1313',
    name: 'Stablecoin Depeg Attack',
    severity: 'critical',
    category: 'exploit',
    description: 'Stablecoin backing mechanism vulnerability (UXD pattern).',
    detection: {
      patterns: [
        /stablecoin/i,
        /peg.*mechanism/i,
        /backing.*ratio/i,
        /mint.*redeem/i
      ]
    },
    recommendation: 'Over-collateralize. Add peg stability mechanisms.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL1314',
    name: 'Program Close With Funds',
    severity: 'critical',
    category: 'exploit',
    description: 'Program closed with user funds locked (OptiFi $661K pattern).',
    detection: {
      patterns: [
        /close_program/i,
        /program.*close/i,
        /shutdown/i,
        /deprecate/i
      ]
    },
    recommendation: 'Never close program with active funds. Add withdrawal grace period.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL1315',
    name: 'NPM Package Attack',
    severity: 'critical',
    category: 'exploit',
    description: 'NPM supply chain attack (Web3.js $164K pattern).',
    detection: {
      patterns: [
        /require\s*\(/i,
        /import.*from/i,
        /package\.json/i,
        /node_modules/i
      ]
    },
    recommendation: 'Pin package versions. Use npm audit. Verify package integrity.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL1316',
    name: 'Frontend Phishing Attack',
    severity: 'high',
    category: 'exploit',
    description: 'Compromised frontend for phishing (Parcl pattern).',
    detection: {
      patterns: [
        /connect.*wallet/i,
        /approve.*transaction/i,
        /sign.*message/i
      ]
    },
    recommendation: 'Use hardware wallet. Verify domain. Check transaction details.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL1317',
    name: 'DDoS Service Disruption',
    severity: 'medium',
    category: 'exploit',
    description: 'Service disruption via DDoS (Jito, Phantom patterns).',
    detection: {
      patterns: [
        /rate_limit/i,
        /request.*throttle/i,
        /connection.*limit/i
      ]
    },
    recommendation: 'Implement rate limiting. Use CDN protection.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL1318',
    name: 'Zero-Account DoS',
    severity: 'medium',
    category: 'exploit',
    description: 'DoS via zero-account spam (Candy Machine pattern).',
    detection: {
      patterns: [
        /create_account/i,
        /init_account/i,
        /account.*creation/i
      ]
    },
    recommendation: 'Charge for account creation. Add rate limits.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  // ========================================
  // SEC3 2025 VULNERABILITY CATEGORIES
  // ========================================
  {
    id: 'SOL1319',
    name: 'Business Logic - State Machine Error',
    severity: 'critical',
    category: 'business-logic',
    description: 'State machine transition allows invalid state (38.5% of vulns per Sec3).',
    detection: {
      patterns: [
        /state.*=\s*\w+/i,
        /status.*transition/i,
        /machine.*state/i,
        /current_state/i
      ]
    },
    recommendation: 'Define explicit state transitions. Validate all state changes.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1320',
    name: 'Business Logic - Economic Exploit',
    severity: 'critical',
    category: 'business-logic',
    description: 'Economic incentives can be exploited.',
    detection: {
      patterns: [
        /incentive/i,
        /reward.*distribution/i,
        /economic.*model/i,
        /tokenomics/i
      ]
    },
    recommendation: 'Model economic attacks. Add bounds on incentives.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1321',
    name: 'Business Logic - Protocol Invariant Violation',
    severity: 'critical',
    category: 'business-logic',
    description: 'Protocol invariant can be violated.',
    detection: {
      patterns: [
        /invariant/i,
        /assert.*balance/i,
        /total.*must.*equal/i
      ]
    },
    recommendation: 'Define and check invariants. Add post-condition checks.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1322',
    name: 'Input Validation - Instruction Data',
    severity: 'high',
    category: 'input-validation',
    description: 'Instruction data not properly validated (25% of vulns per Sec3).',
    detection: {
      patterns: [
        /instruction_data/i,
        /ix_data/i,
        /payload/i,
        /msg_data/i
      ]
    },
    recommendation: 'Validate all instruction parameters. Add bounds checks.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1323',
    name: 'Input Validation - Deserialization Attack',
    severity: 'critical',
    category: 'input-validation',
    description: 'Deserialization vulnerable to malicious input.',
    detection: {
      patterns: [
        /deserialize/i,
        /try_from_slice/i,
        /BorshDeserialize/i,
        /decode/i
      ]
    },
    recommendation: 'Validate input length before deserialization. Handle errors.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1324',
    name: 'Input Validation - Numeric Bounds',
    severity: 'high',
    category: 'input-validation',
    description: 'Numeric inputs not bounded.',
    detection: {
      patterns: [
        /amount.*param/i,
        /value.*input/i,
        /quantity.*arg/i
      ]
    },
    recommendation: 'Add min/max bounds to all numeric inputs.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1325',
    name: 'Input Validation - String Length',
    severity: 'medium',
    category: 'input-validation',
    description: 'String length not validated.',
    detection: {
      patterns: [
        /String/i,
        /name.*param/i,
        /uri.*input/i,
        /description/i
      ]
    },
    recommendation: 'Limit string lengths. Validate character sets.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1326',
    name: 'Input Validation - Timestamp',
    severity: 'high',
    category: 'input-validation',
    description: 'Timestamp input not validated.',
    detection: {
      patterns: [
        /timestamp.*param/i,
        /time.*input/i,
        /deadline.*arg/i,
        /expiry.*param/i
      ]
    },
    recommendation: 'Validate timestamp is within acceptable range.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1327',
    name: 'Access Control - Authority Revocation',
    severity: 'high',
    category: 'access-control',
    description: 'No mechanism to revoke authority (19% of vulns per Sec3).',
    detection: {
      patterns: [
        /authority[\s\S]{0,200}(?!revoke|remove|transfer)/i,
        /admin[\s\S]{0,200}(?!revoke)/i
      ]
    },
    recommendation: 'Implement authority revocation. Add key rotation.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1328',
    name: 'Access Control - Delegation Chain',
    severity: 'high',
    category: 'access-control',
    description: 'Delegation chain not properly validated.',
    detection: {
      patterns: [
        /delegate.*delegate/i,
        /sub_authority/i,
        /delegation_chain/i
      ]
    },
    recommendation: 'Limit delegation depth. Validate entire chain.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1329',
    name: 'Access Control - Time-Based Bypass',
    severity: 'high',
    category: 'access-control',
    description: 'Time-based access control can be bypassed.',
    detection: {
      patterns: [
        /time.*check/i,
        /after.*timestamp/i,
        /before.*deadline/i
      ]
    },
    recommendation: 'Use on-chain clock. Add buffer for time checks.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1330',
    name: 'Access Control - Emergency Override',
    severity: 'high',
    category: 'access-control',
    description: 'Emergency override mechanism exploitable.',
    detection: {
      patterns: [
        /emergency/i,
        /override/i,
        /bypass.*normal/i
      ]
    },
    recommendation: 'Require multisig for emergencies. Add time delay.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1331',
    name: 'Access Control - Role Confusion',
    severity: 'high',
    category: 'access-control',
    description: 'Different roles have overlapping permissions.',
    detection: {
      patterns: [
        /role/i,
        /permission/i,
        /access_level/i
      ]
    },
    recommendation: 'Define clear role boundaries. Test role combinations.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1332',
    name: 'Data Integrity - Index Corruption',
    severity: 'critical',
    category: 'data-integrity',
    description: 'Index or counter can be corrupted (8.9% of vulns per Sec3).',
    detection: {
      patterns: [
        /index/i,
        /counter/i,
        /sequence/i,
        /nonce/i
      ]
    },
    recommendation: 'Use atomic updates. Add corruption detection.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1333',
    name: 'Data Integrity - Merkle Proof Attack',
    severity: 'critical',
    category: 'data-integrity',
    description: 'Merkle proof verification vulnerable.',
    detection: {
      patterns: [
        /merkle/i,
        /proof.*verify/i,
        /tree.*root/i
      ]
    },
    recommendation: 'Verify proof against correct root. Check leaf index.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1334',
    name: 'Data Integrity - Hash Collision',
    severity: 'high',
    category: 'data-integrity',
    description: 'Potential for hash collision attacks.',
    detection: {
      patterns: [
        /hash/i,
        /keccak/i,
        /sha256/i,
        /blake/i
      ]
    },
    recommendation: 'Include length in hash input. Use domain separation.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1335',
    name: 'DoS - Unbounded Loop',
    severity: 'high',
    category: 'dos',
    description: 'Unbounded loop can exhaust compute (8.5% of vulns per Sec3).',
    detection: {
      patterns: [
        /for.*in/i,
        /while/i,
        /loop/i,
        /iter\(\)/i
      ]
    },
    recommendation: 'Add iteration limits. Use pagination.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1336',
    name: 'DoS - Account Bloat',
    severity: 'medium',
    category: 'dos',
    description: 'Account data can grow unboundedly.',
    detection: {
      patterns: [
        /Vec.*push/i,
        /append/i,
        /extend/i,
        /realloc/i
      ]
    },
    recommendation: 'Limit data growth. Use separate accounts for lists.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1337',
    name: 'DoS - Compute Budget Attack',
    severity: 'medium',
    category: 'dos',
    description: 'Operation can exceed compute budget.',
    detection: {
      patterns: [
        /compute.*intensive/i,
        /expensive.*operation/i,
        /heavy.*calculation/i
      ]
    },
    recommendation: 'Profile compute usage. Add compute budget requests.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1338',
    name: 'DoS - Spam Account Creation',
    severity: 'medium',
    category: 'dos',
    description: 'Spam account creation possible.',
    detection: {
      patterns: [
        /create_account/i,
        /init/i,
        /initialize/i
      ]
    },
    recommendation: 'Require stake for account creation. Add rate limits.',
    references: ['https://solanasec25.sec3.dev/']
  },
  // ========================================
  // ADVANCED ATTACK VECTORS
  // ========================================
  {
    id: 'SOL1339',
    name: 'Simulation-Execution Divergence',
    severity: 'high',
    category: 'advanced',
    description: 'Behavior differs between simulation and execution.',
    detection: {
      patterns: [
        /simulate/i,
        /preflight/i,
        /simulateTransaction/i
      ]
    },
    recommendation: 'Dont rely on simulation for security. Add on-chain checks.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1340',
    name: 'ALT Poisoning Attack',
    severity: 'high',
    category: 'advanced',
    description: 'Address Lookup Table can be poisoned.',
    detection: {
      patterns: [
        /lookup_table/i,
        /address_lookup/i,
        /alt.*extend/i
      ]
    },
    recommendation: 'Validate ALT contents. Use owned lookup tables.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1341',
    name: 'Versioned Transaction Confusion',
    severity: 'medium',
    category: 'advanced',
    description: 'Legacy vs versioned transaction handling differs.',
    detection: {
      patterns: [
        /VersionedTransaction/i,
        /legacy.*transaction/i,
        /v0.*transaction/i
      ]
    },
    recommendation: 'Handle both transaction types consistently.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1342',
    name: 'Priority Fee Manipulation',
    severity: 'medium',
    category: 'advanced',
    description: 'Priority fees can be manipulated for MEV.',
    detection: {
      patterns: [
        /priority_fee/i,
        /compute_unit_price/i,
        /prioritization_fee/i
      ]
    },
    recommendation: 'Consider MEV implications. Use private transactions.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1343',
    name: 'Jito Bundle Atomicity',
    severity: 'high',
    category: 'advanced',
    description: 'Jito bundle atomicity assumptions incorrect.',
    detection: {
      patterns: [
        /jito/i,
        /bundle/i,
        /atomic.*execution/i,
        /mev.*protection/i
      ]
    },
    recommendation: 'Understand bundle guarantees. Add fallback handling.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1344',
    name: 'Durable Nonce Replay',
    severity: 'high',
    category: 'advanced',
    description: 'Durable nonce transactions can be replayed.',
    detection: {
      patterns: [
        /durable_nonce/i,
        /nonce_account/i,
        /advance_nonce/i
      ]
    },
    recommendation: 'Advance nonce before signature. Track used nonces.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1345',
    name: 'Slot Hash Randomness',
    severity: 'critical',
    category: 'advanced',
    description: 'Slot hashes used for randomness are predictable.',
    detection: {
      patterns: [
        /SlotHashes/i,
        /slot_hash/i,
        /recent_slot/i,
        /random.*slot/i
      ]
    },
    recommendation: 'Use VRF (Switchboard/Orao). Never use slot for randomness.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1346',
    name: 'Stake History Manipulation',
    severity: 'medium',
    category: 'advanced',
    description: 'Stake history data used incorrectly.',
    detection: {
      patterns: [
        /StakeHistory/i,
        /stake_history/i,
        /epoch.*stake/i
      ]
    },
    recommendation: 'Use current epoch data. Validate stake history source.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1347',
    name: 'Vote Program Authority',
    severity: 'high',
    category: 'advanced',
    description: 'Vote program authority operations vulnerable.',
    detection: {
      patterns: [
        /vote_program/i,
        /vote.*authority/i,
        /validator.*identity/i
      ]
    },
    recommendation: 'Secure vote authority keys. Use hardware wallets.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1348',
    name: 'Config Program Data',
    severity: 'medium',
    category: 'advanced',
    description: 'Config program data modification attack.',
    detection: {
      patterns: [
        /config_program/i,
        /Config.*Account/i,
        /config.*data/i
      ]
    },
    recommendation: 'Validate config account ownership. Use PDAs.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1349',
    name: 'Recent Blockhashes Staleness',
    severity: 'medium',
    category: 'advanced',
    description: 'Recent blockhashes used incorrectly.',
    detection: {
      patterns: [
        /recent_blockhash/i,
        /blockhash.*valid/i,
        /RecentBlockhashes/i
      ]
    },
    recommendation: 'Check blockhash recency. Handle expiration.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1350',
    name: 'Instructions Sysvar Introspection',
    severity: 'high',
    category: 'advanced',
    description: 'Instructions sysvar can leak transaction info.',
    detection: {
      patterns: [
        /instructions.*sysvar/i,
        /get_instruction_relative/i,
        /load_instruction_at/i
      ]
    },
    recommendation: 'Validate instruction sources. Dont trust blindly.',
    references: ['https://solanasec25.sec3.dev/']
  },
  // ========================================
  // PROTOCOL-SPECIFIC DEEP PATTERNS
  // ========================================
  {
    id: 'SOL1351',
    name: 'Pyth Network Confidence',
    severity: 'high',
    category: 'protocol',
    description: 'Pyth price confidence not checked.',
    detection: {
      patterns: [
        /pyth/i,
        /price_feed/i,
        /price\.price/i
      ]
    },
    recommendation: 'Check price.conf < threshold. Reject wide confidence.',
    references: ['https://pyth.network/']
  },
  {
    id: 'SOL1352',
    name: 'Switchboard Staleness',
    severity: 'high',
    category: 'protocol',
    description: 'Switchboard result timestamp not checked.',
    detection: {
      patterns: [
        /switchboard/i,
        /AggregatorAccountData/i,
        /latest_confirmed_round/i
      ]
    },
    recommendation: 'Verify result.timestamp within acceptable range.',
    references: ['https://switchboard.xyz/']
  },
  {
    id: 'SOL1353',
    name: 'Marinade Stake Ticket',
    severity: 'medium',
    category: 'protocol',
    description: 'Marinade delayed unstake ticket handling.',
    detection: {
      patterns: [
        /marinade/i,
        /delayed_unstake/i,
        /ticket/i,
        /msol/i
      ]
    },
    recommendation: 'Handle ticket timing. Verify ticket ownership.',
    references: ['https://marinade.finance/']
  },
  {
    id: 'SOL1354',
    name: 'Jupiter Route Validation',
    severity: 'high',
    category: 'protocol',
    description: 'Jupiter swap route not properly validated.',
    detection: {
      patterns: [
        /jupiter/i,
        /swap.*route/i,
        /route.*plan/i
      ]
    },
    recommendation: 'Verify route endpoints. Check slippage.',
    references: ['https://jup.ag/']
  },
  {
    id: 'SOL1355',
    name: 'cNFT Merkle Proof',
    severity: 'high',
    category: 'protocol',
    description: 'Compressed NFT merkle proof not verified.',
    detection: {
      patterns: [
        /cnft/i,
        /compressed.*nft/i,
        /bubblegum/i,
        /merkle.*tree/i
      ]
    },
    recommendation: 'Verify merkle proof. Check tree authority.',
    references: ['https://developers.metaplex.com/']
  },
  {
    id: 'SOL1356',
    name: 'Orca Whirlpool Tick',
    severity: 'medium',
    category: 'protocol',
    description: 'Orca whirlpool tick array handling issue.',
    detection: {
      patterns: [
        /whirlpool/i,
        /tick_array/i,
        /tick.*current/i
      ]
    },
    recommendation: 'Validate tick boundaries. Handle tick array loading.',
    references: ['https://orca.so/']
  },
  {
    id: 'SOL1357',
    name: 'Raydium V4 Pool',
    severity: 'medium',
    category: 'protocol',
    description: 'Raydium V4 pool state validation.',
    detection: {
      patterns: [
        /raydium/i,
        /amm.*pool/i,
        /open_orders/i
      ]
    },
    recommendation: 'Verify pool accounts match expected. Check AMM state.',
    references: ['https://raydium.io/']
  },
  {
    id: 'SOL1358',
    name: 'Drift Protocol Oracle',
    severity: 'high',
    category: 'protocol',
    description: 'Drift perpetuals oracle configuration.',
    detection: {
      patterns: [
        /drift/i,
        /perp.*oracle/i,
        /market.*oracle/i
      ]
    },
    recommendation: 'Verify oracle sources. Check guardrails.',
    references: ['https://drift.trade/']
  },
  {
    id: 'SOL1359',
    name: 'Mango V4 Health',
    severity: 'high',
    category: 'protocol',
    description: 'Mango V4 health calculation issue.',
    detection: {
      patterns: [
        /mango/i,
        /health.*calculation/i,
        /init_health/i,
        /maint_health/i
      ]
    },
    recommendation: 'Verify health components. Handle edge cases.',
    references: ['https://mango.markets/']
  },
  {
    id: 'SOL1360',
    name: 'Phoenix DEX Order',
    severity: 'medium',
    category: 'protocol',
    description: 'Phoenix orderbook order handling.',
    detection: {
      patterns: [
        /phoenix/i,
        /order_book/i,
        /limit_order/i,
        /market.*seat/i
      ]
    },
    recommendation: 'Validate order parameters. Check seat authority.',
    references: ['https://phoenix.ellipsis.finance/']
  },
  // ========================================
  // SUPPLY CHAIN SECURITY
  // ========================================
  {
    id: 'SOL1361',
    name: 'Cargo Dependency Vulnerability',
    severity: 'high',
    category: 'supply-chain',
    description: 'Rust cargo dependencies may have vulnerabilities.',
    detection: {
      patterns: [
        /Cargo\.toml/i,
        /\[dependencies\]/i,
        /version.*=/i
      ]
    },
    recommendation: 'Run cargo audit. Pin dependency versions.',
    references: ['https://rustsec.org/']
  },
  {
    id: 'SOL1362',
    name: 'NPM Typosquatting',
    severity: 'critical',
    category: 'supply-chain',
    description: 'NPM package name typosquatting (Sept 2025 attacks).',
    detection: {
      patterns: [
        /@solana/i,
        /@project-serum/i,
        /@coral-xyz/i
      ]
    },
    recommendation: 'Verify package names exactly. Use lockfiles.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1363',
    name: 'RPC Endpoint Hijacking',
    severity: 'high',
    category: 'supply-chain',
    description: 'RPC endpoint could be compromised.',
    detection: {
      patterns: [
        /rpc.*endpoint/i,
        /connection.*url/i,
        /cluster.*api/i
      ]
    },
    recommendation: 'Use trusted RPC providers. Validate responses.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1364',
    name: 'Upgrade Authority Custody',
    severity: 'high',
    category: 'supply-chain',
    description: 'Upgrade authority key not properly secured.',
    detection: {
      patterns: [
        /upgrade_authority/i,
        /BpfUpgradeable/i,
        /program.*upgrade/i
      ]
    },
    recommendation: 'Use hardware wallet. Consider immutable deployment.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1365',
    name: 'Build Reproducibility',
    severity: 'medium',
    category: 'supply-chain',
    description: 'Build may not be reproducible.',
    detection: {
      patterns: [
        /anchor.*build/i,
        /cargo.*build-sbf/i,
        /solana.*program.*deploy/i
      ]
    },
    recommendation: 'Use Anchor verifiable builds. Document build environment.',
    references: ['https://solanasec25.sec3.dev/']
  },
  // ========================================
  // TOKEN-2022 EXTENDED
  // ========================================
  {
    id: 'SOL1366',
    name: 'Token-2022 Confidential Transfer',
    severity: 'high',
    category: 'token2022',
    description: 'Confidential transfer handling vulnerable.',
    detection: {
      patterns: [
        /confidential_transfer/i,
        /encrypted_balance/i,
        /ElGamalPubkey/i
      ]
    },
    recommendation: 'Verify encryption. Handle decryption failures.',
    references: ['https://spl.solana.com/token-2022']
  },
  {
    id: 'SOL1367',
    name: 'Token-2022 Permanent Delegate',
    severity: 'critical',
    category: 'token2022',
    description: 'Permanent delegate can drain tokens.',
    detection: {
      patterns: [
        /permanent_delegate/i,
        /PermanentDelegate/i,
        /delegate.*extension/i
      ]
    },
    recommendation: 'Check for permanent delegate before accepting tokens.',
    references: ['https://spl.solana.com/token-2022']
  },
  {
    id: 'SOL1368',
    name: 'Token-2022 Non-Transferable',
    severity: 'medium',
    category: 'token2022',
    description: 'Non-transferable token handling.',
    detection: {
      patterns: [
        /non_transferable/i,
        /NonTransferable/i,
        /soulbound/i
      ]
    },
    recommendation: 'Verify transfer restrictions. Handle appropriately.',
    references: ['https://spl.solana.com/token-2022']
  },
  {
    id: 'SOL1369',
    name: 'Token-2022 Interest Bearing',
    severity: 'high',
    category: 'token2022',
    description: 'Interest bearing token calculation.',
    detection: {
      patterns: [
        /interest_bearing/i,
        /InterestBearingConfig/i,
        /rate_bps/i
      ]
    },
    recommendation: 'Account for accrued interest. Update regularly.',
    references: ['https://spl.solana.com/token-2022']
  },
  {
    id: 'SOL1370',
    name: 'Token-2022 Metadata Pointer',
    severity: 'medium',
    category: 'token2022',
    description: 'Token metadata pointer spoofing.',
    detection: {
      patterns: [
        /metadata_pointer/i,
        /MetadataPointer/i,
        /token_metadata/i
      ]
    },
    recommendation: 'Verify metadata source. Dont trust blindly.',
    references: ['https://spl.solana.com/token-2022']
  }
];

// Export function to run all patterns in this batch
export function runBatchedPatterns43(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';
  
  if (!content) return findings;
  
  for (const pattern of batchedPatterns43) {
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

export { batchedPatterns43 };
export const BATCH_43_COUNT = batchedPatterns43.length; // 70 patterns
