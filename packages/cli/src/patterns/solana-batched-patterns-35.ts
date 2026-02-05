import { SecurityPattern } from '../types';

/**
 * SolGuard Security Patterns - Batch 35
 * SOL845-SOL874: 2024-2025 Real-World Exploits & Business Logic
 * 
 * Source: Helius Blog "Solana Hacks Complete History", Sec3 2025 Report
 * Focus: Business Logic (38.5%), Input Validation (25%), Access Control (19%)
 */

export const batchedPatterns35: SecurityPattern[] = [
  // === 2024-2025 REAL EXPLOITS ===
  {
    id: 'SOL845',
    name: 'Loopscale RateX PT Token Valuation Flaw',
    severity: 'critical',
    category: 'business-logic',
    description: 'Loopscale was exploited for $5.8M in April 2025 due to incorrect RateX PT token valuation in lending calculations. The protocol miscalculated collateral values, allowing undercollateralized borrowing.',
    detection: {
      patterns: [
        /pt_token.*value/i,
        /rate.*exchange.*token/i,
        /collateral.*valuation/i,
        /yield.*token.*price/i,
        /principal.*token.*worth/i
      ]
    },
    recommendation: 'Always validate yield-bearing token valuations against underlying. Use time-weighted pricing for PT tokens. Implement valuation sanity checks.',
    references: ['https://threesigma.xyz/blog/rust-memory-safety-on-solana', 'https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL846',
    name: 'Pump.fun Employee Insider Exploit',
    severity: 'critical',
    category: 'access-control',
    description: 'Pump.fun lost $1.9M when an employee exploited privileged access to perform unauthorized withdrawals. Protocol fully recovered funds.',
    detection: {
      patterns: [
        /employee.*withdraw/i,
        /internal.*access/i,
        /privileged.*user/i,
        /admin.*transfer/i,
        /operator.*fund/i
      ]
    },
    recommendation: 'Implement multi-sig for privileged operations. Use hardware security modules. Enforce least-privilege access. Add withdrawal delays for large amounts.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL847',
    name: 'Thunder Terminal MongoDB Injection',
    severity: 'high',
    category: 'input-validation',
    description: 'Thunder Terminal lost $240K through MongoDB injection in 9 minutes. Third-party database integration allowed unauthorized access to session data.',
    detection: {
      patterns: [
        /mongodb/i,
        /nosql.*inject/i,
        /\$where/,
        /\$regex/,
        /session.*token/i,
        /database.*query/i
      ]
    },
    recommendation: 'Sanitize all database inputs. Use parameterized queries. Never store session tokens in queryable format. Implement WAF rules.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL848',
    name: 'DEXX Private Key Hot Wallet Exposure',
    severity: 'critical',
    category: 'key-management',
    description: 'DEXX lost $30M when hot wallet private keys were exposed. Trading aggregator stored keys insecurely, allowing mass wallet drainage.',
    detection: {
      patterns: [
        /private.*key.*store/i,
        /hot.*wallet.*key/i,
        /secret.*key.*memory/i,
        /keypair.*storage/i,
        /seed.*phrase.*log/i
      ]
    },
    recommendation: 'Never store private keys in memory or logs. Use HSM or secure enclaves. Implement key rotation. Use multisig for high-value wallets.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL849',
    name: 'Banana Gun Trading Bot Vulnerability',
    severity: 'high',
    category: 'business-logic',
    description: 'Banana Gun lost $1.4M through trading bot vulnerability. Users were fully refunded. Bot logic allowed exploitation of trade execution.',
    detection: {
      patterns: [
        /trading.*bot/i,
        /auto.*trade/i,
        /snipe.*bot/i,
        /mev.*bot/i,
        /arbitrage.*bot/i
      ]
    },
    recommendation: 'Implement trade validation. Use slippage protection. Add rate limiting. Verify order integrity before execution.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL850',
    name: 'Solareum Bot Payment Exploit',
    severity: 'high',
    category: 'business-logic',
    description: 'Solareum trading bot exploited for $500K+. Team went dark after incident. Payment processing logic was flawed.',
    detection: {
      patterns: [
        /payment.*process/i,
        /subscription.*fee/i,
        /bot.*payment/i,
        /fee.*collect/i,
        /revenue.*share/i
      ]
    },
    recommendation: 'Validate all payment flows. Use escrow for subscription payments. Implement refund mechanisms. Add payment audit logging.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL851',
    name: 'Cypher Protocol Insider Theft',
    severity: 'critical',
    category: 'access-control',
    description: 'Cypher lost $1.35M ($1M attack + $317K insider theft). Insider threat during recovery led to additional losses.',
    detection: {
      patterns: [
        /insider.*threat/i,
        /trusted.*actor/i,
        /internal.*theft/i,
        /recovery.*exploit/i,
        /team.*member.*withdraw/i
      ]
    },
    recommendation: 'Use multi-sig for all treasury operations. Implement time-locked withdrawals. Add on-chain governance for fund movements.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL852',
    name: 'NoOnes P2P Hot Wallet Compromise',
    severity: 'critical',
    category: 'key-management',
    description: 'NoOnes P2P platform lost $4M through hot wallet compromise. Detected by ZachXBT. Key management failure.',
    detection: {
      patterns: [
        /p2p.*wallet/i,
        /escrow.*hot.*wallet/i,
        /trade.*wallet.*key/i,
        /custodial.*key/i,
        /platform.*wallet/i
      ]
    },
    recommendation: 'Use cold storage for majority of funds. Implement hot wallet limits. Use MPC wallets. Add withdrawal monitoring.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL853',
    name: 'io.net Sybil GPU Attack',
    severity: 'medium',
    category: 'input-validation',
    description: 'io.net suffered Sybil attack with fake GPUs gaining rewards. Decentralized compute validation was insufficient.',
    detection: {
      patterns: [
        /sybil.*attack/i,
        /fake.*device/i,
        /proof.*of.*work.*validation/i,
        /compute.*verification/i,
        /node.*authenticity/i
      ]
    },
    recommendation: 'Implement hardware attestation. Use stake-weighted validation. Add compute challenges. Verify device uniqueness.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL854',
    name: 'SVT Token Honeypot Pattern',
    severity: 'high',
    category: 'malicious-code',
    description: 'SVT Token used honeypot pattern to trap buyers. Token could be bought but not sold. Detected by CertiK.',
    detection: {
      patterns: [
        /transfer.*block/i,
        /sell.*disable/i,
        /honeypot/i,
        /whitelist.*sell/i,
        /blacklist.*transfer/i
      ]
    },
    recommendation: 'Verify token transfer functions allow both buy and sell. Check for hidden blacklists. Audit transfer restrictions.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },

  // === BUSINESS LOGIC PATTERNS (38.5% of vulns per Sec3) ===
  {
    id: 'SOL855',
    name: 'Lending Interest Rate Manipulation',
    severity: 'high',
    category: 'business-logic',
    description: 'Interest rate calculations can be manipulated through flash loans to extract value from lending protocols.',
    detection: {
      patterns: [
        /interest.*rate.*calculate/i,
        /borrow.*rate/i,
        /utilization.*rate/i,
        /rate.*model/i,
        /accrued.*interest/i
      ]
    },
    recommendation: 'Use time-weighted average rates. Implement rate bounds. Add flash loan guards around rate calculations.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL856',
    name: 'Vault Share Inflation Attack',
    severity: 'critical',
    category: 'business-logic',
    description: 'First depositor can inflate share price by donating assets, causing subsequent depositors to receive zero shares.',
    detection: {
      patterns: [
        /total.*supply\s*==\s*0/,
        /first.*deposit/i,
        /share.*mint.*amount/i,
        /vault.*share.*price/i,
        /deposit.*share.*ratio/i
      ]
    },
    recommendation: 'Mint dead shares on vault creation. Use minimum deposit amounts. Implement share price bounds.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL857',
    name: 'Reward Distribution Timing Exploit',
    severity: 'high',
    category: 'business-logic',
    description: 'Staking reward timing can be exploited by depositing just before distribution and withdrawing after.',
    detection: {
      patterns: [
        /reward.*distribute/i,
        /stake.*reward.*claim/i,
        /emission.*schedule/i,
        /reward.*per.*share/i,
        /pending.*reward/i
      ]
    },
    recommendation: 'Implement reward vesting. Use time-weighted staking. Add withdrawal cooldowns around reward epochs.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL858',
    name: 'AMM Constant Product Invariant Violation',
    severity: 'critical',
    category: 'business-logic',
    description: 'AMM invariant checks may be bypassed during complex swap sequences, allowing value extraction.',
    detection: {
      patterns: [
        /k\s*=.*x\s*\*\s*y/,
        /constant.*product/i,
        /invariant.*check/i,
        /swap.*invariant/i,
        /pool.*balance.*check/i
      ]
    },
    recommendation: 'Verify invariant before AND after swaps. Check invariant in all code paths. Add tolerance for rounding.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL859',
    name: 'Liquidation Bonus Manipulation',
    severity: 'high',
    category: 'business-logic',
    description: 'Liquidation bonus parameters can be manipulated to make liquidations profitable beyond intended levels.',
    detection: {
      patterns: [
        /liquidation.*bonus/i,
        /liquidator.*incentive/i,
        /close.*factor/i,
        /liquidate.*profit/i,
        /underwater.*position/i
      ]
    },
    recommendation: 'Cap liquidation bonus. Use gradual liquidation. Implement liquidation auctions for large positions.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL860',
    name: 'Oracle Price Band Escape',
    severity: 'high',
    category: 'business-logic',
    description: 'Price bands designed to limit oracle manipulation can be escaped through gradual price movements.',
    detection: {
      patterns: [
        /price.*band/i,
        /oracle.*limit/i,
        /price.*deviation/i,
        /max.*price.*change/i,
        /price.*circuit.*breaker/i
      ]
    },
    recommendation: 'Use multiple oracle sources. Implement TWAP. Add price movement rate limits. Pause on extreme deviations.',
    references: ['https://solanasec25.sec3.dev/']
  },

  // === INPUT VALIDATION PATTERNS (25% of vulns per Sec3) ===
  {
    id: 'SOL861',
    name: 'Instruction Data Length Validation Missing',
    severity: 'medium',
    category: 'input-validation',
    description: 'Missing validation of instruction data length can lead to buffer overreads or incorrect parsing.',
    detection: {
      patterns: [
        /instruction_data\[/,
        /data\.len\(\)/,
        /slice.*instruction/i,
        /parse.*instruction.*data/i
      ]
    },
    recommendation: 'Always validate instruction data length before parsing. Use safe slice operations. Define minimum/maximum lengths.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL862',
    name: 'Account Data Deserialization Without Bounds',
    severity: 'high',
    category: 'input-validation',
    description: 'Deserializing account data without bounds checking can lead to panics or memory issues.',
    detection: {
      patterns: [
        /try_from_slice/,
        /deserialize.*account/i,
        /borsh.*deserialize/i,
        /unpack.*account/i
      ]
    },
    recommendation: 'Validate account data length matches expected size. Use safe deserialization with error handling.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL863',
    name: 'Numeric Input Range Validation Missing',
    severity: 'medium',
    category: 'input-validation',
    description: 'User-provided numeric inputs without range validation can cause overflow or unexpected behavior.',
    detection: {
      patterns: [
        /amount:\s*u64/,
        /price:\s*u64/,
        /quantity:\s*u64/,
        /user.*input.*number/i
      ]
    },
    recommendation: 'Validate all numeric inputs against min/max bounds. Check for zero amounts where inappropriate.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL864',
    name: 'String Input Sanitization Missing',
    severity: 'medium',
    category: 'input-validation',
    description: 'User-provided strings without sanitization can cause issues with external systems or storage.',
    detection: {
      patterns: [
        /String::from/,
        /user.*string/i,
        /metadata.*name/i,
        /uri.*input/i
      ]
    },
    recommendation: 'Validate string lengths. Sanitize special characters. Use allowlists for expected formats.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL865',
    name: 'Timestamp Input Manipulation',
    severity: 'high',
    category: 'input-validation',
    description: 'User-provided timestamps can be manipulated to bypass time-based access controls.',
    detection: {
      patterns: [
        /user.*timestamp/i,
        /input.*time/i,
        /expiry.*param/i,
        /deadline.*input/i
      ]
    },
    recommendation: 'Use on-chain clock for time validation. Never trust user-provided timestamps for access control.',
    references: ['https://solanasec25.sec3.dev/']
  },

  // === ACCESS CONTROL PATTERNS (19% of vulns per Sec3) ===
  {
    id: 'SOL866',
    name: 'Missing Authority Revocation Check',
    severity: 'high',
    category: 'access-control',
    description: 'Authority revocation may not be properly validated, allowing revoked authorities to still act.',
    detection: {
      patterns: [
        /authority.*revoke/i,
        /remove.*admin/i,
        /disable.*authority/i,
        /revocation.*check/i
      ]
    },
    recommendation: 'Check authority status before every privileged operation. Use on-chain authority registry.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL867',
    name: 'Delegation Depth Exploitation',
    severity: 'high',
    category: 'access-control',
    description: 'Deep delegation chains can be exploited to gain unintended privileges through chained delegations.',
    detection: {
      patterns: [
        /delegate.*to.*delegate/i,
        /delegation.*chain/i,
        /re-delegate/i,
        /sub-delegate/i
      ]
    },
    recommendation: 'Limit delegation depth. Track delegation origins. Implement delegation expiry.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL868',
    name: 'Time-Based Access Control Bypass',
    severity: 'high',
    category: 'access-control',
    description: 'Time-locked operations can be bypassed through timestamp manipulation or validator timing.',
    detection: {
      patterns: [
        /time.*lock/i,
        /unlock.*time/i,
        /vesting.*schedule/i,
        /cliff.*period/i
      ]
    },
    recommendation: 'Use slot-based timing. Implement multi-block confirmation. Add buffer periods.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL869',
    name: 'Emergency Function Access Control',
    severity: 'critical',
    category: 'access-control',
    description: 'Emergency functions like pause/unpause may have weak access controls, enabling abuse.',
    detection: {
      patterns: [
        /emergency.*pause/i,
        /circuit.*breaker/i,
        /kill.*switch/i,
        /emergency.*withdraw/i
      ]
    },
    recommendation: 'Use multi-sig for emergency functions. Add time delays. Implement governance approval.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL870',
    name: 'Role-Based Access Confusion',
    severity: 'high',
    category: 'access-control',
    description: 'Multiple roles with overlapping permissions can lead to privilege confusion and escalation.',
    detection: {
      patterns: [
        /role.*admin/i,
        /permission.*level/i,
        /access.*role/i,
        /operator.*permission/i
      ]
    },
    recommendation: 'Define clear role hierarchy. Use principle of least privilege. Document role permissions.',
    references: ['https://solanasec25.sec3.dev/']
  },

  // === ADDITIONAL HIGH-IMPACT PATTERNS ===
  {
    id: 'SOL871',
    name: 'Cross-Program Invocation State Corruption',
    severity: 'critical',
    category: 'cpi-safety',
    description: 'CPI calls may corrupt state if account modifications are not properly isolated between calls.',
    detection: {
      patterns: [
        /invoke_signed.*modify/i,
        /cpi.*state.*change/i,
        /cross.*program.*write/i,
        /invoke.*then.*read/i
      ]
    },
    recommendation: 'Reload account state after CPI calls. Use account versioning. Validate state consistency.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL872',
    name: 'Governance Proposal Frontrunning',
    severity: 'high',
    category: 'governance',
    description: 'Governance proposals can be frontrun to manipulate voting outcomes or extract value.',
    detection: {
      patterns: [
        /proposal.*create/i,
        /vote.*before.*deadline/i,
        /governance.*frontrun/i,
        /proposal.*timing/i
      ]
    },
    recommendation: 'Use commit-reveal voting. Implement proposal delays. Add anti-manipulation cooldowns.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL873',
    name: 'NFT Metadata Immutability Violation',
    severity: 'medium',
    category: 'nft-security',
    description: 'NFT metadata may be modified after minting if update authority is not properly managed.',
    detection: {
      patterns: [
        /update.*authority/i,
        /metadata.*mutable/i,
        /change.*metadata/i,
        /nft.*update/i
      ]
    },
    recommendation: 'Revoke update authority after mint. Use immutable metadata. Document mutability clearly.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL874',
    name: 'Token-2022 Extension Interaction Bug',
    severity: 'high',
    category: 'token-2022',
    description: 'Multiple Token-2022 extensions can interact unexpectedly, causing transfer failures or value loss.',
    detection: {
      patterns: [
        /transfer.*fee.*hook/i,
        /extension.*conflict/i,
        /token.*2022.*multi/i,
        /extension.*order/i
      ]
    },
    recommendation: 'Test extension combinations thoroughly. Document extension interactions. Handle extension errors gracefully.',
    references: ['https://spl.solana.com/token-2022/extensions']
  }
];

export default batchedPatterns35;
