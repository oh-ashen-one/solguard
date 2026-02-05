import { SecurityPattern } from '../types';

/**
 * SolGuard Security Patterns - Batch 36
 * SOL875-SOL904: Data Integrity, DoS, and Advanced Attack Vectors
 * 
 * Source: Sec3 2025 Report, Neodyme/OtterSec Research
 * Focus: Data Integrity (8.9%), Denial of Service (8.5%), Advanced Attacks
 */

export const batchedPatterns36: SecurityPattern[] = [
  // === DATA INTEGRITY & ARITHMETIC (8.9% of vulns per Sec3) ===
  {
    id: 'SOL875',
    name: 'Precision Loss in Fee Calculations',
    severity: 'high',
    category: 'arithmetic',
    description: 'Fee calculations with integer division can lose precision, accumulating to significant value over time.',
    detection: {
      patterns: [
        /fee\s*=.*\/\s*\d+/,
        /fee.*divide/i,
        /protocol.*fee.*calc/i,
        /basis.*points.*div/i
      ]
    },
    recommendation: 'Use higher precision intermediate calculations. Round in protocol favor. Track rounding errors.',
    references: ['https://blog.neodyme.io/posts/lending_disclosure']
  },
  {
    id: 'SOL876',
    name: 'Share to Asset Conversion Rounding',
    severity: 'high',
    category: 'arithmetic',
    description: 'Rounding in share-to-asset conversions can be exploited through repeated small transactions.',
    detection: {
      patterns: [
        /share.*to.*asset/i,
        /redeem.*share/i,
        /withdraw.*share/i,
        /asset.*per.*share/i
      ]
    },
    recommendation: 'Use floor for redemptions, ceil for deposits. Implement minimum transaction amounts.',
    references: ['https://blog.neodyme.io/posts/lending_disclosure']
  },
  {
    id: 'SOL877',
    name: 'Interest Accrual Precision Attack',
    severity: 'high',
    category: 'arithmetic',
    description: 'Interest accrual with frequent small updates can lose precision compared to less frequent large updates.',
    detection: {
      patterns: [
        /accrue.*interest/i,
        /compound.*rate/i,
        /interest.*accumulate/i,
        /rate.*per.*second/i
      ]
    },
    recommendation: 'Use high-precision math libraries. Batch interest updates. Track precision loss.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL878',
    name: 'Price Ratio Overflow in Swaps',
    severity: 'critical',
    category: 'arithmetic',
    description: 'Large price ratios in swap calculations can overflow, leading to incorrect trade execution.',
    detection: {
      patterns: [
        /price.*ratio/i,
        /swap.*multiply/i,
        /exchange.*rate.*calc/i,
        /token.*ratio.*overflow/i
      ]
    },
    recommendation: 'Use u128 for intermediate calculations. Implement price bounds. Check for overflow explicitly.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL879',
    name: 'Cumulative Rounding Exploitation',
    severity: 'high',
    category: 'arithmetic',
    description: 'Repeated operations with small rounding errors can be exploited to drain value through many transactions.',
    detection: {
      patterns: [
        /for.*loop.*transfer/i,
        /batch.*rounding/i,
        /iterate.*calculate/i,
        /sum.*rounded/i
      ]
    },
    recommendation: 'Process batch calculations atomically. Track cumulative rounding. Limit operation frequency.',
    references: ['https://blog.neodyme.io/posts/lending_disclosure']
  },
  {
    id: 'SOL880',
    name: 'Fixed Point Math Library Misuse',
    severity: 'medium',
    category: 'arithmetic',
    description: 'Incorrect use of fixed-point math libraries can lead to precision issues or overflows.',
    detection: {
      patterns: [
        /fixed.*point/i,
        /decimal.*scale/i,
        /WAD|RAY|RAD/,
        /precision.*constant/i
      ]
    },
    recommendation: 'Use well-audited fixed-point libraries. Understand precision limits. Test edge cases.',
    references: ['https://solanasec25.sec3.dev/']
  },

  // === DENIAL OF SERVICE & LIVENESS (8.5% of vulns per Sec3) ===
  {
    id: 'SOL881',
    name: 'Unbounded Account Iteration DoS',
    severity: 'high',
    category: 'denial-of-service',
    description: 'Iterating over unbounded account lists can exceed compute limits, bricking contract functions.',
    detection: {
      patterns: [
        /for.*remaining_accounts/i,
        /iterate.*all.*accounts/i,
        /loop.*account.*list/i,
        /foreach.*member/i
      ]
    },
    recommendation: 'Implement pagination. Limit iteration count. Use efficient data structures.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL882',
    name: 'Account Spam Griefing Attack',
    severity: 'medium',
    category: 'denial-of-service',
    description: 'Creating many small accounts to bloat iteration or storage can grief protocol operations.',
    detection: {
      patterns: [
        /create.*many.*accounts/i,
        /account.*spam/i,
        /storage.*bloat/i,
        /dust.*account/i
      ]
    },
    recommendation: 'Require minimum account balance. Implement creation fees. Use account compression.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL883',
    name: 'Compute Budget Exhaustion Attack',
    severity: 'high',
    category: 'denial-of-service',
    description: 'Crafted inputs can cause excessive computation, exhausting the compute budget and failing legitimate transactions.',
    detection: {
      patterns: [
        /compute.*budget/i,
        /CU.*limit/i,
        /expensive.*operation/i,
        /recursive.*call/i
      ]
    },
    recommendation: 'Profile compute usage. Add early validation. Limit recursive depth. Use compute budget guards.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL884',
    name: 'Phantom Wallet Spam DoS Pattern',
    severity: 'medium',
    category: 'denial-of-service',
    description: 'Spamming wallets with dust transactions or NFTs to degrade user experience.',
    detection: {
      patterns: [
        /spam.*wallet/i,
        /dust.*nft/i,
        /airdrop.*spam/i,
        /unwanted.*token/i
      ]
    },
    recommendation: 'Implement token filtering. Add spam detection. Provide user controls for token visibility.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL885',
    name: 'Jito Bundle Rejection DoS',
    severity: 'medium',
    category: 'denial-of-service',
    description: 'Submitting invalid bundles can waste validator resources and delay legitimate bundles.',
    detection: {
      patterns: [
        /jito.*bundle/i,
        /bundle.*reject/i,
        /mev.*spam/i,
        /bundle.*validation/i
      ]
    },
    recommendation: 'Validate bundles before submission. Implement rate limiting. Add bundle simulation.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL886',
    name: 'Candy Machine Zero Account DoS',
    severity: 'high',
    category: 'denial-of-service',
    description: 'Creating zero-balance accounts in minting sequence can block NFT mints by filling allocations.',
    detection: {
      patterns: [
        /candy.*machine.*mint/i,
        /nft.*mint.*sequence/i,
        /allocation.*block/i,
        /mint.*slot.*exhaust/i
      ]
    },
    recommendation: 'Require minimum balance for mint slots. Implement cleanup mechanisms. Add whitelist phases.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },

  // === ADVANCED ATTACK PATTERNS ===
  {
    id: 'SOL887',
    name: 'Transaction Simulation Divergence',
    severity: 'high',
    category: 'advanced',
    description: 'Transactions may behave differently in simulation vs execution due to state changes between calls.',
    detection: {
      patterns: [
        /simulate.*transaction/i,
        /preflight.*check/i,
        /simulation.*diverge/i
      ]
    },
    recommendation: 'Use fresh state for simulation. Implement atomic checks. Handle simulation failures gracefully.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL888',
    name: 'Cross-Program Reentrancy via Callbacks',
    severity: 'critical',
    category: 'reentrancy',
    description: 'CPI to external programs can call back, modifying state before original transaction completes.',
    detection: {
      patterns: [
        /invoke.*callback/i,
        /cpi.*reenter/i,
        /external.*program.*call/i,
        /hook.*callback/i
      ]
    },
    recommendation: 'Complete state updates before CPI. Use reentrancy guards. Validate state post-CPI.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL889',
    name: 'Address Lookup Table Poisoning',
    severity: 'high',
    category: 'advanced',
    description: 'Malicious lookup tables can map to unexpected addresses, redirecting program invocations.',
    detection: {
      patterns: [
        /lookup.*table/i,
        /address.*lookup/i,
        /alt.*poisoning/i,
        /v0.*transaction/i
      ]
    },
    recommendation: 'Validate lookup table authority. Verify resolved addresses. Use hardcoded program IDs for critical calls.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL890',
    name: 'Versioned Transaction Downgrade',
    severity: 'medium',
    category: 'advanced',
    description: 'Forcing transactions to use legacy format may bypass v0-specific security checks.',
    detection: {
      patterns: [
        /version.*0.*legacy/i,
        /transaction.*version/i,
        /downgrade.*version/i
      ]
    },
    recommendation: 'Require specific transaction versions. Validate version before processing.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL891',
    name: 'Priority Fee Auction Manipulation',
    severity: 'medium',
    category: 'mev',
    description: 'Manipulating priority fee auctions to front-run or censor transactions.',
    detection: {
      patterns: [
        /priority.*fee/i,
        /compute.*unit.*price/i,
        /fee.*auction/i,
        /transaction.*priority/i
      ]
    },
    recommendation: 'Use dynamic priority fees. Implement private mempools. Add censorship resistance.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL892',
    name: 'Durable Nonce Replay Attack',
    severity: 'high',
    category: 'advanced',
    description: 'Durable nonces can be replayed if not properly advanced after use.',
    detection: {
      patterns: [
        /durable.*nonce/i,
        /nonce.*advance/i,
        /offline.*signing/i,
        /nonce.*account/i
      ]
    },
    recommendation: 'Always advance nonce after use. Validate nonce authority. Use nonce only for intended purpose.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL893',
    name: 'Slot Hashes Predictability Exploit',
    severity: 'high',
    category: 'randomness',
    description: 'Using slot hashes for randomness is predictable and can be manipulated by validators.',
    detection: {
      patterns: [
        /SlotHashes/,
        /slot.*hash.*random/i,
        /recent.*slot.*seed/i,
        /sysvar.*slot/i
      ]
    },
    recommendation: 'Use VRF for randomness. Implement commit-reveal schemes. Never use on-chain data as sole entropy source.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL894',
    name: 'Stake Account Authority Confusion',
    severity: 'high',
    category: 'staking',
    description: 'Confusion between stake and withdraw authorities can lead to locked or stolen stakes.',
    detection: {
      patterns: [
        /stake.*authority/i,
        /withdraw.*authority/i,
        /stake.*account.*auth/i,
        /delegation.*authority/i
      ]
    },
    recommendation: 'Clearly separate stake and withdraw authorities. Validate authority for each operation.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL895',
    name: 'Vote Account Manipulation',
    severity: 'critical',
    category: 'staking',
    description: 'Manipulating vote accounts can affect validator rewards and network consensus.',
    detection: {
      patterns: [
        /vote.*account/i,
        /validator.*vote/i,
        /commission.*change/i,
        /vote.*authority/i
      ]
    },
    recommendation: 'Secure vote account authorities. Implement commission change delays. Monitor vote account changes.',
    references: ['https://solanasec25.sec3.dev/']
  },

  // === PROTOCOL-SPECIFIC PATTERNS ===
  {
    id: 'SOL896',
    name: 'Pyth Oracle Confidence Interval Ignore',
    severity: 'high',
    category: 'oracle',
    description: 'Ignoring Pyth oracle confidence intervals can lead to using unreliable prices.',
    detection: {
      patterns: [
        /pyth.*price/i,
        /confidence.*interval/i,
        /price.*feed.*confidence/i,
        /oracle.*uncertainty/i
      ]
    },
    recommendation: 'Always check confidence intervals. Reject prices with high uncertainty. Implement fallback oracles.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL897',
    name: 'Switchboard Oracle Feed Staleness',
    severity: 'high',
    category: 'oracle',
    description: 'Stale Switchboard oracle feeds can provide outdated prices for time-sensitive operations.',
    detection: {
      patterns: [
        /switchboard.*feed/i,
        /oracle.*staleness/i,
        /feed.*last.*update/i,
        /price.*timestamp/i
      ]
    },
    recommendation: 'Check oracle update timestamp. Implement staleness thresholds. Add freshness requirements.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL898',
    name: 'Marinade Stake Pool Ticket Manipulation',
    severity: 'high',
    category: 'defi',
    description: 'Liquid staking ticket mechanisms can be manipulated for early redemption or value extraction.',
    detection: {
      patterns: [
        /ticket.*redeem/i,
        /unstake.*ticket/i,
        /delayed.*unstake/i,
        /liquid.*stake.*withdraw/i
      ]
    },
    recommendation: 'Implement ticket cooldowns. Validate ticket ownership. Add redemption rate limits.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL899',
    name: 'Jupiter Aggregator Route Manipulation',
    severity: 'high',
    category: 'defi',
    description: 'Manipulating aggregator routes can lead to worse execution prices through malicious intermediate swaps.',
    detection: {
      patterns: [
        /aggregator.*route/i,
        /swap.*path/i,
        /route.*manipulation/i,
        /intermediate.*hop/i
      ]
    },
    recommendation: 'Verify route integrity. Implement minimum output checks. Use trusted route sources.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL900',
    name: 'Compressed NFT Merkle Proof Forgery',
    severity: 'critical',
    category: 'cnft',
    description: 'Forged merkle proofs can claim ownership of compressed NFTs without legitimate proof.',
    detection: {
      patterns: [
        /merkle.*proof/i,
        /cnft.*verify/i,
        /compressed.*nft.*proof/i,
        /tree.*proof/i
      ]
    },
    recommendation: 'Verify merkle proofs on-chain. Validate proof length. Check tree authority.',
    references: ['https://solanasec25.sec3.dev/']
  },

  // === SUPPLY CHAIN & INFRASTRUCTURE ===
  {
    id: 'SOL901',
    name: 'NPM Package Typosquatting',
    severity: 'critical',
    category: 'supply-chain',
    description: 'Typosquatted npm packages can inject malicious code into Solana applications.',
    detection: {
      patterns: [
        /@solana\/web3\.js.*typo/i,
        /similar.*package.*name/i,
        /dependency.*confusion/i
      ]
    },
    recommendation: 'Verify package names exactly. Use package-lock.json. Audit dependencies regularly.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL902',
    name: 'Cargo Dependency Vulnerability',
    severity: 'high',
    category: 'supply-chain',
    description: 'Vulnerable Rust crate dependencies can introduce security issues into programs.',
    detection: {
      patterns: [
        /vulnerable.*crate/i,
        /outdated.*dependency/i,
        /cargo.*audit/i,
        /crate.*advisory/i
      ]
    },
    recommendation: 'Run cargo audit regularly. Pin dependency versions. Monitor security advisories.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL903',
    name: 'Frontend RPC Endpoint Hijacking',
    severity: 'high',
    category: 'infrastructure',
    description: 'Compromised RPC endpoints can modify transaction data or steal user information.',
    detection: {
      patterns: [
        /rpc.*endpoint/i,
        /custom.*rpc/i,
        /http.*rpc/i,
        /provider.*url/i
      ]
    },
    recommendation: 'Use trusted RPC providers. Implement RPC endpoint validation. Add transaction verification.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL904',
    name: 'Program Upgrade Authority Compromise',
    severity: 'critical',
    category: 'infrastructure',
    description: 'Compromised upgrade authority can deploy malicious program updates.',
    detection: {
      patterns: [
        /upgrade.*authority/i,
        /program.*data.*authority/i,
        /bpf.*upgrade/i,
        /program.*deploy/i
      ]
    },
    recommendation: 'Use multisig for upgrade authority. Implement timelock. Consider immutable deployments for mature programs.',
    references: ['https://solanasec25.sec3.dev/']
  }
];

export default batchedPatterns36;
