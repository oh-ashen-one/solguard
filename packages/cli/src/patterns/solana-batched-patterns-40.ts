/**
 * SolGuard Pattern Batch 40
 * Protocol-Specific Deep Patterns & Edge Cases
 * Patterns SOL1081-SOL1160
 * 
 * Deep patterns for: Lending, DEX, Staking, Bridges, NFTs, Gaming
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

const batchedPatterns40: BatchPattern[] = [
  // ========================================
  // LENDING PROTOCOL DEEP PATTERNS
  // ========================================
  {
    id: 'SOL1081',
    name: 'First Depositor Attack',
    severity: 'critical',
    category: 'lending',
    description: 'First depositor can manipulate share price by donating tokens.',
    detection: {
      patterns: [
        /total_supply\s*==\s*0/i,
        /first.*deposit/i,
        /initial.*deposit/i,
        /share.*price/i
      ]
    },
    recommendation: 'Use virtual offset/shares. Require minimum initial deposit. Mint dead shares.',
    references: ['https://blog.openzeppelin.com/a-]']
  },
  {
    id: 'SOL1082',
    name: 'Interest Rate Model Exploit',
    severity: 'high',
    category: 'lending',
    description: 'Interest rate model can be manipulated through utilization changes.',
    detection: {
      patterns: [
        /interest.*rate.*model/i,
        /utilization/i,
        /borrow.*apy/i,
        /supply.*apy/i
      ]
    },
    recommendation: 'Use kink-based models with bounds. Implement rate smoothing.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1083',
    name: 'Bad Debt Socialization',
    severity: 'critical',
    category: 'lending',
    description: 'Bad debt is socialized across depositors unfairly.',
    detection: {
      patterns: [
        /bad.*debt/i,
        /shortfall/i,
        /insurance.*fund/i,
        /deficit/i
      ]
    },
    recommendation: 'Implement insurance fund. Cap bad debt per market. Add liquidation incentives.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1084',
    name: 'Borrow Cap Bypass',
    severity: 'high',
    category: 'lending',
    description: 'Borrow caps can be bypassed through multiple positions.',
    detection: {
      patterns: [
        /borrow.*cap/i,
        /max.*borrow/i,
        /borrow.*limit/i,
        /debt.*ceiling/i
      ]
    },
    recommendation: 'Track borrows at protocol level. Implement per-user limits.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1085',
    name: 'Reserve Factor Manipulation',
    severity: 'medium',
    category: 'lending',
    description: 'Reserve factor can be changed to extract protocol fees.',
    detection: {
      patterns: [
        /reserve.*factor/i,
        /protocol.*fee/i,
        /spread/i
      ]
    },
    recommendation: 'Use timelock for fee changes. Implement maximum bounds.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1086',
    name: 'Isolated Market Escape',
    severity: 'critical',
    category: 'lending',
    description: 'Isolated market positions can affect cross-margin positions.',
    detection: {
      patterns: [
        /isolated/i,
        /siloed/i,
        /emode/i,
        /efficiency.*mode/i
      ]
    },
    recommendation: 'Strictly enforce isolation. Separate risk engines.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1087',
    name: 'Oracle Staleness in Liquidation',
    severity: 'critical',
    category: 'lending',
    description: 'Stale oracle prices used for liquidation decisions.',
    detection: {
      patterns: [
        /liquidation/i,
        /price.*staleness/i,
        /last.*update/i,
        /price.*age/i
      ]
    },
    recommendation: 'Check price freshness. Use heartbeat monitoring. Pause on stale prices.',
    references: ['https://solanasec25.sec3.dev/']
  },

  // ========================================
  // DEX & AMM DEEP PATTERNS
  // ========================================
  {
    id: 'SOL1088',
    name: 'Concentrated Liquidity Reorg',
    severity: 'high',
    category: 'dex',
    description: 'CLMM positions can be manipulated during tick transitions.',
    detection: {
      patterns: [
        /tick/i,
        /concentrated.*liquidity/i,
        /range.*order/i,
        /sqrt.*price/i
      ]
    },
    recommendation: 'Handle tick boundaries atomically. Validate position ranges.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1089',
    name: 'LP Token Flash Mint',
    severity: 'critical',
    category: 'dex',
    description: 'LP tokens can be flash-minted for governance attacks.',
    detection: {
      patterns: [
        /lp.*token/i,
        /liquidity.*token/i,
        /mint.*lp/i,
        /pool.*share/i
      ]
    },
    recommendation: 'Snapshot LP balances for governance. Add minting delays.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1090',
    name: 'Imbalanced Pool Attack',
    severity: 'critical',
    category: 'dex',
    description: 'Pool can be pushed to extreme imbalance for manipulation.',
    detection: {
      patterns: [
        /pool.*balance/i,
        /reserve[s]?\s*=/i,
        /token.*[ab].*amount/i
      ]
    },
    recommendation: 'Implement imbalance limits. Use circuit breakers at extremes.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1091',
    name: 'Virtual Reserve Manipulation',
    severity: 'high',
    category: 'dex',
    description: 'Virtual reserves can diverge from actual balances.',
    detection: {
      patterns: [
        /virtual.*reserve/i,
        /virtual.*balance/i,
        /k.*value/i,
        /constant.*product/i
      ]
    },
    recommendation: 'Sync virtual and actual reserves. Validate k-value preservation.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1092',
    name: 'Routing Attack',
    severity: 'high',
    category: 'dex',
    description: 'DEX aggregator routing can be manipulated for worse execution.',
    detection: {
      patterns: [
        /route/i,
        /aggregator/i,
        /best.*price/i,
        /split.*swap/i
      ]
    },
    recommendation: 'Validate routes. Compare multiple quotes. Implement minimum return.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1093',
    name: 'Fee Tier Manipulation',
    severity: 'medium',
    category: 'dex',
    description: 'Attackers can game fee tier systems.',
    detection: {
      patterns: [
        /fee.*tier/i,
        /fee.*discount/i,
        /vip.*level/i,
        /trading.*volume/i
      ]
    },
    recommendation: 'Use time-weighted volume. Implement sybil resistance.',
    references: ['https://solanasec25.sec3.dev/']
  },

  // ========================================
  // STAKING & VALIDATOR PATTERNS
  // ========================================
  {
    id: 'SOL1094',
    name: 'Liquid Staking Rate Manipulation',
    severity: 'critical',
    category: 'staking',
    description: 'Liquid staking exchange rate can be manipulated.',
    detection: {
      patterns: [
        /exchange.*rate/i,
        /st.*sol/i,
        /m.*sol/i,
        /staking.*derivative/i
      ]
    },
    recommendation: 'Use conservative rate updates. Implement rate bounds.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1095',
    name: 'Validator Set Manipulation',
    severity: 'high',
    category: 'staking',
    description: 'Validator selection can be gamed for MEV or attacks.',
    detection: {
      patterns: [
        /validator.*set/i,
        /stake.*delegation/i,
        /validator.*list/i,
        /stake.*pool/i
      ]
    },
    recommendation: 'Randomize validator selection. Cap stake per validator.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1096',
    name: 'Instant Unstake Arbitrage',
    severity: 'high',
    category: 'staking',
    description: 'Instant unstake can be arbitraged against delayed unstake.',
    detection: {
      patterns: [
        /instant.*unstake/i,
        /immediate.*withdrawal/i,
        /flash.*unstake/i
      ]
    },
    recommendation: 'Price instant unstake fairly. Implement dynamic fees.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1097',
    name: 'Epoch Boundary Staking',
    severity: 'medium',
    category: 'staking',
    description: 'Staking at epoch boundary can gain extra rewards.',
    detection: {
      patterns: [
        /epoch/i,
        /stake.*activation/i,
        /deactivation/i,
        /warmup/i
      ]
    },
    recommendation: 'Pro-rate rewards at boundaries. Implement warmup periods.',
    references: ['https://solanasec25.sec3.dev/']
  },

  // ========================================
  // BRIDGE & CROSS-CHAIN PATTERNS
  // ========================================
  {
    id: 'SOL1098',
    name: 'Message Replay Attack',
    severity: 'critical',
    category: 'bridge',
    description: 'Cross-chain messages can be replayed for double-spend.',
    detection: {
      patterns: [
        /message.*id/i,
        /nonce/i,
        /replay.*protection/i,
        /processed.*message/i
      ]
    },
    recommendation: 'Track processed messages. Use unique message IDs. Implement nonces.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL1099',
    name: 'Insufficient Finality Wait',
    severity: 'critical',
    category: 'bridge',
    description: 'Bridge releases funds before sufficient confirmations.',
    detection: {
      patterns: [
        /confirmation/i,
        /finality/i,
        /block.*height/i,
        /proof.*verification/i
      ]
    },
    recommendation: 'Wait for probabilistic finality. Use conservative confirmation counts.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL1100',
    name: 'Relayer Censorship',
    severity: 'high',
    category: 'bridge',
    description: 'Bridge relayers can censor or delay transactions.',
    detection: {
      patterns: [
        /relayer/i,
        /relaying/i,
        /submit.*message/i,
        /deliver/i
      ]
    },
    recommendation: 'Use permissionless relaying. Implement incentives for fast delivery.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1101',
    name: 'Oracle Bridge Disagreement',
    severity: 'critical',
    category: 'bridge',
    description: 'Bridge oracles can disagree causing stuck funds.',
    detection: {
      patterns: [
        /oracle.*consensus/i,
        /guardian/i,
        /attestation/i,
        /sign.*message/i
      ]
    },
    recommendation: 'Implement dispute resolution. Add fallback mechanisms.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },

  // ========================================
  // NFT & GAMING PATTERNS
  // ========================================
  {
    id: 'SOL1102',
    name: 'NFT Metadata Manipulation',
    severity: 'medium',
    category: 'nft',
    description: 'NFT metadata can be changed after sale to deceive buyers.',
    detection: {
      patterns: [
        /metadata/i,
        /uri/i,
        /update.*metadata/i,
        /set.*uri/i
      ]
    },
    recommendation: 'Use immutable metadata or decentralized storage (IPFS/Arweave).',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1103',
    name: 'Royalty Evasion via Escrow',
    severity: 'high',
    category: 'nft',
    description: 'Royalties can be evaded through escrow or wrapper contracts.',
    detection: {
      patterns: [
        /royalt/i,
        /creator.*fee/i,
        /seller.*fee/i
      ]
    },
    recommendation: 'Use pNFTs with enforced royalties. Implement marketplace enforcement.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1104',
    name: 'Compressed NFT Proof Forgery',
    severity: 'critical',
    category: 'nft',
    description: 'Compressed NFT merkle proofs can be forged.',
    detection: {
      patterns: [
        /compressed.*nft/i,
        /cnft/i,
        /merkle.*proof/i,
        /concurrent.*merkle/i
      ]
    },
    recommendation: 'Verify proofs against on-chain root. Use trusted RPC providers.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1105',
    name: 'Gaming Randomness Exploit',
    severity: 'critical',
    category: 'gaming',
    description: 'Game randomness can be predicted or manipulated.',
    detection: {
      patterns: [
        /random/i,
        /slot.*hash/i,
        /recent.*blockhash/i,
        /vrf/i
      ]
    },
    recommendation: 'Use Switchboard VRF or commit-reveal. Never use block hashes alone.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1106',
    name: 'Game Item Duplication',
    severity: 'critical',
    category: 'gaming',
    description: 'Game items can be duplicated through race conditions.',
    detection: {
      patterns: [
        /item.*transfer/i,
        /inventory/i,
        /equip/i,
        /unequip/i
      ]
    },
    recommendation: 'Use atomic operations. Implement proper locking. Validate ownership.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1107',
    name: 'Play-to-Earn Inflation',
    severity: 'high',
    category: 'gaming',
    description: 'Game rewards can be farmed faster than intended.',
    detection: {
      patterns: [
        /reward.*rate/i,
        /earn.*token/i,
        /game.*reward/i,
        /daily.*limit/i
      ]
    },
    recommendation: 'Implement anti-bot measures. Use time-weighted rewards. Cap emissions.',
    references: ['https://solanasec25.sec3.dev/']
  },

  // ========================================
  // GOVERNANCE DEEP PATTERNS
  // ========================================
  {
    id: 'SOL1108',
    name: 'Flash Loan Governance',
    severity: 'critical',
    category: 'governance',
    description: 'Governance tokens can be flash-borrowed to pass proposals.',
    detection: {
      patterns: [
        /governance.*token/i,
        /voting.*power/i,
        /proposal/i,
        /quorum/i
      ]
    },
    recommendation: 'Snapshot voting power at proposal creation. Use time-weighted voting.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL1109',
    name: 'Proposal Griefing',
    severity: 'medium',
    category: 'governance',
    description: 'Attackers can grief governance with spam proposals.',
    detection: {
      patterns: [
        /create.*proposal/i,
        /proposal.*fee/i,
        /proposal.*threshold/i
      ]
    },
    recommendation: 'Require proposal deposit. Implement proposal limits.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1110',
    name: 'Timelock Bypass',
    severity: 'critical',
    category: 'governance',
    description: 'Governance timelock can be bypassed through upgrade.',
    detection: {
      patterns: [
        /timelock/i,
        /delay/i,
        /queue.*execution/i,
        /eta/i
      ]
    },
    recommendation: 'Apply timelock to all admin functions. Include upgrades.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1111',
    name: 'Vote Delegation Exploit',
    severity: 'high',
    category: 'governance',
    description: 'Vote delegation can be exploited for double-voting.',
    detection: {
      patterns: [
        /delegate/i,
        /delegated.*vote/i,
        /proxy.*vote/i
      ]
    },
    recommendation: 'Prevent self-delegation loops. Track delegation chains.',
    references: ['https://solanasec25.sec3.dev/']
  },

  // ========================================
  // ANCHOR-SPECIFIC PATTERNS
  // ========================================
  {
    id: 'SOL1112',
    name: 'Anchor Constraint Missing',
    severity: 'critical',
    category: 'anchor',
    description: 'Critical Anchor constraint missing on account.',
    detection: {
      patterns: [
        /#\[account\]/i,
        /AccountInfo/i,
        /UncheckedAccount/i
      ]
    },
    recommendation: 'Add has_one, seeds, constraint, or other validation.',
    references: ['https://www.zellic.io/blog/the-vulnerabilities-youll-write-with-anchor/']
  },
  {
    id: 'SOL1113',
    name: 'Anchor Init If Needed',
    severity: 'high',
    category: 'anchor',
    description: 'init_if_needed can cause unexpected reinitializations.',
    detection: {
      patterns: [
        /init_if_needed/i
      ]
    },
    recommendation: 'Prefer separate init and operate instructions. Add realloc protection.',
    references: ['https://www.zellic.io/blog/the-vulnerabilities-youll-write-with-anchor/']
  },
  {
    id: 'SOL1114',
    name: 'Anchor Realloc Without Zero',
    severity: 'high',
    category: 'anchor',
    description: 'Realloc without zeroing can leak previous data.',
    detection: {
      patterns: [
        /realloc/i,
        /realloc.*=.*false/i
      ]
    },
    recommendation: 'Use realloc::zero = true to clear new space.',
    references: ['https://www.zellic.io/blog/the-vulnerabilities-youll-write-with-anchor/']
  },
  {
    id: 'SOL1115',
    name: 'Anchor Close Without Destination',
    severity: 'high',
    category: 'anchor',
    description: 'Account close without validating destination.',
    detection: {
      patterns: [
        /close\s*=/i,
        /#\[account.*close/i
      ]
    },
    recommendation: 'Validate close destination. Consider using Treasury account.',
    references: ['https://www.zellic.io/blog/the-vulnerabilities-youll-write-with-anchor/']
  },
  {
    id: 'SOL1116',
    name: 'Anchor Seeds Collision',
    severity: 'critical',
    category: 'anchor',
    description: 'PDA seeds can collide allowing account substitution.',
    detection: {
      patterns: [
        /seeds\s*=/i,
        /bump\s*=/i,
        /#\[account.*seeds/i
      ]
    },
    recommendation: 'Use unique seed prefixes. Include discriminating fields in seeds.',
    references: ['https://www.zellic.io/blog/the-vulnerabilities-youll-write-with-anchor/']
  },

  // ========================================
  // SUPPLY CHAIN & DEPENDENCY PATTERNS
  // ========================================
  {
    id: 'SOL1117',
    name: 'Malicious Dependency',
    severity: 'critical',
    category: 'supply-chain',
    description: 'Project may include compromised dependency.',
    detection: {
      patterns: [
        /npm.*install/i,
        /cargo.*add/i,
        /crates\.io/i,
        /dependency/i
      ]
    },
    recommendation: 'Pin all dependencies. Audit dependency updates. Use lockfiles.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL1118',
    name: 'Build Process Compromise',
    severity: 'critical',
    category: 'supply-chain',
    description: 'Build process can be compromised to inject malicious code.',
    detection: {
      patterns: [
        /build\.rs/i,
        /proc.*macro/i,
        /build.*script/i
      ]
    },
    recommendation: 'Verify build outputs. Use reproducible builds. Audit build scripts.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL1119',
    name: 'Frontend Injection',
    severity: 'critical',
    category: 'supply-chain',
    description: 'Frontend can be compromised to steal funds.',
    detection: {
      patterns: [
        /frontend/i,
        /cdn/i,
        /script.*src/i
      ]
    },
    recommendation: 'Use subresource integrity. Self-host critical assets. IPFS deploy.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },

  // ========================================
  // ADDITIONAL EDGE CASES
  // ========================================
  {
    id: 'SOL1120',
    name: 'Dust Attack Vector',
    severity: 'low',
    category: 'edge-case',
    description: 'Account can be dusted with tokens to cause issues.',
    detection: {
      patterns: [
        /dust/i,
        /small.*amount/i,
        /minimum.*balance/i
      ]
    },
    recommendation: 'Handle dust gracefully. Implement minimum thresholds.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1121',
    name: 'Account Revival Attack',
    severity: 'critical',
    category: 'edge-case',
    description: 'Closed account can be revived with old state.',
    detection: {
      patterns: [
        /close.*account/i,
        /account.*close/i,
        /transfer.*lamports/i
      ]
    },
    recommendation: 'Zero account data before closing. Check for revival in subsequent ops.',
    references: ['https://blog.neodyme.io/posts/solana_common_pitfalls']
  },
  {
    id: 'SOL1122',
    name: 'Remaining Accounts Exploit',
    severity: 'high',
    category: 'edge-case',
    description: 'Remaining accounts can be used to pass unexpected data.',
    detection: {
      patterns: [
        /remaining_accounts/i,
        /ctx\.remaining/i
      ]
    },
    recommendation: 'Validate all remaining accounts. Implement expected account count.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1123',
    name: 'Return Data Injection',
    severity: 'high',
    category: 'edge-case',
    description: 'CPI return data can be manipulated by malicious programs.',
    detection: {
      patterns: [
        /return.*data/i,
        /get_return_data/i,
        /set_return_data/i
      ]
    },
    recommendation: 'Validate return data source program. Don\'t trust arbitrary return data.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1124',
    name: 'Lookup Table Manipulation',
    severity: 'high',
    category: 'edge-case',
    description: 'Address lookup tables can be manipulated to substitute accounts.',
    detection: {
      patterns: [
        /lookup.*table/i,
        /address.*lookup/i,
        /alt/i
      ]
    },
    recommendation: 'Verify lookup table ownership. Check table is not modifiable.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1125',
    name: 'Versioned Transaction Confusion',
    severity: 'medium',
    category: 'edge-case',
    description: 'Versioned transaction handling can cause issues.',
    detection: {
      patterns: [
        /versioned/i,
        /transaction.*version/i,
        /v0/i
      ]
    },
    recommendation: 'Support both legacy and versioned transactions. Validate version.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1126',
    name: 'Simulation vs Execution Divergence',
    severity: 'critical',
    category: 'edge-case',
    description: 'Transaction behaves differently in simulation vs execution.',
    detection: {
      patterns: [
        /simulat/i,
        /preflight/i,
        /skip.*preflight/i
      ]
    },
    recommendation: 'Ensure deterministic behavior. Don\'t rely on simulation results.',
    references: ['https://opcodes.fr/en/publications/2022-01/detecting-transaction-simulation/']
  },
  {
    id: 'SOL1127',
    name: 'Compute Unit Estimation',
    severity: 'medium',
    category: 'edge-case',
    description: 'Compute unit estimation can fail causing transaction revert.',
    detection: {
      patterns: [
        /compute.*unit/i,
        /SetComputeUnitLimit/i,
        /RequestUnits/i
      ]
    },
    recommendation: 'Add buffer to compute estimates. Test worst-case scenarios.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1128',
    name: 'Account Size Increase Attack',
    severity: 'medium',
    category: 'edge-case',
    description: 'Account size can be increased to exhaust payer rent.',
    detection: {
      patterns: [
        /realloc/i,
        /account.*size/i,
        /space\s*=/i
      ]
    },
    recommendation: 'Cap account size increases. Verify payer can afford rent.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1129',
    name: 'Program Account Data Leak',
    severity: 'medium',
    category: 'edge-case',
    description: 'Program account data may leak sensitive information.',
    detection: {
      patterns: [
        /program.*data/i,
        /executable/i,
        /bpf.*loader/i
      ]
    },
    recommendation: 'Don\'t store secrets in program data. Assume all data is public.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1130',
    name: 'Heap Allocation DoS',
    severity: 'high',
    category: 'edge-case',
    description: 'Excessive heap allocation can fail transactions.',
    detection: {
      patterns: [
        /Vec::with_capacity/i,
        /vec!/i,
        /alloc/i,
        /heap/i
      ]
    },
    recommendation: 'Bound allocation sizes. Use fixed-size arrays where possible.',
    references: ['https://solanasec25.sec3.dev/']
  },

  // ========================================
  // MORE EXPLOIT PATTERNS FROM HELIUS
  // ========================================
  {
    id: 'SOL1131',
    name: 'Cypher Protocol Double Claim',
    severity: 'critical',
    category: 'exploit-pattern',
    description: 'Rewards can be claimed multiple times due to state mismanagement.',
    detection: {
      patterns: [
        /claim.*reward/i,
        /claimed/i,
        /has_claimed/i
      ]
    },
    recommendation: 'Mark claims atomically. Verify not already claimed before processing.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL1132',
    name: 'Solareum Wallet Drain',
    severity: 'critical',
    category: 'exploit-pattern',
    description: 'Wallet private keys stored insecurely allowing drain.',
    detection: {
      patterns: [
        /private.*key/i,
        /keypair/i,
        /seed.*phrase/i
      ]
    },
    recommendation: 'Never store private keys server-side. Use secure enclaves if necessary.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL1133',
    name: 'io.net Bot Network Attack',
    severity: 'high',
    category: 'exploit-pattern',
    description: 'Distributed bot network compromised for fund theft.',
    detection: {
      patterns: [
        /bot/i,
        /automation/i,
        /scheduled/i
      ]
    },
    recommendation: 'Secure bot credentials. Implement least-privilege access.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL1134',
    name: 'Synthetify DAO Proposal Attack',
    severity: 'critical',
    category: 'exploit-pattern',
    description: 'Malicious DAO proposal passes unnoticed draining treasury.',
    detection: {
      patterns: [
        /proposal.*execute/i,
        /dao.*action/i,
        /treasury.*transfer/i
      ]
    },
    recommendation: 'Implement proposal monitoring. Add execution delays. Community alerts.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL1135',
    name: 'Aurory Game Exploit',
    severity: 'high',
    category: 'exploit-pattern',
    description: 'Gaming protocol exploited through game mechanics.',
    detection: {
      patterns: [
        /game.*logic/i,
        /player.*action/i,
        /game.*state/i
      ]
    },
    recommendation: 'Audit game mechanics. Implement fair play checks. Rate limit actions.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL1136',
    name: 'Saga DAO Governance Takeover',
    severity: 'critical',
    category: 'exploit-pattern',
    description: 'DAO governance system taken over through vote manipulation.',
    detection: {
      patterns: [
        /governance/i,
        /vote.*weight/i,
        /proposal.*create/i
      ]
    },
    recommendation: 'Use time-locked voting. Snapshot at proposal creation.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL1137',
    name: 'SVT Token Exploit',
    severity: 'critical',
    category: 'exploit-pattern',
    description: 'Token contract vulnerability allowing unauthorized minting.',
    detection: {
      patterns: [
        /mint.*authority/i,
        /mint_to/i,
        /token.*mint/i
      ]
    },
    recommendation: 'Validate mint authority. Implement supply caps.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL1138',
    name: 'Parcl Frontend Compromise',
    severity: 'critical',
    category: 'exploit-pattern',
    description: 'Frontend compromised to drain user wallets.',
    detection: {
      patterns: [
        /frontend/i,
        /dapp/i,
        /web.*app/i
      ]
    },
    recommendation: 'Use IPFS deployment. Subresource integrity. Domain monitoring.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL1139',
    name: 'Phantom DDoS Pattern',
    severity: 'medium',
    category: 'exploit-pattern',
    description: 'Wallet DDoS can prevent users from accessing funds.',
    detection: {
      patterns: [
        /rpc/i,
        /endpoint/i,
        /rate.*limit/i
      ]
    },
    recommendation: 'Use multiple RPC providers. Implement fallback mechanisms.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL1140',
    name: 'Candy Machine V1 Exploit',
    severity: 'critical',
    category: 'exploit-pattern',
    description: 'Candy Machine configuration allows unauthorized minting.',
    detection: {
      patterns: [
        /candy.*machine/i,
        /mint.*config/i,
        /whitelist/i
      ]
    },
    recommendation: 'Use latest Candy Machine version. Verify configuration thoroughly.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },

  // ========================================
  // FINAL PATTERNS
  // ========================================
  {
    id: 'SOL1141',
    name: 'Cross-Instance Attack',
    severity: 'critical',
    category: 'advanced',
    description: 'Attack spans multiple protocol instances.',
    detection: {
      patterns: [
        /instance/i,
        /market.*id/i,
        /pool.*id/i
      ]
    },
    recommendation: 'Isolate instances. Implement cross-instance checks.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1142',
    name: 'Vault Strategy Exploit',
    severity: 'critical',
    category: 'advanced',
    description: 'Yield vault strategy can be exploited for profit extraction.',
    detection: {
      patterns: [
        /strategy/i,
        /harvest/i,
        /compound/i,
        /yield/i
      ]
    },
    recommendation: 'Audit all strategy interactions. Implement harvest delays.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1143',
    name: 'Fee-on-Transfer Token Issue',
    severity: 'high',
    category: 'advanced',
    description: 'Fee-on-transfer tokens break accounting assumptions.',
    detection: {
      patterns: [
        /transfer.*fee/i,
        /fee.*on.*transfer/i,
        /token.*2022/i
      ]
    },
    recommendation: 'Check actual received amount. Support fee-on-transfer explicitly.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1144',
    name: 'Rebasing Token Issue',
    severity: 'high',
    category: 'advanced',
    description: 'Rebasing tokens change balance without transfers.',
    detection: {
      patterns: [
        /rebase/i,
        /elastic.*supply/i,
        /balance.*change/i
      ]
    },
    recommendation: 'Use share-based accounting. Track underlying amounts.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1145',
    name: 'Pausable Token Griefing',
    severity: 'medium',
    category: 'advanced',
    description: 'Pausable tokens can grief protocols by pausing transfers.',
    detection: {
      patterns: [
        /pause/i,
        /pausable/i,
        /frozen/i
      ]
    },
    recommendation: 'Check token pausability before integrating. Add fallback mechanisms.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1146',
    name: 'Blacklistable Token Issue',
    severity: 'high',
    category: 'advanced',
    description: 'Token blacklist can trap user funds in protocol.',
    detection: {
      patterns: [
        /blacklist/i,
        /blocklist/i,
        /deny.*list/i
      ]
    },
    recommendation: 'Allow blacklisted funds to emergency withdraw. Check blacklist status.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1147',
    name: 'Permit/Approval Race',
    severity: 'high',
    category: 'advanced',
    description: 'Token approval race condition allows double spending.',
    detection: {
      patterns: [
        /approve/i,
        /allowance/i,
        /permit/i
      ]
    },
    recommendation: 'Use increase/decrease allowance. Set to 0 before changing.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1148',
    name: 'Reentrancy via Callback',
    severity: 'critical',
    category: 'advanced',
    description: 'Callback mechanism allows reentrancy attack.',
    detection: {
      patterns: [
        /callback/i,
        /hook/i,
        /on_receive/i,
        /before_transfer/i
      ]
    },
    recommendation: 'Use reentrancy guards. Follow checks-effects-interactions.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1149',
    name: 'Batch Instruction Attack',
    severity: 'high',
    category: 'advanced',
    description: 'Multiple instructions in transaction create exploit opportunity.',
    detection: {
      patterns: [
        /instruction.*introspection/i,
        /previous.*instruction/i,
        /sysvar.*instructions/i
      ]
    },
    recommendation: 'Validate instruction ordering. Use atomic bundles.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1150',
    name: 'Cross-Program Return Injection',
    severity: 'high',
    category: 'advanced',
    description: 'Cross-program return data can be injected.',
    detection: {
      patterns: [
        /return_data/i,
        /cpi.*result/i,
        /invoke.*return/i
      ]
    },
    recommendation: 'Verify return data source program ID. Validate data format.',
    references: ['https://solanasec25.sec3.dev/']
  },
];

// Pattern execution logic
function runBatch40Patterns(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';
  
  if (!content) return findings;
  
  const lines = content.split('\n');
  
  for (const pattern of batchedPatterns40) {
    for (const regex of pattern.detection.patterns) {
      try {
        const flags = regex.flags.includes('g') ? regex.flags : regex.flags + 'g';
        const searchRegex = new RegExp(regex.source, flags);
        const matches = [...content.matchAll(searchRegex)];
        
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
            location: { file: input.path, line: lineNum },
            recommendation: pattern.recommendation,
            code: snippet.substring(0, 200),
          });
          
          // Only one finding per pattern per file
          break;
        }
      } catch (e) {
        // Skip invalid patterns
      }
    }
  }
  
  return findings;
}

export { batchedPatterns40, runBatch40Patterns };
export default batchedPatterns40;
