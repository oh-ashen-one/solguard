/**
 * SolGuard Pattern Batch 37
 * Based on Helius "Solana Hacks, Bugs, and Exploits: A Complete History" (Q1 2025)
 * Patterns SOL905-SOL960
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

const batchedPatterns37: BatchPattern[] = [
  // Loopscale Exploit Patterns (Jan 2025)
  {
    id: 'SOL905',
    name: 'Loopscale Undercollateralized Loan',
    severity: 'critical',
    category: 'lending',
    description: 'Undercollateralized loan creation allows flash loan attacks to drain collateral.',
    detection: {
      patterns: [
        /loan.*collateral/i,
        /collateral_ratio/i,
        /under.*collat/i,
        /ltv.*check/i
      ]
    },
    recommendation: 'Enforce strict collateralization ratios. Validate collateral value before loan creation. Add flash loan protection.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL906',
    name: 'Collateral Price Oracle Delay',
    severity: 'high',
    category: 'oracle',
    description: 'Delayed oracle updates allow creation of undercollateralized positions.',
    detection: {
      patterns: [
        /oracle.*price.*delay/i,
        /stale.*price/i,
        /price.*update.*time/i,
        /last_update_slot/i
      ]
    },
    recommendation: 'Check oracle staleness. Require recent price updates. Implement multiple oracle sources.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  
  // NoOnes Platform Exploit (Jan 2025)
  {
    id: 'SOL907',
    name: 'P2P Escrow Trade Manipulation',
    severity: 'critical',
    category: 'escrow',
    description: 'P2P escrow vulnerabilities allow manipulation of trade confirmation.',
    detection: {
      patterns: [
        /escrow.*trade/i,
        /p2p.*confirm/i,
        /trade.*release/i,
        /payment.*confirm/i
      ]
    },
    recommendation: 'Require multi-party confirmation. Add time delays for large trades. Implement dispute resolution.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL908',
    name: 'Hot Wallet Session Vulnerability',
    severity: 'critical',
    category: 'wallet',
    description: 'Hot wallet session management flaws enable unauthorized withdrawals.',
    detection: {
      patterns: [
        /hot.*wallet/i,
        /session.*token/i,
        /withdraw.*session/i,
        /wallet.*auth/i
      ]
    },
    recommendation: 'Implement cold wallet for majority of funds. Use hardware security modules. Add withdrawal delays.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  
  // DEXX Exploit (Nov 2024)
  {
    id: 'SOL909',
    name: 'DEXX Private Key Server Storage',
    severity: 'critical',
    category: 'key-management',
    description: 'Storing private keys on backend servers enables mass wallet drains.',
    detection: {
      patterns: [
        /server.*private.*key/i,
        /backend.*key.*store/i,
        /centralized.*key/i,
        /key.*database/i
      ]
    },
    recommendation: 'Never store private keys server-side. Use client-side key generation. Implement MPC or threshold signatures.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL910',
    name: 'Custodial Wallet Masquerading',
    severity: 'critical',
    category: 'wallet',
    description: 'Non-custodial claims while actually storing keys centrally.',
    detection: {
      patterns: [
        /custodial/i,
        /non.*custodial/i,
        /user.*key.*store/i,
        /wallet.*custody/i
      ]
    },
    recommendation: 'Verify truly non-custodial architecture. Use client-side encryption. Provide key export functionality.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  
  // Banana Gun Bot Exploit (Sep 2024)
  {
    id: 'SOL911',
    name: 'Trading Bot Session Token Theft',
    severity: 'critical',
    category: 'bot',
    description: 'Session token compromise in trading bots enables fund theft.',
    detection: {
      patterns: [
        /bot.*session/i,
        /trading.*token/i,
        /snipe.*auth/i,
        /trade.*session/i
      ]
    },
    recommendation: 'Implement hardware-backed sessions. Use time-limited tokens. Add IP binding for sessions.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL912',
    name: 'EVM Message Handler Vulnerability',
    severity: 'critical',
    category: 'cross-chain',
    description: 'EVM message handler flaws allow cross-chain fund extraction.',
    detection: {
      patterns: [
        /evm.*message/i,
        /cross.*chain.*handler/i,
        /message.*verify/i,
        /chain.*bridge/i
      ]
    },
    recommendation: 'Validate all cross-chain messages cryptographically. Implement replay protection. Use multiple validators.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  
  // Aurory SyncSpace Exploit (Dec 2023)
  {
    id: 'SOL913',
    name: 'Game Token Withdrawal Exploit',
    severity: 'high',
    category: 'gaming',
    description: 'Privileged wallet compromise enables unauthorized game token withdrawals.',
    detection: {
      patterns: [
        /game.*withdraw/i,
        /token.*sync/i,
        /game.*wallet/i,
        /nft.*withdraw/i
      ]
    },
    recommendation: 'Use multisig for game treasury. Implement withdrawal limits. Add monitoring and alerts.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL914',
    name: 'Off-Chain to On-Chain Sync Vulnerability',
    severity: 'high',
    category: 'gaming',
    description: 'Vulnerabilities in syncing off-chain game state to on-chain tokens.',
    detection: {
      patterns: [
        /sync.*state/i,
        /off.*chain.*sync/i,
        /game.*state.*verify/i,
        /merkle.*game/i
      ]
    },
    recommendation: 'Cryptographically sign off-chain state. Use merkle proofs for sync verification. Rate limit sync operations.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  
  // io.net Exploit (Apr 2024)
  {
    id: 'SOL915',
    name: 'GPU Network Reward Manipulation',
    severity: 'high',
    category: 'depin',
    description: 'Sybil attacks on decentralized compute networks to claim fraudulent rewards.',
    detection: {
      patterns: [
        /gpu.*reward/i,
        /compute.*claim/i,
        /node.*reward/i,
        /depin.*earn/i
      ]
    },
    recommendation: 'Implement proof-of-work verification. Use hardware attestation. Add stake-based sybil resistance.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL916',
    name: 'SQL Injection in DePIN APIs',
    severity: 'critical',
    category: 'infrastructure',
    description: 'SQL injection in API endpoints enables reward manipulation.',
    detection: {
      patterns: [
        /sql.*query/i,
        /database.*exec/i,
        /raw.*query/i,
        /string.*concat.*sql/i
      ]
    },
    recommendation: 'Use parameterized queries. Implement input validation. Use ORM with prepared statements.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  
  // Saga DAO Exploit (May 2024)
  {
    id: 'SOL917',
    name: 'Minimal Quorum Governance Attack',
    severity: 'critical',
    category: 'governance',
    description: 'Low quorum requirements allow attackers to pass malicious proposals.',
    detection: {
      patterns: [
        /quorum.*threshold/i,
        /min.*votes/i,
        /proposal.*pass/i,
        /governance.*threshold/i
      ]
    },
    recommendation: 'Set appropriate quorum thresholds. Add proposal veto mechanisms. Implement timelock delays.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL918',
    name: 'DAO Treasury Drain via Proposal',
    severity: 'critical',
    category: 'governance',
    description: 'Malicious governance proposals can drain DAO treasury funds.',
    detection: {
      patterns: [
        /treasury.*transfer/i,
        /dao.*withdraw/i,
        /proposal.*execute/i,
        /funds.*proposal/i
      ]
    },
    recommendation: 'Implement multi-stage proposal execution. Add treasury withdrawal limits. Use guardian veto powers.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  
  // Solareum Exploit (Jun 2024)
  {
    id: 'SOL919',
    name: 'Trading Bot Private Key Leak',
    severity: 'critical',
    category: 'bot',
    description: 'Trading bot private key exposure enables wallet drains.',
    detection: {
      patterns: [
        /bot.*key/i,
        /trade.*private/i,
        /sniper.*wallet/i,
        /auto.*trade.*key/i
      ]
    },
    recommendation: 'Use hardware wallets for bot operations. Implement key derivation. Add spending limits.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL920',
    name: 'Centralized Bot Infrastructure',
    severity: 'high',
    category: 'infrastructure',
    description: 'Centralized trading infrastructure creates single point of failure.',
    detection: {
      patterns: [
        /central.*server/i,
        /single.*endpoint/i,
        /main.*server/i,
        /backend.*only/i
      ]
    },
    recommendation: 'Implement decentralized architecture. Use redundant systems. Add failover mechanisms.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  
  // Web3.js Supply Chain Attack (Dec 2024)
  {
    id: 'SOL921',
    name: 'NPM Package Backdoor',
    severity: 'critical',
    category: 'supply-chain',
    description: 'Malicious code injected into widely-used NPM packages.',
    detection: {
      patterns: [
        /@solana\/web3\.js/i,
        /npm.*install/i,
        /package.*json/i,
        /dependency.*version/i
      ]
    },
    recommendation: 'Pin dependency versions. Use package-lock.json. Audit dependencies regularly. Use npm audit.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL922',
    name: 'Private Key Exfiltration via Dependency',
    severity: 'critical',
    category: 'supply-chain',
    description: 'Compromised packages exfiltrate private keys to attacker servers.',
    detection: {
      patterns: [
        /exfil.*key/i,
        /send.*private/i,
        /upload.*secret/i,
        /post.*key/i
      ]
    },
    recommendation: 'Review dependency code changes. Use Snyk or similar tools. Implement CSP policies.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  
  // Parcl Front-End Attack (Nov 2024)
  {
    id: 'SOL923',
    name: 'Frontend Transaction Manipulation',
    severity: 'critical',
    category: 'frontend',
    description: 'Compromised frontend modifies transactions before signing.',
    detection: {
      patterns: [
        /transaction.*modify/i,
        /frontend.*sign/i,
        /ui.*transaction/i,
        /client.*build.*tx/i
      ]
    },
    recommendation: 'Verify transaction details on hardware wallet. Use simulation. Implement transaction verification UI.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL924',
    name: 'CDN/Hosting Compromise',
    severity: 'critical',
    category: 'infrastructure',
    description: 'CDN or hosting provider compromise enables frontend manipulation.',
    detection: {
      patterns: [
        /cdn.*script/i,
        /external.*script/i,
        /hosted.*bundle/i,
        /cloudflare.*inject/i
      ]
    },
    recommendation: 'Use Subresource Integrity (SRI). Self-host critical scripts. Implement CSP headers.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  
  // Sec3 Report 2025 - Top Vulnerability Categories
  {
    id: 'SOL925',
    name: 'Business Logic Flaw - State Machine',
    severity: 'critical',
    category: 'business-logic',
    description: 'Incorrect state machine transitions allow bypassing protocol rules.',
    detection: {
      patterns: [
        /state.*transition/i,
        /status.*change/i,
        /phase.*update/i,
        /stage.*advance/i
      ]
    },
    recommendation: 'Implement strict state machine validation. Add state transition guards. Test all state paths.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL926',
    name: 'Business Logic Flaw - Race Condition',
    severity: 'high',
    category: 'business-logic',
    description: 'Race conditions in business logic allow double-spending or duplicate claims.',
    detection: {
      patterns: [
        /claim.*reward/i,
        /withdraw.*balance/i,
        /process.*payment/i,
        /execute.*order/i
      ]
    },
    recommendation: 'Use atomic operations. Implement claim tracking. Add reentrancy guards.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL927',
    name: 'Business Logic Flaw - Invariant Violation',
    severity: 'critical',
    category: 'business-logic',
    description: 'Protocol invariants can be violated through specific operation sequences.',
    detection: {
      patterns: [
        /invariant/i,
        /assert.*equal/i,
        /require.*balance/i,
        /check.*total/i
      ]
    },
    recommendation: 'Define and enforce protocol invariants. Add invariant checks after each operation. Use formal verification.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL928',
    name: 'Input Validation - Unchecked User Input',
    severity: 'high',
    category: 'input-validation',
    description: 'User-controlled input is used without proper validation.',
    detection: {
      patterns: [
        /user.*input/i,
        /param.*unchecked/i,
        /instruction.*data/i,
        /args\./i
      ]
    },
    recommendation: 'Validate all user inputs. Use type-safe deserialization. Implement bounds checking.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL929',
    name: 'Input Validation - Malicious Account Data',
    severity: 'critical',
    category: 'input-validation',
    description: 'Account data deserialization without proper validation.',
    detection: {
      patterns: [
        /try_from_slice/i,
        /deserialize/i,
        /unpack/i,
        /from_bytes/i
      ]
    },
    recommendation: 'Validate account discriminators. Check data length before deserialization. Use Anchor macros.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL930',
    name: 'Access Control - Missing Role Check',
    severity: 'critical',
    category: 'access-control',
    description: 'Administrative functions lack proper role verification.',
    detection: {
      patterns: [
        /admin.*function/i,
        /owner.*only/i,
        /privileged/i,
        /authority.*action/i
      ]
    },
    recommendation: 'Implement role-based access control. Verify authority accounts. Use has_one constraints.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL931',
    name: 'Access Control - Privilege Escalation',
    severity: 'critical',
    category: 'access-control',
    description: 'Users can escalate privileges through specific operation sequences.',
    detection: {
      patterns: [
        /set.*admin/i,
        /change.*authority/i,
        /upgrade.*role/i,
        /grant.*permission/i
      ]
    },
    recommendation: 'Use multi-step authority transfers. Implement timelock for privilege changes. Add veto mechanisms.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL932',
    name: 'Data Integrity - Unchecked Return Value',
    severity: 'high',
    category: 'data-integrity',
    description: 'Return values from critical operations are not checked.',
    detection: {
      patterns: [
        /let\s+_\s*=/i,
        /ignore.*result/i,
        /\.ok\(\)/i,
        /drop.*result/i
      ]
    },
    recommendation: 'Always check return values. Use ? operator for error propagation. Handle all error cases.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL933',
    name: 'Data Integrity - Precision Loss',
    severity: 'high',
    category: 'data-integrity',
    description: 'Arithmetic operations lose precision affecting financial calculations.',
    detection: {
      patterns: [
        /as\s+u\d+/i,
        /\.div\(/i,
        /\/\s*\d+/i,
        /truncate/i
      ]
    },
    recommendation: 'Use fixed-point math. Round in favor of protocol. Check for precision loss.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL934',
    name: 'DoS - Unbounded Loop',
    severity: 'high',
    category: 'denial-of-service',
    description: 'Unbounded loops can exceed compute budget causing transaction failures.',
    detection: {
      patterns: [
        /for.*in/i,
        /while.*true/i,
        /loop\s*\{/i,
        /iter\(\)/i
      ]
    },
    recommendation: 'Limit iteration counts. Implement pagination. Check compute budget consumption.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL935',
    name: 'DoS - Resource Exhaustion',
    severity: 'high',
    category: 'denial-of-service',
    description: 'Attackers can exhaust protocol resources blocking legitimate users.',
    detection: {
      patterns: [
        /vec.*push/i,
        /account.*create/i,
        /grow.*array/i,
        /extend/i
      ]
    },
    recommendation: 'Limit resource creation. Require stake or fee. Implement cleanup mechanisms.',
    references: ['https://solanasec25.sec3.dev/']
  },
  
  // Additional Exploit Patterns from Research
  {
    id: 'SOL936',
    name: 'Jet Protocol Break Bug',
    severity: 'high',
    category: 'business-logic',
    description: 'Unintended use of break statement bypasses critical validation.',
    detection: {
      patterns: [
        /break;/,
        /early.*return/i,
        /short.*circuit/i,
        /skip.*check/i
      ]
    },
    recommendation: 'Review all break and return statements. Ensure critical checks cannot be bypassed.',
    references: ['https://github.com/sannykim/solsec']
  },
  {
    id: 'SOL937',
    name: 'SPL Lending Rounding Exploit',
    severity: 'critical',
    category: 'arithmetic',
    description: 'Rounding errors in lending protocols enable small but repeated profit extraction.',
    detection: {
      patterns: [
        /\.round\(/i,
        /round_up/i,
        /round_down/i,
        /nearest/i
      ]
    },
    recommendation: 'Use floor() for user-favorable operations. Use ceil() for protocol-favorable. Document rounding direction.',
    references: ['https://blog.neodyme.io/posts/lending_disclosure']
  },
  {
    id: 'SOL938',
    name: 'Cope Roulette Revert Exploit',
    severity: 'high',
    category: 'business-logic',
    description: 'Exploiting reverting transactions to game random outcomes.',
    detection: {
      patterns: [
        /random.*outcome/i,
        /commit.*reveal/i,
        /vrf/i,
        /randomness/i
      ]
    },
    recommendation: 'Use VRF (Verifiable Random Function). Implement commit-reveal schemes. Add anti-retry mechanisms.',
    references: ['https://github.com/sannykim/solsec']
  },
  {
    id: 'SOL939',
    name: 'Schrodinger NFT Incinerator Attack',
    severity: 'critical',
    category: 'nft',
    description: 'Chained small exploits create significant combined impact on NFT protocols.',
    detection: {
      patterns: [
        /burn.*nft/i,
        /incinerator/i,
        /close.*token/i,
        /destroy.*mint/i
      ]
    },
    recommendation: 'Audit full operation chain. Consider attack combinations. Implement circuit breakers.',
    references: ['https://github.com/sannykim/solsec']
  },
  {
    id: 'SOL940',
    name: 'Candy Machine Zero-Init Exploit',
    severity: 'critical',
    category: 'nft',
    description: 'Missing zero-check on init allows stealing from Candy Machine.',
    detection: {
      patterns: [
        /init.*account/i,
        /zero.*check/i,
        /#\[account\(init/i,
        /initialize/i
      ]
    },
    recommendation: 'Use Anchor init constraints. Check is_initialized before operations. Prevent reinitialization.',
    references: ['https://github.com/sannykim/solsec']
  },
  
  // Solana Core Protocol Vulnerabilities
  {
    id: 'SOL941',
    name: 'Turbine Block Propagation Bug',
    severity: 'critical',
    category: 'infrastructure',
    description: 'Block propagation issues cause network partitioning or outages.',
    detection: {
      patterns: [
        /turbine/i,
        /block.*propagat/i,
        /shred/i,
        /erasure.*coding/i
      ]
    },
    recommendation: 'Monitor network health. Implement failover RPC. Handle network partitions gracefully.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL942',
    name: 'Durable Nonce Stale Transaction',
    severity: 'high',
    category: 'transaction',
    description: 'Stale durable nonce transactions can be replayed unexpectedly.',
    detection: {
      patterns: [
        /durable.*nonce/i,
        /advance.*nonce/i,
        /nonce.*account/i,
        /blockhash.*nonce/i
      ]
    },
    recommendation: 'Advance nonce before signing. Verify nonce freshness. Implement transaction expiry.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL943',
    name: 'Duplicate Block Consensus Bug',
    severity: 'critical',
    category: 'infrastructure',
    description: 'Consensus issues from duplicate blocks affect transaction finality.',
    detection: {
      patterns: [
        /duplicate.*block/i,
        /fork.*choice/i,
        /consensus/i,
        /finality/i
      ]
    },
    recommendation: 'Wait for sufficient confirmations. Implement finality checks. Handle reorgs gracefully.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL944',
    name: 'JIT Cache Bug',
    severity: 'high',
    category: 'infrastructure',
    description: 'JIT compilation bugs cause unexpected program behavior.',
    detection: {
      patterns: [
        /jit.*cache/i,
        /sbpf/i,
        /rbpf/i,
        /vm.*execute/i
      ]
    },
    recommendation: 'Test on devnet before mainnet. Monitor for unexpected behavior. Have rollback plans.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL945',
    name: 'ELF Address Alignment',
    severity: 'critical',
    category: 'infrastructure',
    description: 'ELF binary alignment issues enable memory corruption.',
    detection: {
      patterns: [
        /elf/i,
        /alignment/i,
        /memory.*corrupt/i,
        /buffer.*overflow/i
      ]
    },
    recommendation: 'Use latest Solana toolchain. Audit program binaries. Monitor validator logs.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  
  // Additional DeFi Attack Patterns
  {
    id: 'SOL946',
    name: 'LP Token Fair Pricing Attack',
    severity: 'critical',
    category: 'defi',
    description: 'LP tokens priced using reserve ratios enabling oracle manipulation.',
    detection: {
      patterns: [
        /lp.*price/i,
        /pool.*value/i,
        /reserve.*price/i,
        /liquidity.*value/i
      ]
    },
    recommendation: 'Use fair LP pricing formulas. Implement reserve ratio limits. Check for manipulation.',
    references: ['https://osec.io/blog/reports/2022-02-16-lp-token-oracle-manipulation/']
  },
  {
    id: 'SOL947',
    name: 'Token Approval Persistence',
    severity: 'high',
    category: 'token',
    description: 'Token approvals persist after intended use enabling future drains.',
    detection: {
      patterns: [
        /approve/i,
        /delegate/i,
        /allowance/i,
        /authorized_amount/i
      ]
    },
    recommendation: 'Revoke unused approvals. Use exact approval amounts. Implement approval expiry.',
    references: ['https://github.com/sannykim/solsec']
  },
  {
    id: 'SOL948',
    name: 'Cross-Chain Message Replay',
    severity: 'critical',
    category: 'cross-chain',
    description: 'Cross-chain messages can be replayed on different chains or after upgrades.',
    detection: {
      patterns: [
        /message.*verify/i,
        /cross.*chain/i,
        /bridge.*msg/i,
        /chain_id/i
      ]
    },
    recommendation: 'Include chain ID in messages. Track processed messages. Implement replay protection.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL949',
    name: 'Stake Pool Delegation Attack',
    severity: 'high',
    category: 'staking',
    description: 'Semantic inconsistency in stake pool allows unauthorized delegation changes.',
    detection: {
      patterns: [
        /stake.*pool/i,
        /delegation/i,
        /validator.*list/i,
        /stake.*account/i
      ]
    },
    recommendation: 'Validate delegation authority. Implement delegation limits. Add monitoring for changes.',
    references: ['https://www.sec3.dev/blog/solana-stake-pool']
  },
  {
    id: 'SOL950',
    name: 'Lending Market Configuration Attack',
    severity: 'critical',
    category: 'lending',
    description: 'Malicious lending market creation enables user fund extraction.',
    detection: {
      patterns: [
        /lending.*market/i,
        /reserve.*config/i,
        /market.*create/i,
        /lending.*pool/i
      ]
    },
    recommendation: 'Validate lending market authenticity. Use protocol-approved markets. Check market parameters.',
    references: ['https://github.com/sannykim/solsec']
  },
  
  // Insider and Social Engineering Patterns
  {
    id: 'SOL951',
    name: 'Insider Threat - Employee Access',
    severity: 'critical',
    category: 'insider',
    description: 'Employees with privileged access can steal funds.',
    detection: {
      patterns: [
        /admin.*access/i,
        /privileged.*wallet/i,
        /internal.*key/i,
        /team.*wallet/i
      ]
    },
    recommendation: 'Implement multi-party access controls. Use time-locked operations. Audit privileged actions.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL952',
    name: 'Social Engineering - Phishing Frontend',
    severity: 'critical',
    category: 'social',
    description: 'Phishing sites mimicking legitimate frontends steal user funds.',
    detection: {
      patterns: [
        /phish/i,
        /fake.*site/i,
        /imperson/i,
        /lookalike/i
      ]
    },
    recommendation: 'Verify website URLs. Use bookmarks. Enable domain monitoring.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL953',
    name: 'DNS Hijacking',
    severity: 'critical',
    category: 'infrastructure',
    description: 'DNS hijacking redirects users to malicious frontends.',
    detection: {
      patterns: [
        /dns/i,
        /domain.*redirect/i,
        /nameserver/i,
        /registrar/i
      ]
    },
    recommendation: 'Use DNSSEC. Monitor DNS records. Implement CAA records.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  
  // Token Extension Vulnerabilities (Token-2022)
  {
    id: 'SOL954',
    name: 'Token-2022 Transfer Fee Bypass',
    severity: 'high',
    category: 'token-2022',
    description: 'Transfer fee mechanisms can be bypassed through specific operation sequences.',
    detection: {
      patterns: [
        /transfer.*fee/i,
        /fee.*config/i,
        /withheld.*fee/i,
        /transfer_fee_basis_points/i
      ]
    },
    recommendation: 'Test all transfer paths. Verify fee collection. Implement fee enforcement checks.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL955',
    name: 'Token-2022 Confidential Transfer Leak',
    severity: 'high',
    category: 'token-2022',
    description: 'Confidential transfer amounts may be leaked through side channels.',
    detection: {
      patterns: [
        /confidential.*transfer/i,
        /elgamal/i,
        /encrypted.*amount/i,
        /zk.*proof/i
      ]
    },
    recommendation: 'Audit confidential transfer implementations. Test for timing attacks. Validate ZK proofs.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL956',
    name: 'Permanent Delegate Abuse',
    severity: 'high',
    category: 'token-2022',
    description: 'Permanent delegate authority can drain tokens without user consent.',
    detection: {
      patterns: [
        /permanent.*delegate/i,
        /token.*delegate/i,
        /delegate.*authority/i,
        /TransferChecked/i
      ]
    },
    recommendation: 'Warn users about permanent delegates. Implement delegate monitoring. Allow delegate revocation.',
    references: ['https://solanasec25.sec3.dev/']
  },
  
  // Advanced Attack Patterns
  {
    id: 'SOL957',
    name: 'Sandwich Attack on AMM',
    severity: 'high',
    category: 'mev',
    description: 'MEV bots sandwich user trades for profit extraction.',
    detection: {
      patterns: [
        /slippage/i,
        /min.*amount.*out/i,
        /swap.*exact/i,
        /price.*impact/i
      ]
    },
    recommendation: 'Set appropriate slippage. Use private transactions. Implement MEV protection.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL958',
    name: 'Jito Bundle Manipulation',
    severity: 'high',
    category: 'mev',
    description: 'Jito bundles can be manipulated to extract value from users.',
    detection: {
      patterns: [
        /jito/i,
        /bundle/i,
        /tip/i,
        /searcher/i
      ]
    },
    recommendation: 'Use bundle protection services. Verify transaction ordering. Implement backrun protection.',
    references: ['https://www.helius.dev/blog/solana-hacks']
  },
  {
    id: 'SOL959',
    name: 'Pyth Oracle Confidence Interval',
    severity: 'high',
    category: 'oracle',
    description: 'Ignoring Pyth confidence intervals enables price manipulation.',
    detection: {
      patterns: [
        /pyth.*price/i,
        /confidence/i,
        /price_data/i,
        /get_price_unchecked/i
      ]
    },
    recommendation: 'Check Pyth confidence intervals. Reject low-confidence prices. Use multiple oracles.',
    references: ['https://github.com/sannykim/solsec']
  },
  {
    id: 'SOL960',
    name: 'Switchboard VRF Manipulation',
    severity: 'high',
    category: 'oracle',
    description: 'VRF randomness can be biased through selective revelation.',
    detection: {
      patterns: [
        /switchboard/i,
        /vrf/i,
        /random.*callback/i,
        /randomness.*request/i
      ]
    },
    recommendation: 'Use proper VRF integration. Implement commit-reveal. Add randomness verification.',
    references: ['https://github.com/sannykim/solsec']
  }
];

export function runBatchedPatterns37(content: string, path: string): Finding[] {
  const findings: Finding[] = [];
  const lines = content.split('\n');
  
  for (const pattern of batchedPatterns37) {
    for (const regex of pattern.detection.patterns) {
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
        
        findings.push({
          id: pattern.id,
          title: pattern.name,
          severity: pattern.severity,
          description: pattern.description,
          location: { file: path, line: lineNum },
          recommendation: pattern.recommendation,
        });
      }
    }
  }
  
  // Deduplicate
  const seen = new Set<string>();
  return findings.filter(f => {
    const key = `${f.id}-${f.location.line}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

export default batchedPatterns37;
