/**
 * SolGuard Security Patterns - Batch 90
 * 
 * Feb 6, 2026 5:00 AM - Latest 2025-2026 Research + Sec3 Final + Academic Deep Dive
 * Sources:
 * - arXiv:2504.07419 "Exploring Vulnerabilities in Solana Smart Contracts" (Apr 2025)
 * - Sec3 2025 Security Ecosystem Review (163 audits, 1,669 vulnerabilities)
 * - Helius Complete Solana Hacks History (38 incidents, $600M+)
 * - Medium "Comprehensive Analysis of Solana's Security History Q1 2025"
 * - CyberDaily DeFi Security 2025 ($3.1B breaches)
 * 
 * Patterns: SOL5001-SOL5100
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

const BATCH_90_PATTERNS: PatternDef[] = [
  // ============================================
  // arXiv 2025 Academic Research Patterns
  // From "Exploring Vulnerabilities in Solana Smart Contracts"
  // ============================================
  {
    id: 'SOL5001',
    name: 'arXiv: BPF Verifier Bypass',
    severity: 'critical',
    pattern: /unsafe\s*\{[\s\S]*?std::mem::transmute|std::ptr::read_unaligned/i,
    description: 'arXiv research: BPF verifier can be bypassed with unsafe memory operations, leading to arbitrary code execution.',
    recommendation: 'Avoid unsafe blocks in Solana programs. Use safe Rust abstractions.'
  },
  {
    id: 'SOL5002',
    name: 'arXiv: Stack Overflow via Recursion',
    severity: 'high',
    pattern: /fn\s+\w+\([^)]*\)\s*(?:->.*?)?\s*\{[\s\S]*?self\.\w+\(/i,
    description: 'arXiv research: Recursive function calls can exhaust 4KB stack limit, causing program crash.',
    recommendation: 'Avoid recursion. Use iterative approaches with explicit stack management.'
  },
  {
    id: 'SOL5003',
    name: 'arXiv: Heap Exhaustion Attack',
    severity: 'high',
    pattern: /Vec::with_capacity\s*\(\s*\w+|vec!\s*\[\s*0\s*;\s*\w+\s*\]/i,
    description: 'arXiv research: Dynamic allocation without bounds can exhaust 32KB heap.',
    recommendation: 'Bound all dynamic allocations. Validate sizes before allocating.'
  },
  {
    id: 'SOL5004',
    name: 'arXiv: Compute Budget Exhaustion',
    severity: 'medium',
    pattern: /for\s+\w+\s+in\s+\d+\.\.[\s\S]*?invoke(?:_signed)?\s*\(/i,
    description: 'arXiv research: Loops with CPI calls can exceed 48M compute unit limit.',
    recommendation: 'Profile compute usage. Break large operations into multiple transactions.'
  },
  {
    id: 'SOL5005',
    name: 'arXiv: Sysvar Spoofing Attack',
    severity: 'critical',
    pattern: /AccountInfo[\s\S]*?clock|rent|epoch(?![\s\S]{0,50}from_account_info)/i,
    description: 'arXiv research: Sysvars passed as AccountInfo can be spoofed with fake accounts.',
    recommendation: 'Use Sysvar::from_account_info() or Anchor #[account(address = sysvar::X)].'
  },
  {
    id: 'SOL5006',
    name: 'arXiv: Account Race Condition',
    severity: 'high',
    pattern: /init(?:_if_needed)?[\s\S]{0,100}payer\s*=(?![\s\S]{0,50}constraint)/i,
    description: 'arXiv research: Account initialization without constraints can be frontrun.',
    recommendation: 'Add constraints to init accounts. Use seeds for deterministic addresses.'
  },
  {
    id: 'SOL5007',
    name: 'arXiv: Serialization Entropy Loss',
    severity: 'medium',
    pattern: /borsh::(?:to_vec|serialize)(?![\s\S]{0,50}try_)/i,
    description: 'arXiv research: Serialization errors can cause data corruption if not handled.',
    recommendation: 'Use try_to_vec() and handle serialization errors explicitly.'
  },
  {
    id: 'SOL5008',
    name: 'arXiv: Parallel Transaction Conflict',
    severity: 'medium',
    pattern: /mut\s+\w+\s*:\s*Account[\s\S]*?mut\s+\w+\s*:\s*Account/i,
    description: 'arXiv research: Multiple mutable accounts can conflict in parallel execution.',
    recommendation: 'Minimize mutable account overlap. Use lock ordering conventions.'
  },
  
  // ============================================
  // Sec3 2025 Final Report Patterns
  // 163 audits, 1,669 vulnerabilities analyzed
  // ============================================
  {
    id: 'SOL5009',
    name: 'Sec3-2025: Business Logic Invariant Drift (38.5%)',
    severity: 'critical',
    pattern: /(?:balance|amount|shares|supply)[\s\S]{0,100}(?:add|sub|mul|div)(?![\s\S]{0,50}invariant|[\s\S]{0,50}assert)/i,
    description: 'Sec3 2025: Business logic errors are 38.5% of all findings. State invariants must be verified after mutations.',
    recommendation: 'Add invariant checks after every state mutation. Use formal verification.'
  },
  {
    id: 'SOL5010',
    name: 'Sec3-2025: Input Validation Missing (25%)',
    severity: 'high',
    pattern: /pub\s+fn\s+\w+\s*\([\s\S]*?amount\s*:\s*u64[\s\S]*?\)\s*(?:->)?[\s\S]*?\{(?![\s\S]{0,100}require!.*?amount)/i,
    description: 'Sec3 2025: Input validation gaps are 25% of findings. All numeric inputs need bounds checking.',
    recommendation: 'Validate all inputs at function entry. Check for zero, overflow, underflow.'
  },
  {
    id: 'SOL5011',
    name: 'Sec3-2025: Access Control Gap (19%)',
    severity: 'critical',
    pattern: /admin|authority|owner[\s\S]{0,50}AccountInfo(?![\s\S]{0,100}has_one|[\s\S]{0,100}constraint)/i,
    description: 'Sec3 2025: Access control issues are 19% of findings. Authority accounts need constraints.',
    recommendation: 'Use Anchor #[account(has_one = authority)] or manual verification.'
  },
  {
    id: 'SOL5012',
    name: 'Sec3-2025: Data Integrity Race (8.9%)',
    severity: 'high',
    pattern: /invoke(?:_signed)?[\s\S]{0,200}(?:balance|amount|state)\s*[=+-]/i,
    description: 'Sec3 2025: Data integrity issues are 8.9% of findings. State must be updated before CPI.',
    recommendation: 'Update local state before CPI. Reload state after CPI if needed.'
  },
  {
    id: 'SOL5013',
    name: 'Sec3-2025: DoS Liveness Risk (8.5%)',
    severity: 'high',
    pattern: /for\s+\w+\s+in\s+0\.\.(?:\w+\.len\(\)|accounts\.len\(\))/i,
    description: 'Sec3 2025: DoS/Liveness issues are 8.5% of findings. Unbounded loops can exhaust compute.',
    recommendation: 'Bound all loops. Use pagination for large data sets.'
  },
  
  // ============================================
  // CyberDaily 2025 DeFi Security Patterns
  // $3.1B in breaches, preventable vulnerabilities
  // ============================================
  {
    id: 'SOL5014',
    name: 'CyberDaily-2025: Reentrancy via CPI',
    severity: 'critical',
    pattern: /invoke(?:_signed)?[\s\S]*?\.try_borrow_mut|\.borrow_mut/i,
    description: 'CyberDaily 2025: Reentrancy still causes billions in losses. CPI can reenter and mutate state.',
    recommendation: 'Use checks-effects-interactions pattern. Update state before CPI.'
  },
  {
    id: 'SOL5015',
    name: 'CyberDaily-2025: Oracle Manipulation',
    severity: 'critical',
    pattern: /price|oracle[\s\S]{0,100}(?:get|fetch|read)(?![\s\S]{0,100}twap|[\s\S]{0,100}staleness)/i,
    description: 'CyberDaily 2025: Oracle manipulation is a top attack vector. Single-source oracles are vulnerable.',
    recommendation: 'Use TWAP, multiple oracles, and staleness checks.'
  },
  {
    id: 'SOL5016',
    name: 'CyberDaily-2025: Access Control Failure',
    severity: 'critical',
    pattern: /set_authority|transfer_authority(?![\s\S]{0,100}timelock|[\s\S]{0,100}multisig)/i,
    description: 'CyberDaily 2025: Missing access controls allow unauthorized admin actions.',
    recommendation: 'Implement timelock + multisig for sensitive operations.'
  },
  {
    id: 'SOL5017',
    name: 'CyberDaily-2025: Account Validation Failure',
    severity: 'critical',
    pattern: /#\[account\][\s\S]*?pub\s+\w+\s*:\s*AccountInfo(?![\s\S]{0,50}CHECK)/i,
    description: 'CyberDaily 2025: Unvalidated accounts lead to fund theft. AccountInfo must be verified.',
    recommendation: 'Use Account<T> with proper type checking, not raw AccountInfo.'
  },
  
  // ============================================
  // Helius 2025-2026 Emerging Threat Patterns
  // Based on 38 verified incidents, $600M+ losses
  // ============================================
  {
    id: 'SOL5018',
    name: 'Helius-2026: Whale Liquidation Cascade',
    severity: 'critical',
    pattern: /liquidat(?:e|ion)[\s\S]{0,200}(?:position|margin)(?![\s\S]{0,100}circuit_breaker)/i,
    description: 'Helius 2026: Large liquidations ($258M Nov 2025) cascade through DeFi. Circuit breakers needed.',
    recommendation: 'Implement circuit breakers, liquidation limits, and cascade protection.'
  },
  {
    id: 'SOL5019',
    name: 'Helius-2026: Validator Concentration Risk',
    severity: 'high',
    pattern: /validator|stake_pool(?![\s\S]{0,100}decentraliz|[\s\S]{0,100}distribut)/i,
    description: 'Helius 2026: 88% Jito client dominance, 43% hosting concentration creates systemic risk.',
    recommendation: 'Monitor validator diversity. Avoid single points of failure.'
  },
  {
    id: 'SOL5020',
    name: 'Helius-2026: MEV Sandwich Attack',
    severity: 'high',
    pattern: /swap|exchange(?![\s\S]{0,100}min_amount_out|[\s\S]{0,100}deadline)/i,
    description: 'Helius 2026: MEV sandwich attacks extract value from swaps without slippage protection.',
    recommendation: 'Require min_amount_out and deadline for all swaps.'
  },
  {
    id: 'SOL5021',
    name: 'Helius-2026: Private Key Exposure Pattern',
    severity: 'critical',
    pattern: /private_key|secret_key|mnemonic|seed_phrase/i,
    description: 'Helius 2026: DEXX ($30M), Slope ($8M) - private key exposure in logs/requests.',
    recommendation: 'Never log or transmit private keys. Use HSM for hot wallets.'
  },
  {
    id: 'SOL5022',
    name: 'Helius-2026: Supply Chain NPM Attack',
    severity: 'critical',
    pattern: /postinstall|preinstall[\s\S]*?fetch|http|child_process/i,
    description: 'Helius 2026: Web3.js v1.95.5-7 backdoor exfiltrated keys via postinstall.',
    recommendation: 'Pin exact versions. Audit postinstall scripts. Use lockfiles.'
  },
  {
    id: 'SOL5023',
    name: 'Helius-2026: Insider Threat Pattern',
    severity: 'critical',
    pattern: /single.*?admin|1.*?of.*?1.*?multisig|solo.*?authority/i,
    description: 'Helius 2026: Pump.fun ($1.9M), Cypher ($317K) - insider access to funds.',
    recommendation: 'Use multi-sig (2-of-3+). Rotate credentials. Audit access logs.'
  },
  {
    id: 'SOL5024',
    name: 'Helius-2026: Bridge Guardian Bypass',
    severity: 'critical',
    pattern: /guardian|bridge[\s\S]{0,100}verify(?![\s\S]{0,100}quorum|[\s\S]{0,100}threshold)/i,
    description: 'Helius 2026: Wormhole ($326M) - guardian signature verification bypass.',
    recommendation: 'Verify full guardian quorum. Check signature set validity.'
  },
  
  // ============================================
  // Token-2022 Advanced Security Patterns
  // Emerging attack vectors on new token standard
  // ============================================
  {
    id: 'SOL5025',
    name: 'Token-2022: Transfer Hook Reentrancy',
    severity: 'critical',
    pattern: /transfer_hook|on_transfer(?![\s\S]{0,100}reentrancy_guard)/i,
    description: 'Token-2022 transfer hooks can be exploited for reentrancy attacks.',
    recommendation: 'Add reentrancy guard to transfer hook implementations.'
  },
  {
    id: 'SOL5026',
    name: 'Token-2022: Permanent Delegate Abuse',
    severity: 'critical',
    pattern: /permanent_delegate|PermanentDelegate(?![\s\S]{0,100}check|[\s\S]{0,100}verify)/i,
    description: 'Token-2022 permanent delegate can drain user tokens at any time.',
    recommendation: 'Verify permanent delegate is trusted. Warn users about delegation.'
  },
  {
    id: 'SOL5027',
    name: 'Token-2022: Confidential Transfer Privacy Leak',
    severity: 'high',
    pattern: /confidential_transfer|ConfidentialTransfer(?![\s\S]{0,100}zk_proof)/i,
    description: 'Token-2022 confidential transfers require proper ZK proof handling.',
    recommendation: 'Verify ZK proofs. Handle decryption errors securely.'
  },
  {
    id: 'SOL5028',
    name: 'Token-2022: Interest-Bearing Manipulation',
    severity: 'high',
    pattern: /interest_bearing|InterestBearing[\s\S]{0,50}rate(?![\s\S]{0,100}cap)/i,
    description: 'Token-2022 interest-bearing tokens can have rate manipulation attacks.',
    recommendation: 'Cap interest rates. Use time-weighted calculations.'
  },
  {
    id: 'SOL5029',
    name: 'Token-2022: Non-Transferable Bypass',
    severity: 'high',
    pattern: /non_transferable|NonTransferable(?![\s\S]{0,100}enforce)/i,
    description: 'Token-2022 non-transferable flag can be bypassed through CPI.',
    recommendation: 'Enforce non-transferable at program level, not just token level.'
  },
  {
    id: 'SOL5030',
    name: 'Token-2022: Transfer Fee Extraction',
    severity: 'medium',
    pattern: /transfer_fee|TransferFee[\s\S]{0,50}(?:max|rate)(?![\s\S]{0,50}limit)/i,
    description: 'Token-2022 transfer fees can be set to extract excessive value.',
    recommendation: 'Check transfer fee rates before interacting with unknown tokens.'
  },
  
  // ============================================
  // Compressed NFT (cNFT) Security Patterns
  // Bubblegum and merkle tree vulnerabilities
  // ============================================
  {
    id: 'SOL5031',
    name: 'cNFT: Merkle Proof Validation Missing',
    severity: 'critical',
    pattern: /merkle|bubblegum[\s\S]{0,100}transfer(?![\s\S]{0,100}verify_proof)/i,
    description: 'cNFT operations without merkle proof verification allow unauthorized transfers.',
    recommendation: 'Always verify merkle proofs for cNFT operations.'
  },
  {
    id: 'SOL5032',
    name: 'cNFT: Canopy Depth Insufficient',
    severity: 'medium',
    pattern: /create_tree[\s\S]{0,50}canopy_depth\s*:\s*(?:0|1|2)\b/i,
    description: 'cNFT trees with low canopy depth require expensive on-chain proofs.',
    recommendation: 'Use adequate canopy depth (8-14) for cost-effective operations.'
  },
  {
    id: 'SOL5033',
    name: 'cNFT: Leaf Index Manipulation',
    severity: 'high',
    pattern: /leaf_index|nonce(?![\s\S]{0,100}verify|[\s\S]{0,100}check)/i,
    description: 'cNFT leaf index/nonce must be verified to prevent replay attacks.',
    recommendation: 'Verify leaf index matches expected value from merkle tree.'
  },
  {
    id: 'SOL5034',
    name: 'cNFT: Tree Authority Bypass',
    severity: 'critical',
    pattern: /tree_authority|merkle_tree[\s\S]{0,50}authority(?![\s\S]{0,100}signer)/i,
    description: 'cNFT tree authority must sign operations to prevent unauthorized minting.',
    recommendation: 'Require tree authority signature for all tree modifications.'
  },
  
  // ============================================
  // MEV and Jito-Specific Patterns
  // Bundle and priority fee vulnerabilities
  // ============================================
  {
    id: 'SOL5035',
    name: 'MEV: Jito Bundle Sandwich',
    severity: 'high',
    pattern: /bundle|jito[\s\S]{0,100}(?:swap|trade)(?![\s\S]{0,100}private)/i,
    description: 'Jito bundles can be used to sandwich non-private transactions.',
    recommendation: 'Use private transactions or slippage protection.'
  },
  {
    id: 'SOL5036',
    name: 'MEV: Priority Fee Griefing',
    severity: 'medium',
    pattern: /priority_fee|compute_budget(?![\s\S]{0,100}limit)/i,
    description: 'High priority fees can be used to grief or front-run transactions.',
    recommendation: 'Set reasonable priority fee limits. Monitor for griefing patterns.'
  },
  {
    id: 'SOL5037',
    name: 'MEV: JIT Liquidity Attack',
    severity: 'high',
    pattern: /liquidity[\s\S]{0,100}(?:add|remove)[\s\S]{0,100}swap/i,
    description: 'JIT liquidity can be added/removed around swaps to extract MEV.',
    recommendation: 'Use time-weighted LP token valuations.'
  },
  {
    id: 'SOL5038',
    name: 'MEV: Backrunning Oracle Updates',
    severity: 'high',
    pattern: /oracle[\s\S]{0,100}update[\s\S]{0,100}(?:liquidat|trade)/i,
    description: 'Oracle updates can be backrun for profitable liquidations or trades.',
    recommendation: 'Add randomness or delay to oracle-dependent operations.'
  },
  
  // ============================================
  // Governance and DAO Security Patterns
  // Based on Audius, Synthetify, Saga DAO exploits
  // ============================================
  {
    id: 'SOL5039',
    name: 'DAO: Governance Proposal Injection',
    severity: 'critical',
    pattern: /proposal[\s\S]{0,100}execute(?![\s\S]{0,100}timelock|[\s\S]{0,100}delay)/i,
    description: 'Audius $6.1M - malicious proposals can execute immediately without timelock.',
    recommendation: 'Implement mandatory timelock (24-48h) for all proposals.'
  },
  {
    id: 'SOL5040',
    name: 'DAO: Low Quorum Attack',
    severity: 'high',
    pattern: /quorum[\s\S]{0,50}(?:\d+\s*%?|threshold)(?![\s\S]{0,50}minimum)/i,
    description: 'Saga DAO $1.5M - low quorum thresholds allow minority takeover.',
    recommendation: 'Set quorum to at least 10-15% of voting power.'
  },
  {
    id: 'SOL5041',
    name: 'DAO: Flash Loan Voting',
    severity: 'critical',
    pattern: /vote[\s\S]{0,100}power(?![\s\S]{0,100}snapshot|[\s\S]{0,100}checkpoint)/i,
    description: 'Flash loans can temporarily acquire voting power to pass proposals.',
    recommendation: 'Snapshot voting power before proposal. Use checkpoint system.'
  },
  {
    id: 'SOL5042',
    name: 'DAO: Vote Buying Detection',
    severity: 'medium',
    pattern: /delegate[\s\S]{0,100}vote(?![\s\S]{0,100}lock|[\s\S]{0,100}vesting)/i,
    description: 'Delegation without lock allows vote buying and selling.',
    recommendation: 'Lock delegated tokens during voting period.'
  },
  
  // ============================================
  // Lending Protocol Security Patterns
  // Based on Solend, Port Finance, Jet Protocol exploits
  // ============================================
  {
    id: 'SOL5043',
    name: 'Lending: First Depositor Attack',
    severity: 'critical',
    pattern: /deposit[\s\S]{0,100}shares?\s*=\s*0|total_supply\s*==?\s*0/i,
    description: 'First depositor can manipulate share price with small deposit + donation.',
    recommendation: 'Mint dead shares on first deposit. Use virtual reserves.'
  },
  {
    id: 'SOL5044',
    name: 'Lending: Interest Rate Kink Manipulation',
    severity: 'high',
    pattern: /utilization[\s\S]{0,100}(?:kink|slope)(?![\s\S]{0,100}cap)/i,
    description: 'Interest rate models can be manipulated at utilization kinks.',
    recommendation: 'Smooth interest rate curves. Add rate caps.'
  },
  {
    id: 'SOL5045',
    name: 'Lending: Bad Debt Socialization',
    severity: 'high',
    pattern: /bad_debt|underwater[\s\S]{0,100}(?:socialize|distribute)/i,
    description: 'Bad debt from failed liquidations is socialized to all depositors.',
    recommendation: 'Maintain insurance fund. Set conservative collateral factors.'
  },
  {
    id: 'SOL5046',
    name: 'Lending: Reserve Configuration Bypass',
    severity: 'critical',
    pattern: /reserve[\s\S]{0,50}config(?![\s\S]{0,100}timelock|[\s\S]{0,100}governance)/i,
    description: 'Solend Aug 2021 - reserve configuration can be changed without timelock.',
    recommendation: 'Timelock all reserve configuration changes.'
  },
  {
    id: 'SOL5047',
    name: 'Lending: Liquidation Bonus Inflation',
    severity: 'high',
    pattern: /liquidation[\s\S]{0,50}(?:bonus|incentive)(?![\s\S]{0,50}cap)/i,
    description: 'Excessive liquidation bonuses can drain protocol reserves.',
    recommendation: 'Cap liquidation bonus at 10-15%. Monitor liquidation frequency.'
  },
  
  // ============================================
  // AMM and DEX Security Patterns
  // Based on Crema, Raydium, Orca exploits
  // ============================================
  {
    id: 'SOL5048',
    name: 'AMM: K-Value Invariant Violation',
    severity: 'critical',
    pattern: /(?:reserve|pool)[\s\S]{0,50}(?:mul|div)(?![\s\S]{0,100}k_value|[\s\S]{0,100}invariant)/i,
    description: 'AMM invariant (x*y=k) must be verified after every swap.',
    recommendation: 'Check invariant after swap. Revert if violated.'
  },
  {
    id: 'SOL5049',
    name: 'AMM: CLMM Tick Account Spoofing',
    severity: 'critical',
    pattern: /tick[\s\S]{0,50}account(?![\s\S]{0,100}owner\s*==|[\s\S]{0,100}verify)/i,
    description: 'Crema $8.8M - tick accounts can be spoofed without ownership check.',
    recommendation: 'Verify tick account ownership matches pool authority.'
  },
  {
    id: 'SOL5050',
    name: 'AMM: LP Share Inflation Attack',
    severity: 'critical',
    pattern: /lp[\s\S]{0,50}mint[\s\S]{0,100}(?:total_supply\s*==?\s*0|first)/i,
    description: 'LP token minting can be manipulated on first deposit.',
    recommendation: 'Initialize pools with virtual reserves. Mint dead shares.'
  },
  {
    id: 'SOL5051',
    name: 'AMM: Fee Accumulator Manipulation',
    severity: 'high',
    pattern: /fee[\s\S]{0,50}(?:accumulator|accrued)(?![\s\S]{0,100}checkpoint)/i,
    description: 'Crema-style fee accumulator can be manipulated with flash positions.',
    recommendation: 'Checkpoint fees per block. Use time-weighted calculations.'
  },
  
  // ============================================
  // Bridge Security Patterns
  // Based on Wormhole $326M exploit
  // ============================================
  {
    id: 'SOL5052',
    name: 'Bridge: Guardian Set Validation',
    severity: 'critical',
    pattern: /guardian[\s\S]{0,100}(?:set|signature)(?![\s\S]{0,100}quorum)/i,
    description: 'Wormhole $326M - guardian signatures not validated against current set.',
    recommendation: 'Verify guardian signatures against current guardian set with quorum.'
  },
  {
    id: 'SOL5053',
    name: 'Bridge: VAA Message Replay',
    severity: 'critical',
    pattern: /vaa|message[\s\S]{0,100}(?:process|execute)(?![\s\S]{0,100}nonce|[\s\S]{0,100}sequence)/i,
    description: 'Bridge messages can be replayed if nonce/sequence not checked.',
    recommendation: 'Track processed message nonces. Reject duplicates.'
  },
  {
    id: 'SOL5054',
    name: 'Bridge: Cross-Chain Decimal Mismatch',
    severity: 'high',
    pattern: /decimals[\s\S]{0,50}(?:source|target)(?![\s\S]{0,100}normalize)/i,
    description: 'Token decimals differ across chains, causing value discrepancies.',
    recommendation: 'Normalize decimals when bridging. Use canonical representations.'
  },
  {
    id: 'SOL5055',
    name: 'Bridge: Finality Assumption Error',
    severity: 'critical',
    pattern: /confirm(?:ation)?s?[\s\S]{0,50}(?:\d+|block)(?![\s\S]{0,50}finality)/i,
    description: 'Insufficient confirmation wait can allow double-spend via reorg.',
    recommendation: 'Wait for source chain finality before releasing funds.'
  },
  
  // ============================================
  // Staking and Validator Security Patterns
  // ============================================
  {
    id: 'SOL5056',
    name: 'Staking: Commission Rate Manipulation',
    severity: 'high',
    pattern: /commission[\s\S]{0,50}(?:rate|percent)(?![\s\S]{0,100}cap|[\s\S]{0,100}max)/i,
    description: 'Validators can change commission rates to drain staker rewards.',
    recommendation: 'Cap commission rate changes. Require notice period.'
  },
  {
    id: 'SOL5057',
    name: 'Staking: Instant Unstake Bypass',
    severity: 'high',
    pattern: /unstake|withdraw[\s\S]{0,100}(?:instant|immediate)(?![\s\S]{0,100}penalty)/i,
    description: 'Instant unstaking can be exploited to avoid slashing or earn rewards.',
    recommendation: 'Enforce cooldown period. Apply penalty for instant unstake.'
  },
  {
    id: 'SOL5058',
    name: 'Staking: Reward Rate Manipulation',
    severity: 'high',
    pattern: /reward[\s\S]{0,50}(?:rate|per_share)(?![\s\S]{0,100}time_weighted)/i,
    description: 'Reward rates can be manipulated with flash staking.',
    recommendation: 'Use time-weighted reward calculations.'
  },
  {
    id: 'SOL5059',
    name: 'Staking: Slashing Condition Bypass',
    severity: 'high',
    pattern: /slash[\s\S]{0,100}(?:condition|trigger)(?![\s\S]{0,100}verify)/i,
    description: 'Slashing conditions can be bypassed with careful timing.',
    recommendation: 'Implement robust slashing detection with multiple validators.'
  },
  
  // ============================================
  // NFT and Gaming Security Patterns
  // ============================================
  {
    id: 'SOL5060',
    name: 'NFT: Royalty Bypass via Transfer',
    severity: 'medium',
    pattern: /transfer[\s\S]{0,100}nft(?![\s\S]{0,100}royalt)/i,
    description: 'NFT transfers can bypass royalty payments on non-enforced standards.',
    recommendation: 'Use pNFT for enforced royalties. Implement transfer hooks.'
  },
  {
    id: 'SOL5061',
    name: 'NFT: Metadata URI Manipulation',
    severity: 'high',
    pattern: /metadata[\s\S]{0,50}uri(?![\s\S]{0,100}immutable|[\s\S]{0,100}frozen)/i,
    description: 'Mutable metadata URI can be changed to rugs.',
    recommendation: 'Use immutable metadata. Verify on-chain content hash.'
  },
  {
    id: 'SOL5062',
    name: 'Gaming: Randomness Prediction',
    severity: 'critical',
    pattern: /random[\s\S]{0,100}(?:slot|clock|hash)(?![\s\S]{0,100}vrf|[\s\S]{0,100}commit)/i,
    description: 'On-chain randomness from slot/clock is predictable by validators.',
    recommendation: 'Use VRF (Switchboard, Orao) for verifiable randomness.'
  },
  {
    id: 'SOL5063',
    name: 'Gaming: Asset Duplication',
    severity: 'critical',
    pattern: /(?:mint|create)[\s\S]{0,100}(?:game_asset|item)(?![\s\S]{0,100}unique|[\s\S]{0,100}supply)/i,
    description: 'Game assets can be duplicated without proper supply tracking.',
    recommendation: 'Track total supply. Verify uniqueness constraints.'
  },
  
  // ============================================
  // Perpetuals and Derivatives Patterns
  // ============================================
  {
    id: 'SOL5064',
    name: 'Perps: Funding Rate Manipulation',
    severity: 'high',
    pattern: /funding[\s\S]{0,50}rate(?![\s\S]{0,100}cap|[\s\S]{0,100}twap)/i,
    description: 'Mango-style funding rate manipulation can extract value.',
    recommendation: 'Cap funding rates. Use TWAP for rate calculation.'
  },
  {
    id: 'SOL5065',
    name: 'Perps: Mark Price Oracle Divergence',
    severity: 'high',
    pattern: /mark[\s\S]{0,50}price[\s\S]{0,50}(?:oracle|index)(?![\s\S]{0,100}band)/i,
    description: 'Mark price divergence from index allows liquidation manipulation.',
    recommendation: 'Limit mark-index divergence. Use multiple price sources.'
  },
  {
    id: 'SOL5066',
    name: 'Perps: ADL Cascade Attack',
    severity: 'critical',
    pattern: /adl|auto_deleverage(?![\s\S]{0,100}insurance|[\s\S]{0,100}circuit)/i,
    description: 'ADL cascades can wipe out winning positions in volatile markets.',
    recommendation: 'Maintain insurance fund. Implement circuit breakers.'
  },
  {
    id: 'SOL5067',
    name: 'Perps: Position Size Manipulation',
    severity: 'high',
    pattern: /position[\s\S]{0,50}size(?![\s\S]{0,100}limit|[\s\S]{0,100}max)/i,
    description: 'Unbounded position sizes can create systemic risk.',
    recommendation: 'Limit position sizes per account and globally.'
  },
  
  // ============================================
  // Options Protocol Patterns
  // ============================================
  {
    id: 'SOL5068',
    name: 'Options: Strike Price Oracle',
    severity: 'high',
    pattern: /strike[\s\S]{0,50}price(?![\s\S]{0,100}settlement|[\s\S]{0,100}oracle)/i,
    description: 'Options settlement requires reliable strike price at expiry.',
    recommendation: 'Use settlement oracle with finality checks.'
  },
  {
    id: 'SOL5069',
    name: 'Options: Exercise Window Attack',
    severity: 'high',
    pattern: /exercise[\s\S]{0,50}(?:window|period)(?![\s\S]{0,100}verify)/i,
    description: 'Exercise windows can be manipulated to prevent valid exercise.',
    recommendation: 'Use wide exercise windows. Allow emergency exercise.'
  },
  {
    id: 'SOL5070',
    name: 'Options: Premium Calculation Error',
    severity: 'high',
    pattern: /premium[\s\S]{0,100}(?:calculate|compute)(?![\s\S]{0,100}black_scholes)/i,
    description: 'Incorrect premium calculation leads to mispriced options.',
    recommendation: 'Use verified pricing models. Validate greeks.'
  },
  
  // ============================================
  // Yield Aggregator Patterns
  // Based on Tulip, Francium exploits
  // ============================================
  {
    id: 'SOL5071',
    name: 'Yield: Strategy Audit Missing',
    severity: 'high',
    pattern: /strategy[\s\S]{0,100}(?:deploy|add)(?![\s\S]{0,100}audit|[\s\S]{0,100}review)/i,
    description: 'Tulip $5.2M - unaudited strategies can drain vaults.',
    recommendation: 'Audit all strategies. Use timelock for strategy changes.'
  },
  {
    id: 'SOL5072',
    name: 'Yield: Harvest Sandwich',
    severity: 'high',
    pattern: /harvest[\s\S]{0,100}(?:reward|compound)(?![\s\S]{0,100}private)/i,
    description: 'Harvest transactions can be sandwiched for MEV extraction.',
    recommendation: 'Use private mempool for harvests. Randomize timing.'
  },
  {
    id: 'SOL5073',
    name: 'Yield: Share Price Manipulation',
    severity: 'critical',
    pattern: /share[\s\S]{0,50}price[\s\S]{0,50}(?:calculate|compute)(?![\s\S]{0,100}twap)/i,
    description: 'Share prices can be manipulated with flash loans.',
    recommendation: 'Use TWAP for share price. Limit deposit/withdraw per block.'
  },
  {
    id: 'SOL5074',
    name: 'Yield: Emergency Exit Blocked',
    severity: 'high',
    pattern: /emergency[\s\S]{0,50}(?:exit|withdraw)(?![\s\S]{0,100}always_available)/i,
    description: 'Emergency exits can be blocked by malicious strategy.',
    recommendation: 'Ensure emergency exit always works. Bypass strategy if needed.'
  },
  
  // ============================================
  // Infrastructure and Off-Chain Patterns
  // ============================================
  {
    id: 'SOL5075',
    name: 'Infra: RPC Provider Dependency',
    severity: 'medium',
    pattern: /rpc[\s\S]{0,50}(?:url|endpoint)(?![\s\S]{0,100}fallback)/i,
    description: 'Single RPC provider creates availability risk.',
    recommendation: 'Use multiple RPC providers with fallback.'
  },
  {
    id: 'SOL5076',
    name: 'Infra: Frontend Wallet Drainer',
    severity: 'critical',
    pattern: /window\.solana|phantom|solflare(?![\s\S]{0,100}simulate)/i,
    description: 'Parcl-style frontend compromise can drain wallets.',
    recommendation: 'Verify transaction content in wallet. Use simulation.'
  },
  {
    id: 'SOL5077',
    name: 'Infra: API Key Exposure',
    severity: 'critical',
    pattern: /api_key|apikey|api-key[\s\S]{0,20}=[\s\S]{0,10}["'][a-zA-Z0-9]{16,}/i,
    description: 'API keys exposed in code or logs can be exploited.',
    recommendation: 'Use environment variables. Rotate keys regularly.'
  },
  {
    id: 'SOL5078',
    name: 'Infra: Blockhash Caching Attack',
    severity: 'medium',
    pattern: /blockhash[\s\S]{0,50}(?:cache|store)(?![\s\S]{0,100}expir)/i,
    description: 'Stale blockhash allows transaction replay.',
    recommendation: 'Expire blockhashes after ~60 seconds.'
  },
  
  // ============================================
  // 2026 Emerging Threat Patterns
  // AI Agents, Restaking, Intent Systems
  // ============================================
  {
    id: 'SOL5079',
    name: '2026: AI Agent Wallet Compromise',
    severity: 'critical',
    pattern: /ai[\s\S]{0,30}agent[\s\S]{0,50}(?:wallet|key|sign)/i,
    description: '2026: AI trading agents with wallet access are high-value targets.',
    recommendation: 'Use session keys with spending limits. Multi-sig for large amounts.'
  },
  {
    id: 'SOL5080',
    name: '2026: LLM Prompt Injection via Tx',
    severity: 'high',
    pattern: /memo[\s\S]{0,50}(?:parse|process)[\s\S]{0,100}ai|llm/i,
    description: '2026: Transaction memos can inject prompts into LLM-based systems.',
    recommendation: 'Sanitize all on-chain data before LLM processing.'
  },
  {
    id: 'SOL5081',
    name: '2026: Restaking Slash Cascade',
    severity: 'critical',
    pattern: /restake|restaking[\s\S]{0,100}(?:slash|penalty)/i,
    description: '2026: Restaking layers amplify slashing risks across protocols.',
    recommendation: 'Limit restaking exposure. Diversify across operators.'
  },
  {
    id: 'SOL5082',
    name: '2026: Intent System Solver Manipulation',
    severity: 'high',
    pattern: /intent[\s\S]{0,50}(?:solver|filler|executor)/i,
    description: '2026: Intent-based systems vulnerable to solver collusion.',
    recommendation: 'Use multiple competing solvers. Verify execution quality.'
  },
  {
    id: 'SOL5083',
    name: '2026: LRT Depeg Attack',
    severity: 'critical',
    pattern: /lrt|liquid[\s\S]{0,30}restaking[\s\S]{0,50}(?:redeem|withdraw)/i,
    description: '2026: Liquid restaking tokens can depeg under redemption pressure.',
    recommendation: 'Monitor LRT backing. Limit redemption velocity.'
  },
  {
    id: 'SOL5084',
    name: '2026: ZK State Proof Bypass',
    severity: 'critical',
    pattern: /zk[\s\S]{0,30}(?:proof|verify)(?![\s\S]{0,100}trusted_setup)/i,
    description: '2026: ZK proof systems require careful parameter management.',
    recommendation: 'Use audited ZK circuits. Verify trusted setup.'
  },
  {
    id: 'SOL5085',
    name: '2026: FHE Key Extraction',
    severity: 'critical',
    pattern: /fhe|fully_homomorphic[\s\S]{0,50}(?:key|decrypt)/i,
    description: '2026: FHE key management is critical for encrypted computation.',
    recommendation: 'Use threshold FHE. Rotate keys periodically.'
  },
  
  // ============================================
  // Testing and Audit Patterns
  // ============================================
  {
    id: 'SOL5086',
    name: 'Audit: Fuzz Testing Missing',
    severity: 'medium',
    pattern: /\/\/\s*TODO.*?fuzz|fuzz[\s\S]{0,50}test(?![\s\S]{0,100}implemented)/i,
    description: 'Fuzz testing is essential for finding edge cases.',
    recommendation: 'Use Trident or custom fuzzers. Cover all instructions.'
  },
  {
    id: 'SOL5087',
    name: 'Audit: Invariant Testing Missing',
    severity: 'medium',
    pattern: /#\[test\](?![\s\S]{0,500}assert.*?invariant)/i,
    description: 'Tests should verify protocol invariants hold.',
    recommendation: 'Add invariant tests for all state transitions.'
  },
  {
    id: 'SOL5088',
    name: 'Audit: Error Path Coverage',
    severity: 'low',
    pattern: /Err\s*\(|Error::|return\s+err(?![\s\S]{0,200}#\[test\])/i,
    description: 'Error paths should be tested for proper handling.',
    recommendation: 'Test all error conditions. Verify error messages.'
  },
  
  // ============================================
  // Economic Security Patterns
  // ============================================
  {
    id: 'SOL5089',
    name: 'Economics: TVL Concentration Risk',
    severity: 'high',
    pattern: /tvl[\s\S]{0,50}(?:limit|cap)(?![\s\S]{0,100}per_user)/i,
    description: 'High TVL concentration creates whale manipulation risk.',
    recommendation: 'Limit per-user deposits. Monitor concentration.'
  },
  {
    id: 'SOL5090',
    name: 'Economics: Protocol Revenue Drain',
    severity: 'high',
    pattern: /protocol[\s\S]{0,30}(?:fee|revenue)[\s\S]{0,50}withdraw(?![\s\S]{0,100}multisig)/i,
    description: 'Protocol revenue withdrawal should require multisig.',
    recommendation: 'Use timelock + multisig for revenue withdrawal.'
  },
  {
    id: 'SOL5091',
    name: 'Economics: Insurance Fund Underfunded',
    severity: 'high',
    pattern: /insurance[\s\S]{0,30}fund(?![\s\S]{0,100}target|[\s\S]{0,100}ratio)/i,
    description: 'Insurance funds should target a percentage of TVL.',
    recommendation: 'Target 5-10% of TVL for insurance fund.'
  },
  
  // ============================================
  // Core Solana Runtime Patterns
  // ============================================
  {
    id: 'SOL5092',
    name: 'Runtime: Account Size Limit',
    severity: 'medium',
    pattern: /realloc[\s\S]{0,50}(?:size|len)(?![\s\S]{0,100}MAX_PERMITTED)/i,
    description: 'Accounts have 10MB size limit. Unbounded growth causes failure.',
    recommendation: 'Track account size. Use pagination for large data.'
  },
  {
    id: 'SOL5093',
    name: 'Runtime: CPI Depth Exhaustion',
    severity: 'medium',
    pattern: /invoke(?:_signed)?[\s\S]{0,200}invoke(?:_signed)?[\s\S]{0,200}invoke(?:_signed)?/i,
    description: 'CPI depth limited to 4 levels. Deep nesting fails.',
    recommendation: 'Minimize CPI depth. Flatten call chains.'
  },
  {
    id: 'SOL5094',
    name: 'Runtime: Return Data Truncation',
    severity: 'low',
    pattern: /return[\s\S]{0,30}data[\s\S]{0,50}(?:set|write)(?![\s\S]{0,100}1024)/i,
    description: 'CPI return data limited to 1024 bytes. Excess is truncated.',
    recommendation: 'Keep return data under 1024 bytes. Use events for large data.'
  },
  {
    id: 'SOL5095',
    name: 'Runtime: Transaction Size Limit',
    severity: 'medium',
    pattern: /transaction[\s\S]{0,30}(?:build|create)(?![\s\S]{0,100}lookup_table)/i,
    description: 'Transactions limited to 1232 bytes. Use lookup tables.',
    recommendation: 'Use Address Lookup Tables for many accounts.'
  },
  
  // ============================================
  // Anchor Framework Specific Patterns
  // ============================================
  {
    id: 'SOL5096',
    name: 'Anchor: init_if_needed Race',
    severity: 'critical',
    pattern: /init_if_needed(?![\s\S]{0,100}constraint)/i,
    description: 'init_if_needed can be frontrun to initialize with attacker data.',
    recommendation: 'Avoid init_if_needed. Use separate init instruction.'
  },
  {
    id: 'SOL5097',
    name: 'Anchor: Remaining Accounts Unchecked',
    severity: 'high',
    pattern: /remaining_accounts(?![\s\S]{0,100}verify|[\s\S]{0,100}check)/i,
    description: 'remaining_accounts can inject arbitrary accounts.',
    recommendation: 'Validate all remaining_accounts before use.'
  },
  {
    id: 'SOL5098',
    name: 'Anchor: Seeds Without Bump',
    severity: 'high',
    pattern: /seeds\s*=\s*\[[\s\S]*?\](?![\s\S]{0,30}bump)/i,
    description: 'PDA seeds without bump allows non-canonical address.',
    recommendation: 'Always include bump in seeds constraint.'
  },
  {
    id: 'SOL5099',
    name: 'Anchor: UncheckedAccount Misuse',
    severity: 'critical',
    pattern: /UncheckedAccount(?![\s\S]{0,100}\/\/\/\s*CHECK)/i,
    description: 'UncheckedAccount requires explicit CHECK comment justification.',
    recommendation: 'Add /// CHECK: comment explaining safety.'
  },
  {
    id: 'SOL5100',
    name: 'Anchor: Discriminator Collision',
    severity: 'critical',
    pattern: /#\[account\][\s\S]*?pub\s+struct\s+\w{1,7}\b/i,
    description: 'Short struct names can cause 8-byte discriminator collisions.',
    recommendation: 'Use descriptive struct names (8+ chars recommended).'
  }
];

/**
 * Run Batch 90 security patterns against parsed Rust code
 */
export function checkBatch90Patterns(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';
  const fileName = input.path || input.rust?.filePath || 'unknown';

  if (!content) {
    return findings;
  }

  const lines = content.split('\n');

  for (const pattern of BATCH_90_PATTERNS) {
    try {
      const flags = pattern.pattern.flags.includes('g') 
        ? pattern.pattern.flags 
        : pattern.pattern.flags + 'g';
      const regex = new RegExp(pattern.pattern.source, flags);
      const matches = [...content.matchAll(regex)];

      for (const match of matches) {
        const matchIndex = match.index || 0;

        // Find line number
        let lineNum = 1;
        let charCount = 0;
        for (let i = 0; i < lines.length; i++) {
          charCount += lines[i].length + 1;
          if (charCount > matchIndex) {
            lineNum = i + 1;
            break;
          }
        }

        // Get code snippet
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

export const BATCH_90_PATTERN_COUNT = BATCH_90_PATTERNS.length;
