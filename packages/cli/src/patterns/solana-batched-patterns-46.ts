/**
 * SolGuard Batched Patterns 46 - Phishing, Social Engineering & Advanced Attack Vectors
 * 
 * Based on SlowMist Research (Dec 2025), Solana Phishing Attacks Analysis
 * and CyberPress security reports
 * 
 * Patterns SOL1511-SOL1580 (70 patterns)
 */

import type { Finding, PatternInput } from './index.js';

const BATCH_46_PATTERNS: {
  id: string;
  name: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  pattern: RegExp;
  description: string;
  recommendation: string;
}[] = [
  // Account Transfer Phishing (SlowMist Dec 2025 - $3M+ incident)
  {
    id: 'SOL1511',
    name: 'SetAuthority Without Explicit User Consent',
    severity: 'critical',
    pattern: /set_authority|SetAuthority[\s\S]{0,100}(?!require.*confirm|user_consent|explicit_auth)/i,
    description: 'SetAuthority can silently transfer account control. SlowMist Dec 2025 - $3M stolen via deceptive transactions.',
    recommendation: 'Require explicit user confirmation with clear UI explaining authority transfer.'
  },
  {
    id: 'SOL1512',
    name: 'Hidden Authority Change in Transaction',
    severity: 'critical',
    pattern: /instructions.*set_authority|bundle.*authority_change/i,
    description: 'Authority change hidden among other instructions in transaction bundle.',
    recommendation: 'Scan all instructions for authority changes, highlight prominently in UI.'
  },
  {
    id: 'SOL1513',
    name: 'Token Account Delegation Attack',
    severity: 'critical',
    pattern: /delegate[\s\S]{0,100}token.*account|approve.*delegate[\s\S]{0,50}(?!limit|max)/i,
    description: 'Delegating token account without amount limits allows full drainage.',
    recommendation: 'Always set explicit delegation limits, never approve unlimited delegation.'
  },
  {
    id: 'SOL1514',
    name: 'Account Ownership Transfer Phishing',
    severity: 'critical',
    pattern: /transfer_ownership|change_owner[\s\S]{0,100}(?!timelock|delay|require)/i,
    description: 'Phishing transactions that transfer account ownership to attacker.',
    recommendation: 'Add mandatory timelock for ownership transfers with cancellation window.'
  },
  {
    id: 'SOL1515',
    name: 'Silent Account Authority Modification',
    severity: 'critical',
    pattern: /authority.*=.*new_auth|new_authority\s*:\s*Pubkey/i,
    description: 'Authority modified without logging or event emission.',
    recommendation: 'Emit events for all authority changes, require multi-step confirmation.'
  },

  // Deceptive Transaction Patterns
  {
    id: 'SOL1516',
    name: 'Memo Instruction Phishing',
    severity: 'high',
    pattern: /memo[\s\S]{0,50}(?:claim|reward|airdrop|free|bonus)/i,
    description: 'Deceptive memo messages trick users into signing malicious transactions.',
    recommendation: 'Clearly separate memo content from transaction effects in wallet UI.'
  },
  {
    id: 'SOL1517',
    name: 'Simulated Airdrop Phishing',
    severity: 'high',
    pattern: /airdrop[\s\S]{0,100}claim[\s\S]{0,50}(?!verified|official)/i,
    description: 'Fake airdrop claim transactions that actually drain wallets.',
    recommendation: 'Verify airdrop sources against official announcements, never auto-claim.'
  },
  {
    id: 'SOL1518',
    name: 'NFT Claim Phishing Vector',
    severity: 'high',
    pattern: /claim.*nft|nft.*mint[\s\S]{0,100}(?!verified_collection|official)/i,
    description: 'Fake NFT claim sites trick users into signing wallet-draining transactions.',
    recommendation: 'Only claim NFTs from verified collection pages, check transaction details.'
  },
  {
    id: 'SOL1519',
    name: 'Fake DEX Swap Transaction',
    severity: 'high',
    pattern: /swap[\s\S]{0,100}(?:maximum.*slippage\s*=\s*100|min.*out\s*=\s*0)/i,
    description: 'Swap transaction with 100% slippage allows complete fund extraction.',
    recommendation: 'Enforce maximum slippage limits (1-5%), validate minimum output amounts.'
  },
  {
    id: 'SOL1520',
    name: 'Transaction Simulation Mismatch',
    severity: 'critical',
    pattern: /simulate[\s\S]{0,100}(?!verify.*actual|match.*execution)/i,
    description: 'Transaction simulates differently than it executes, deceiving users.',
    recommendation: 'Compare simulation results with post-execution state, warn on discrepancies.'
  },

  // Wallet Security Patterns
  {
    id: 'SOL1521',
    name: 'Blind Signing Enabled',
    severity: 'high',
    pattern: /sign.*transaction[\s\S]{0,100}(?!preview|simulation|display)/i,
    description: 'Signing transactions without preview enables phishing attacks.',
    recommendation: 'Always display transaction simulation before signing, never blind sign.'
  },
  {
    id: 'SOL1522',
    name: 'Unknown Program Invocation',
    severity: 'high',
    pattern: /invoke[\s\S]{0,50}(?!verified|known|whitelist)/i,
    description: 'Invoking unknown/unverified programs without warning.',
    recommendation: 'Warn users prominently when interacting with unverified programs.'
  },
  {
    id: 'SOL1523',
    name: 'Excessive Account Access Request',
    severity: 'medium',
    pattern: /request.*accounts[\s\S]{0,50}(?:all|unlimited|\*)/i,
    description: 'dApp requesting access to all accounts instead of specific ones.',
    recommendation: 'Implement principle of least privilege - request only needed accounts.'
  },
  {
    id: 'SOL1524',
    name: 'Seed Phrase Input on Web',
    severity: 'critical',
    pattern: /seed.*phrase|mnemonic|recovery.*words[\s\S]{0,50}input/i,
    description: 'Websites should never request seed phrase input - always phishing.',
    recommendation: 'NEVER enter seed phrases on any website, only in official wallet apps.'
  },
  {
    id: 'SOL1525',
    name: 'Private Key Export Request',
    severity: 'critical',
    pattern: /export.*private.*key|show.*secret|reveal.*keypair/i,
    description: 'Requesting private key export is usually phishing or malware.',
    recommendation: 'Keys should never leave hardware/secure enclave, use signing instead.'
  },

  // MEV and Front-Running Patterns
  {
    id: 'SOL1526',
    name: 'Unprotected Swap Transaction',
    severity: 'high',
    pattern: /swap[\s\S]{0,100}(?!jito|bundle|private|protected)/i,
    description: 'Swap without MEV protection is vulnerable to sandwich attacks.',
    recommendation: 'Use Jito bundles or private transaction pools for swaps.'
  },
  {
    id: 'SOL1527',
    name: 'Predictable Transaction Ordering',
    severity: 'high',
    pattern: /priority.*fee\s*=\s*0|no.*priority[\s\S]{0,50}swap/i,
    description: 'Zero priority fee makes transaction ordering predictable for MEV extraction.',
    recommendation: 'Use dynamic priority fees based on network conditions.'
  },
  {
    id: 'SOL1528',
    name: 'Liquidation Front-Running',
    severity: 'high',
    pattern: /liquidate[\s\S]{0,100}(?!atomic|bundle|protected)/i,
    description: 'Liquidation transactions can be front-run by MEV searchers.',
    recommendation: 'Use atomic liquidation bundles or liquidation pools.'
  },
  {
    id: 'SOL1529',
    name: 'Oracle Update Front-Running',
    severity: 'high',
    pattern: /update.*oracle|oracle.*update[\s\S]{0,100}(?!commit.*reveal|protected)/i,
    description: 'Oracle updates can be front-run to exploit price differences.',
    recommendation: 'Use commit-reveal schemes or protected update mechanisms.'
  },
  {
    id: 'SOL1530',
    name: 'JIT Liquidity Sandwich',
    severity: 'medium',
    pattern: /jit.*liquidity|just.*in.*time[\s\S]{0,100}(?!protect|detect)/i,
    description: 'JIT liquidity can extract value from large swaps.',
    recommendation: 'Use private pools or split large swaps across multiple transactions.'
  },

  // Sybil and Identity Attacks
  {
    id: 'SOL1531',
    name: 'Wallet Count as Identity',
    severity: 'high',
    pattern: /unique.*wallets|wallet.*count[\s\S]{0,100}(?!stake|history|proof)/i,
    description: 'Using wallet count as identity measure enables sybil attacks.',
    recommendation: 'Use proof-of-stake, proof-of-history, or ZK identity proofs.'
  },
  {
    id: 'SOL1532',
    name: 'Airdrop Farming Vulnerability',
    severity: 'medium',
    pattern: /airdrop[\s\S]{0,100}(?!sybil.*resist|snapshot.*behavior|minimum.*history)/i,
    description: 'Airdrop mechanism vulnerable to sybil farming with multiple wallets.',
    recommendation: 'Use behavior-based distribution, minimum history requirements.'
  },
  {
    id: 'SOL1533',
    name: 'One Transaction Identity',
    severity: 'medium',
    pattern: /new.*user|first.*transaction[\s\S]{0,100}reward/i,
    description: 'Rewarding new users without history enables infinite sybil farming.',
    recommendation: 'Require minimum transaction history or staked value for rewards.'
  },
  {
    id: 'SOL1534',
    name: 'io.net Style GPU Sybil',
    severity: 'high',
    pattern: /gpu.*verify|compute.*proof[\s\S]{0,100}(?!tee|sgx|physical.*attestation)/i,
    description: 'io.net attack - fake GPU verification through spoofed compute proofs.',
    recommendation: 'Use hardware attestation (TEE/SGX) for compute resource verification.'
  },
  {
    id: 'SOL1535',
    name: 'Vote Multiplication Attack',
    severity: 'high',
    pattern: /vote.*per.*wallet|one.*wallet.*one.*vote[\s\S]{0,50}(?!nft|soul.*bound|kyc)/i,
    description: 'One-wallet-one-vote enables vote multiplication via multiple wallets.',
    recommendation: 'Use soulbound NFTs, KYC, or stake-weighted voting.'
  },

  // Honeypot and Rug Pull Detection
  {
    id: 'SOL1536',
    name: 'Hidden Sell Restriction',
    severity: 'critical',
    pattern: /sell[\s\S]{0,50}(?:restrict|block|disable)[\s\S]{0,50}(?!documented|disclosed)/i,
    description: 'Honeypot pattern - token has hidden sell restrictions.',
    recommendation: 'Audit token contract for sell restrictions before buying.'
  },
  {
    id: 'SOL1537',
    name: 'Owner Can Modify Tax',
    severity: 'high',
    pattern: /set.*tax|tax.*=.*(?!immutable|fixed|max)/i,
    description: 'Owner can set arbitrary tax rates, classic rug pull setup.',
    recommendation: 'Verify tax rates are immutable or have maximum bounds.'
  },
  {
    id: 'SOL1538',
    name: 'Hidden Mint Function',
    severity: 'critical',
    pattern: /mint[\s\S]{0,100}(?:hidden|internal|_mint)[\s\S]{0,50}(?!documented|emit)/i,
    description: 'Hidden mint function allows infinite supply dilution.',
    recommendation: 'Verify mint authority is burned or controlled by DAO.'
  },
  {
    id: 'SOL1539',
    name: 'Liquidity Lock Bypass',
    severity: 'high',
    pattern: /liquidity.*lock[\s\S]{0,100}(?:bypass|override|admin)/i,
    description: 'Liquidity lock can be bypassed by admin, enabling rug pull.',
    recommendation: 'Verify liquidity lock is in immutable contract with no admin override.'
  },
  {
    id: 'SOL1540',
    name: 'Emergency Withdraw Without Delay',
    severity: 'high',
    pattern: /emergency.*withdraw[\s\S]{0,100}(?!timelock|delay|multisig)/i,
    description: 'Emergency withdraw without delay allows instant rug.',
    recommendation: 'Require minimum 48-72h timelock on emergency functions.'
  },

  // Cross-Chain Bridge Vulnerabilities
  {
    id: 'SOL1541',
    name: 'Bridge Message Replay',
    severity: 'critical',
    pattern: /bridge.*message[\s\S]{0,100}(?!nonce|sequence|replay.*protect)/i,
    description: 'Cross-chain messages can be replayed without nonce tracking.',
    recommendation: 'Track processed message nonces, reject duplicates.'
  },
  {
    id: 'SOL1542',
    name: 'Insufficient Guardian Threshold',
    severity: 'critical',
    pattern: /guardian.*threshold[\s\S]{0,30}(?:[12]\/[345]|minority)/i,
    description: 'Wormhole pattern - low guardian threshold enables collusion attacks.',
    recommendation: 'Require at least 2/3 or 13/19 guardian signatures.'
  },
  {
    id: 'SOL1543',
    name: 'Cross-Chain Finality Assumptions',
    severity: 'high',
    pattern: /finality[\s\S]{0,50}(?:instant|immediate|1\s*block)/i,
    description: 'Assuming instant finality on source chain enables reorg attacks.',
    recommendation: 'Wait for sufficient confirmations based on source chain security.'
  },
  {
    id: 'SOL1544',
    name: 'Token Mapping Not Verified',
    severity: 'critical',
    pattern: /token.*mapping|bridge.*token[\s\S]{0,100}(?!verify.*contract|official.*address)/i,
    description: 'Bridged token mapping not verified against canonical contract.',
    recommendation: 'Maintain verified token registry, validate source chain contract.'
  },
  {
    id: 'SOL1545',
    name: 'Bridge Oracle Single Point',
    severity: 'high',
    pattern: /bridge.*oracle[\s\S]{0,100}(?!redundant|multiple|backup)/i,
    description: 'Single oracle for bridge price feeds creates manipulation risk.',
    recommendation: 'Use multiple independent oracles with aggregation.'
  },

  // Validator and Staking Attacks
  {
    id: 'SOL1546',
    name: 'Validator Commission Manipulation',
    severity: 'high',
    pattern: /commission[\s\S]{0,50}(?:change|update|set)[\s\S]{0,50}(?!lock|max|delay)/i,
    description: 'Validators can suddenly increase commission after attracting stake.',
    recommendation: 'Implement commission change cooldowns and maximum rate limits.'
  },
  {
    id: 'SOL1547',
    name: 'Stake Concentration Attack',
    severity: 'high',
    pattern: /stake[\s\S]{0,100}(?!decentraliz|distributed|threshold)/i,
    description: 'Stake concentration in few validators enables censorship/MEV extraction.',
    recommendation: 'Monitor stake distribution, implement concentration limits.'
  },
  {
    id: 'SOL1548',
    name: 'Slashing Event Cascade',
    severity: 'high',
    pattern: /slash[\s\S]{0,100}(?!protect|insurance|recovery)/i,
    description: 'Correlated slashing events can trigger cascade liquidations.',
    recommendation: 'Implement slashing insurance and gradual unstaking mechanisms.'
  },
  {
    id: 'SOL1549',
    name: 'Unbonding Period Exploit',
    severity: 'medium',
    pattern: /unbond[\s\S]{0,50}(?:instant|immediate|no.*delay)/i,
    description: 'Short/no unbonding period enables stake attack and run.',
    recommendation: 'Enforce minimum unbonding period (1-3 epochs) for security.'
  },
  {
    id: 'SOL1550',
    name: 'Validator Key Compromise',
    severity: 'critical',
    pattern: /validator.*key[\s\S]{0,100}(?!rotate|hardware|hsm)/i,
    description: 'Validator keys without rotation or hardware protection.',
    recommendation: 'Use HSM for validator keys, implement key rotation schedule.'
  },

  // Compute and Resource Exhaustion
  {
    id: 'SOL1551',
    name: 'Unbounded Iteration DoS',
    severity: 'high',
    pattern: /for\s+\w+\s+in[\s\S]{0,50}(?!\.iter\(\)\.take|\.\.MAX)/,
    description: 'Unbounded iteration can exhaust compute budget, causing DoS.',
    recommendation: 'Always bound iterations: for item in collection.iter().take(MAX_ITEMS)'
  },
  {
    id: 'SOL1552',
    name: 'Recursive CPI Bomb',
    severity: 'high',
    pattern: /invoke.*invoke|cpi.*cpi[\s\S]{0,50}(?!depth.*check|max.*recursion)/i,
    description: 'Recursive CPI calls can exhaust stack and compute budget.',
    recommendation: 'Track CPI depth, limit recursion to 4 levels.'
  },
  {
    id: 'SOL1553',
    name: 'Account Data Bloat',
    severity: 'medium',
    pattern: /realloc[\s\S]{0,50}(?!max.*size|limit|bounded)/i,
    description: 'Account data growth without limits increases rent and processing costs.',
    recommendation: 'Define maximum account size, refuse excessive reallocation.'
  },
  {
    id: 'SOL1554',
    name: 'Log Spam Attack',
    severity: 'low',
    pattern: /msg!.*loop|for[\s\S]{0,50}msg!|emit.*unbounded/i,
    description: 'Excessive logging in loops wastes compute and obscures important events.',
    recommendation: 'Emit aggregate events, avoid logging in loops.'
  },
  {
    id: 'SOL1555',
    name: 'Serialization DoS',
    severity: 'medium',
    pattern: /serialize[\s\S]{0,50}large|borsh.*vec[\s\S]{0,50}(?!max.*len)/i,
    description: 'Deserializing large structures can exhaust compute.',
    recommendation: 'Limit serialized data size, use zero-copy where possible.'
  },

  // NFT Specific Vulnerabilities
  {
    id: 'SOL1556',
    name: 'NFT Metadata Injection',
    severity: 'high',
    pattern: /metadata.*uri|uri\s*:\s*String[\s\S]{0,50}(?!sanitize|validate|whitelist)/i,
    description: 'Unsanitized metadata URI can inject malicious content.',
    recommendation: 'Validate and sanitize all metadata URIs, use content allowlist.'
  },
  {
    id: 'SOL1557',
    name: 'Collection Authority Bypass',
    severity: 'high',
    pattern: /collection[\s\S]{0,100}verify[\s\S]{0,50}(?!authority.*check|creator.*sign)/i,
    description: 'NFT added to collection without proper authority verification.',
    recommendation: 'Verify collection authority signature for all collection modifications.'
  },
  {
    id: 'SOL1558',
    name: 'Royalty Enforcement Bypass',
    severity: 'medium',
    pattern: /transfer.*nft[\s\S]{0,100}(?!royalty.*check|enforce.*royalty)/i,
    description: 'NFT transfer without royalty enforcement hurts creators.',
    recommendation: 'Use Metaplex royalty enforcement or Token-2022 transfer hooks.'
  },
  {
    id: 'SOL1559',
    name: 'cNFT Merkle Proof Manipulation',
    severity: 'high',
    pattern: /merkle.*proof[\s\S]{0,100}(?!verify.*root|validate.*tree)/i,
    description: 'Compressed NFT merkle proofs not properly validated.',
    recommendation: 'Verify proof against current tree root, check leaf data hash.'
  },
  {
    id: 'SOL1560',
    name: 'NFT Burn Authority Abuse',
    severity: 'high',
    pattern: /burn.*authority[\s\S]{0,50}(?!owner_only|holder_consent)/i,
    description: 'External burn authority can destroy NFTs without holder consent.',
    recommendation: 'Require holder signature for burns, or clearly document burn authority.'
  },

  // DeFi Protocol Specific
  {
    id: 'SOL1561',
    name: 'Lending Pool Isolation Missing',
    severity: 'high',
    pattern: /lending.*pool[\s\S]{0,100}(?!isolated|cross.*collateral.*check)/i,
    description: 'Shared lending pools allow cross-collateral manipulation.',
    recommendation: 'Implement pool isolation or strict cross-collateral rules.'
  },
  {
    id: 'SOL1562',
    name: 'Liquidation Bonus Exploitation',
    severity: 'high',
    pattern: /liquidation.*bonus[\s\S]{0,30}(?:>|=)\s*(?:[2-9]\d|[1-9]\d{2})/i,
    description: 'Excessive liquidation bonus (>20%) incentivizes self-liquidation attacks.',
    recommendation: 'Limit liquidation bonus to 5-15% based on collateral risk.'
  },
  {
    id: 'SOL1563',
    name: 'AMM Constant Product Bypass',
    severity: 'critical',
    pattern: /swap[\s\S]{0,200}(?!k.*=.*x.*\*.*y|constant.*product|invariant)/i,
    description: 'AMM swap not enforcing constant product invariant.',
    recommendation: 'Verify k = x * y after every swap, reject violating transactions.'
  },
  {
    id: 'SOL1564',
    name: 'LP Share Inflation Attack',
    severity: 'critical',
    pattern: /mint.*lp|lp.*shares[\s\S]{0,100}(?!first.*deposit.*check|minimum.*liquidity)/i,
    description: 'First depositor can inflate LP share value to exploit subsequent deposits.',
    recommendation: 'Lock minimum liquidity on first deposit, use virtual reserves.'
  },
  {
    id: 'SOL1565',
    name: 'Interest Rate Model Manipulation',
    severity: 'high',
    pattern: /interest.*rate[\s\S]{0,100}(?!cap|max|bounds|smooth)/i,
    description: 'Interest rate can spike causing unexpected liquidations.',
    recommendation: 'Implement interest rate caps and smoothing mechanisms.'
  },

  // Governance Advanced
  {
    id: 'SOL1566',
    name: 'Proposal Data Injection',
    severity: 'critical',
    pattern: /proposal.*data[\s\S]{0,100}(?!validate|whitelist|safe_instruction)/i,
    description: 'Arbitrary instruction data in proposals enables malicious execution.',
    recommendation: 'Whitelist allowed instruction types and validate all parameters.'
  },
  {
    id: 'SOL1567',
    name: 'Voting Period Too Short',
    severity: 'medium',
    pattern: /voting.*period[\s\S]{0,30}(?:\d{1,4})\s*(?:seconds?|minutes?|hours?)/i,
    description: 'Short voting period enables surprise governance attacks.',
    recommendation: 'Minimum 3-7 day voting period for important proposals.'
  },
  {
    id: 'SOL1568',
    name: 'No Proposal Threshold',
    severity: 'medium',
    pattern: /create.*proposal[\s\S]{0,100}(?!threshold|minimum.*stake|requirement)/i,
    description: 'Anyone can create proposals, enabling spam and governance attacks.',
    recommendation: 'Require minimum stake or token balance to create proposals.'
  },
  {
    id: 'SOL1569',
    name: 'Delegation Without Limits',
    severity: 'medium',
    pattern: /delegate.*vote[\s\S]{0,100}(?!max.*delegation|limit|cap)/i,
    description: 'Unlimited vote delegation enables vote concentration.',
    recommendation: 'Implement delegation caps and prevent delegation chains.'
  },
  {
    id: 'SOL1570',
    name: 'Emergency Action Without Governance',
    severity: 'high',
    pattern: /emergency[\s\S]{0,100}(?:owner|admin)[\s\S]{0,50}(?!require.*vote|multisig)/i,
    description: 'Emergency actions bypass governance, enabling rug pulls.',
    recommendation: 'Require multisig or expedited governance vote for emergencies.'
  },

  // Testing and Deployment Safety
  {
    id: 'SOL1571',
    name: 'Debug Code in Production',
    severity: 'high',
    pattern: /(?:#\[cfg\(debug|debug_assert|println!|dbg!)/,
    description: 'Debug code left in production can leak information or cause issues.',
    recommendation: 'Remove all debug code before mainnet deployment.'
  },
  {
    id: 'SOL1572',
    name: 'Hardcoded Devnet Address',
    severity: 'high',
    pattern: /devnet|testnet[\s\S]{0,50}(?:address|pubkey|program_id)/i,
    description: 'Devnet/testnet addresses hardcoded in production code.',
    recommendation: 'Use environment-based configuration for network addresses.'
  },
  {
    id: 'SOL1573',
    name: 'Unverified Program Deployment',
    severity: 'medium',
    pattern: /deploy[\s\S]{0,100}(?!verify|audit|checksum)/i,
    description: 'Program deployed without verification against audited source.',
    recommendation: 'Verify deployed bytecode matches audited source code.'
  },
  {
    id: 'SOL1574',
    name: 'No Upgrade Authority Multisig',
    severity: 'high',
    pattern: /upgrade.*authority[\s\S]{0,100}(?!multisig|dao|council)/i,
    description: 'Single upgrade authority is centralization and rug risk.',
    recommendation: 'Transfer upgrade authority to multisig or DAO.'
  },
  {
    id: 'SOL1575',
    name: 'Missing Mainnet Safety Checks',
    severity: 'high',
    pattern: /cluster[\s\S]{0,50}mainnet[\s\S]{0,100}(?!confirm|safety|rate_limit)/i,
    description: 'Production deployment without mainnet-specific safety measures.',
    recommendation: 'Add rate limits, confirmation steps, and monitoring for mainnet.'
  },

  // Miscellaneous Advanced Patterns
  {
    id: 'SOL1576',
    name: 'Timestamp Dependence',
    severity: 'medium',
    pattern: /clock.*unix_timestamp[\s\S]{0,100}(?!tolerance|range|slot)/i,
    description: 'Relying on exact timestamps can be manipulated by validators.',
    recommendation: 'Use slot numbers or timestamp ranges instead of exact times.'
  },
  {
    id: 'SOL1577',
    name: 'Slot Number for Randomness',
    severity: 'high',
    pattern: /slot[\s\S]{0,50}(?:random|seed|entropy)/i,
    description: 'Slot numbers are predictable and unsuitable for randomness.',
    recommendation: 'Use VRF (Switchboard/Chainlink) for on-chain randomness.'
  },
  {
    id: 'SOL1578',
    name: 'Unchecked CPI Return',
    severity: 'high',
    pattern: /invoke[\s\S]{0,50}(?:;\s*$|\?\s*;)[\s\S]{0,50}(?!check|verify|result)/,
    description: 'CPI return value not checked for success/failure.',
    recommendation: 'Always check CPI return: invoke(...)? and handle errors.'
  },
  {
    id: 'SOL1579',
    name: 'Account Close Without Zero Balance',
    severity: 'high',
    pattern: /close.*account[\s\S]{0,100}(?!balance.*==.*0|empty|zero)/i,
    description: 'Closing account without verifying zero balance loses funds.',
    recommendation: 'Verify account balance is zero before closing.'
  },
  {
    id: 'SOL1580',
    name: 'Rent Exemption Not Maintained',
    severity: 'medium',
    pattern: /lamports\s*-=[\s\S]{0,50}(?!rent_exempt|minimum_balance)/i,
    description: 'Reducing lamports below rent exemption causes account deletion.',
    recommendation: 'Always maintain minimum balance: lamports >= rent.minimum_balance(size).'
  },
];

/**
 * Run batch 46 patterns
 */
export function runBatch46Patterns(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';
  const fileName = input.path || 'unknown';
  
  if (!content) return findings;
  
  const lines = content.split('\n');
  
  for (const pattern of BATCH_46_PATTERNS) {
    try {
      const regex = new RegExp(pattern.pattern.source, pattern.pattern.flags + (pattern.pattern.flags.includes('g') ? '' : 'g'));
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
        
        findings.push({
          id: pattern.id,
          title: pattern.name,
          severity: pattern.severity,
          description: pattern.description,
          location: { file: fileName, line: lineNum },
          recommendation: pattern.recommendation,
        });
      }
    } catch (e) {
      // Skip invalid patterns
    }
  }
  
  return findings;
}

export { BATCH_46_PATTERNS };
export default BATCH_46_PATTERNS;
