/**
 * SolGuard Batched Patterns 51 - SOL1861-SOL1930
 * Cantina Security Guide + Advanced Protocol Patterns
 * Added: Feb 5, 2026 1:30 PM CST
 * 
 * Source: Cantina "Securing Solana: A Developer's Guide" + arXiv:2504.07419
 */

import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

interface PatternDef {
  id: string;
  name: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  pattern: RegExp;
  description: string;
  recommendation: string;
  cwe?: string;
}

const PATTERNS: PatternDef[] = [
  // === CANTINA GUIDE: Account Data Matching ===
  {
    id: 'SOL1861',
    name: 'Account Data Mismatch - Admin Check',
    severity: 'critical',
    pattern: /pub\s+fn\s+update_\w*admin|fn\s+\w*admin\w*setting(?![\s\S]{0,200}admin\.key\(\)\s*==|[\s\S]{0,200}constraint\s*=)/i,
    description: 'Admin update function without verifying signer matches stored admin. Cantina: "Account data matching vulnerabilities occur when developers fail to verify that an account\'s stored data matches expected values."',
    recommendation: 'Add: if ctx.accounts.admin.key() != ctx.accounts.config_data.admin { return Err(Unauthorized) }',
    cwe: 'CWE-863'
  },
  {
    id: 'SOL1862',
    name: 'Config Update Without Authority Verification',
    severity: 'critical',
    pattern: /config_data\.settings\s*=|config\.update(?![\s\S]{0,150}authority\.key\(\)|[\s\S]{0,150}has_one)/i,
    description: 'Configuration update without verifying authority account matches stored authority.',
    recommendation: 'Use Anchor constraint: #[account(mut, constraint = config_data.admin == admin.key())]',
    cwe: 'CWE-863'
  },
  {
    id: 'SOL1863',
    name: 'Permission Check Missing - Stored Key',
    severity: 'high',
    pattern: /\.key\(\)\s*(?!==|!=)[\s\S]{0,30}(config|state|data)\./,
    description: 'Account key accessed but not compared against stored permission keys.',
    recommendation: 'Always verify: require!(signer.key() == stored_state.authorized_key, Unauthorized)',
    cwe: 'CWE-285'
  },

  // === CANTINA GUIDE: Account Data Reallocation ===
  {
    id: 'SOL1864',
    name: 'Realloc Without Zero Init After Decrease',
    severity: 'high',
    pattern: /\.realloc\([^,]+,\s*false\s*\)(?![\s\S]{0,100}zero|[\s\S]{0,100}memset)/,
    description: 'Cantina: "Use zero_init to true when increasing size after reducing it to prevent stale data exposure."',
    recommendation: 'Set zero_init=true when reallocating after size decrease, or manually zero memory.',
    cwe: 'CWE-226'
  },
  {
    id: 'SOL1865',
    name: 'Frequent Realloc Without ALT',
    severity: 'medium',
    pattern: /realloc\([^)]+\)[\s\S]{0,500}realloc\([^)]+\)/,
    description: 'Multiple reallocations detected - consider using Address Lookup Tables (ALTs) for efficiency.',
    recommendation: 'Use ALTs instead of frequent reallocation to optimize compute and memory.',
    cwe: 'CWE-400'
  },
  {
    id: 'SOL1866',
    name: 'Dynamic Size Calculation Without Bounds',
    severity: 'medium',
    pattern: /calculate_\w*len|required_\w*len(?![\s\S]{0,100}min\(|[\s\S]{0,100}max\(|[\s\S]{0,100}MAX_)/i,
    description: 'Dynamic size calculation without bounds checking could exceed account limits.',
    recommendation: 'Add bounds: let required_len = calculate_len(&data).min(MAX_ACCOUNT_SIZE);',
    cwe: 'CWE-119'
  },

  // === CANTINA GUIDE: Account Reloading After CPI ===
  {
    id: 'SOL1867',
    name: 'Missing Account Reload After CPI',
    severity: 'high',
    pattern: /cpi::\w+\([^)]+\)\?[\s\S]{0,100}(ctx\.accounts\.\w+\.\w+|account\.\w+)(?![\s\S]{0,50}\.reload\(\))/,
    description: 'Cantina: "Anchor does not automatically refresh account states after CPI. Program may operate on stale data."',
    recommendation: 'Call ctx.accounts.affected_account.reload()? after any CPI that modifies the account.',
    cwe: 'CWE-662'
  },
  {
    id: 'SOL1868',
    name: 'Stale Data After External Call',
    severity: 'high',
    pattern: /invoke(?:_signed)?\([^)]+\)[\s\S]{0,150}(?:balance|amount|rewards|stake)(?![\s\S]{0,50}reload)/,
    description: 'Balance/amount accessed after external invocation without reload - may be stale.',
    recommendation: 'Reload account data after invoke: account_info.data.borrow() or .reload()',
    cwe: 'CWE-662'
  },
  {
    id: 'SOL1869',
    name: 'CPI Result Not Verified',
    severity: 'medium',
    pattern: /cpi::\w+\([^)]+\)\?;[\s\S]{0,30}(?:Ok\(\)|return)/,
    description: 'CPI called but result/state changes not verified before returning success.',
    recommendation: 'After CPI, verify expected state: reload account and check values match expectations.',
    cwe: 'CWE-754'
  },

  // === CANTINA GUIDE: Arbitrary CPI ===
  {
    id: 'SOL1870',
    name: 'CPI Target From User Input',
    severity: 'critical',
    pattern: /program_id:\s*(ctx\.accounts\.\w+_program|program)(?![\s\S]{0,100}==\s*&?\w+_PROGRAM_ID|[\s\S]{0,100}require!)/,
    description: 'Cantina: "If a program allows arbitrary CPIs without verifying target program identity, attackers could execute malicious programs."',
    recommendation: 'Hardcode expected program IDs: require!(program.key() == &expected::ID, InvalidProgram)',
    cwe: 'CWE-610'
  },
  {
    id: 'SOL1871',
    name: 'Dynamic Program Invocation',
    severity: 'critical',
    pattern: /invoke\([^,]+,\s*&?\[[\s\S]{0,50}program_id(?![\s\S]{0,100}==|[\s\S]{0,100}TOKEN_PROGRAM_ID|[\s\S]{0,100}SYSTEM_PROGRAM_ID)/,
    description: 'Dynamic program ID in invoke without validation against known program list.',
    recommendation: 'Validate program ID against allowlist before invocation.',
    cwe: 'CWE-610'
  },
  {
    id: 'SOL1872',
    name: 'Unconstrained CPI Program Account',
    severity: 'high',
    pattern: /\/\/\/\s*CHECK[\s\S]{0,100}program[\s\S]{0,50}AccountInfo(?![\s\S]{0,200}executable|[\s\S]{0,200}program_id)/i,
    description: 'Program account marked CHECK without verifying it is executable or correct ID.',
    recommendation: 'Add: constraint = program.executable && program.key() == &expected_program::ID',
    cwe: 'CWE-610'
  },

  // === CANTINA GUIDE: Computational Unit (CU) Exhaustion ===
  {
    id: 'SOL1873',
    name: 'Unbounded Loop CU Risk',
    severity: 'high',
    pattern: /for\s+\w+\s+in\s+(0\.\.|\w+\.iter\(\)|&\w+)(?![\s\S]{0,50}\.take\(|[\s\S]{0,50}MAX_|[\s\S]{0,50}\.len\(\)\s*<)/,
    description: 'Cantina: "Exceeding 48M CU limit can cause transactions to fail. Attackers can disrupt critical operations."',
    recommendation: 'Add iteration limits: for item in items.iter().take(MAX_ITEMS)',
    cwe: 'CWE-834'
  },
  {
    id: 'SOL1874',
    name: 'Nested Loop Without Bounds',
    severity: 'high',
    pattern: /for[\s\S]{0,100}for[\s\S]{0,100}for(?![\s\S]{0,100}MAX_|[\s\S]{0,100}\.take\()/,
    description: 'Triple-nested loops can easily exceed CU limits. Needs strict bounds.',
    recommendation: 'Flatten nested loops or add strict MAX_ITERATIONS constants.',
    cwe: 'CWE-834'
  },
  {
    id: 'SOL1875',
    name: 'Recursive Function Without Depth Limit',
    severity: 'high',
    pattern: /fn\s+(\w+)[^{]+\{[\s\S]{0,500}\1\s*\((?![\s\S]{0,200}depth|[\s\S]{0,200}MAX_RECURSION)/,
    description: 'Recursive function without depth tracking can exceed CU limits or stack depth.',
    recommendation: 'Add depth parameter: fn process(data: Data, depth: u8) { if depth > MAX_DEPTH { return Err(...) } }',
    cwe: 'CWE-674'
  },

  // === CANTINA GUIDE: Dependencies ===
  {
    id: 'SOL1876',
    name: 'Outdated Anchor Version',
    severity: 'medium',
    pattern: /anchor-lang\s*=\s*["']0\.(2[0-7]|1\d|[0-9])\.(?![\s\S]{0,10}["'])/,
    description: 'Cantina: "Using outdated dependencies is a common yet avoidable security risk." Old Anchor versions have known vulnerabilities.',
    recommendation: 'Update to latest stable Anchor (0.30+) and run cargo audit regularly.',
    cwe: 'CWE-1104'
  },
  {
    id: 'SOL1877',
    name: 'Missing Cargo Audit',
    severity: 'info',
    pattern: /\[dependencies\][\s\S]{0,500}(?!#.*audit|.*cargo.*audit)/,
    description: 'No evidence of cargo audit in project. Should audit dependencies regularly.',
    recommendation: 'Run `cargo audit` regularly and add to CI pipeline.',
    cwe: 'CWE-1104'
  },

  // === SOLANA ATTACKER-CONTROLLED MODEL ===
  {
    id: 'SOL1878',
    name: 'Account Type Not Verified',
    severity: 'critical',
    pattern: /AccountInfo[\s\S]{0,100}(?!discriminator|Account<|[\s\S]{0,50}try_from)/,
    description: 'Cantina: "Attackers have ability to pass any account. Without type verification, malicious accounts can be injected."',
    recommendation: 'Use Anchor Account<> types or manually verify discriminator bytes.',
    cwe: 'CWE-843'
  },
  {
    id: 'SOL1879',
    name: 'Owner Check Missing - Raw AccountInfo',
    severity: 'critical',
    pattern: /AccountInfo[\s\S]{0,200}(?!owner\s*==|\.owner\s*==|has_one|constraint)/,
    description: 'Raw AccountInfo without owner verification allows attacker-controlled accounts.',
    recommendation: 'Verify: require!(account.owner == &expected_program_id, WrongOwner)',
    cwe: 'CWE-284'
  },
  {
    id: 'SOL1880',
    name: 'Signer Status Not Checked',
    severity: 'critical',
    pattern: /authority.*AccountInfo(?![\s\S]{0,100}Signer|[\s\S]{0,100}is_signer|[\s\S]{0,100}#\[account\(signer)/i,
    description: 'Authority account without signer verification - anyone can execute privileged operations.',
    recommendation: 'Use Signer<> type or check: require!(authority.is_signer, MissingSigner)',
    cwe: 'CWE-287'
  },

  // === INTEGER/ARITHMETIC (Cantina + arXiv) ===
  {
    id: 'SOL1881',
    name: 'Release Mode Integer Wrapping',
    severity: 'high',
    pattern: /(\w+)\s*=\s*\1\s*[-+]\s*\d+(?![\s\S]{0,20}checked_|[\s\S]{0,20}saturating_|[\s\S]{0,20}wrapping_)/,
    description: 'Cantina: "Rust prevents overflows in debug mode but defaults to wrapping in release mode."',
    recommendation: 'Use checked_add/checked_sub or enable overflow-checks = true in release profile.',
    cwe: 'CWE-190'
  },
  {
    id: 'SOL1882',
    name: 'Fixed-Point Precision Loss',
    severity: 'high',
    pattern: /(\d+)\s*\/\s*(\d+)[\s\S]{0,30}\*\s*\d+(?![\s\S]{0,50}PRECISION|[\s\S]{0,50}DECIMALS)/,
    description: 'Cantina: "Incorrect handling of decimal precision can result in rounding errors affecting balances."',
    recommendation: 'Use fixed-point arithmetic: multiply first, then divide with proper precision constants.',
    cwe: 'CWE-682'
  },
  {
    id: 'SOL1883',
    name: 'Division Before Multiplication',
    severity: 'medium',
    pattern: /\/\s*\w+[\s\S]{0,10}\*\s*\w+(?![\s\S]{0,30}PRECISION)/,
    description: 'Division before multiplication causes precision loss. Order matters in integer math.',
    recommendation: 'Reorder: (a * b) / c instead of (a / c) * b',
    cwe: 'CWE-682'
  },

  // === REENTRANCY (Cantina) ===
  {
    id: 'SOL1884',
    name: 'State Modified After CPI',
    severity: 'high',
    pattern: /invoke(?:_signed)?\([^)]+\)\?[\s\S]{0,100}(ctx\.accounts\.\w+\.\w+\s*=|\.\w+\s*=\s*[^=])/,
    description: 'Cantina: "Poorly structured programs can be vulnerable to state manipulation through intermediate program calls."',
    recommendation: 'Modify state BEFORE CPI (checks-effects-interactions pattern).',
    cwe: 'CWE-696'
  },
  {
    id: 'SOL1885',
    name: 'Missing Reentrancy Guard',
    severity: 'medium',
    pattern: /pub\s+fn\s+\w*(withdraw|claim|transfer|swap)[\s\S]{0,300}invoke(?![\s\S]{0,200}reentrancy|[\s\S]{0,200}locked|[\s\S]{0,200}processing)/i,
    description: 'Sensitive function with CPI lacks reentrancy protection.',
    recommendation: 'Add reentrancy guard: require!(!state.is_processing, ReentrancyDetected); state.is_processing = true;',
    cwe: 'CWE-696'
  },
  {
    id: 'SOL1886',
    name: 'CPI Depth Could Enable Reentrancy',
    severity: 'medium',
    pattern: /invoke[\s\S]{0,200}invoke[\s\S]{0,200}invoke(?![\s\S]{0,100}depth)/,
    description: 'Multiple nested CPIs increase reentrancy risk within Solana\'s 4-level recursion limit.',
    recommendation: 'Track CPI depth and verify state consistency after each level.',
    cwe: 'CWE-696'
  },

  // === arXiv PAPER: Cross-Instance Reinitialization ===
  {
    id: 'SOL1887',
    name: 'Cross-Instance Reinitialization Attack',
    severity: 'critical',
    pattern: /init[\s\S]{0,50}(?!init_if_needed)[\s\S]{0,100}(?!is_initialized|discriminator)/,
    description: 'arXiv 3.1.5: "An attacker reinitializes account from another program instance to gain unauthorized access."',
    recommendation: 'Check is_initialized flag and verify account was created by current program instance.',
    cwe: 'CWE-665'
  },
  {
    id: 'SOL1888',
    name: 'Account Validation Across Programs',
    severity: 'high',
    pattern: /owner\s*==\s*&?\w+::ID(?![\s\S]{0,100}program_id)/,
    description: 'Validating account owner but not verifying account wasn\'t created maliciously.',
    recommendation: 'Also verify account seeds/derivation match expected values.',
    cwe: 'CWE-346'
  },

  // === arXiv PAPER: Deprecated APIs ===
  {
    id: 'SOL1889',
    name: 'Deprecated Solana API Usage',
    severity: 'medium',
    pattern: /solana_program::(sysvar::instructions|program_stubs|short_vec)(?![\s\S]{0,20}deprecated)/,
    description: 'arXiv: Deprecated Solana APIs may have known security issues.',
    recommendation: 'Use current stable APIs and check Solana deprecation notices.',
    cwe: 'CWE-477'
  },
  {
    id: 'SOL1890',
    name: 'Legacy verify_signatures Usage',
    severity: 'high',
    pattern: /verify_signatures?\s*\((?![\s\S]{0,100}ed25519_program|[\s\S]{0,100}secp256k1_program)/i,
    description: 'Legacy signature verification may not use current secure patterns.',
    recommendation: 'Use official Solana signature verification precompiles.',
    cwe: 'CWE-327'
  },

  // === ADVANCED PROTOCOL PATTERNS ===
  {
    id: 'SOL1891',
    name: 'Price Oracle Single Source',
    severity: 'high',
    pattern: /price[\s\S]{0,50}(pyth|switchboard|chainlink)(?![\s\S]{0,200}(pyth|switchboard|chainlink))/i,
    description: 'Single oracle source for critical price data. Multi-source recommended.',
    recommendation: 'Use multiple oracle sources with median/aggregation for price feeds.',
    cwe: 'CWE-346'
  },
  {
    id: 'SOL1892',
    name: 'Oracle Staleness Window Too Long',
    severity: 'high',
    pattern: /staleness[\s\S]{0,20}(3600|7200|86400|\d{5,})/,
    description: 'Oracle staleness window >1 hour allows price manipulation during volatile periods.',
    recommendation: 'Reduce staleness window to 60-300 seconds for DeFi applications.',
    cwe: 'CWE-613'
  },
  {
    id: 'SOL1893',
    name: 'Missing Oracle Confidence Check',
    severity: 'high',
    pattern: /price[\s\S]{0,100}(get_price|get_current)(?![\s\S]{0,150}confidence|[\s\S]{0,150}conf\s*[<>])/i,
    description: 'Oracle price used without checking confidence interval.',
    recommendation: 'Verify: require!(price.confidence < price.price * MAX_CONFIDENCE_RATIO)',
    cwe: 'CWE-754'
  },

  // === LENDING/BORROWING PATTERNS ===
  {
    id: 'SOL1894',
    name: 'Collateral Ratio Bypass Risk',
    severity: 'critical',
    pattern: /collateral[\s\S]{0,100}borrow(?![\s\S]{0,200}health_factor|[\s\S]{0,200}ltv|[\s\S]{0,200}collateral_ratio)/i,
    description: 'Borrow operation without explicit collateral ratio verification.',
    recommendation: 'Check: require!(collateral_value * LTV > borrow_value, InsufficientCollateral)',
    cwe: 'CWE-754'
  },
  {
    id: 'SOL1895',
    name: 'Liquidation Bonus Manipulation',
    severity: 'high',
    pattern: /liquidat[\s\S]{0,100}bonus(?![\s\S]{0,150}MAX_|[\s\S]{0,150}min\(|[\s\S]{0,150}cap)/i,
    description: 'Liquidation bonus without caps can be exploited for excess profits.',
    recommendation: 'Cap liquidation bonus: let bonus = bonus.min(MAX_LIQUIDATION_BONUS);',
    cwe: 'CWE-682'
  },
  {
    id: 'SOL1896',
    name: 'Interest Rate Model Manipulation',
    severity: 'high',
    pattern: /interest_rate[\s\S]{0,100}utilization(?![\s\S]{0,150}kink|[\s\S]{0,150}jump|[\s\S]{0,150}optimal)/i,
    description: 'Interest rate model without kink/jump rate allows manipulation at high utilization.',
    recommendation: 'Implement kinked interest rate model with jump rate above optimal utilization.',
    cwe: 'CWE-682'
  },

  // === AMM PATTERNS ===
  {
    id: 'SOL1897',
    name: 'Constant Product Invariant Not Verified',
    severity: 'critical',
    pattern: /swap[\s\S]{0,200}(reserve|amount)[\s\S]{0,200}(?!k\s*==|invariant|reserve_a\s*\*\s*reserve_b)/i,
    description: 'AMM swap without verifying constant product (x*y=k) invariant.',
    recommendation: 'After swap: require!(new_reserve_a * new_reserve_b >= old_k, InvariantBroken)',
    cwe: 'CWE-682'
  },
  {
    id: 'SOL1898',
    name: 'LP Share Inflation Attack',
    severity: 'critical',
    pattern: /mint_to[\s\S]{0,100}(lp_|shares)(?![\s\S]{0,200}total_supply\s*==\s*0|[\s\S]{0,200}MINIMUM_LIQUIDITY)/i,
    description: 'LP token minting without first-depositor attack protection.',
    recommendation: 'On first mint, burn MINIMUM_LIQUIDITY to prevent share inflation attacks.',
    cwe: 'CWE-682'
  },
  {
    id: 'SOL1899',
    name: 'Slippage Calculation Error',
    severity: 'high',
    pattern: /slippage[\s\S]{0,50}(100|1000|10000)(?![\s\S]{0,50}BASIS_POINTS|[\s\S]{0,50}PERCENTAGE)/,
    description: 'Slippage calculation may use wrong base (percentage vs basis points).',
    recommendation: 'Use explicit constants: const SLIPPAGE_BPS: u64 = 50; // 0.5%',
    cwe: 'CWE-682'
  },
  {
    id: 'SOL1900',
    name: 'Missing Sandwich Attack Protection',
    severity: 'high',
    pattern: /swap[\s\S]{0,200}(?!deadline|expires|min_amount_out|slippage_check)/i,
    description: 'Swap without deadline or minimum output allows sandwich attacks.',
    recommendation: 'Add deadline: require!(clock.unix_timestamp < deadline, Expired); Add min_out check.',
    cwe: 'CWE-362'
  },

  // === STAKING PATTERNS ===
  {
    id: 'SOL1901',
    name: 'Stake Rewards Without Time Accounting',
    severity: 'high',
    pattern: /stake[\s\S]{0,100}reward(?![\s\S]{0,200}last_update|[\s\S]{0,200}reward_per_token|[\s\S]{0,200}timestamp)/i,
    description: 'Staking rewards without time-based accounting allows reward manipulation.',
    recommendation: 'Track reward_per_token_stored and last_update_time for correct distribution.',
    cwe: 'CWE-682'
  },
  {
    id: 'SOL1902',
    name: 'Unbonding Period Bypass',
    severity: 'high',
    pattern: /unstake[\s\S]{0,200}transfer(?![\s\S]{0,200}cooldown|[\s\S]{0,200}unbonding|[\s\S]{0,200}lock_)/i,
    description: 'Unstaking with immediate transfer - missing unbonding period.',
    recommendation: 'Implement unbonding: stake.unbonding_end = clock.unix_timestamp + UNBONDING_PERIOD;',
    cwe: 'CWE-613'
  },
  {
    id: 'SOL1903',
    name: 'Reward Rate Manipulation',
    severity: 'medium',
    pattern: /reward_rate[\s\S]{0,50}=(?![\s\S]{0,100}if\s*\(|[\s\S]{0,100}duration|[\s\S]{0,100}require!)/,
    description: 'Reward rate set without validation or duration check.',
    recommendation: 'Validate: new_reward_rate = total_rewards.checked_div(duration)?;',
    cwe: 'CWE-682'
  },

  // === BRIDGE PATTERNS ===
  {
    id: 'SOL1904',
    name: 'Bridge Message Replay',
    severity: 'critical',
    pattern: /message[\s\S]{0,100}verify(?![\s\S]{0,200}nonce|[\s\S]{0,200}sequence|[\s\S]{0,200}used_messages)/i,
    description: 'Cross-chain message verification without replay protection.',
    recommendation: 'Track used messages: require!(!used_messages.contains(&msg_hash), MessageReplayed)',
    cwe: 'CWE-294'
  },
  {
    id: 'SOL1905',
    name: 'Insufficient Guardian Quorum',
    severity: 'critical',
    pattern: /guardian[\s\S]{0,100}verify(?![\s\S]{0,200}quorum|[\s\S]{0,200}threshold|[\s\S]{0,200}2\/3)/i,
    description: 'Guardian signature verification without quorum threshold check.',
    recommendation: 'Verify: require!(valid_signatures >= guardians.len() * 2 / 3 + 1, InsufficientQuorum)',
    cwe: 'CWE-287'
  },
  {
    id: 'SOL1906',
    name: 'Source Chain Not Verified',
    severity: 'high',
    pattern: /bridge[\s\S]{0,100}process(?![\s\S]{0,200}source_chain|[\s\S]{0,200}emitter_chain|[\s\S]{0,200}chain_id)/i,
    description: 'Bridge message processed without verifying source chain.',
    recommendation: 'Check: require!(message.emitter_chain == EXPECTED_SOURCE_CHAIN, InvalidSourceChain)',
    cwe: 'CWE-346'
  },

  // === NFT PATTERNS ===
  {
    id: 'SOL1907',
    name: 'NFT Collection Authority Not Verified',
    severity: 'high',
    pattern: /collection[\s\S]{0,100}verify(?![\s\S]{0,200}update_authority|[\s\S]{0,200}collection_key)/i,
    description: 'NFT collection verification without checking collection authority.',
    recommendation: 'Verify: require!(nft.collection.verified && nft.collection.key == expected_collection)',
    cwe: 'CWE-346'
  },
  {
    id: 'SOL1908',
    name: 'Royalty Enforcement Missing',
    severity: 'medium',
    pattern: /transfer[\s\S]{0,100}nft(?![\s\S]{0,200}royalt|[\s\S]{0,200}creator_fee|[\s\S]{0,200}pnft)/i,
    description: 'NFT transfer without royalty enforcement check.',
    recommendation: 'Use Metaplex Programmable NFTs (pNFT) for enforced royalties.',
    cwe: 'CWE-284'
  },
  {
    id: 'SOL1909',
    name: 'Metadata URI Injection',
    severity: 'medium',
    pattern: /metadata[\s\S]{0,50}uri[\s\S]{0,30}=(?![\s\S]{0,100}validate|[\s\S]{0,100}sanitize)/i,
    description: 'Metadata URI set without validation could enable phishing.',
    recommendation: 'Validate URI format and optionally restrict to known domains.',
    cwe: 'CWE-79'
  },

  // === TOKEN-2022 ADVANCED ===
  {
    id: 'SOL1910',
    name: 'Transfer Hook Reentrancy',
    severity: 'high',
    pattern: /transfer_hook[\s\S]{0,200}invoke(?![\s\S]{0,200}reentrancy|[\s\S]{0,200}locked)/i,
    description: 'Token-2022 transfer hooks can enable reentrancy if not properly guarded.',
    recommendation: 'Add reentrancy guard in transfer hook: require!(!hook_state.is_executing)',
    cwe: 'CWE-696'
  },
  {
    id: 'SOL1911',
    name: 'Confidential Transfer Leak',
    severity: 'high',
    pattern: /confidential[\s\S]{0,100}(amount|balance)[\s\S]{0,50}(msg!|log|emit)/i,
    description: 'Confidential transfer amounts may be leaked through logging.',
    recommendation: 'Never log or emit confidential transfer amounts.',
    cwe: 'CWE-532'
  },
  {
    id: 'SOL1912',
    name: 'Transfer Fee Bypass',
    severity: 'high',
    pattern: /transfer[\s\S]{0,100}(?!transfer_fee|fee_config|get_fee)/i,
    description: 'Transfer operation may bypass Token-2022 transfer fees.',
    recommendation: 'Use transfer_with_fee instruction for Token-2022 tokens with fees.',
    cwe: 'CWE-284'
  },

  // === GOVERNANCE ===
  {
    id: 'SOL1913',
    name: 'Flash Loan Governance Attack',
    severity: 'critical',
    pattern: /vote[\s\S]{0,100}(balance|power)(?![\s\S]{0,200}snapshot|[\s\S]{0,200}lock|[\s\S]{0,200}checkpoint)/i,
    description: 'Voting power from current balance allows flash loan governance attacks.',
    recommendation: 'Use snapshotted voting power: vote_power = get_past_votes(user, snapshot_block)',
    cwe: 'CWE-362'
  },
  {
    id: 'SOL1914',
    name: 'Proposal Execution Without Timelock',
    severity: 'high',
    pattern: /proposal[\s\S]{0,100}execute(?![\s\S]{0,200}timelock|[\s\S]{0,200}delay|[\s\S]{0,200}eta)/i,
    description: 'Governance proposal can execute immediately without timelock delay.',
    recommendation: 'Add timelock: require!(clock.unix_timestamp >= proposal.eta, TimelockNotPassed)',
    cwe: 'CWE-362'
  },
  {
    id: 'SOL1915',
    name: 'Quorum Manipulation',
    severity: 'high',
    pattern: /quorum[\s\S]{0,50}(total_supply|current_supply)(?![\s\S]{0,150}fixed|[\s\S]{0,150}snapshot)/i,
    description: 'Dynamic quorum based on current supply allows manipulation via burns/mints.',
    recommendation: 'Use fixed quorum or snapshot supply at proposal creation.',
    cwe: 'CWE-682'
  },

  // === TESTING/DEPLOYMENT ===
  {
    id: 'SOL1916',
    name: 'Devnet Address in Production Code',
    severity: 'critical',
    pattern: /(devnet|testnet|localhost|127\.0\.0\.1)[\s\S]{0,30}(program|endpoint|cluster)/i,
    description: 'Development/test addresses found in production code.',
    recommendation: 'Use environment variables or feature flags for network selection.',
    cwe: 'CWE-489'
  },
  {
    id: 'SOL1917',
    name: 'Debug Code in Production',
    severity: 'high',
    pattern: /(#\[cfg\(debug_assertions\)\]|println!|dbg!|panic!.*debug)/,
    description: 'Debug code or assertions may be present in release build.',
    recommendation: 'Remove or guard debug code: #[cfg(not(feature = "production"))]',
    cwe: 'CWE-489'
  },
  {
    id: 'SOL1918',
    name: 'Missing Program Verification',
    severity: 'medium',
    pattern: /program_id[\s\S]{0,30}verify(?![\s\S]{0,100}source|[\s\S]{0,100}anchor verify)/i,
    description: 'Program may not be verified on-chain.',
    recommendation: 'Verify deployed program with: anchor verify <program_id>',
    cwe: 'CWE-345'
  },

  // === MISCELLANEOUS ADVANCED ===
  {
    id: 'SOL1919',
    name: 'Slot-Based Randomness',
    severity: 'high',
    pattern: /(slot|block)[\s\S]{0,30}(random|seed|entropy)/i,
    description: 'Using slot/block data for randomness is predictable by validators.',
    recommendation: 'Use VRF (Switchboard VRF, Orao) for unpredictable randomness.',
    cwe: 'CWE-330'
  },
  {
    id: 'SOL1920',
    name: 'Timestamp Manipulation Window',
    severity: 'medium',
    pattern: /unix_timestamp[\s\S]{0,30}(==|<\s*\d{1,3}[^0-9])/,
    description: 'Timestamp comparison with tight window - validators have ~1 second drift.',
    recommendation: 'Use windows of at least 2-5 seconds for timestamp comparisons.',
    cwe: 'CWE-367'
  },
  {
    id: 'SOL1921',
    name: 'Priority Fee Not Considered',
    severity: 'low',
    pattern: /compute_budget(?![\s\S]{0,100}priority|[\s\S]{0,100}set_compute_unit_price)/i,
    description: 'Compute budget set without priority fees may cause transaction delays.',
    recommendation: 'Include priority fee: SetComputeUnitPrice for time-sensitive operations.',
    cwe: 'CWE-400'
  },
  {
    id: 'SOL1922',
    name: 'Account Dust After Close',
    severity: 'medium',
    pattern: /close\s*=[\s\S]{0,100}(?![\s\S]{0,50}zero|[\s\S]{0,50}realloc\s*=\s*false)/,
    description: 'Closed account may leave dust lamports or data traces.',
    recommendation: 'Zero account data before closing: account.data.borrow_mut().fill(0);',
    cwe: 'CWE-226'
  },
  {
    id: 'SOL1923',
    name: 'Missing Rent Exemption Check',
    severity: 'medium',
    pattern: /lamports[\s\S]{0,50}(transfer|sub)(?![\s\S]{0,150}rent_exempt|[\s\S]{0,150}minimum_balance)/,
    description: 'Lamport transfer without ensuring account stays rent-exempt.',
    recommendation: 'Check: require!(account.lamports() - amount >= Rent::get()?.minimum_balance(account.data_len()))',
    cwe: 'CWE-682'
  },
  {
    id: 'SOL1924',
    name: 'PDA Seed Collision Risk',
    severity: 'high',
    pattern: /find_program_address\([^,]+,\s*&\[[\s\S]{0,30}\](?![\s\S]{0,100}user|[\s\S]{0,100}unique)/,
    description: 'PDA seeds without user-specific component risk collision.',
    recommendation: 'Include user pubkey in seeds: &[b"state", user.key().as_ref()]',
    cwe: 'CWE-327'
  },
  {
    id: 'SOL1925',
    name: 'Borsh Deserialization DoS',
    severity: 'medium',
    pattern: /try_from_slice|deserialize[\s\S]{0,50}(?![\s\S]{0,100}MAX_|[\s\S]{0,100}\.take\()/,
    description: 'Unbounded deserialization could exhaust compute with malicious data.',
    recommendation: 'Limit deserialization: account_data.get(..MAX_SIZE).ok_or(InvalidSize)?',
    cwe: 'CWE-502'
  },
  {
    id: 'SOL1926',
    name: 'Excessive Logging in Production',
    severity: 'low',
    pattern: /msg!\s*\([\s\S]{0,100}(password|secret|key|private)/i,
    description: 'Logging may expose sensitive information or waste compute.',
    recommendation: 'Remove sensitive data from logs and minimize logging in production.',
    cwe: 'CWE-532'
  },
  {
    id: 'SOL1927',
    name: 'Heap Allocation Exhaustion',
    severity: 'medium',
    pattern: /Vec::with_capacity\s*\(\s*\w+(?![\s\S]{0,50}min\(|[\s\S]{0,50}MAX_)/,
    description: 'Dynamic heap allocation with user-controlled size risks exhaustion.',
    recommendation: 'Cap allocation: Vec::with_capacity(requested_size.min(MAX_VEC_SIZE))',
    cwe: 'CWE-770'
  },
  {
    id: 'SOL1928',
    name: 'Feature Flag Security',
    severity: 'medium',
    pattern: /#\[cfg\(feature\s*=\s*["'][\w-]+["']\)\][\s\S]{0,100}(admin|authority|upgrade)/i,
    description: 'Security-critical code behind feature flags may be accidentally enabled.',
    recommendation: 'Critical security features should not be toggleable by feature flags.',
    cwe: 'CWE-489'
  },
  {
    id: 'SOL1929',
    name: 'Cross-Program Return Data Trust',
    severity: 'high',
    pattern: /get_return_data\(\)(?![\s\S]{0,150}program_id\s*==|[\s\S]{0,150}verify)/,
    description: 'Trusting CPI return data without verifying source program.',
    recommendation: 'Verify return data source: let (program_id, data) = get_return_data().unwrap(); require!(program_id == expected)',
    cwe: 'CWE-346'
  },
  {
    id: 'SOL1930',
    name: 'ALT (Address Lookup Table) Poisoning',
    severity: 'high',
    pattern: /address_lookup_table|lookup_table(?![\s\S]{0,200}authority|[\s\S]{0,200}verify)/i,
    description: 'Using Address Lookup Tables without verifying authority/contents.',
    recommendation: 'Verify ALT authority and contents haven\'t been maliciously modified.',
    cwe: 'CWE-346'
  },
];

export function runBatch51Patterns(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';
  
  if (!content) return findings;
  
  const lines = content.split('\n');
  
  for (const pattern of PATTERNS) {
    try {
      const regex = new RegExp(pattern.pattern.source, pattern.pattern.flags + 'g');
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
          description: pattern.description,
          location: { file: input.path, line: lineNum },
          suggestion: pattern.recommendation,
          cwe: pattern.cwe,
          code: snippet.substring(0, 200),
        });
      }
    } catch (e) {
      // Skip on regex error
    }
  }
  
  return findings;
}

export const BATCH_51_COUNT = PATTERNS.length;
export { PATTERNS as BATCH_51_PATTERNS };
