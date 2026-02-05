/**
 * SolGuard Batched Patterns 45 - 2025 Developer Education Security
 * 
 * Based on DEV.to "Solana Vulnerabilities Every Developer Should Know" (Feb 2025)
 * and Sec3 2025 Ecosystem Review findings
 * 
 * Patterns SOL1441-SOL1510 (70 patterns)
 */

import type { Finding, PatternInput } from './index.js';

// Pattern definitions
const BATCH_45_PATTERNS: {
  id: string;
  name: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  pattern: RegExp;
  description: string;
  recommendation: string;
}[] = [
  // Critical Access Control Issues
  {
    id: 'SOL1441',
    name: 'Signer Check via Key Comparison Only',
    severity: 'critical',
    pattern: /authority\.key\s*==|\.key\(\)\s*==\s*vault\.authority(?![\s\S]{0,50}is_signer)/i,
    description: 'Comparing public keys without verifying signature. Attacker can pass any public key without owning it. Solend attempted exploit (Aug 2021).',
    recommendation: 'Always use Signer<\'info> or verify is_signer flag. Key comparison alone is insufficient.'
  },
  {
    id: 'SOL1442',
    name: 'Authority Stored But Not Verified',
    severity: 'critical',
    pattern: /pub\s+authority:\s*Pubkey(?![\s\S]{0,200}Signer|[\s\S]{0,200}is_signer)/,
    description: 'Authority field stored as Pubkey but never enforced as signer on privileged operations.',
    recommendation: 'Use has_one constraint and Signer type for authority accounts.'
  },
  {
    id: 'SOL1443',
    name: 'AccountInfo Instead of Signer',
    severity: 'critical',
    pattern: /pub\s+(?:authority|admin|owner|signer)\s*:\s*AccountInfo(?!.*Signer)/i,
    description: 'Critical authority account declared as AccountInfo instead of Signer. No automatic signature verification.',
    recommendation: 'Replace AccountInfo with Signer<\'info> for authority accounts.'
  },
  {
    id: 'SOL1444',
    name: 'Unchecked Account Owner Program',
    severity: 'critical',
    pattern: /AccountInfo[\s\S]{0,100}(?!owner\s*==|\.owner\(\)|owner\s*=\s*&)/,
    description: 'AccountInfo used without verifying the owning program. Attacker can create fake accounts owned by SystemProgram.',
    recommendation: 'Use Account<\'info, T> which auto-verifies ownership, or manually check owner == program_id.'
  },
  {
    id: 'SOL1445',
    name: 'Fake Account via Owner Bypass',
    severity: 'critical',
    pattern: /Account<.*>[\s\S]{0,50}owner|owner\s*:\s*AccountInfo[\s\S]{0,100}(?!constraint)/i,
    description: 'Crema Finance pattern ($8.8M) - fake tick accounts accepted because ownership not validated.',
    recommendation: 'Always verify account.owner == expected_program_id before trusting account data.'
  },

  // Account Data Matching Vulnerabilities
  {
    id: 'SOL1446',
    name: 'Token Account Without Mint Constraint',
    severity: 'high',
    pattern: /Account<.*TokenAccount>[\s\S]{0,100}(?!constraint\s*=.*mint|token_account\.mint)/i,
    description: 'Token account accepted without verifying it matches expected mint. Can substitute different token.',
    recommendation: 'Add constraint = token_account.mint == expected_mint.'
  },
  {
    id: 'SOL1447',
    name: 'Pool Token Without Owner Constraint',
    severity: 'high',
    pattern: /pool_token[\s\S]{0,100}Account[\s\S]{0,100}(?!constraint\s*=.*owner|\.owner\s*==)/i,
    description: 'Pool token account lacks owner constraint. Solend oracle manipulation pattern ($1.26M).',
    recommendation: 'Verify token_account.owner == pool.key() or expected authority.'
  },
  {
    id: 'SOL1448',
    name: 'Oracle Feed Without Source Validation',
    severity: 'critical',
    pattern: /price_feed|oracle[\s\S]{0,100}(?!constraint\s*=.*address|==\s*expected)/i,
    description: 'Oracle price feed accepted without validating it\'s the correct source. Can pass manipulated feed.',
    recommendation: 'Validate oracle account address matches expected price feed for the specific asset.'
  },
  {
    id: 'SOL1449',
    name: 'Missing Relationship Constraint',
    severity: 'high',
    pattern: /constraint\s*=\s*\w+\.key\(\)[\s\S]{0,50}(?!constraint\s*=|\])/,
    description: 'Single constraint without relationship validation. All related accounts must be validated together.',
    recommendation: 'Add constraints for all account relationships: parent-child, mint-token, pool-authority.'
  },
  {
    id: 'SOL1450',
    name: 'Accepting Any Valid Type',
    severity: 'high',
    pattern: /Account<.*>[\s\S]{0,100}(?!seeds\s*=|constraint\s*=|has_one)/,
    description: 'Account accepts any instance of a type without specific instance validation.',
    recommendation: 'Use seeds, has_one, or constraint to validate specific account instances.'
  },

  // Type Cosplay Vulnerabilities
  {
    id: 'SOL1451',
    name: 'Type Cosplay - Similar Struct Layouts',
    severity: 'critical',
    pattern: /pub\s+struct\s+\w+\s*\{[\s\S]{0,100}pub\s+\w+:\s*Pubkey[\s\S]{0,100}pub\s+\w+:\s*u64/,
    description: 'Account structs with similar layouts (Pubkey + u64) vulnerable to type confusion if discriminator not checked.',
    recommendation: 'Use Anchor discriminators or implement 8-byte type identifiers at offset 0.'
  },
  {
    id: 'SOL1452',
    name: 'Manual Deserialization Without Discriminator',
    severity: 'critical',
    pattern: /try_from_slice|deserialize[\s\S]{0,50}(?!discriminator|\[0\.\.8\])/i,
    description: 'Deserializing account data without first verifying type discriminator.',
    recommendation: 'Check 8-byte discriminator before deserializing: if &data[0..8] != EXPECTED_DISC { return Err }.'
  },
  {
    id: 'SOL1453',
    name: 'Discriminator Length Too Short',
    severity: 'high',
    pattern: /discriminator.*\[u8;\s*[1-4]\]|DISC.*=.*\[[\s\S]{0,10}\]/,
    description: 'Discriminator shorter than 8 bytes increases collision probability.',
    recommendation: 'Use full 8-byte discriminators: sha256("account:TypeName")[0..8].'
  },
  {
    id: 'SOL1454',
    name: 'Shared Discriminator Prefix',
    severity: 'high',
    pattern: /discriminator\s*=.*"(vault|user|pool)".*discriminator\s*=.*"\1/i,
    description: 'Multiple account types share discriminator prefix, enabling type confusion.',
    recommendation: 'Ensure each account type has globally unique discriminator.'
  },
  {
    id: 'SOL1455',
    name: 'AccountInfo Cast Without Type Check',
    severity: 'critical',
    pattern: /AccountInfo[\s\S]{0,100}as\s*&?mut?\s*\w+|\.data\.borrow\(\)[\s\S]{0,50}as\s*&/,
    description: 'Casting AccountInfo to struct type without discriminator validation.',
    recommendation: 'Verify discriminator before interpreting account data as a specific type.'
  },

  // PDA Bump Canonicalization
  {
    id: 'SOL1456',
    name: 'Non-Canonical PDA Bump Accepted',
    severity: 'high',
    pattern: /create_program_address[\s\S]{0,100}(?!find_program_address|bump\s*==\s*canonical)/,
    description: 'Using create_program_address with arbitrary bump instead of canonical. Shadow PDAs possible.',
    recommendation: 'Always use find_program_address to get canonical bump, store it, and verify on subsequent calls.'
  },
  {
    id: 'SOL1457',
    name: 'PDA Bump Not Stored',
    severity: 'high',
    pattern: /find_program_address[\s\S]{0,100}(?!\.bump\s*=|bump:\s*bump)/,
    description: 'Finding PDA but not storing canonical bump for later validation.',
    recommendation: 'Store bump in account data: account.bump = canonical_bump;'
  },
  {
    id: 'SOL1458',
    name: 'PDA Validation Without Bump Check',
    severity: 'high',
    pattern: /seeds\s*=\s*\[[\s\S]{0,100}\][\s\S]{0,30}(?!bump\s*=|bump\s*:|canonical)/,
    description: 'PDA seeds checked but bump seed not validated against stored canonical value.',
    recommendation: 'Add bump = account.bump constraint to verify canonical PDA.'
  },
  {
    id: 'SOL1459',
    name: 'User-Supplied PDA Bump',
    severity: 'high',
    pattern: /bump\s*:\s*u8[\s\S]{0,50}(?:instruction_data|args\.|ctx\.accounts)/i,
    description: 'PDA bump taken from user input instead of derived/stored value.',
    recommendation: 'Never accept bump from user input. Always derive or retrieve from stored state.'
  },
  {
    id: 'SOL1460',
    name: 'PDA with Variable Seeds Missing Bump Storage',
    severity: 'high',
    pattern: /seeds\s*=\s*\[[\s\S]*user\.key|owner\.key[\s\S]{0,50}bump\s*\]/,
    description: 'User-specific PDA without proper bump storage mechanism.',
    recommendation: 'Store bump per-account when PDAs vary by user to prevent shadow accounts.'
  },

  // Account Reinitialization
  {
    id: 'SOL1461',
    name: 'Initialize Without Existence Check',
    severity: 'critical',
    pattern: /fn\s+initialize[\s\S]{0,200}(?!is_initialized|init\s*,|AccountAlreadyInitialized)/,
    description: 'Initialize function doesn\'t check if account already exists. Can overwrite existing data.',
    recommendation: 'Use Anchor init constraint or check is_initialized flag.'
  },
  {
    id: 'SOL1462',
    name: 'Reinitializable Account Data',
    severity: 'critical',
    pattern: /\.authority\s*=|set_authority[\s\S]{0,100}(?!is_initialized|require!)/,
    description: 'Authority can be overwritten without checking initialization state.',
    recommendation: 'Check account.is_initialized before any authority modification.'
  },
  {
    id: 'SOL1463',
    name: 'Zero Discriminator Check Missing',
    severity: 'high',
    pattern: /init[\s\S]{0,100}(?!\[0\.\.8\].*==.*0|lamports\s*==\s*0)/,
    description: 'Not checking for zero discriminator to confirm account is uninitialized.',
    recommendation: 'Verify account data starts with zeros before initialization.'
  },
  {
    id: 'SOL1464',
    name: 'Init Without Space Allocation',
    severity: 'high',
    pattern: /init[\s\S]{0,50}(?!space\s*=|allocate)/,
    description: 'Initializing without proper space allocation can cause data corruption.',
    recommendation: 'Always specify space = 8 + sizeof(AccountData) in init constraint.'
  },
  {
    id: 'SOL1465',
    name: 'Close and Reinitialize Race',
    severity: 'critical',
    pattern: /close\s*=[\s\S]{0,200}init\s*,|init[\s\S]{0,200}close\s*=/,
    description: 'Account can be closed and reinitialized in same transaction, bypassing checks.',
    recommendation: 'Add time lock between close and re-initialization.'
  },

  // Arbitrary CPI Vulnerabilities
  {
    id: 'SOL1466',
    name: 'CPI with User-Provided Program ID',
    severity: 'critical',
    pattern: /invoke[\s\S]{0,100}ctx\.accounts\.\w+\.key\(\)|CpiContext[\s\S]{0,50}program:\s*\w+\.to_account_info/,
    description: 'CPI target program taken from user input. Attacker can redirect to malicious program.',
    recommendation: 'Hardcode expected program IDs or verify against known allowlist.'
  },
  {
    id: 'SOL1467',
    name: 'CPI Without Program ID Verification',
    severity: 'critical',
    pattern: /invoke(?:_signed)?[\s\S]{0,100}(?!program_id\s*==|\.key\(\)\s*==\s*expected)/,
    description: 'Cross-program invocation without verifying target program identity.',
    recommendation: 'Always verify: target_program.key() == expected_program_id.'
  },
  {
    id: 'SOL1468',
    name: 'Token Transfer to Arbitrary Program',
    severity: 'critical',
    pattern: /transfer[\s\S]{0,100}(?!token_program\.key\(\)\s*==\s*TOKEN_PROGRAM_ID)/i,
    description: 'Token transfer CPI without verifying it goes to legit token program.',
    recommendation: 'Verify token_program.key() == spl_token::ID before any transfer CPI.'
  },
  {
    id: 'SOL1469',
    name: 'Invoke with Arbitrary Seeds',
    severity: 'high',
    pattern: /invoke_signed[\s\S]{0,100}seeds\s*:\s*&?ctx\.accounts|seeds\s*=.*args\./,
    description: 'PDA signing seeds taken from user input, allowing unauthorized signatures.',
    recommendation: 'Derive seeds from program logic, never from user input.'
  },
  {
    id: 'SOL1470',
    name: 'CPI Callback Without Validation',
    severity: 'high',
    pattern: /invoke[\s\S]{0,100}callback|after_invoke[\s\S]{0,50}(?!require!|assert)/,
    description: 'CPI callback executes without validating return state.',
    recommendation: 'Validate all state after CPI completes, don\'t trust external program behavior.'
  },

  // Integer Overflow/Underflow Patterns
  {
    id: 'SOL1471',
    name: 'Arithmetic in Fee Calculation',
    severity: 'high',
    pattern: /fee\s*=.*[\*\/][\s\S]{0,30}(?!checked_|saturating_)/i,
    description: 'Fee calculation without overflow protection can cause zero fees or massive overcharges.',
    recommendation: 'Use checked_mul and checked_div for all fee calculations.'
  },
  {
    id: 'SOL1472',
    name: 'Balance Subtraction Overflow',
    severity: 'critical',
    pattern: /balance\s*-=|balance\s*=.*-[\s\S]{0,20}(?!checked_sub|saturating_sub)/,
    description: 'Balance subtraction without underflow check can wrap to max value.',
    recommendation: 'Use balance.checked_sub(amount).ok_or(ErrorCode::InsufficientFunds)?'
  },
  {
    id: 'SOL1473',
    name: 'Supply Calculation Overflow',
    severity: 'critical',
    pattern: /total_supply\s*\+|supply\s*+=[\s\S]{0,20}(?!checked_add)/i,
    description: 'Token supply addition without overflow check enables infinite mint.',
    recommendation: 'Use checked_add for all supply modifications.'
  },
  {
    id: 'SOL1474',
    name: 'Timestamp Arithmetic',
    severity: 'high',
    pattern: /timestamp[\s\S]{0,30}[\+\-\*][\s\S]{0,20}(?!checked_|saturating_)/i,
    description: 'Time calculations without overflow protection can cause lock bypasses.',
    recommendation: 'Use checked arithmetic for all timestamp operations.'
  },
  {
    id: 'SOL1475',
    name: 'Price Multiplication Overflow',
    severity: 'high',
    pattern: /price\s*\*\s*amount|amount\s*\*\s*price[\s\S]{0,20}(?!checked_mul)/i,
    description: 'Price * amount calculation can overflow, causing wrong payment amounts.',
    recommendation: 'Use u128 for intermediate calculations or checked_mul.'
  },

  // Reentrancy and State Consistency
  {
    id: 'SOL1476',
    name: 'State Update After CPI',
    severity: 'critical',
    pattern: /invoke[\s\S]{0,200}\.\w+\s*=.*amount|invoke[\s\S]{0,200}balance\s*[+\-]=/,
    description: 'State modified after CPI completes, vulnerable to reentrancy-like attacks.',
    recommendation: 'Update all state BEFORE making CPIs (checks-effects-interactions pattern).'
  },
  {
    id: 'SOL1477',
    name: 'Reentrancy via Callback',
    severity: 'critical',
    pattern: /callback|on_complete|after_transfer[\s\S]{0,100}invoke/i,
    description: 'Callback function makes another CPI, creating reentrancy path.',
    recommendation: 'Use reentrancy guards or ensure state is finalized before callbacks.'
  },
  {
    id: 'SOL1478',
    name: 'Missing Reentrancy Guard',
    severity: 'high',
    pattern: /pub\s+fn\s+(?:withdraw|transfer|swap)[\s\S]{0,200}(?!reentrancy|guard|locked)/i,
    description: 'Critical financial function lacks reentrancy protection.',
    recommendation: 'Add reentrancy guard: if account.locked { return Err } account.locked = true;'
  },
  {
    id: 'SOL1479',
    name: 'Inconsistent State During CPI',
    severity: 'high',
    pattern: /\.amount\s*-=[\s\S]{0,50}invoke|invoke[\s\S]{0,50}\.amount\s*\+=/,
    description: 'Balance partially updated before CPI, inconsistent if CPI fails.',
    recommendation: 'Use try/catch pattern or update state atomically after CPI success.'
  },
  {
    id: 'SOL1480',
    name: 'Cross-Instruction State Leak',
    severity: 'high',
    pattern: /remaining_accounts[\s\S]{0,100}mut[\s\S]{0,50}(?!validate|require)/,
    description: 'Mutable remaining accounts can leak state between instructions.',
    recommendation: 'Validate all remaining accounts and limit mutation scope.'
  },

  // Flashloan Specific Vulnerabilities  
  {
    id: 'SOL1481',
    name: 'Flashloan Without Repayment Check',
    severity: 'critical',
    pattern: /flash_loan|flashloan[\s\S]{0,300}(?!repay|return.*amount|balance.*>=)/i,
    description: 'Flashloan issued without ensuring repayment in same transaction.',
    recommendation: 'Verify repayment amount >= borrowed + fee at end of instruction.'
  },
  {
    id: 'SOL1482',
    name: 'Flashloan Fee Bypass',
    severity: 'high',
    pattern: /flash.*fee[\s\S]{0,50}(?:==\s*0|skip|exempt)/i,
    description: 'Flashloan fee can be bypassed or set to zero.',
    recommendation: 'Enforce minimum fee and validate fee calculation cannot be manipulated.'
  },
  {
    id: 'SOL1483',
    name: 'Flashloan Oracle Manipulation Window',
    severity: 'critical',
    pattern: /flash_loan[\s\S]{0,500}get_price|oracle[\s\S]{0,500}flash_loan/i,
    description: 'Oracle price read during flashloan execution window - Mango Markets pattern ($116M).',
    recommendation: 'Use TWAP oracles or require price to be stale-checked outside flashloan.'
  },
  {
    id: 'SOL1484',
    name: 'Flashloan Collateral Manipulation',
    severity: 'critical',
    pattern: /flash[\s\S]{0,200}collateral[\s\S]{0,100}(?!snapshot|before_balance)/i,
    description: 'Collateral can be manipulated during flashloan for inflated borrowing.',
    recommendation: 'Snapshot collateral values before flashloan, verify after.'
  },
  {
    id: 'SOL1485',
    name: 'Flashloan in Liquidation',
    severity: 'high',
    pattern: /liquidate[\s\S]{0,200}flash|flash[\s\S]{0,200}liquidat/i,
    description: 'Flashloans can be used to self-liquidate at favorable rates.',
    recommendation: 'Add delay between borrowing and liquidation eligibility.'
  },

  // Oracle Security Patterns
  {
    id: 'SOL1486',
    name: 'Single Oracle Source',
    severity: 'high',
    pattern: /oracle[\s\S]{0,100}(?!backup|secondary|fallback|median)/i,
    description: 'Relying on single oracle source. Solend pattern - single pool manipulation.',
    recommendation: 'Use multiple oracle sources with median/average pricing.'
  },
  {
    id: 'SOL1487',
    name: 'Oracle Staleness Not Checked',
    severity: 'high',
    pattern: /get_price[\s\S]{0,100}(?!stale|timestamp|last_update.*<)/i,
    description: 'Using oracle price without checking if data is stale.',
    recommendation: 'Verify oracle.last_update_timestamp > current_time - MAX_STALENESS.'
  },
  {
    id: 'SOL1488',
    name: 'Oracle Confidence Interval Ignored',
    severity: 'medium',
    pattern: /pyth.*price[\s\S]{0,100}(?!conf|confidence|uncertainty)/i,
    description: 'Using Pyth price without checking confidence interval.',
    recommendation: 'Verify price.conf / price.price < MAX_CONFIDENCE_RATIO.'
  },
  {
    id: 'SOL1489',
    name: 'TWAP Window Too Short',
    severity: 'high',
    pattern: /twap.*window.*(?:\d{1,3})\s*(?:seconds?|sec)|time_window.*=.*\d{1,3}/i,
    description: 'TWAP window under 5 minutes is vulnerable to manipulation.',
    recommendation: 'Use TWAP window of at least 5-15 minutes for price calculations.'
  },
  {
    id: 'SOL1490',
    name: 'Oracle Account Not Verified',
    severity: 'critical',
    pattern: /oracle[\s\S]{0,50}AccountInfo[\s\S]{0,100}(?!\.key\(\)\s*==|constraint)/i,
    description: 'Oracle account accepted without verifying it\'s the expected feed.',
    recommendation: 'Verify oracle.key() == EXPECTED_ORACLE_ADDRESS.'
  },

  // Governance and DAO Vulnerabilities
  {
    id: 'SOL1491',
    name: 'Flash Voting Attack',
    severity: 'critical',
    pattern: /vote[\s\S]{0,200}(?!lock|snapshot|before_proposal)/i,
    description: 'Voting without token lock enables flash loan governance attacks.',
    recommendation: 'Snapshot voting power at proposal creation, require token lock period.'
  },
  {
    id: 'SOL1492',
    name: 'Proposal Execution Without Delay',
    severity: 'high',
    pattern: /execute_proposal[\s\S]{0,100}(?!timelock|delay|wait_period)/i,
    description: 'Proposals can execute immediately after passing without timelock.',
    recommendation: 'Enforce minimum timelock period (24-72h) before execution.'
  },
  {
    id: 'SOL1493',
    name: 'Quorum Too Low',
    severity: 'high',
    pattern: /quorum[\s\S]{0,30}(?:\d{1,2})%|quorum.*=.*0?\.\d{1,2}/,
    description: 'Governance quorum below 10% allows minority control.',
    recommendation: 'Set quorum to minimum 10-20% of total voting power.'
  },
  {
    id: 'SOL1494',
    name: 'Governance Proposal Injection',
    severity: 'critical',
    pattern: /proposal\.instructions[\s\S]{0,100}(?!validate|whitelist|allowed_programs)/,
    description: 'Arbitrary instructions can be injected into governance proposals.',
    recommendation: 'Whitelist allowed instruction targets and validate all proposal data.'
  },
  {
    id: 'SOL1495',
    name: 'Vote Weight Manipulation',
    severity: 'high',
    pattern: /voting_power[\s\S]{0,100}(?!snapshot|at_slot|historical)/i,
    description: 'Current balance used for voting power instead of snapshot.',
    recommendation: 'Use historical snapshot of token balance at proposal creation.'
  },

  // Token-2022 Specific Patterns
  {
    id: 'SOL1496',
    name: 'Transfer Hook Reentrancy',
    severity: 'critical',
    pattern: /transfer_hook[\s\S]{0,200}invoke|on_transfer[\s\S]{0,100}(?!guard|locked)/i,
    description: 'Token-2022 transfer hooks can create reentrancy vectors.',
    recommendation: 'Add reentrancy guards in transfer hook implementations.'
  },
  {
    id: 'SOL1497',
    name: 'Confidential Transfer Balance Leak',
    severity: 'high',
    pattern: /confidential[\s\S]{0,100}(?:log|emit|event|msg!)/i,
    description: 'Logging or emitting confidential transfer amounts defeats privacy.',
    recommendation: 'Never log confidential balances or transfer amounts.'
  },
  {
    id: 'SOL1498',
    name: 'Transfer Fee Not Accounted',
    severity: 'high',
    pattern: /transfer[\s\S]{0,100}amount[\s\S]{0,50}(?!fee|net_amount|after_fee)/i,
    description: 'Token-2022 transfer fees not deducted from expected receive amount.',
    recommendation: 'Calculate net_amount = amount - transfer_fee for Token-2022 mints.'
  },
  {
    id: 'SOL1499',
    name: 'Interest Bearing Token Exploitation',
    severity: 'high',
    pattern: /interest_bearing[\s\S]{0,100}(?!rate_change|max_rate)/i,
    description: 'Interest bearing token rate can be manipulated by authority.',
    recommendation: 'Validate interest rate changes against maximum bounds.'
  },
  {
    id: 'SOL1500',
    name: 'Permanent Delegate Abuse',
    severity: 'high',
    pattern: /permanent_delegate[\s\S]{0,100}(?!revoke|restrict|allowlist)/i,
    description: 'Permanent delegate can transfer tokens without owner consent forever.',
    recommendation: 'Implement allowlist or time-limited delegation for Token-2022.'
  },

  // Supply Chain and Infrastructure
  {
    id: 'SOL1501',
    name: 'NPM Package Address Swap',
    severity: 'critical',
    pattern: /@solana\/web3\.js.*\d+\.\d+\.\d+(?!-)|solana-web3|web3\.js/i,
    description: 'Web3.js supply chain attack (Dec 2024) - compromised versions swap addresses.',
    recommendation: 'Pin to exact known-good versions, verify package checksums, use lockfiles.'
  },
  {
    id: 'SOL1502',
    name: 'Cargo Dependency Vulnerability',
    severity: 'high',
    pattern: /anchor-lang\s*=\s*"(?:0\.[12][0-9]|0\.[0-9])"/,
    description: 'Outdated Anchor version may contain known vulnerabilities.',
    recommendation: 'Run cargo audit regularly, update to latest stable versions.'
  },
  {
    id: 'SOL1503',
    name: 'RPC Endpoint Manipulation',
    severity: 'high',
    pattern: /rpc.*endpoint.*(?:env|config|user)|connection.*new\(\s*url/i,
    description: 'RPC endpoint from user input can redirect to malicious node.',
    recommendation: 'Hardcode trusted RPC endpoints or use verified endpoint registry.'
  },
  {
    id: 'SOL1504',
    name: 'Upgrade Authority Centralization',
    severity: 'high',
    pattern: /upgrade_authority[\s\S]{0,100}(?!multisig|council|timelock)/i,
    description: 'Single upgrade authority is centralization risk and rug vector.',
    recommendation: 'Use multisig or DAO for program upgrade authority.'
  },
  {
    id: 'SOL1505',
    name: 'Private Key in Environment',
    severity: 'critical',
    pattern: /PRIVATE_KEY|SECRET_KEY|KEYPAIR.*env|process\.env.*key/i,
    description: 'Private keys stored in environment variables can leak in logs.',
    recommendation: 'Use hardware wallets, HSMs, or secure key management services.'
  },

  // DEXX Specific Patterns ($30M Nov 2024)
  {
    id: 'SOL1506',
    name: 'Hot Wallet Key Exposure',
    severity: 'critical',
    pattern: /hot_wallet|trading_wallet[\s\S]{0,100}(?!hardware|hsm|coldstart)/i,
    description: 'DEXX pattern - hot wallet private keys exposed through poor key management.',
    recommendation: 'Use cold storage for majority of funds, hardware signing for hot wallets.'
  },
  {
    id: 'SOL1507',
    name: 'Centralized Custody Architecture',
    severity: 'high',
    pattern: /custody[\s\S]{0,100}(?!multisig|mpc|threshold|distributed)/i,
    description: 'Centralized custody is single point of failure - DEXX lost $30M.',
    recommendation: 'Implement MPC or multisig for any custodial funds.'
  },
  {
    id: 'SOL1508',
    name: 'User Funds in Platform Wallet',
    severity: 'critical',
    pattern: /deposit.*platform|user.*funds.*pool[\s\S]{0,100}(?!escrow|segregated)/i,
    description: 'Commingling user funds in platform wallet enables total loss.',
    recommendation: 'Segregate user funds in individual escrow accounts or PDAs.'
  },
  {
    id: 'SOL1509',
    name: 'No Withdrawal Limits',
    severity: 'high',
    pattern: /withdraw[\s\S]{0,200}(?!limit|max.*amount|daily.*cap|rate_limit)/i,
    description: 'No withdrawal limits allows instant drainage if keys compromised.',
    recommendation: 'Implement daily/hourly withdrawal limits with escalation for larger amounts.'
  },
  {
    id: 'SOL1510',
    name: 'Missing Cold Storage Architecture',
    severity: 'high',
    pattern: /treasury|reserve|pool[\s\S]{0,100}(?!cold|offline|airgapped)/i,
    description: 'No cold storage for reserves means all funds at risk from key compromise.',
    recommendation: 'Keep 90%+ of funds in cold storage with airgapped signing.'
  },
];

/**
 * Run batch 45 patterns
 */
export function runBatch45Patterns(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';
  const fileName = input.path || 'unknown';
  
  if (!content) return findings;
  
  const lines = content.split('\n');
  
  for (const pattern of BATCH_45_PATTERNS) {
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

export { BATCH_45_PATTERNS };
export default BATCH_45_PATTERNS;
