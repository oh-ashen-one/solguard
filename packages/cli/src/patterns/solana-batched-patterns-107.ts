/**
 * Batch 107: DEV.to 15 Critical Vulnerabilities + Helius Complete Exploit History
 * 
 * Sources:
 * 1. DEV.to: "Solana Vulnerabilities Every Developer Should Know" (Feb 2026)
 *    - 15 critical vulnerabilities with real exploit examples
 * 2. Helius Complete History (38 verified incidents, ~$600M gross losses)
 *    - Solend Auth Bypass ($16k), Audius Governance ($6.1M), Nirvana ($3.5M)
 *    - OptiFi Lockup ($661k), UXD/Tulip Mango exposure, Solareum, Aurory, Saga DAO
 * 3. Real-world exploit analysis from $450M+ in losses 2021-2025
 * 
 * Pattern IDs: SOL6901-SOL7050
 */

import type { PatternInput, Finding } from './index.js';

interface PatternDef {
  id: string;
  name: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  pattern: RegExp;
  description: string;
  recommendation: string;
}

const BATCH_107_PATTERNS: PatternDef[] = [
  // ============================================
  // DEV.to VULNERABILITY #1: MISSING SIGNER CHECK (SOL6901-SOL6910)
  // Real exploit: Solend $2M attempted bypass (Aug 2021)
  // ============================================
  {
    id: 'SOL6901',
    name: 'DEV.to #1: Authority Without Signer Constraint',
    severity: 'critical',
    pattern: /authority[\s\S]{0,50}AccountInfo(?![\s\S]{0,30}Signer)/i,
    description: 'Authority account using AccountInfo instead of Signer. Solend nearly lost $2M in Aug 2021 from bypassed admin checks.',
    recommendation: 'Use Signer<\'info> instead of AccountInfo for all authority accounts.'
  },
  {
    id: 'SOL6902',
    name: 'DEV.to #1: is_signer Check Missing',
    severity: 'critical',
    pattern: /(?:authority|admin|owner)[\s\S]{0,100}(?:\.key\(\)|\.key)[\s\S]{0,50}(?!is_signer)/i,
    description: 'Authority key check without is_signer verification. Attacker can pass any pubkey without owning private key.',
    recommendation: 'Always verify is_signer for authority accounts before processing.'
  },
  {
    id: 'SOL6903',
    name: 'DEV.to #1: Vault Authority Key Match Only',
    severity: 'critical',
    pattern: /vault\.authority\s*==[\s\S]{0,50}(?!is_signer|Signer)/i,
    description: 'Checking vault.authority == passed_key without signature verification.',
    recommendation: 'Add: if !authority.is_signer { return Err(...) }'
  },
  {
    id: 'SOL6904',
    name: 'DEV.to #1: Privileged Action Without Signer',
    severity: 'critical',
    pattern: /(?:withdraw|transfer|update_config|set_authority)[\s\S]{0,200}AccountInfo[\s\S]{0,100}(?!is_signer|Signer)/i,
    description: 'Privileged action handler accepting AccountInfo without signer verification.',
    recommendation: 'Use Signer<\'info> for all privileged operations.'
  },

  // ============================================
  // DEV.to VULNERABILITY #2: MISSING OWNER CHECK (SOL6911-SOL6920)
  // Real exploits: Solend Aug 2021, Crema Finance $8.8M Jul 2022
  // ============================================
  {
    id: 'SOL6911',
    name: 'DEV.to #2: Account Owner Not Verified',
    severity: 'critical',
    pattern: /AccountInfo[\s\S]{0,200}(?!owner\s*==|\.owner\(\)\s*==|Program<)/i,
    description: 'Using AccountInfo without verifying owner. Crema lost $8.8M to fake tick accounts.',
    recommendation: 'Always verify account.owner == program_id for program-owned accounts.'
  },
  {
    id: 'SOL6912',
    name: 'DEV.to #2: Fake Account Vulnerability',
    severity: 'critical',
    pattern: /(?:tick|position|pool|vault)[\s\S]{0,100}AccountInfo(?![\s\S]{0,100}owner)/i,
    description: 'Critical account type without owner check. Attackers can create fake accounts with identical data layout.',
    recommendation: 'Use Account<\'info, T> which automatically verifies ownership.'
  },
  {
    id: 'SOL6913',
    name: 'DEV.to #2: Price Data Account Spoofing',
    severity: 'critical',
    pattern: /(?:price|oracle|feed)[\s\S]{0,100}AccountInfo(?![\s\S]{0,100}owner)/i,
    description: 'Oracle/price account without owner verification. Enables fake price data injection.',
    recommendation: 'Verify oracle account is owned by trusted oracle program.'
  },
  {
    id: 'SOL6914',
    name: 'DEV.to #2: Lending Market Spoofing',
    severity: 'critical',
    pattern: /(?:market|lending|pool)[\s\S]{0,100}data\(\)(?![\s\S]{0,100}owner)/i,
    description: 'Reading lending market data without ownership check. Solend exploit pattern.',
    recommendation: 'Validate market account owner before reading configuration.'
  },

  // ============================================
  // DEV.to VULNERABILITY #3: ACCOUNT DATA MATCHING (SOL6921-SOL6930)
  // Real exploit: Solend oracle manipulation Nov 2022 ($1.26M)
  // ============================================
  {
    id: 'SOL6921',
    name: 'DEV.to #3: Token Account Mint Mismatch',
    severity: 'high',
    pattern: /token_account[\s\S]{0,100}(?!mint\s*==|constraint\s*=\s*.*mint)/i,
    description: 'Token account without mint verification. Attacker can substitute token account with different mint.',
    recommendation: 'Add constraint: user_token.mint == pool.mint'
  },
  {
    id: 'SOL6922',
    name: 'DEV.to #3: Pool Token Mismatch',
    severity: 'high',
    pattern: /(?:pool|vault)[\s\S]{0,50}token[\s\S]{0,100}(?!constraint|mint\s*==)/i,
    description: 'Pool/vault token relationship not validated. Enables token substitution attacks.',
    recommendation: 'Validate mint relationships: pool.token_mint == token_account.mint'
  },
  {
    id: 'SOL6923',
    name: 'DEV.to #3: Single Oracle Price Source',
    severity: 'high',
    pattern: /(?:price|oracle)[\s\S]{0,100}(?:get_price|load)(?![\s\S]{0,200}(?:twap|multiple|aggregate))/i,
    description: 'Single price source without validation. Solend lost $1.26M to single-pool oracle manipulation.',
    recommendation: 'Use TWAP or aggregate prices from multiple sources.'
  },
  {
    id: 'SOL6924',
    name: 'DEV.to #3: Context Relationship Missing',
    severity: 'high',
    pattern: /(?:user_token|source|destination)[\s\S]{0,100}Account<[\s\S]{0,100}(?!constraint)/i,
    description: 'Account relationships not constrained. Type checks pass but context is wrong.',
    recommendation: 'Add constraints for all account relationships.'
  },

  // ============================================
  // DEV.to VULNERABILITY #4: TYPE COSPLAY (SOL6931-SOL6940)
  // Found in multiple audits - account type confusion
  // ============================================
  {
    id: 'SOL6931',
    name: 'DEV.to #4: Missing Account Discriminator',
    severity: 'critical',
    pattern: /pub\s+struct\s+\w+\s*\{(?![\s\S]{0,50}discriminator)/i,
    description: 'Account struct without discriminator. Different account types can be confused if fields align.',
    recommendation: 'Use Anchor #[account] which adds automatic 8-byte discriminator.'
  },
  {
    id: 'SOL6932',
    name: 'DEV.to #4: Manual Deserialization Risk',
    severity: 'high',
    pattern: /try_from_slice|deserialize(?![\s\S]{0,100}discriminator)/i,
    description: 'Manual deserialization without discriminator check. Enables type cosplay attacks.',
    recommendation: 'Check discriminator before deserializing: if disc != EXPECTED_DISC { return Err(...) }'
  },
  {
    id: 'SOL6933',
    name: 'DEV.to #4: Overlapping Field Offsets',
    severity: 'high',
    pattern: /\[offset\s*=\s*\d+\][\s\S]{0,200}\[offset\s*=\s*\d+\]/i,
    description: 'Manual field offsets can create overlap vulnerabilities with other types.',
    recommendation: 'Use unique discriminators per type or Anchor automatic handling.'
  },

  // ============================================
  // DEV.to VULNERABILITY #5: PDA BUMP CANONICALIZATION (SOL6941-SOL6950)
  // Found in numerous audits - shadow PDA attacks
  // ============================================
  {
    id: 'SOL6941',
    name: 'DEV.to #5: Non-Canonical Bump Accepted',
    severity: 'high',
    pattern: /create_program_address(?![\s\S]{0,100}find_program_address)/i,
    description: 'Using create_program_address without finding canonical bump. Shadow PDAs possible.',
    recommendation: 'Always use find_program_address to get canonical bump, then store it.'
  },
  {
    id: 'SOL6942',
    name: 'DEV.to #5: Bump Not Stored',
    severity: 'high',
    pattern: /find_program_address[\s\S]{0,100}(?!bump\s*=|\.bump\s*=)/i,
    description: 'Finding PDA without storing the bump seed. Cannot verify canonical PDA later.',
    recommendation: 'Store canonical bump in account: vault.bump = bump;'
  },
  {
    id: 'SOL6943',
    name: 'DEV.to #5: Bump Not Verified',
    severity: 'high',
    pattern: /seeds\s*=\s*\[[\s\S]{0,100}\](?![\s\S]{0,50}bump\s*=)/i,
    description: 'PDA seeds without bump verification in Anchor. Non-canonical PDAs accepted.',
    recommendation: 'Add bump = vault.bump to verify canonical PDA.'
  },

  // ============================================
  // DEV.to VULNERABILITY #6: ACCOUNT REINITIALIZATION (SOL6951-SOL6960)
  // Early Solana programs, security review after Slope
  // ============================================
  {
    id: 'SOL6951',
    name: 'DEV.to #6: Initialize Without Init Check',
    severity: 'critical',
    pattern: /(?:pub\s+fn|fn)\s+initialize[\s\S]{0,200}(?!is_initialized|init\s)/i,
    description: 'Initialize function without checking if already initialized. Account can be overwritten.',
    recommendation: 'Use Anchor init constraint or check is_initialized flag.'
  },
  {
    id: 'SOL6952',
    name: 'DEV.to #6: Authority Overwrite Possible',
    severity: 'critical',
    pattern: /authority\s*=[\s\S]{0,50}(?!if\s+!|require!|assert!)/i,
    description: 'Authority field assignment without initialization check. Attacker can take over account.',
    recommendation: 'Check is_initialized before setting authority: if !is_initialized { ... }'
  },
  {
    id: 'SOL6953',
    name: 'DEV.to #6: Missing Discriminator Set',
    severity: 'high',
    pattern: /(?:pub\s+fn|fn)\s+initialize[\s\S]{0,300}(?!discriminator|init\s)/i,
    description: 'Initialize without setting discriminator. Reinitialization detection fails.',
    recommendation: 'Set discriminator on init: account.discriminator = VAULT_DISCRIMINATOR;'
  },

  // ============================================
  // DEV.to VULNERABILITY #7: ARBITRARY CPI (SOL6961-SOL6970)
  // Found regularly in audits - program impersonation
  // ============================================
  {
    id: 'SOL6961',
    name: 'DEV.to #7: User-Supplied Program ID',
    severity: 'critical',
    pattern: /invoke[\s\S]{0,100}(?:program_id|program\.key)(?![\s\S]{0,50}==)/i,
    description: 'CPI with user-supplied program ID. Attacker can redirect to malicious program.',
    recommendation: 'Hardcode expected program IDs: const TOKEN_PROGRAM_ID = ...'
  },
  {
    id: 'SOL6962',
    name: 'DEV.to #7: Token Program Not Verified',
    severity: 'critical',
    pattern: /(?:token_program|token_prog)[\s\S]{0,50}AccountInfo(?![\s\S]{0,100}Program<)/i,
    description: 'Token program as AccountInfo without verification. CPI could go to attacker program.',
    recommendation: 'Use Program<\'info, Token> to enforce program identity.'
  },
  {
    id: 'SOL6963',
    name: 'DEV.to #7: CPI Without Program Check',
    severity: 'critical',
    pattern: /invoke_signed[\s\S]{0,200}(?!program_id\s*==|IncorrectProgramId)/i,
    description: 'invoke_signed without verifying target program. PDA signatures sent to unknown program.',
    recommendation: 'Always verify: if program.key != EXPECTED_ID { return Err(...) }'
  },

  // ============================================
  // DEV.to VULNERABILITY #8: INTEGER OVERFLOW (SOL6971-SOL6980)
  // Real exploit: Nirvana Finance $3.5M Jul 2022
  // ============================================
  {
    id: 'SOL6971',
    name: 'DEV.to #8: Unchecked Subtraction',
    severity: 'high',
    pattern: /balance\s*-\s*amount(?![\s\S]{0,30}checked_sub)/i,
    description: 'Unchecked subtraction can underflow. 10 - 11 = 18446744073709551615 (u64 max).',
    recommendation: 'Use: balance.checked_sub(amount).ok_or(InsufficientFunds)?'
  },
  {
    id: 'SOL6972',
    name: 'DEV.to #8: Unchecked Addition',
    severity: 'high',
    pattern: /balance\s*\+\s*(?:amount|value)(?![\s\S]{0,30}checked_add)/i,
    description: 'Unchecked addition can overflow. Balance wraps to small value.',
    recommendation: 'Use: balance.checked_add(amount).ok_or(Overflow)?'
  },
  {
    id: 'SOL6973',
    name: 'DEV.to #8: Unchecked Multiplication',
    severity: 'high',
    pattern: /(?:amount|price|rate)\s*\*\s*\w+(?![\s\S]{0,30}checked_mul)/i,
    description: 'Unchecked multiplication in financial calculation. Can overflow silently.',
    recommendation: 'Use: value.checked_mul(multiplier).ok_or(Overflow)?'
  },
  {
    id: 'SOL6974',
    name: 'DEV.to #8: Release Profile Missing Overflow Check',
    severity: 'medium',
    pattern: /\[profile\.release\](?![\s\S]{0,100}overflow-checks\s*=\s*true)/i,
    description: 'Release profile without overflow checks. Arithmetic panics only in debug.',
    recommendation: 'Add to Cargo.toml: [profile.release] overflow-checks = true'
  },
  {
    id: 'SOL6975',
    name: 'DEV.to #8: Nirvana Bonding Curve Pattern',
    severity: 'critical',
    pattern: /(?:bonding_curve|price_curve)[\s\S]{0,200}(?:flash|loan)(?![\s\S]{0,100}protection)/i,
    description: 'Bonding curve vulnerable to flash loan manipulation. Nirvana lost $3.5M.',
    recommendation: 'Add flash loan protection to bonding curve calculations.'
  },

  // ============================================
  // DEV.to VULNERABILITY #9: ACCOUNT REVIVAL (SOL6981-SOL6990)
  // Persistent issue, Raydium security review focus
  // ============================================
  {
    id: 'SOL6981',
    name: 'DEV.to #9: Close Without Zero Data',
    severity: 'high',
    pattern: /lamports[\s\S]{0,50}=\s*0(?![\s\S]{0,100}(?:fill\(0\)|data\.fill|zero))/i,
    description: 'Account closure transferring lamports without zeroing data. Account can be revived.',
    recommendation: 'Zero all data before closing: account.data.fill(0);'
  },
  {
    id: 'SOL6982',
    name: 'DEV.to #9: Stale Authority After Close',
    severity: 'high',
    pattern: /close[\s\S]{0,100}destination(?![\s\S]{0,100}(?:zero|fill\(0\)|close\s*=))/i,
    description: 'Manual close without using Anchor close constraint. Data remains intact.',
    recommendation: 'Use Anchor: #[account(mut, close = destination)]'
  },
  {
    id: 'SOL6983',
    name: 'DEV.to #9: Revivable Account Pattern',
    severity: 'high',
    pattern: /transfer.*lamports[\s\S]{0,200}(?!realloc\(0|fill\(0\)|close\s*=)/i,
    description: 'Lamport transfer in close operation without data clear. Revival possible.',
    recommendation: 'Clear discriminator and data before lamport transfer.'
  },

  // ============================================
  // DEV.to VULNERABILITY #10: DUPLICATE MUTABLE (SOL6991-SOL7000)
  // Jet Protocol potential $25M Dec 2021
  // ============================================
  {
    id: 'SOL6991',
    name: 'DEV.to #10: Same Account as Source and Dest',
    severity: 'high',
    pattern: /(?:source|from)[\s\S]{0,100}(?:destination|to)[\s\S]{0,100}(?!key\(\)\s*!=|constraint.*!=)/i,
    description: 'Source and destination accounts not checked for equality. Jet Protocol pattern.',
    recommendation: 'Add constraint: source.key() != destination.key()'
  },
  {
    id: 'SOL6992',
    name: 'DEV.to #10: Double Mutable Reference',
    severity: 'high',
    pattern: /#\[account\(mut\)\][\s\S]{0,50}pub\s+\w+[\s\S]{0,100}#\[account\(mut\)\][\s\S]{0,50}pub\s+\w+(?![\s\S]{0,100}constraint)/i,
    description: 'Two mutable accounts of same type without differentiation constraint.',
    recommendation: 'Add constraint to ensure accounts are different.'
  },
  {
    id: 'SOL6993',
    name: 'DEV.to #10: Self-Transfer Vulnerability',
    severity: 'high',
    pattern: /transfer[\s\S]{0,100}(?:from|source)[\s\S]{0,100}(?:to|dest)(?![\s\S]{0,100}!=)/i,
    description: 'Transfer without checking source != destination. Can create tokens from nothing.',
    recommendation: 'Validate: if from.key() == to.key() { return Err(...) }'
  },

  // ============================================
  // DEV.to VULNERABILITY #11: INSECURE RANDOMNESS (SOL7001-SOL7010)
  // NFT mints and gaming exploits
  // ============================================
  {
    id: 'SOL7001',
    name: 'DEV.to #11: Slot-Based Randomness',
    severity: 'high',
    pattern: /Clock[\s\S]{0,50}slot[\s\S]{0,50}%/i,
    description: 'Using slot number for randomness. Completely predictable and exploitable.',
    recommendation: 'Use Switchboard VRF, Chainlink VRF, or commit-reveal scheme.'
  },
  {
    id: 'SOL7002',
    name: 'DEV.to #11: Timestamp-Based Randomness',
    severity: 'high',
    pattern: /(?:unix_timestamp|Clock::get)[\s\S]{0,100}(?:rand|random|%)/i,
    description: 'Using timestamp for randomness. Validators can manipulate within tolerance.',
    recommendation: 'Use verifiable random function (VRF) for any random selection.'
  },
  {
    id: 'SOL7003',
    name: 'DEV.to #11: Blockhash Randomness',
    severity: 'high',
    pattern: /(?:recent_blockhash|blockhash)[\s\S]{0,100}(?:rand|random|%|hash)/i,
    description: 'Using blockhash for randomness. Known before transaction execution.',
    recommendation: 'Implement commit-reveal or use on-chain VRF oracle.'
  },
  {
    id: 'SOL7004',
    name: 'DEV.to #11: NFT Trait Predictability',
    severity: 'medium',
    pattern: /(?:trait|rarity|attribute)[\s\S]{0,100}(?:slot|timestamp|hash)/i,
    description: 'NFT trait generation using predictable on-chain values. Farming possible.',
    recommendation: 'Use VRF for trait assignment or off-chain reveal.'
  },

  // ============================================
  // DEV.to VULNERABILITY #12: SYSVAR VALIDATION (SOL7011-SOL7020)
  // Real exploit: Wormhole $325M Feb 2022
  // ============================================
  {
    id: 'SOL7011',
    name: 'DEV.to #12: Wormhole Sysvar Pattern',
    severity: 'critical',
    pattern: /load_instruction_at(?![\s\S]{0,100}sysvar::instructions::ID)/i,
    description: 'CRITICAL: Wormhole $325M exploit pattern. load_instruction_at without sysvar verification.',
    recommendation: 'Always verify: #[account(address = sysvar::instructions::ID)]'
  },
  {
    id: 'SOL7012',
    name: 'DEV.to #12: Fake Instructions Sysvar',
    severity: 'critical',
    pattern: /instructions[\s\S]{0,50}AccountInfo(?![\s\S]{0,100}(?:sysvar|address\s*=))/i,
    description: 'Instructions sysvar as AccountInfo without address check. Fake sysvar injection possible.',
    recommendation: 'Use: #[account(address = sysvar::instructions::ID)]'
  },
  {
    id: 'SOL7013',
    name: 'DEV.to #12: Clock Sysvar Spoofing',
    severity: 'high',
    pattern: /clock[\s\S]{0,50}AccountInfo(?![\s\S]{0,100}(?:Sysvar|address\s*=))/i,
    description: 'Clock sysvar without verification. Fake timestamps injectable.',
    recommendation: 'Use Clock::get()? or verify address == sysvar::clock::ID'
  },
  {
    id: 'SOL7014',
    name: 'DEV.to #12: Rent Sysvar Spoofing',
    severity: 'medium',
    pattern: /rent[\s\S]{0,50}AccountInfo(?![\s\S]{0,100}(?:Sysvar|address\s*=))/i,
    description: 'Rent sysvar without verification. Fake rent exemption data injectable.',
    recommendation: 'Use Rent::get()? or verify address == sysvar::rent::ID'
  },

  // ============================================
  // HELIUS: SOLEND AUTH BYPASS (SOL7021-SOL7025)
  // Aug 2021 - $2M at risk, $16k lost, 41-min detection
  // ============================================
  {
    id: 'SOL7021',
    name: 'Helius: Solend UpdateReserveConfig Pattern',
    severity: 'critical',
    pattern: /(?:update|modify)[\s\S]{0,50}(?:reserve|config|param)[\s\S]{0,100}(?!has_one|constraint)/i,
    description: 'Solend-style config update without proper constraints. Aug 2021: $2M at risk.',
    recommendation: 'Add has_one constraint for lending market authority.'
  },
  {
    id: 'SOL7022',
    name: 'Helius: Lending Market Authority Bypass',
    severity: 'critical',
    pattern: /lending_market[\s\S]{0,100}authority(?![\s\S]{0,100}has_one)/i,
    description: 'Lending market authority check bypassable by creating fake market.',
    recommendation: 'Verify lending_market is trusted before checking its authority.'
  },
  {
    id: 'SOL7023',
    name: 'Helius: Liquidation Parameter Manipulation',
    severity: 'critical',
    pattern: /liquidation[\s\S]{0,100}(?:threshold|bonus|penalty)[\s\S]{0,100}(?!bounds|limit|range)/i,
    description: 'Liquidation parameters without bounds checking. Solend: threshold=1%, bonus=90%.',
    recommendation: 'Enforce reasonable bounds: threshold > 80%, bonus < 20%'
  },

  // ============================================
  // HELIUS: AUDIUS GOVERNANCE (SOL7026-SOL7030)
  // Jul 2022 - $6.1M stolen from treasury
  // ============================================
  {
    id: 'SOL7026',
    name: 'Helius: Audius Governance Proposal Bypass',
    severity: 'critical',
    pattern: /(?:proposal|governance)[\s\S]{0,100}(?:submit|execute)(?![\s\S]{0,200}timelock)/i,
    description: 'Audius pattern: Governance proposal execution without timelock. $6.1M lost.',
    recommendation: 'Add mandatory timelock between proposal submission and execution.'
  },
  {
    id: 'SOL7027',
    name: 'Helius: Treasury Permission Reconfiguration',
    severity: 'critical',
    pattern: /treasury[\s\S]{0,100}(?:permission|authority|config)[\s\S]{0,100}(?!multisig|timelock)/i,
    description: 'Treasury permissions modifiable without delay. Audius treasury drained.',
    recommendation: 'Require multisig + timelock for treasury configuration changes.'
  },

  // ============================================
  // HELIUS: OPTIFI PROGRAM CLOSURE (SOL7031-SOL7035)
  // Aug 2022 - $661k locked forever, coding error
  // ============================================
  {
    id: 'SOL7031',
    name: 'Helius: OptiFi Program Close Pattern',
    severity: 'critical',
    pattern: /(?:program|contract)[\s\S]{0,50}close(?![\s\S]{0,100}(?:peer_review|multi_sig|confirm))/i,
    description: 'OptiFi pattern: Program closure without peer review. $661k locked permanently.',
    recommendation: 'Require 3+ team member review for program close operations.'
  },
  {
    id: 'SOL7032',
    name: 'Helius: Irreversible Operation Without Confirmation',
    severity: 'high',
    pattern: /(?:close|terminate|shutdown)[\s\S]{0,100}mainnet(?![\s\S]{0,100}confirm)/i,
    description: 'Irreversible mainnet operation without confirmation step.',
    recommendation: 'Add confirmation dialog/delay for destructive operations.'
  },

  // ============================================
  // HELIUS: UXD/TULIP MANGO EXPOSURE (SOL7036-SOL7040)
  // Oct 2022 - $19.9M + $2.5M exposure from Mango exploit
  // ============================================
  {
    id: 'SOL7036',
    name: 'Helius: Protocol Dependency Concentration',
    severity: 'high',
    pattern: /(?:deposit|lend|stake)[\s\S]{0,100}(?:mango|raydium|solend)[\s\S]{0,100}(?!diversif|limit)/i,
    description: 'Single protocol dependency. UXD had $19.9M frozen in Mango during exploit.',
    recommendation: 'Diversify protocol dependencies and set exposure limits.'
  },
  {
    id: 'SOL7037',
    name: 'Helius: Third-Party Risk Management',
    severity: 'medium',
    pattern: /(?:external|third_party|partner)[\s\S]{0,100}(?:pool|vault|protocol)(?![\s\S]{0,100}insurance)/i,
    description: 'Third-party protocol integration without insurance fund. Tulip pattern.',
    recommendation: 'Maintain insurance fund for external protocol exposure.'
  },

  // ============================================
  // HELIUS: SOLAREUM PHISHING (SOL7041-SOL7045)
  // 2023 - Private key exposure through phishing
  // ============================================
  {
    id: 'SOL7041',
    name: 'Helius: Private Key in Environment',
    severity: 'critical',
    pattern: /(?:PRIVATE_KEY|SECRET_KEY|ADMIN_KEY)[\s\S]{0,30}(?:env|process\.env|std::env)/i,
    description: 'Private key in environment variable. Phishing/social engineering risk.',
    recommendation: 'Use HSM or multisig for admin keys. Never single-key in env.'
  },
  {
    id: 'SOL7042',
    name: 'Helius: Admin Key Single Point of Failure',
    severity: 'critical',
    pattern: /admin(?:_key|_authority)[\s\S]{0,100}Pubkey(?![\s\S]{0,100}multisig)/i,
    description: 'Single admin key without multisig. Phishing one key compromises protocol.',
    recommendation: 'Use 2-of-3 or 3-of-5 multisig for all admin operations.'
  },

  // ============================================
  // HELIUS: PUMP.FUN INSIDER (SOL7046-SOL7050)
  // May 2024 - $1.9M employee exploit
  // ============================================
  {
    id: 'SOL7046',
    name: 'Helius: Pump.fun Early Access Pattern',
    severity: 'high',
    pattern: /(?:launch|sale|mint)[\s\S]{0,100}early(?![\s\S]{0,100}(?:delay|lock|vesting))/i,
    description: 'Launch mechanism without delay. Pump.fun employee exploited early access.',
    recommendation: 'Add launch delay and lock periods to prevent insider front-running.'
  },
  {
    id: 'SOL7047',
    name: 'Helius: Bonding Curve Privileged Access',
    severity: 'high',
    pattern: /bonding[\s\S]{0,100}(?:admin|owner|operator)(?![\s\S]{0,100}timelock)/i,
    description: 'Bonding curve with privileged operations. Insider can manipulate launch.',
    recommendation: 'Time-lock all bonding curve modifications.'
  },
  {
    id: 'SOL7048',
    name: 'Helius: Employee Access Control',
    severity: 'medium',
    pattern: /(?:employee|operator|team)[\s\S]{0,100}(?:access|privilege|role)(?![\s\S]{0,100}audit)/i,
    description: 'Employee access without audit trail. Pump.fun insider threat pattern.',
    recommendation: 'Implement comprehensive access logging and regular audits.'
  },

  // ============================================
  // ADDITIONAL HELIUS PATTERNS (SOL7049-SOL7050)
  // ============================================
  {
    id: 'SOL7049',
    name: 'Helius: Raydium Admin Key Compromise Pattern',
    severity: 'critical',
    pattern: /pool[\s\S]{0,100}admin[\s\S]{0,100}(?:withdraw|drain)(?![\s\S]{0,100}multisig)/i,
    description: 'Pool admin operations without multisig. Raydium lost $4.4M to key compromise.',
    recommendation: 'Implement multisig for all pool admin functions.'
  },
  {
    id: 'SOL7050',
    name: 'Helius: SVT Token Infinite Mint',
    severity: 'critical',
    pattern: /mint[\s\S]{0,100}(?:amount|quantity)(?![\s\S]{0,100}(?:cap|max_supply|limit))/i,
    description: 'Mint function without supply cap. CertiK alerted SVT Token infinite mint.',
    recommendation: 'Enforce max supply: require!(total_supply + amount <= MAX_SUPPLY)'
  },
];

/**
 * Run Batch 107 patterns
 */
export function checkBatch107Patterns(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';
  const fileName = input.path || input.rust?.filePath || 'unknown';
  
  if (!content) return findings;
  
  const lines = content.split('\n');
  
  for (const pattern of BATCH_107_PATTERNS) {
    try {
      const flags = pattern.pattern.flags.includes('g') ? pattern.pattern.flags : pattern.pattern.flags + 'g';
      const regex = new RegExp(pattern.pattern.source, flags);
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
          location: { file: fileName, line: lineNum },
          recommendation: pattern.recommendation,
          code: snippet.substring(0, 200),
        });
      }
    } catch (error) {
      // Skip pattern on error
    }
  }
  
  return findings;
}

export { BATCH_107_PATTERNS };
