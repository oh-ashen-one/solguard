/**
 * SolGuard Batch 78 Security Patterns
 * Based on: Step Finance $30M Hack (Jan 31, 2026), DEV.to Deep Dive, NoOnes Bridge, Feb 2026 Threats
 * 
 * Pattern IDs: SOL3876 - SOL3975 (100 patterns)
 * Created: Feb 6, 2026 1:00 AM CST
 * 
 * Sources:
 * - Step Finance Treasury Breach (Jan 31, 2026 - $30M+)
 * - DEV.to "Solana Vulnerabilities Every Developer Should Know" (Feb 2026)
 * - NoOnes P2P Bridge Exploit ($8M, Jan 2025)
 * - CryptoSlate Solana Vulnerabilities Disclosure (Dec 2025)
 * - CertiK January 2026 Report ($400M+ total losses)
 * - Upbit Hot Wallet Pattern ($36M, Nov 2025)
 */

import type { Finding, PatternInput } from './index.js';

// ============================================================================
// STEP FINANCE TREASURY BREACH PATTERNS (Jan 31, 2026)
// ============================================================================

const STEP_FINANCE_PATTERNS: {
  id: string;
  name: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  pattern: RegExp;
  description: string;
  recommendation: string;
}[] = [
  {
    id: 'SOL3876',
    name: 'Step Finance - Treasury Wallet Without Multisig',
    severity: 'critical',
    pattern: /(?:treasury|protocol_wallet|reserve)[\s\S]{0,100}(?:Signer|authority)[\s\S]{0,50}(?!multisig|threshold|quorum)/i,
    description: 'Treasury wallet controlled by single signer. Step Finance lost $30M+ when treasury keys were compromised.',
    recommendation: 'Implement multisig (2-of-3 or higher) for all treasury operations. Use Squads or similar.'
  },
  {
    id: 'SOL3877',
    name: 'Step Finance - Executive Key Exposure',
    severity: 'critical',
    pattern: /(?:admin|owner|authority)[\s\S]{0,80}(?:single|solo|direct)[\s\S]{0,50}(?:transfer|withdraw|drain)/i,
    description: 'Single executive key controls critical operations. Step Finance breach involved executive wallet compromise.',
    recommendation: 'Distribute authority across multiple keys with threshold requirements.'
  },
  {
    id: 'SOL3878',
    name: 'Step Finance - Commission Fund Drain Risk',
    severity: 'high',
    pattern: /(?:commission|fee|revenue)[\s\S]{0,80}(?:withdraw|transfer|claim)[\s\S]{0,50}(?!timelock|delay|multisig)/i,
    description: 'Commission funds withdrawable without delay. Step Finance treasury included accumulated fees.',
    recommendation: 'Implement withdrawal delays and multisig for protocol fees.'
  },
  {
    id: 'SOL3879',
    name: 'Step Finance - Monero Conversion Risk',
    severity: 'high',
    pattern: /(?:bridge|swap|convert)[\s\S]{0,100}(?:cross.?chain|external|off.?chain)/i,
    description: 'Stolen funds were rapidly converted to Monero for obfuscation. Consider tracking mechanisms.',
    recommendation: 'Implement large transfer delays and circuit breakers for suspicious conversion patterns.'
  },
  {
    id: 'SOL3880',
    name: 'Step Finance - STEP Token Price Impact',
    severity: 'medium',
    pattern: /(?:token|native)[\s\S]{0,80}(?:price|value)[\s\S]{0,50}(?:treasury|protocol)/i,
    description: 'Treasury breach caused STEP token to crater. Protocol token should have protective mechanisms.',
    recommendation: 'Implement buyback mechanisms and treasury diversification.'
  },
  {
    id: 'SOL3881',
    name: 'Step Finance - Hot Wallet Authority Pattern',
    severity: 'critical',
    pattern: /(?:hot.?wallet|operational|active)[\s\S]{0,80}(?:authority|admin|owner)[\s\S]{0,50}(?:treasury|reserve)/i,
    description: 'Hot wallet has authority over treasury funds. Step Finance pattern of executive key compromise.',
    recommendation: 'Cold storage for treasury with hardware wallet multisig.'
  },
  {
    id: 'SOL3882',
    name: 'Step Finance - Missing Withdrawal Limits',
    severity: 'high',
    pattern: /(?:withdraw|transfer|drain)[\s\S]{0,100}amount[\s\S]{0,50}(?!max|limit|cap|threshold)/i,
    description: 'Unlimited withdrawal amounts possible. Attackers drained 261,854 SOL (~$30M) in single operation.',
    recommendation: 'Implement daily/weekly withdrawal limits with escalating approval requirements.'
  },
  {
    id: 'SOL3883',
    name: 'Step Finance - No Emergency Pause',
    severity: 'high',
    pattern: /(?:treasury|withdraw|transfer)[\s\S]{0,200}(?!pause|freeze|halt|emergency)/i,
    description: 'No emergency pause mechanism for treasury operations.',
    recommendation: 'Implement emergency pause controlled by security council.'
  },
  {
    id: 'SOL3884',
    name: 'Step Finance - Missing Anomaly Detection',
    severity: 'medium',
    pattern: /(?:treasury|protocol|reserve)[\s\S]{0,150}(?!monitor|alert|detect|anomaly)/i,
    description: 'No on-chain anomaly detection for treasury operations.',
    recommendation: 'Implement transaction monitoring and automated alerts for unusual patterns.'
  },
  {
    id: 'SOL3885',
    name: 'Step Finance - Destination Validation Missing',
    severity: 'high',
    pattern: /(?:withdraw|transfer)[\s\S]{0,100}(?:destination|recipient|to)[\s\S]{0,50}(?!whitelist|allowlist|validate)/i,
    description: 'No destination validation for large transfers. Funds went to attacker-controlled addresses.',
    recommendation: 'Implement address whitelisting for treasury withdrawals.'
  },

  // ============================================================================
  // DEV.TO DEEP DIVE - INTEGER OVERFLOW/UNDERFLOW (Feb 2026)
  // ============================================================================
  
  {
    id: 'SOL3886',
    name: 'DEV.to #8 - Fee Calculation Overflow',
    severity: 'critical',
    pattern: /(?:fee|commission|tax)[\s\S]{0,30}\*[\s\S]{0,20}(?:amount|balance|value)/i,
    description: 'Fee multiplication without overflow protection. Integer overflow can zero out fees.',
    recommendation: 'Use checked_mul or saturating_mul for all fee calculations.'
  },
  {
    id: 'SOL3887',
    name: 'DEV.to #8 - Balance Subtraction Underflow',
    severity: 'critical',
    pattern: /balance[\s\S]{0,20}-[\s\S]{0,20}(?:amount|withdrawal|transfer)[\s\S]{0,30}(?!checked|saturating)/i,
    description: 'Balance subtraction without underflow check can wrap to max u64.',
    recommendation: 'Use checked_sub for all balance decrements.'
  },
  {
    id: 'SOL3888',
    name: 'DEV.to #8 - Token Supply Overflow',
    severity: 'critical',
    pattern: /(?:supply|total_minted)[\s\S]{0,20}\+[\s\S]{0,20}(?:mint_amount|new_tokens)[\s\S]{0,30}(?!checked|saturating)/i,
    description: 'Token supply addition without overflow check.',
    recommendation: 'Use checked_add for supply changes with MAX_SUPPLY validation.'
  },
  {
    id: 'SOL3889',
    name: 'DEV.to #8 - i32 Timestamp Year 2038',
    severity: 'medium',
    pattern: /(?:timestamp|time|date)[\s\S]{0,30}i32/i,
    description: 'Using i32 for timestamps will overflow on January 19, 2038.',
    recommendation: 'Use i64 or u64 for all timestamp values.'
  },
  {
    id: 'SOL3890',
    name: 'DEV.to #8 - Price Calculation Overflow',
    severity: 'critical',
    pattern: /(?:price|rate|exchange)[\s\S]{0,30}\*[\s\S]{0,20}(?:amount|quantity)[\s\S]{0,30}(?!u128|checked|saturating)/i,
    description: 'Price * amount can easily overflow u64. Use u128 for intermediate calculations.',
    recommendation: 'Cast to u128 for multiplication, then validate result fits in u64.'
  },

  // ============================================================================
  // DEV.TO DEEP DIVE - DUPLICATE MUTABLE ACCOUNTS (#10)
  // ============================================================================

  {
    id: 'SOL3891',
    name: 'DEV.to #10 - Duplicate Mutable Account Risk',
    severity: 'critical',
    pattern: /(?:transfer|move)[\s\S]{0,100}(?:from|source)[\s\S]{0,50}(?:to|destination)[\s\S]{0,30}(?!key.*!=|!=.*key)/i,
    description: 'Transfer without checking source != destination. Can double balance via self-transfer.',
    recommendation: 'Always validate from_account.key() != to_account.key().'
  },
  {
    id: 'SOL3892',
    name: 'DEV.to #10 - Self-Reference Account Attack',
    severity: 'critical',
    pattern: /(?:debit|subtract)[\s\S]{0,50}(?:credit|add)[\s\S]{0,100}(?!same|duplicate|!=)/i,
    description: 'Debit and credit operations can be applied to same account, creating money.',
    recommendation: 'Check all account pairs for uniqueness before operations.'
  },
  {
    id: 'SOL3893',
    name: 'DEV.to #10 - Anchor Duplicate Account Check Missing',
    severity: 'high',
    pattern: /#\[account\([\s\S]{0,100}mut[\s\S]{0,100}(?!constraint.*!=)/i,
    description: 'Mutable accounts without constraint checking uniqueness.',
    recommendation: 'Add constraint = from.key() != to.key() for account pairs.'
  },

  // ============================================================================
  // DEV.TO DEEP DIVE - CLOSE ACCOUNT WITHOUT ZEROING (#9)
  // ============================================================================

  {
    id: 'SOL3894',
    name: 'DEV.to #9 - Close Account Data Not Zeroed',
    severity: 'critical',
    pattern: /(?:close|lamports.*=.*0)[\s\S]{0,100}(?!data.*=.*0|zero|clear|memset)/i,
    description: 'Closing account without zeroing data allows resurrection with stale data.',
    recommendation: 'Zero all account data bytes before close. Use Anchor close constraint.'
  },
  {
    id: 'SOL3895',
    name: 'DEV.to #9 - Close Without Discriminator Clear',
    severity: 'critical',
    pattern: /(?:close|destroy)[\s\S]{0,80}(?!discriminator.*0|disc.*clear)/i,
    description: 'Discriminator not cleared on close. Account can be reopened with same type.',
    recommendation: 'Set discriminator to zero or CLOSED marker on close.'
  },
  {
    id: 'SOL3896',
    name: 'DEV.to #9 - Rent Siphoning Attack',
    severity: 'high',
    pattern: /close[\s\S]{0,80}(?:lamports|rent)[\s\S]{0,50}(?!minimum|exempt|check)/i,
    description: 'Rent can be drained from account before close by making it non-exempt.',
    recommendation: 'Verify rent exemption before closing to recover full lamports.'
  },
  {
    id: 'SOL3897',
    name: 'DEV.to #9 - Close Account Resurrection',
    severity: 'critical',
    pattern: /(?:close|destroy)[\s\S]{0,100}(?:same.*slot|block|transaction)/i,
    description: 'Closed account can be resurrected within same transaction block.',
    recommendation: 'Implement close account cooldown or permanent closure markers.'
  },

  // ============================================================================
  // NOONES P2P BRIDGE EXPLOIT ($8M, Jan 2025)
  // ============================================================================

  {
    id: 'SOL3898',
    name: 'NoOnes - P2P Bridge Authentication Bypass',
    severity: 'critical',
    pattern: /(?:bridge|cross.?chain|p2p)[\s\S]{0,100}(?:transfer|withdraw)[\s\S]{0,50}(?!verify|auth|sig)/i,
    description: 'P2P bridge without proper authentication. NoOnes lost $8M across multiple chains.',
    recommendation: 'Implement multi-party verification for all bridge operations.'
  },
  {
    id: 'SOL3899',
    name: 'NoOnes - Cross-Chain Message Replay',
    severity: 'critical',
    pattern: /(?:message|payload)[\s\S]{0,80}(?:bridge|relay)[\s\S]{0,50}(?!nonce|sequence|unique)/i,
    description: 'Cross-chain messages can be replayed. NoOnes exploit involved replay attacks.',
    recommendation: 'Include unique nonce or sequence number in all bridge messages.'
  },
  {
    id: 'SOL3900',
    name: 'NoOnes - Multi-Chain Coordination Failure',
    severity: 'high',
    pattern: /(?:multi.?chain|cross.?chain)[\s\S]{0,100}(?:transfer|bridge)[\s\S]{0,50}(?!finality|confirm)/i,
    description: 'Multi-chain operations without proper finality checks.',
    recommendation: 'Wait for source chain finality before executing destination chain operations.'
  },

  // ============================================================================
  // UPBIT HOT WALLET PATTERN ($36M, Nov 2025)
  // ============================================================================

  {
    id: 'SOL3901',
    name: 'Upbit - Exchange Hot Wallet Isolation Failure',
    severity: 'critical',
    pattern: /(?:hot.?wallet|exchange)[\s\S]{0,100}(?:deposit|withdraw)[\s\S]{0,50}(?!hsm|isolated|air.?gap)/i,
    description: 'Exchange hot wallet without HSM isolation. Upbit lost $36M from hot wallet breach.',
    recommendation: 'Use HSM for hot wallet keys with strict access controls.'
  },
  {
    id: 'SOL3902',
    name: 'Upbit - Deposit Address Validation Missing',
    severity: 'high',
    pattern: /(?:deposit|receive)[\s\S]{0,80}(?:address|account)[\s\S]{0,50}(?!validate|verify|whitelist)/i,
    description: 'Deposit addresses not properly validated. Can accept attacker-controlled addresses.',
    recommendation: 'Validate all deposit addresses against known user accounts.'
  },
  {
    id: 'SOL3903',
    name: 'Upbit - Withdrawal API Abuse',
    severity: 'critical',
    pattern: /(?:withdraw|api)[\s\S]{0,100}(?!rate.?limit|throttle|cooldown)/i,
    description: 'Withdrawal API without rate limiting. Enables rapid fund extraction.',
    recommendation: 'Implement rate limits, velocity checks, and cooling periods for withdrawals.'
  },

  // ============================================================================
  // DECEMBER 2025 SOLANA CONSENSUS VULNERABILITIES
  // ============================================================================

  {
    id: 'SOL3904',
    name: 'Consensus Vuln - Network Stalling Attack Vector',
    severity: 'critical',
    pattern: /(?:consensus|validator|vote)[\s\S]{0,100}(?:block|slot)[\s\S]{0,50}(?:stall|halt|freeze)/i,
    description: 'December 2025 disclosed consensus vulnerabilities could stall network.',
    recommendation: 'Update to patched Solana client versions (Anza/Firedancer/Jito coordinated fix).'
  },
  {
    id: 'SOL3905',
    name: 'Consensus Vuln - Validator Concentration Risk',
    severity: 'high',
    pattern: /(?:validator|stake)[\s\S]{0,100}(?:concentration|centralize|single)/i,
    description: 'High validator concentration (Jito 88%) amplifies consensus vulnerabilities.',
    recommendation: 'Monitor validator client diversity and stake distribution.'
  },

  // ============================================================================
  // TRUST WALLET CHROME EXTENSION BREACH ($7M)
  // ============================================================================

  {
    id: 'SOL3906',
    name: 'Trust Wallet - Analytics Library Key Harvesting',
    severity: 'critical',
    pattern: /(?:analytics|posthog|telemetry)[\s\S]{0,100}(?:key|private|seed|secret)/i,
    description: 'Analytics libraries can harvest keys. Trust Wallet lost $7M via posthog-js vulnerability.',
    recommendation: 'Never pass sensitive data to analytics. Audit all third-party dependencies.'
  },
  {
    id: 'SOL3907',
    name: 'Trust Wallet - Third-Party Library Exposure',
    severity: 'high',
    pattern: /(?:import|require|from)[\s\S]{0,50}(?:analytics|tracking|telemetry)/i,
    description: 'Third-party analytics libraries are a supply chain attack vector.',
    recommendation: 'Minimize third-party dependencies. Use CSP to restrict data exfiltration.'
  },
  {
    id: 'SOL3908',
    name: 'Trust Wallet - Browser Extension Security',
    severity: 'high',
    pattern: /(?:extension|browser|chrome)[\s\S]{0,100}(?:storage|key|private)/i,
    description: 'Browser extension key storage vulnerable to malicious extensions or XSS.',
    recommendation: 'Use encrypted storage with user-derived keys. Never store raw secrets.'
  },

  // ============================================================================
  // CERTIK JANUARY 2026 - $400M+ LOSSES
  // ============================================================================

  {
    id: 'SOL3909',
    name: 'CertiK 2026 - Private Key Logging',
    severity: 'critical',
    pattern: /(?:log|print|debug|console)[\s\S]{0,50}(?:key|secret|private|seed)/i,
    description: 'Private keys logged to output. CertiK reports key exposure as top vulnerability.',
    recommendation: 'Never log sensitive data. Use dedicated secrets management.'
  },
  {
    id: 'SOL3910',
    name: 'CertiK 2026 - Exit Scam Function',
    severity: 'critical',
    pattern: /(?:drain|rug|emergency_withdraw|owner_withdraw)[\s\S]{0,50}(?:all|entire|full)/i,
    description: 'Function to drain all funds. Common rug pull indicator.',
    recommendation: 'Remove owner-only drain functions. Use timelock for emergency operations.'
  },
  {
    id: 'SOL3911',
    name: 'CertiK 2026 - Flash Loan Without Guard',
    severity: 'high',
    pattern: /(?:flash.?loan|borrow.?return)[\s\S]{0,100}(?!reentrancy|guard|lock)/i,
    description: 'Flash loan implementation without reentrancy protection.',
    recommendation: 'Implement reentrancy guards for all flash loan functions.'
  },
  {
    id: 'SOL3912',
    name: 'CertiK 2026 - Single Oracle Dependency',
    severity: 'high',
    pattern: /(?:oracle|price.?feed)[\s\S]{0,100}(?!fallback|backup|aggregate|multiple)/i,
    description: 'Single oracle without fallback. Oracle manipulation is #1 DeFi attack vector.',
    recommendation: 'Use multiple oracle sources with median or weighted aggregation.'
  },
  {
    id: 'SOL3913',
    name: 'CertiK 2026 - Protocol Without Insurance',
    severity: 'medium',
    pattern: /(?:protocol|defi|lending)[\s\S]{0,200}(?!insurance|reserve|coverage)/i,
    description: 'Protocol without insurance fund for black swan events.',
    recommendation: 'Maintain insurance reserve of 5-10% of TVL.'
  },

  // ============================================================================
  // ADVANCED ACCOUNT VALIDATION (DEV.to Deep Patterns)
  // ============================================================================

  {
    id: 'SOL3914',
    name: 'Advanced - AccountInfo Without Framework',
    severity: 'high',
    pattern: /AccountInfo[\s\S]{0,100}(?!Account<|Signer<|UncheckedAccount)/i,
    description: 'Raw AccountInfo usage without Anchor type wrappers increases vulnerability surface.',
    recommendation: 'Use Anchor Account<T> types for automatic validation.'
  },
  {
    id: 'SOL3915',
    name: 'Advanced - Manual Deserialization Risk',
    severity: 'high',
    pattern: /(?:try_from_slice|deserialize|borsh::from)[\s\S]{0,80}(?!discriminator|check)/i,
    description: 'Manual deserialization without discriminator verification.',
    recommendation: 'Always check discriminator bytes before deserializing account data.'
  },
  {
    id: 'SOL3916',
    name: 'Advanced - UncheckedAccount Without Doc',
    severity: 'medium',
    pattern: /UncheckedAccount[\s\S]{0,30}(?!CHECK:|SAFETY:)/i,
    description: 'UncheckedAccount without safety documentation.',
    recommendation: 'Add /// CHECK: comment explaining why account is safe to use unchecked.'
  },
  {
    id: 'SOL3917',
    name: 'Advanced - Shared Data Layout Attack',
    severity: 'critical',
    pattern: /struct[\s\S]{0,200}pub[\s\S]{0,30}:[\s\S]{0,30}u64[\s\S]{0,100}pub[\s\S]{0,30}:[\s\S]{0,30}Pubkey/i,
    description: 'Struct layout similar to other types enables type cosplay attacks.',
    recommendation: 'Use unique discriminators and validate account type before use.'
  },
  {
    id: 'SOL3918',
    name: 'Advanced - Zero Discriminator Check',
    severity: 'critical',
    pattern: /discriminator[\s\S]{0,30}==[\s\S]{0,20}\[0[\s\S]{0,20}\]/i,
    description: 'Zero discriminator check allows uninitialized accounts to pass validation.',
    recommendation: 'Check for non-zero discriminator and match expected type.'
  },

  // ============================================================================
  // PDA SECURITY (DEV.to #5 Deep Patterns)
  // ============================================================================

  {
    id: 'SOL3919',
    name: 'PDA - create_program_address Without find',
    severity: 'high',
    pattern: /create_program_address[\s\S]{0,100}(?!find_program_address)/i,
    description: 'Using create_program_address directly risks non-canonical bumps.',
    recommendation: 'Always use find_program_address to get canonical bump.'
  },
  {
    id: 'SOL3920',
    name: 'PDA - User-Controlled Seeds',
    severity: 'high',
    pattern: /seeds[\s\S]{0,50}(?:user|input|param)[\s\S]{0,30}(?:\.as_ref|\.to_bytes)/i,
    description: 'User-controlled values in PDA seeds can create collisions or shadow PDAs.',
    recommendation: 'Validate user inputs used in seeds. Use fixed prefixes.'
  },
  {
    id: 'SOL3921',
    name: 'PDA - Bump Not Stored',
    severity: 'medium',
    pattern: /find_program_address[\s\S]{0,100}(?!bump[\s\S]{0,20}=|store.*bump)/i,
    description: 'PDA bump not stored for later verification.',
    recommendation: 'Store canonical bump in account data for subsequent validations.'
  },
  {
    id: 'SOL3922',
    name: 'PDA - Shadow PDA Creation Risk',
    severity: 'high',
    pattern: /seeds[\s\S]{0,80}bump[\s\S]{0,50}(?:user|param|input)/i,
    description: 'User-provided bump allows creation of shadow PDAs at different addresses.',
    recommendation: 'Always derive bump using find_program_address, never accept from input.'
  },

  // ============================================================================
  // CPI SECURITY (DEV.to #7 Deep Patterns)
  // ============================================================================

  {
    id: 'SOL3923',
    name: 'CPI - Unchecked Target Program',
    severity: 'critical',
    pattern: /invoke(?:_signed)?[\s\S]{0,80}(?:program|target)[\s\S]{0,50}(?!spl_token|token_program|system_program)/i,
    description: 'CPI to potentially user-controlled program ID.',
    recommendation: 'Hardcode trusted program IDs or validate against whitelist.'
  },
  {
    id: 'SOL3924',
    name: 'CPI - Program ID From Account',
    severity: 'critical',
    pattern: /(?:program|target)[\s\S]{0,30}\.key[\s\S]{0,50}invoke/i,
    description: 'CPI program ID read from account allows arbitrary program invocation.',
    recommendation: 'Use Program<T> type to verify program ID matches expected.'
  },
  {
    id: 'SOL3925',
    name: 'CPI - Token Transfer Without SPL Verify',
    severity: 'critical',
    pattern: /transfer[\s\S]{0,100}invoke[\s\S]{0,50}(?!spl_token::id|token_program::check)/i,
    description: 'Token transfer CPI without verifying SPL Token program ID.',
    recommendation: 'Always verify token_program.key() == spl_token::id() before CPI.'
  },
  {
    id: 'SOL3926',
    name: 'CPI - Seeds With User Data',
    severity: 'high',
    pattern: /invoke_signed[\s\S]{0,100}seeds[\s\S]{0,50}(?:user|input|param)/i,
    description: 'CPI seeds include user-controlled data, enabling seed manipulation.',
    recommendation: 'Validate all user inputs used in CPI seeds.'
  },
  {
    id: 'SOL3927',
    name: 'CPI - Account Order Manipulation',
    severity: 'high',
    pattern: /invoke[\s\S]{0,100}accounts[\s\S]{0,80}(?:vec!|&\[)[\s\S]{0,50}(?:input|user|param)/i,
    description: 'Account order in CPI can be manipulated if not validated.',
    recommendation: 'Validate account positions match expected program interface.'
  },

  // ============================================================================
  // REENTRANCY (DEV.to Deep Patterns)
  // ============================================================================

  {
    id: 'SOL3928',
    name: 'Reentrancy - State After CPI',
    severity: 'critical',
    pattern: /invoke[\s\S]{0,150}(?:\.amount|\.balance|\.data)[\s\S]{0,30}=/i,
    description: 'State modified after CPI call is vulnerable to reentrancy.',
    recommendation: 'Update all state before CPI calls (checks-effects-interactions).'
  },
  {
    id: 'SOL3929',
    name: 'Reentrancy - Callback Without Guard',
    severity: 'critical',
    pattern: /(?:callback|on_receive|after_transfer)[\s\S]{0,100}(?!reentrancy|guard|lock)/i,
    description: 'Callback function without reentrancy protection.',
    recommendation: 'Implement reentrancy guard using flag or mutex pattern.'
  },
  {
    id: 'SOL3930',
    name: 'Reentrancy - Cross-Instruction Leak',
    severity: 'high',
    pattern: /(?:instruction|ix)[\s\S]{0,100}(?:state|storage)[\s\S]{0,50}(?!reset|clear|finalize)/i,
    description: 'State not finalized between instructions allows cross-instruction attacks.',
    recommendation: 'Finalize all state changes at instruction end.'
  },
  {
    id: 'SOL3931',
    name: 'Reentrancy - CPI Depth Exhaustion',
    severity: 'medium',
    pattern: /invoke[\s\S]{0,80}invoke[\s\S]{0,80}invoke/i,
    description: 'Deep CPI chains can exceed stack depth (4 levels).',
    recommendation: 'Limit CPI depth and handle StackExhausted errors.'
  },

  // ============================================================================
  // PHISHING & SOCIAL ENGINEERING (Jan 2026)
  // ============================================================================

  {
    id: 'SOL3932',
    name: 'Phishing - SetAuthority Without Confirmation',
    severity: 'critical',
    pattern: /(?:set_authority|transfer_authority|change_owner)[\s\S]{0,100}(?!confirm|two.?step|delay)/i,
    description: 'Authority change without two-step confirmation. Top phishing vector in Jan 2026.',
    recommendation: 'Implement two-step authority transfer with timelock.'
  },
  {
    id: 'SOL3933',
    name: 'Phishing - Silent Ownership Transfer',
    severity: 'critical',
    pattern: /(?:owner|authority)[\s\S]{0,50}=[\s\S]{0,50}(?:new|input|param)[\s\S]{0,50}(?!event|emit|log)/i,
    description: 'Ownership transfer without event emission hides malicious changes.',
    recommendation: 'Emit events for all authority/ownership changes.'
  },
  {
    id: 'SOL3934',
    name: 'Phishing - Memo-Based Attack Vector',
    severity: 'medium',
    pattern: /(?:memo|message|note)[\s\S]{0,80}(?:instruction|transaction)/i,
    description: 'Memo fields used for phishing. Users see legitimate-looking messages.',
    recommendation: 'Warn users not to trust memo contents for authorization.'
  },
  {
    id: 'SOL3935',
    name: 'Phishing - Fake Airdrop Claim',
    severity: 'high',
    pattern: /(?:airdrop|claim|reward)[\s\S]{0,100}(?:transfer|approve|delegate)/i,
    description: 'Airdrop claims that secretly approve token access.',
    recommendation: 'Never bundle approval operations with claims.'
  },
  {
    id: 'SOL3936',
    name: 'Phishing - Unlimited Token Approval',
    severity: 'critical',
    pattern: /(?:approve|delegate)[\s\S]{0,50}(?:u64::MAX|MAX_AMOUNT|unlimited)/i,
    description: 'Unlimited token approval enables future wallet drain.',
    recommendation: 'Request only necessary approval amounts with expiration.'
  },
  {
    id: 'SOL3937',
    name: 'Phishing - Session Key Without Expiry',
    severity: 'high',
    pattern: /(?:session|delegate|permission)[\s\S]{0,80}(?!expiry|expires|valid_until|ttl)/i,
    description: 'Session keys without expiration remain perpetually valid.',
    recommendation: 'All delegated permissions must have expiration timestamps.'
  },
  {
    id: 'SOL3938',
    name: 'Phishing - Simulation Bypass via Owner',
    severity: 'critical',
    pattern: /(?:simulate|preview)[\s\S]{0,100}(?:owner|authority)[\s\S]{0,50}(?:change|modify)/i,
    description: 'Owner field changes bypass transaction simulation protection.',
    recommendation: 'Simulation must include full ownership transfer detection.'
  },

  // ============================================================================
  // ORACLE SECURITY DEEP PATTERNS
  // ============================================================================

  {
    id: 'SOL3939',
    name: 'Oracle - Solend Attack Pattern ($1.26M)',
    severity: 'critical',
    pattern: /(?:oracle|price)[\s\S]{0,100}(?:single|one)[\s\S]{0,50}(?:pool|source|feed)/i,
    description: 'Single oracle source like Solend attack. USDH priced at $8.80 instead of $1.',
    recommendation: 'Use multiple price sources with deviation checks.'
  },
  {
    id: 'SOL3940',
    name: 'Oracle - Staleness Without Check',
    severity: 'high',
    pattern: /(?:price|oracle)[\s\S]{0,100}(?!staleness|timestamp|age|fresh)/i,
    description: 'Oracle data used without staleness validation.',
    recommendation: 'Verify oracle timestamp within acceptable freshness window.'
  },
  {
    id: 'SOL3941',
    name: 'Oracle - Confidence Interval Ignored',
    severity: 'high',
    pattern: /(?:pyth|oracle)[\s\S]{0,80}(?:price|value)[\s\S]{0,50}(?!conf|confidence|deviation)/i,
    description: 'Oracle confidence interval not checked. Wide spreads indicate manipulation.',
    recommendation: 'Reject prices where confidence interval exceeds threshold.'
  },
  {
    id: 'SOL3942',
    name: 'Oracle - TWAP Window Too Short',
    severity: 'high',
    pattern: /(?:twap|time.?weighted)[\s\S]{0,50}(?:window|period)[\s\S]{0,30}(?:60|120|300)/i,
    description: 'TWAP window under 10 minutes susceptible to flash manipulation.',
    recommendation: 'Use minimum 30-minute TWAP for price-sensitive operations.'
  },
  {
    id: 'SOL3943',
    name: 'Oracle - Flash Loan Price Attack',
    severity: 'critical',
    pattern: /(?:flash.?loan|borrow)[\s\S]{0,100}(?:price|oracle|value)/i,
    description: 'Price read during flash loan can be manipulated within single transaction.',
    recommendation: 'Use TWAP or block-delayed prices for flash-loan-sensitive operations.'
  },

  // ============================================================================
  // LENDING PROTOCOL SECURITY
  // ============================================================================

  {
    id: 'SOL3944',
    name: 'Lending - Health Factor Bypass',
    severity: 'critical',
    pattern: /(?:health|collateral)[\s\S]{0,80}(?:factor|ratio)[\s\S]{0,50}(?!check|require|assert)/i,
    description: 'Health factor not properly validated before borrow/withdraw.',
    recommendation: 'Require health_factor > 1.0 for all position changes.'
  },
  {
    id: 'SOL3945',
    name: 'Lending - Liquidation Bonus Inflation',
    severity: 'high',
    pattern: /(?:liquidation|bonus|incentive)[\s\S]{0,80}(?!max|cap|limit)/i,
    description: 'Unbounded liquidation bonus can be exploited. Solend pattern.',
    recommendation: 'Cap liquidation bonus at reasonable percentage (5-10%).'
  },
  {
    id: 'SOL3946',
    name: 'Lending - Interest Rate Spike',
    severity: 'high',
    pattern: /(?:interest|rate|apy)[\s\S]{0,80}(?:utilization|curve)[\s\S]{0,50}(?!max|cap|ceiling)/i,
    description: 'Unbounded interest rate can spike to extreme values.',
    recommendation: 'Implement interest rate ceiling and gradual adjustment.'
  },
  {
    id: 'SOL3947',
    name: 'Lending - Bad Debt Socialization',
    severity: 'high',
    pattern: /(?:bad.?debt|underwater|insolvent)[\s\S]{0,100}(?!insurance|reserve|fund)/i,
    description: 'No mechanism to handle bad debt can leave protocol insolvent.',
    recommendation: 'Maintain insurance fund and implement bad debt socialization.'
  },
  {
    id: 'SOL3948',
    name: 'Lending - Borrow Exceeds Collateral',
    severity: 'critical',
    pattern: /(?:borrow|debt)[\s\S]{0,80}(?!<=|<|collateral|max)/i,
    description: 'Borrow amount not properly capped by collateral value.',
    recommendation: 'Enforce borrow_amount <= collateral_value * LTV.'
  },

  // ============================================================================
  // AMM/DEX SECURITY
  // ============================================================================

  {
    id: 'SOL3949',
    name: 'AMM - Constant Product Violation',
    severity: 'critical',
    pattern: /(?:swap|trade)[\s\S]{0,100}(?:reserve|pool)[\s\S]{0,50}(?!invariant|k.*check|product)/i,
    description: 'AMM swap without constant product (k) verification.',
    recommendation: 'Verify reserve_a * reserve_b >= k after every swap.'
  },
  {
    id: 'SOL3950',
    name: 'AMM - LP Token Inflation Attack',
    severity: 'critical',
    pattern: /(?:mint|lp.?token)[\s\S]{0,100}(?:first|initial)[\s\S]{0,50}(?!minimum|burn|lock)/i,
    description: 'First depositor can inflate LP tokens. Classic vault attack.',
    recommendation: 'Burn minimum LP tokens on first deposit or use dead shares.'
  },
  {
    id: 'SOL3951',
    name: 'AMM - Sandwich Attack Vector',
    severity: 'high',
    pattern: /(?:swap|trade)[\s\S]{0,100}(?!slippage|min.?out|deadline)/i,
    description: 'Swap without slippage protection enables sandwich attacks.',
    recommendation: 'Require minimum output amount and deadline for all swaps.'
  },
  {
    id: 'SOL3952',
    name: 'AMM - Reserve Manipulation',
    severity: 'critical',
    pattern: /(?:reserve|pool.?balance)[\s\S]{0,50}=[\s\S]{0,50}(?!sync|update.?balance)/i,
    description: 'Direct reserve manipulation without sync to actual balances.',
    recommendation: 'Sync reserves from actual token balances, not cached values.'
  },

  // ============================================================================
  // GOVERNANCE SECURITY
  // ============================================================================

  {
    id: 'SOL3953',
    name: 'Governance - Flash Vote Attack',
    severity: 'critical',
    pattern: /(?:vote|proposal)[\s\S]{0,100}(?:power|weight)[\s\S]{0,50}(?!snapshot|lock|delay)/i,
    description: 'Voting power not snapshotted allows flash loan governance attacks.',
    recommendation: 'Snapshot voting power at proposal creation.'
  },
  {
    id: 'SOL3954',
    name: 'Governance - No Execution Delay',
    severity: 'high',
    pattern: /(?:proposal|governance)[\s\S]{0,100}(?:execute|apply)[\s\S]{0,50}(?!delay|timelock|queue)/i,
    description: 'Proposals execute immediately without delay for review.',
    recommendation: 'Implement 24-48 hour delay between approval and execution.'
  },
  {
    id: 'SOL3955',
    name: 'Governance - Quorum Manipulation',
    severity: 'high',
    pattern: /(?:quorum|threshold)[\s\S]{0,80}(?:total|supply)[\s\S]{0,50}(?!snapshot|fixed)/i,
    description: 'Quorum based on current supply can be manipulated via minting/burning.',
    recommendation: 'Use fixed or snapshotted quorum values.'
  },
  {
    id: 'SOL3956',
    name: 'Governance - Audius Pattern ($6.1M)',
    severity: 'critical',
    pattern: /(?:proposal|governance)[\s\S]{0,100}(?:create|submit)[\s\S]{0,50}(?!validate|verify)/i,
    description: 'Malicious proposals without validation. Audius lost $6.1M to governance hijack.',
    recommendation: 'Validate proposal data and require multi-sig for sensitive operations.'
  },

  // ============================================================================
  // TOKEN-2022 SECURITY
  // ============================================================================

  {
    id: 'SOL3957',
    name: 'Token-2022 - Transfer Hook Reentrancy',
    severity: 'critical',
    pattern: /(?:transfer.?hook|on.?transfer)[\s\S]{0,100}(?!reentrancy|guard|lock)/i,
    description: 'Transfer hooks can be reentrant, executing arbitrary code mid-transfer.',
    recommendation: 'Implement reentrancy guards in transfer hook handlers.'
  },
  {
    id: 'SOL3958',
    name: 'Token-2022 - Confidential Transfer Leak',
    severity: 'high',
    pattern: /(?:confidential|private)[\s\S]{0,80}(?:transfer|amount)[\s\S]{0,50}(?!decrypt|reveal)/i,
    description: 'Confidential transfer amounts may leak through side channels.',
    recommendation: 'Audit confidential transfer implementation for timing/size leaks.'
  },
  {
    id: 'SOL3959',
    name: 'Token-2022 - Transfer Fee Bypass',
    severity: 'high',
    pattern: /(?:transfer.?fee|fee.?config)[\s\S]{0,100}(?!enforce|validate|require)/i,
    description: 'Transfer fees can be bypassed through approval-based transfers.',
    recommendation: 'Enforce fees on all transfer paths including approvals.'
  },
  {
    id: 'SOL3960',
    name: 'Token-2022 - Interest Bearing Manipulation',
    severity: 'high',
    pattern: /(?:interest|rebase|rate)[\s\S]{0,80}(?:update|change)[\s\S]{0,50}(?!admin|auth|timelock)/i,
    description: 'Interest rate changes without proper authorization.',
    recommendation: 'Require admin + timelock for interest rate modifications.'
  },
  {
    id: 'SOL3961',
    name: 'Token-2022 - Permanent Delegate Abuse',
    severity: 'critical',
    pattern: /(?:permanent|unlimited)[\s\S]{0,50}(?:delegate|approval)/i,
    description: 'Permanent delegate can drain tokens at any time.',
    recommendation: 'Avoid permanent delegates. Use time-limited approvals.'
  },

  // ============================================================================
  // INFRASTRUCTURE SECURITY
  // ============================================================================

  {
    id: 'SOL3962',
    name: 'Infra - Jito Client Concentration',
    severity: 'medium',
    pattern: /(?:validator|client|node)[\s\S]{0,100}(?:jito|mev)/i,
    description: 'Jito client at 88% concentration. Single vulnerability affects entire network.',
    recommendation: 'Encourage client diversity in documentation and partnerships.'
  },
  {
    id: 'SOL3963',
    name: 'Infra - RPC Provider Manipulation',
    severity: 'high',
    pattern: /(?:rpc|provider|endpoint)[\s\S]{0,100}(?!validate|verify|multiple)/i,
    description: 'Single RPC provider can return manipulated data.',
    recommendation: 'Use multiple RPC providers with response validation.'
  },
  {
    id: 'SOL3964',
    name: 'Infra - Address Lookup Table Poisoning',
    severity: 'high',
    pattern: /(?:lookup.?table|alt|address.?table)[\s\S]{0,100}(?!verify|validate|check)/i,
    description: 'Lookup tables can be poisoned with malicious addresses.',
    recommendation: 'Validate all addresses from lookup tables before use.'
  },
  {
    id: 'SOL3965',
    name: 'Infra - Priority Fee Front-Running',
    severity: 'medium',
    pattern: /(?:priority|fee)[\s\S]{0,80}(?:set|compute)/i,
    description: 'Priority fee setting enables MEV extraction through front-running.',
    recommendation: 'Use private transaction submission or Jito bundles.'
  },
  {
    id: 'SOL3966',
    name: 'Infra - Durable Nonce Replay',
    severity: 'high',
    pattern: /(?:durable|nonce)[\s\S]{0,80}(?:advance|use)[\s\S]{0,50}(?!single|once|consume)/i,
    description: 'Durable nonce reuse enables transaction replay.',
    recommendation: 'Consume nonce in same transaction as signed operation.'
  },

  // ============================================================================
  // TESTING & DEPLOYMENT PATTERNS
  // ============================================================================

  {
    id: 'SOL3967',
    name: 'Deploy - Devnet Address in Mainnet',
    severity: 'critical',
    pattern: /(?:devnet|testnet)[\s\S]{0,50}(?:address|pubkey|program)/i,
    description: 'Devnet addresses in mainnet code will fail or use wrong programs.',
    recommendation: 'Use environment-specific configuration for all addresses.'
  },
  {
    id: 'SOL3968',
    name: 'Deploy - Debug Code in Production',
    severity: 'high',
    pattern: /(?:#\[cfg\(debug|println!|dbg!|console\.log)/i,
    description: 'Debug code in production increases attack surface and compute costs.',
    recommendation: 'Remove all debug statements before mainnet deployment.'
  },
  {
    id: 'SOL3969',
    name: 'Deploy - Upgrade Authority Active',
    severity: 'medium',
    pattern: /(?:upgrade|authority)[\s\S]{0,80}(?:active|enabled|present)/i,
    description: 'Active upgrade authority can push malicious updates.',
    recommendation: 'Set upgrade authority to null for immutable programs.'
  },
  {
    id: 'SOL3970',
    name: 'Deploy - Missing Audit',
    severity: 'high',
    pattern: /(?:mainnet|production)[\s\S]{0,100}(?!audit|review|certik|ottersec|sec3)/i,
    description: 'Deployment to mainnet without security audit.',
    recommendation: 'Obtain professional security audit before mainnet launch.'
  },

  // ============================================================================
  // MISCELLANEOUS CRITICAL PATTERNS
  // ============================================================================

  {
    id: 'SOL3971',
    name: 'Misc - Slot-Based Randomness',
    severity: 'high',
    pattern: /(?:random|seed)[\s\S]{0,50}(?:slot|clock|timestamp)/i,
    description: 'Slot/timestamp-based randomness is predictable by validators.',
    recommendation: 'Use VRF (Switchboard) or commit-reveal for randomness.'
  },
  {
    id: 'SOL3972',
    name: 'Misc - CPI Return Data Spoofing',
    severity: 'high',
    pattern: /(?:return.?data|get_return|sol_get_return)/i,
    description: 'CPI return data can be spoofed by malicious programs.',
    recommendation: 'Verify calling program ID matches expected before trusting return data.'
  },
  {
    id: 'SOL3973',
    name: 'Misc - Close Account Balance Drain',
    severity: 'high',
    pattern: /(?:close|lamports.*=.*0)[\s\S]{0,80}(?:destination|recipient)/i,
    description: 'Close account destination can be manipulated to drain lamports.',
    recommendation: 'Hardcode or validate close account destination.'
  },
  {
    id: 'SOL3974',
    name: 'Misc - Rent Exemption Threshold',
    severity: 'medium',
    pattern: /(?:rent|lamports)[\s\S]{0,80}(?!minimum|exempt|check)/i,
    description: 'Account below rent exemption will be garbage collected.',
    recommendation: 'Verify rent exemption before account creation.'
  },
  {
    id: 'SOL3975',
    name: 'Misc - Compute Unit Limit Griefing',
    severity: 'medium',
    pattern: /(?:compute|cu)[\s\S]{0,80}(?:limit|budget)[\s\S]{0,50}(?!set|configure)/i,
    description: 'Default compute limits may be insufficient for complex operations.',
    recommendation: 'Set explicit compute unit limits for all instructions.'
  },
];

// Combine all patterns
const ALL_BATCH_78_PATTERNS = [
  ...STEP_FINANCE_PATTERNS,
];

/**
 * Check Batch 78 patterns (Step Finance, DEV.to Deep Dive, NoOnes, Feb 2026 Threats)
 * Pattern IDs: SOL3876-SOL3975 (100 patterns)
 */
export function checkBatch78Patterns(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';
  
  if (!content) return findings;
  
  for (const pattern of ALL_BATCH_78_PATTERNS) {
    if (pattern.pattern.test(content)) {
      // Find line number
      const lines = content.split('\n');
      let lineNumber = 1;
      for (let i = 0; i < lines.length; i++) {
        if (pattern.pattern.test(lines[i])) {
          lineNumber = i + 1;
          break;
        }
      }
      
      findings.push({
        id: pattern.id,
        title: pattern.name,
        severity: pattern.severity,
        description: pattern.description,
        location: { file: input.path, line: lineNumber },
        recommendation: pattern.recommendation,
      });
    }
  }
  
  return findings;
}

export default {
  checkBatch78Patterns,
  patterns: ALL_BATCH_78_PATTERNS,
  count: ALL_BATCH_78_PATTERNS.length,
};
