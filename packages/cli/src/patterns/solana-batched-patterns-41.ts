/**
 * SolGuard Pattern Batch 41
 * Cross-Program Invocation (CPI) Security Patterns
 * Patterns SOL1161-SOL1230
 * 
 * Deep CPI security: reentrancy, arbitrary program calls, account validation
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

const batchedPatterns41: BatchPattern[] = [
  // ========================================
  // CPI SECURITY PATTERNS
  // ========================================
  {
    id: 'SOL1161',
    name: 'CPI to Unchecked Program',
    severity: 'critical',
    category: 'cpi',
    description: 'Cross-program invocation to program without verifying program ID.',
    detection: {
      patterns: [
        /invoke\s*\(/i,
        /invoke_signed\s*\(/i,
        /solana_program::program::invoke/i
      ]
    },
    recommendation: 'Always verify program_id matches expected constant before CPI.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1162',
    name: 'CPI Reentrancy via Token Transfer',
    severity: 'critical',
    category: 'cpi',
    description: 'Token transfers via CPI can trigger reentrancy through transfer hooks.',
    detection: {
      patterns: [
        /spl_token.*transfer/i,
        /token_interface.*transfer/i,
        /transfer_checked/i
      ]
    },
    recommendation: 'Use checks-effects-interactions. Consider reentrancy guards.',
    references: ['https://sec3.dev/']
  },
  {
    id: 'SOL1163',
    name: 'CPI Account Ordering Attack',
    severity: 'high',
    category: 'cpi',
    description: 'CPI account ordering can be manipulated to pass wrong accounts.',
    detection: {
      patterns: [
        /AccountMeta::new/i,
        /accounts\.push/i,
        /remaining_accounts/i
      ]
    },
    recommendation: 'Explicitly name and validate each account in CPI calls.',
    references: ['https://github.com/sannykim/solsec']
  },
  {
    id: 'SOL1164',
    name: 'CPI Return Data Spoofing',
    severity: 'high',
    category: 'cpi',
    description: 'CPI return data can be spoofed by malicious programs.',
    detection: {
      patterns: [
        /get_return_data/i,
        /set_return_data/i,
        /return_data/i
      ]
    },
    recommendation: 'Verify CPI target program before trusting return data.',
    references: ['https://solanasec25.sec3.dev/']
  },
  {
    id: 'SOL1165',
    name: 'Unverified CPI Signer Seeds',
    severity: 'critical',
    category: 'cpi',
    description: 'CPI invoke_signed without proper seeds validation.',
    detection: {
      patterns: [
        /invoke_signed\s*\([^)]*seeds/i,
        /signer_seeds/i,
        /\[&\[&/i
      ]
    },
    recommendation: 'Derive PDA on-chain and verify bump seed matches.',
    references: ['https://sec3.dev/']
  },
  {
    id: 'SOL1166',
    name: 'CPI Program Substitution',
    severity: 'critical',
    category: 'cpi',
    description: 'Attacker can substitute a different program during CPI.',
    detection: {
      patterns: [
        /ctx\.accounts\.[a-z_]+_program/i,
        /program_id.*AccountInfo/i,
        /token_program.*UncheckedAccount/i
      ]
    },
    recommendation: 'Use Program<T> type or explicitly check program ID equals expected.',
    references: ['https://sec3.dev/']
  },
  {
    id: 'SOL1167',
    name: 'CPI Depth Exhaustion',
    severity: 'medium',
    category: 'cpi',
    description: 'CPI depth limit (4) can be exhausted causing transaction failure.',
    detection: {
      patterns: [
        /invoke.*invoke/i,
        /cpi.*cpi/i,
        /nested.*call/i
      ]
    },
    recommendation: 'Design contracts to minimize CPI depth. Document CPI requirements.',
    references: ['https://docs.solana.com/']
  },
  {
    id: 'SOL1168',
    name: 'CPI Account Mutation Side Effects',
    severity: 'high',
    category: 'cpi',
    description: 'CPI calls can mutate accounts unexpectedly.',
    detection: {
      patterns: [
        /invoke.*mut/i,
        /AccountMeta::new\s*\([^,]+,\s*true/i,
        /is_writable:\s*true/i
      ]
    },
    recommendation: 'Reload account data after CPI. Verify expected state changes.',
    references: ['https://sec3.dev/']
  },
  {
    id: 'SOL1169',
    name: 'Arbitrary CPI Target',
    severity: 'critical',
    category: 'cpi',
    description: 'CPI target program is passed as account without validation.',
    detection: {
      patterns: [
        /\*\*.*program.*AccountInfo/i,
        /program_account\.key/i,
        /program_info\.key/i
      ]
    },
    recommendation: 'Hardcode expected program IDs. Use Program<T> wrapper.',
    references: ['https://sec3.dev/']
  },
  {
    id: 'SOL1170',
    name: 'CPI to System Program Abuse',
    severity: 'high',
    category: 'cpi',
    description: 'Improper CPI to system program can drain lamports.',
    detection: {
      patterns: [
        /system_program.*transfer/i,
        /SystemInstruction::Transfer/i,
        /create_account.*lamports/i
      ]
    },
    recommendation: 'Verify transfer amounts and destinations before system CPI.',
    references: ['https://sec3.dev/']
  },
  // ========================================
  // ACCOUNT VALIDATION PATTERNS
  // ========================================
  {
    id: 'SOL1171',
    name: 'Missing Account Discriminator',
    severity: 'critical',
    category: 'account',
    description: 'Account struct lacks discriminator, enabling type confusion.',
    detection: {
      patterns: [
        /#\[account\][\s\S]*?pub\s+struct/,
        /impl.*Account.*\{[\s\S]*?(?!DISCRIMINATOR)/
      ]
    },
    recommendation: 'Use Anchor #[account] or manually add and verify discriminator.',
    references: ['https://sec3.dev/']
  },
  {
    id: 'SOL1172',
    name: 'Account Owner Not Verified',
    severity: 'critical',
    category: 'account',
    description: 'Account ownership is not checked before use.',
    detection: {
      patterns: [
        /AccountInfo[\s\S]{0,100}(?!owner)/,
        /\.data\.borrow\(\)[\s\S]{0,50}(?!owner)/,
        /try_from_slice[\s\S]{0,50}(?!owner)/
      ]
    },
    recommendation: 'Verify account.owner == expected_program_id before deserializing.',
    references: ['https://sec3.dev/']
  },
  {
    id: 'SOL1173',
    name: 'Account Size Not Validated',
    severity: 'high',
    category: 'account',
    description: 'Account data size not verified before deserialization.',
    detection: {
      patterns: [
        /data\.len\(\)/i,
        /try_from_slice/i,
        /AccountDeserialize/i
      ]
    },
    recommendation: 'Verify account.data.len() matches expected size.',
    references: ['https://sec3.dev/']
  },
  {
    id: 'SOL1174',
    name: 'Account Key Not Derived',
    severity: 'critical',
    category: 'account',
    description: 'PDA account key not derived and verified on-chain.',
    detection: {
      patterns: [
        /find_program_address[\s\S]{0,100}(?!==|require)/,
        /Pubkey::create_program_address/i,
        /bump[\s\S]{0,50}(?!verify|check|assert)/i
      ]
    },
    recommendation: 'Derive PDA on-chain and compare against provided account key.',
    references: ['https://sec3.dev/']
  },
  {
    id: 'SOL1175',
    name: 'Unchecked Account in Anchor',
    severity: 'high',
    category: 'account',
    description: 'UncheckedAccount used without proper validation.',
    detection: {
      patterns: [
        /UncheckedAccount/i,
        /AccountInfo.*CHECK/i,
        /\/\/\/\s*CHECK:/i
      ]
    },
    recommendation: 'Add explicit validation for UncheckedAccount or use typed account.',
    references: ['https://sec3.dev/']
  },
  {
    id: 'SOL1176',
    name: 'Account Rent Not Verified',
    severity: 'medium',
    category: 'account',
    description: 'Account may not be rent-exempt, risking deletion.',
    detection: {
      patterns: [
        /lamports[\s\S]{0,100}(?!rent_exempt)/i,
        /create_account[\s\S]{0,50}(?!minimum_balance)/i,
        /Rent::get/i
      ]
    },
    recommendation: 'Ensure accounts have minimum_balance_for_rent_exemption.',
    references: ['https://docs.solana.com/']
  },
  {
    id: 'SOL1177',
    name: 'Account Signer Not Required',
    severity: 'critical',
    category: 'account',
    description: 'Authority account should be signer but constraint missing.',
    detection: {
      patterns: [
        /authority[\s\S]{0,50}AccountInfo[\s\S]{0,50}(?!signer|is_signer)/i,
        /admin[\s\S]{0,50}(?!signer)/i,
        /owner[\s\S]{0,50}(?!signer)/i
      ]
    },
    recommendation: 'Add #[account(signer)] or manually check is_signer.',
    references: ['https://sec3.dev/']
  },
  {
    id: 'SOL1178',
    name: 'Account Writable Not Required',
    severity: 'high',
    category: 'account',
    description: 'Account should be mutable but constraint missing.',
    detection: {
      patterns: [
        /AccountInfo[\s\S]{0,50}(?!mut|is_writable)/,
        /#\[account\([\s\S]{0,30}(?!mut)/
      ]
    },
    recommendation: 'Add mut constraint for accounts that need modification.',
    references: ['https://sec3.dev/']
  },
  {
    id: 'SOL1179',
    name: 'Account Close Without Zero',
    severity: 'critical',
    category: 'account',
    description: 'Account closed without zeroing data, enabling revival attack.',
    detection: {
      patterns: [
        /close\s*=/i,
        /lamports.*=\s*0/i,
        /close_account/i
      ]
    },
    recommendation: 'Zero account data before closing. Use Anchor close constraint.',
    references: ['https://sec3.dev/']
  },
  {
    id: 'SOL1180',
    name: 'Account Reinitialization',
    severity: 'critical',
    category: 'account',
    description: 'Account can be reinitialized, resetting important state.',
    detection: {
      patterns: [
        /init[\s\S]{0,50}(?!if_needed)/i,
        /is_initialized\s*=\s*false/i,
        /initialize[\s\S]{0,100}(?!require.*initialized)/i
      ]
    },
    recommendation: 'Check is_initialized flag. Use init_if_needed only when safe.',
    references: ['https://sec3.dev/']
  },
  // ========================================
  // ARITHMETIC SECURITY PATTERNS
  // ========================================
  {
    id: 'SOL1181',
    name: 'Unchecked Addition',
    severity: 'high',
    category: 'arithmetic',
    description: 'Addition without overflow check.',
    detection: {
      patterns: [
        /\+(?!\s*=)/,
        /\+=(?![\s\S]{0,20}checked)/,
        /\.add\((?![\s\S]{0,10}overflow)/i
      ]
    },
    recommendation: 'Use checked_add() or saturating_add().',
    references: ['https://sec3.dev/']
  },
  {
    id: 'SOL1182',
    name: 'Unchecked Subtraction',
    severity: 'high',
    category: 'arithmetic',
    description: 'Subtraction without underflow check.',
    detection: {
      patterns: [
        /-(?!\s*>)/,
        /-=(?![\s\S]{0,20}checked)/,
        /\.sub\((?![\s\S]{0,10}overflow)/i
      ]
    },
    recommendation: 'Use checked_sub() or saturating_sub().',
    references: ['https://sec3.dev/']
  },
  {
    id: 'SOL1183',
    name: 'Unchecked Multiplication',
    severity: 'high',
    category: 'arithmetic',
    description: 'Multiplication without overflow check.',
    detection: {
      patterns: [
        /\*(?!\s*=)/,
        /\*=(?![\s\S]{0,20}checked)/,
        /\.mul\((?![\s\S]{0,10}overflow)/i
      ]
    },
    recommendation: 'Use checked_mul() or saturating_mul().',
    references: ['https://sec3.dev/']
  },
  {
    id: 'SOL1184',
    name: 'Division by Zero Risk',
    severity: 'critical',
    category: 'arithmetic',
    description: 'Division without zero check.',
    detection: {
      patterns: [
        /\/(?!\s*\/)/,
        /\.div\(/i,
        /checked_div[\s\S]{0,30}(?!require|if|match)/i
      ]
    },
    recommendation: 'Check divisor != 0. Use checked_div().',
    references: ['https://sec3.dev/']
  },
  {
    id: 'SOL1185',
    name: 'Unsafe Type Cast',
    severity: 'high',
    category: 'arithmetic',
    description: 'Type casting without overflow protection.',
    detection: {
      patterns: [
        /as\s+u8/i,
        /as\s+u16/i,
        /as\s+u32/i,
        /as\s+u64/i,
        /as\s+u128/i,
        /as\s+i\d+/i
      ]
    },
    recommendation: 'Use try_into().unwrap_or() or checked casting.',
    references: ['https://sec3.dev/']
  },
  {
    id: 'SOL1186',
    name: 'Rounding Direction Inconsistency',
    severity: 'medium',
    category: 'arithmetic',
    description: 'Rounding direction can favor one party over another.',
    detection: {
      patterns: [
        /\/\s*\d+/,
        /\.floor\(/i,
        /\.ceil\(/i,
        /round/i
      ]
    },
    recommendation: 'Use consistent rounding that favors protocol security.',
    references: ['https://sec3.dev/']
  },
  {
    id: 'SOL1187',
    name: 'Precision Loss in Fee Calculation',
    severity: 'high',
    category: 'arithmetic',
    description: 'Fee calculation loses precision, can be exploited.',
    detection: {
      patterns: [
        /fee.*\/.*\d+/i,
        /fee.*\*.*\d+.*\/.*\d+/i,
        /basis_points/i,
        /bps/i
      ]
    },
    recommendation: 'Calculate fees: amount * fee / 10000. Always round up for protocol.',
    references: ['https://sec3.dev/']
  },
  {
    id: 'SOL1188',
    name: 'Share Calculation Vulnerability',
    severity: 'critical',
    category: 'arithmetic',
    description: 'Share/token calculation vulnerable to manipulation.',
    detection: {
      patterns: [
        /shares.*=.*amount.*\/.*total/i,
        /amount.*=.*shares.*\*.*total/i,
        /lp_tokens.*\/.*supply/i
      ]
    },
    recommendation: 'Use virtual shares pattern. Check for dust amounts.',
    references: ['https://sec3.dev/']
  },
  {
    id: 'SOL1189',
    name: 'Interest Accrual Calculation',
    severity: 'high',
    category: 'arithmetic',
    description: 'Interest accrual can be manipulated through timing.',
    detection: {
      patterns: [
        /interest.*rate/i,
        /accrued.*interest/i,
        /compound/i,
        /borrow.*index/i
      ]
    },
    recommendation: 'Use global index pattern. Limit accrual frequency manipulation.',
    references: ['https://sec3.dev/']
  },
  {
    id: 'SOL1190',
    name: 'Price Calculation Overflow',
    severity: 'critical',
    category: 'arithmetic',
    description: 'Price multiplication can overflow u64/u128.',
    detection: {
      patterns: [
        /price.*\*/i,
        /amount.*\*.*price/i,
        /value.*=.*quantity.*\*.*price/i
      ]
    },
    recommendation: 'Use u128 for intermediate calculations. Check bounds.',
    references: ['https://sec3.dev/']
  },
  // ========================================
  // ORACLE SECURITY PATTERNS
  // ========================================
  {
    id: 'SOL1191',
    name: 'Oracle Price Staleness',
    severity: 'critical',
    category: 'oracle',
    description: 'Oracle price not checked for staleness.',
    detection: {
      patterns: [
        /price[\s\S]{0,100}(?!timestamp|slot|age|stale)/i,
        /oracle[\s\S]{0,100}(?!valid_slot|publish_time)/i,
        /get_price[\s\S]{0,50}(?!stale)/i
      ]
    },
    recommendation: 'Check oracle timestamp/slot. Reject stale prices (>30s for Pyth).',
    references: ['https://pyth.network/']
  },
  {
    id: 'SOL1192',
    name: 'Oracle Confidence Interval',
    severity: 'high',
    category: 'oracle',
    description: 'Oracle confidence interval not verified.',
    detection: {
      patterns: [
        /price[\s\S]{0,100}(?!confidence|conf)/i,
        /pyth[\s\S]{0,50}(?!conf)/i,
        /price_feed[\s\S]{0,100}(?!uncertainty)/i
      ]
    },
    recommendation: 'Reject prices with wide confidence intervals (>1-2%).',
    references: ['https://pyth.network/']
  },
  {
    id: 'SOL1193',
    name: 'Single Oracle Dependency',
    severity: 'high',
    category: 'oracle',
    description: 'Protocol relies on single oracle source.',
    detection: {
      patterns: [
        /price_feed/i,
        /oracle_account/i,
        /switchboard/i,
        /pyth_price/i
      ]
    },
    recommendation: 'Use multiple oracle sources. Implement fallback mechanism.',
    references: ['https://sec3.dev/']
  },
  {
    id: 'SOL1194',
    name: 'Oracle Account Not Validated',
    severity: 'critical',
    category: 'oracle',
    description: 'Oracle account ownership/address not verified.',
    detection: {
      patterns: [
        /oracle.*AccountInfo/i,
        /price_feed.*Account/i,
        /\.key\s*$/i
      ]
    },
    recommendation: 'Verify oracle account is owned by oracle program and matches expected feed.',
    references: ['https://sec3.dev/']
  },
  {
    id: 'SOL1195',
    name: 'Oracle Manipulation via Flash Loan',
    severity: 'critical',
    category: 'oracle',
    description: 'Price oracle vulnerable to flash loan manipulation.',
    detection: {
      patterns: [
        /spot.*price/i,
        /reserve.*ratio/i,
        /pool.*price/i,
        /amm.*price/i
      ]
    },
    recommendation: 'Use TWAP. Dont trust on-chain AMM prices for critical ops.',
    references: ['https://sec3.dev/']
  },
  {
    id: 'SOL1196',
    name: 'Oracle TWAP Window Too Short',
    severity: 'high',
    category: 'oracle',
    description: 'TWAP window too short, vulnerable to manipulation.',
    detection: {
      patterns: [
        /twap/i,
        /time.*weighted/i,
        /window.*\d+/i,
        /interval.*seconds/i
      ]
    },
    recommendation: 'Use TWAP window of at least 30 minutes for critical operations.',
    references: ['https://sec3.dev/']
  },
  {
    id: 'SOL1197',
    name: 'Missing Oracle Status Check',
    severity: 'high',
    category: 'oracle',
    description: 'Oracle status/health not verified.',
    detection: {
      patterns: [
        /oracle[\s\S]{0,100}(?!status|trading|halted)/i,
        /price[\s\S]{0,100}(?!status)/i
      ]
    },
    recommendation: 'Check oracle status. Handle halted/unknown states.',
    references: ['https://sec3.dev/']
  },
  {
    id: 'SOL1198',
    name: 'Pyth EMA Price Not Used',
    severity: 'medium',
    category: 'oracle',
    description: 'Using spot price instead of EMA for less volatile feed.',
    detection: {
      patterns: [
        /price\.price/i,
        /get_price_unchecked/i,
        /pyth[\s\S]{0,50}(?!ema)/i
      ]
    },
    recommendation: 'Consider using EMA price for less volatile critical operations.',
    references: ['https://pyth.network/']
  },
  {
    id: 'SOL1199',
    name: 'Switchboard Aggregator Not Fresh',
    severity: 'high',
    category: 'oracle',
    description: 'Switchboard aggregator result freshness not checked.',
    detection: {
      patterns: [
        /switchboard/i,
        /aggregator/i,
        /latest_confirmed_round/i
      ]
    },
    recommendation: 'Verify result timestamp is within acceptable range.',
    references: ['https://switchboard.xyz/']
  },
  {
    id: 'SOL1200',
    name: 'Oracle Feed Mismatch',
    severity: 'critical',
    category: 'oracle',
    description: 'Oracle feed doesnt match the asset being priced.',
    detection: {
      patterns: [
        /price_feed.*mint/i,
        /oracle.*token/i,
        /feed_id/i
      ]
    },
    recommendation: 'Verify oracle feed ID matches asset. Store mapping on-chain.',
    references: ['https://sec3.dev/']
  },
  // ========================================
  // TOKEN SECURITY PATTERNS
  // ========================================
  {
    id: 'SOL1201',
    name: 'Token Mint Authority Not Verified',
    severity: 'critical',
    category: 'token',
    description: 'Token mint authority not checked before minting.',
    detection: {
      patterns: [
        /mint_to/i,
        /MintTo\s*\{/i,
        /mint.*authority/i
      ]
    },
    recommendation: 'Verify signer is mint authority. Use constraint: mint_authority = authority.',
    references: ['https://sec3.dev/']
  },
  {
    id: 'SOL1202',
    name: 'Token Freeze Authority Risk',
    severity: 'medium',
    category: 'token',
    description: 'Token has active freeze authority that could lock funds.',
    detection: {
      patterns: [
        /freeze_authority/i,
        /FreezeAccount/i,
        /thaw/i
      ]
    },
    recommendation: 'Verify freeze authority is acceptable or set to None.',
    references: ['https://sec3.dev/']
  },
  {
    id: 'SOL1203',
    name: 'Token Account Owner Mismatch',
    severity: 'critical',
    category: 'token',
    description: 'Token account owner not verified against expected.',
    detection: {
      patterns: [
        /token_account[\s\S]{0,100}(?!owner)/i,
        /TokenAccount[\s\S]{0,50}(?!owner)/i,
        /\.owner[\s\S]{0,30}(?!==|require)/i
      ]
    },
    recommendation: 'Add constraint: token::authority = expected_owner.',
    references: ['https://sec3.dev/']
  },
  {
    id: 'SOL1204',
    name: 'Token Mint Mismatch',
    severity: 'critical',
    category: 'token',
    description: 'Token account mint not verified against expected.',
    detection: {
      patterns: [
        /token_account[\s\S]{0,100}(?!mint)/i,
        /TokenAccount[\s\S]{0,50}(?!mint)/i,
        /\.mint[\s\S]{0,30}(?!==|require)/i
      ]
    },
    recommendation: 'Add constraint: token::mint = expected_mint.',
    references: ['https://sec3.dev/']
  },
  {
    id: 'SOL1205',
    name: 'Native SOL vs WSOL Confusion',
    severity: 'high',
    category: 'token',
    description: 'Native SOL and wrapped SOL handled inconsistently.',
    detection: {
      patterns: [
        /native_mint/i,
        /NATIVE_MINT/i,
        /wsol/i,
        /lamports.*spl/i
      ]
    },
    recommendation: 'Handle native SOL and WSOL explicitly. Unwrap/wrap as needed.',
    references: ['https://sec3.dev/']
  },
  {
    id: 'SOL1206',
    name: 'Token-2022 Transfer Hook Not Handled',
    severity: 'high',
    category: 'token',
    description: 'Token-2022 transfer hook may cause unexpected behavior.',
    detection: {
      patterns: [
        /token_2022/i,
        /spl_token_2022/i,
        /transfer_hook/i,
        /token_program.*id/i
      ]
    },
    recommendation: 'Check for transfer hook. Use transfer_checked for Token-2022.',
    references: ['https://spl.solana.com/token-2022']
  },
  {
    id: 'SOL1207',
    name: 'Token-2022 Transfer Fee Not Accounted',
    severity: 'high',
    category: 'token',
    description: 'Token-2022 transfer fee can cause accounting errors.',
    detection: {
      patterns: [
        /token_2022/i,
        /transfer_fee/i,
        /fee_amount/i,
        /withheld_amount/i
      ]
    },
    recommendation: 'Account for transfer fees in calculations. Check withheld amounts.',
    references: ['https://spl.solana.com/token-2022']
  },
  {
    id: 'SOL1208',
    name: 'Approval Frontrunning',
    severity: 'medium',
    category: 'token',
    description: 'Token approval vulnerable to frontrunning attack.',
    detection: {
      patterns: [
        /approve/i,
        /Approve\s*\{/i,
        /delegated_amount/i
      ]
    },
    recommendation: 'Set approval to 0 before new value, or use increaseAllowance pattern.',
    references: ['https://sec3.dev/']
  },
  {
    id: 'SOL1209',
    name: 'Token Decimal Mismatch',
    severity: 'high',
    category: 'token',
    description: 'Token decimal handling inconsistent.',
    detection: {
      patterns: [
        /decimals/i,
        /10\.pow/i,
        /\*\s*10\^/i,
        /LAMPORTS_PER_SOL/i
      ]
    },
    recommendation: 'Always read decimals from mint. Normalize calculations.',
    references: ['https://sec3.dev/']
  },
  {
    id: 'SOL1210',
    name: 'Token Program ID Not Verified',
    severity: 'critical',
    category: 'token',
    description: 'Token program ID could be substituted.',
    detection: {
      patterns: [
        /token_program.*AccountInfo/i,
        /Program.*token/i,
        /spl_token.*id/i
      ]
    },
    recommendation: 'Verify token_program.key() equals expected SPL token program.',
    references: ['https://sec3.dev/']
  },
  // ========================================
  // ACCESS CONTROL PATTERNS
  // ========================================
  {
    id: 'SOL1211',
    name: 'Missing Admin Authorization',
    severity: 'critical',
    category: 'access',
    description: 'Admin function lacks proper authorization.',
    detection: {
      patterns: [
        /admin/i,
        /owner/i,
        /authority[\s\S]{0,100}(?!signer|has_one)/i
      ]
    },
    recommendation: 'Add has_one = authority and signer constraints.',
    references: ['https://sec3.dev/']
  },
  {
    id: 'SOL1212',
    name: 'Authority Transfer Without Validation',
    severity: 'critical',
    category: 'access',
    description: 'Authority can be transferred to zero address or invalid key.',
    detection: {
      patterns: [
        /set_authority/i,
        /transfer_authority/i,
        /new_authority/i,
        /pending_authority/i
      ]
    },
    recommendation: 'Validate new authority. Use two-step transfer pattern.',
    references: ['https://sec3.dev/']
  },
  {
    id: 'SOL1213',
    name: 'Single Point of Failure Authority',
    severity: 'high',
    category: 'access',
    description: 'Single admin key controls critical functions.',
    detection: {
      patterns: [
        /authority.*Pubkey/i,
        /admin.*Pubkey/i,
        /owner.*Pubkey/i
      ]
    },
    recommendation: 'Use multisig or DAO governance for critical operations.',
    references: ['https://sec3.dev/']
  },
  {
    id: 'SOL1214',
    name: 'Upgrade Authority Not Secured',
    severity: 'high',
    category: 'access',
    description: 'Program upgrade authority could be compromised.',
    detection: {
      patterns: [
        /upgrade_authority/i,
        /set_upgrade_authority/i,
        /BpfUpgradeable/i
      ]
    },
    recommendation: 'Use multisig for upgrade authority. Consider timelock.',
    references: ['https://sec3.dev/']
  },
  {
    id: 'SOL1215',
    name: 'Missing Role Check',
    severity: 'high',
    category: 'access',
    description: 'Role-based access control not enforced.',
    detection: {
      patterns: [
        /role/i,
        /permission/i,
        /access_level/i,
        /can_execute/i
      ]
    },
    recommendation: 'Implement and verify role-based permissions.',
    references: ['https://sec3.dev/']
  },
  {
    id: 'SOL1216',
    name: 'Time-Locked Operation Bypass',
    severity: 'high',
    category: 'access',
    description: 'Time-locked operation can be bypassed.',
    detection: {
      patterns: [
        /timelock/i,
        /delay/i,
        /unlock_time/i,
        /execution_time/i
      ]
    },
    recommendation: 'Verify timelock cannot be bypassed. Use on-chain clock.',
    references: ['https://sec3.dev/']
  },
  {
    id: 'SOL1217',
    name: 'Emergency Pause Not Implemented',
    severity: 'medium',
    category: 'access',
    description: 'No emergency pause functionality for critical failure.',
    detection: {
      patterns: [
        /pause/i,
        /emergency/i,
        /circuit_breaker/i,
        /is_paused/i
      ]
    },
    recommendation: 'Implement pausable pattern for emergency situations.',
    references: ['https://sec3.dev/']
  },
  {
    id: 'SOL1218',
    name: 'Pause Authority Centralized',
    severity: 'medium',
    category: 'access',
    description: 'Pause authority controlled by single entity.',
    detection: {
      patterns: [
        /pause_authority/i,
        /guardian/i,
        /emergency_admin/i
      ]
    },
    recommendation: 'Use multisig for pause authority. Add auto-unpause mechanism.',
    references: ['https://sec3.dev/']
  },
  {
    id: 'SOL1219',
    name: 'Fee Recipient Not Validated',
    severity: 'high',
    category: 'access',
    description: 'Fee recipient can be set to arbitrary address.',
    detection: {
      patterns: [
        /fee_recipient/i,
        /treasury/i,
        /fee_account/i,
        /protocol_fee/i
      ]
    },
    recommendation: 'Validate fee recipient is not zero. Use timelock for changes.',
    references: ['https://sec3.dev/']
  },
  {
    id: 'SOL1220',
    name: 'Whitelist/Allowlist Bypass',
    severity: 'high',
    category: 'access',
    description: 'Whitelist check can be bypassed.',
    detection: {
      patterns: [
        /whitelist/i,
        /allowlist/i,
        /approved_list/i,
        /is_whitelisted/i
      ]
    },
    recommendation: 'Use on-chain whitelist. Verify inclusion before operation.',
    references: ['https://sec3.dev/']
  },
  // ========================================
  // GOVERNANCE PATTERNS
  // ========================================
  {
    id: 'SOL1221',
    name: 'Flash Loan Governance Attack',
    severity: 'critical',
    category: 'governance',
    description: 'Governance voting vulnerable to flash loan attack.',
    detection: {
      patterns: [
        /vote/i,
        /governance/i,
        /proposal/i,
        /voting_power/i
      ]
    },
    recommendation: 'Use vote escrow. Snapshot voting power at proposal creation.',
    references: ['https://sec3.dev/']
  },
  {
    id: 'SOL1222',
    name: 'Proposal Execution Without Delay',
    severity: 'high',
    category: 'governance',
    description: 'Governance proposal can execute immediately after passing.',
    detection: {
      patterns: [
        /execute_proposal/i,
        /proposal.*execute/i,
        /execute[\s\S]{0,50}(?!delay|timelock)/i
      ]
    },
    recommendation: 'Implement timelock delay between passing and execution.',
    references: ['https://sec3.dev/']
  },
  {
    id: 'SOL1223',
    name: 'Low Quorum Threshold',
    severity: 'medium',
    category: 'governance',
    description: 'Governance quorum threshold may be too low.',
    detection: {
      patterns: [
        /quorum/i,
        /min_votes/i,
        /threshold/i,
        /vote_threshold/i
      ]
    },
    recommendation: 'Set appropriate quorum based on token distribution.',
    references: ['https://sec3.dev/']
  },
  {
    id: 'SOL1224',
    name: 'Vote Delegation Without Limits',
    severity: 'medium',
    category: 'governance',
    description: 'Vote delegation has no limits or cooldown.',
    detection: {
      patterns: [
        /delegate/i,
        /delegation/i,
        /voting_delegate/i,
        /delegated_voting_power/i
      ]
    },
    recommendation: 'Implement delegation cooldown and max delegatees.',
    references: ['https://sec3.dev/']
  },
  {
    id: 'SOL1225',
    name: 'Proposal Spam Attack',
    severity: 'low',
    category: 'governance',
    description: 'No cost to create proposals enables spam.',
    detection: {
      patterns: [
        /create_proposal/i,
        /new_proposal/i,
        /proposal_count/i
      ]
    },
    recommendation: 'Require minimum token stake to create proposals.',
    references: ['https://sec3.dev/']
  },
  // ========================================
  // MISC SECURITY PATTERNS
  // ========================================
  {
    id: 'SOL1226',
    name: 'Panic on Invalid Input',
    severity: 'medium',
    category: 'misc',
    description: 'Program panics on invalid input instead of returning error.',
    detection: {
      patterns: [
        /unwrap\(\)/i,
        /expect\(/i,
        /panic!/i,
        /assert!/i
      ]
    },
    recommendation: 'Use Result types and proper error handling.',
    references: ['https://sec3.dev/']
  },
  {
    id: 'SOL1227',
    name: 'Insufficient Logging',
    severity: 'low',
    category: 'misc',
    description: 'Critical operations not logged for monitoring.',
    detection: {
      patterns: [
        /transfer[\s\S]{0,100}(?!emit|msg!|log)/i,
        /withdraw[\s\S]{0,100}(?!emit|msg!)/i,
        /admin[\s\S]{0,100}(?!emit|msg!)/i
      ]
    },
    recommendation: 'Emit events for critical state changes.',
    references: ['https://sec3.dev/']
  },
  {
    id: 'SOL1228',
    name: 'Hardcoded Values',
    severity: 'low',
    category: 'misc',
    description: 'Hardcoded values that should be configurable.',
    detection: {
      patterns: [
        /const.*=\s*\d{4,}/i,
        /HARD_CODED/i,
        /MAGIC_NUMBER/i
      ]
    },
    recommendation: 'Use configurable parameters or constants with clear naming.',
    references: ['https://sec3.dev/']
  },
  {
    id: 'SOL1229',
    name: 'Missing Input Bounds Check',
    severity: 'high',
    category: 'misc',
    description: 'User input not validated against bounds.',
    detection: {
      patterns: [
        /amount[\s\S]{0,50}(?!>=|<=|>|<|min|max)/i,
        /input[\s\S]{0,50}(?!validate|check)/i,
        /param[\s\S]{0,50}(?!bounds|limit)/i
      ]
    },
    recommendation: 'Validate all inputs against acceptable ranges.',
    references: ['https://sec3.dev/']
  },
  {
    id: 'SOL1230',
    name: 'Unsafe External Data Usage',
    severity: 'high',
    category: 'misc',
    description: 'External data used without validation.',
    detection: {
      patterns: [
        /instruction_data/i,
        /AccountInfo.*data/i,
        /remaining_accounts/i,
        /data\.borrow\(\)/i
      ]
    },
    recommendation: 'Validate all external data before use.',
    references: ['https://sec3.dev/']
  }
];

// Export function to run all patterns in this batch
export function runBatchedPatterns41(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';
  
  if (!content) return findings;
  
  for (const pattern of batchedPatterns41) {
    for (const regex of pattern.detection.patterns) {
      if (regex.test(content)) {
        const match = content.match(regex);
        if (match) {
          findings.push({
            id: pattern.id,
            title: pattern.name,
            severity: pattern.severity,
            description: pattern.description,
            location: { file: input.path },
            recommendation: pattern.recommendation,
          });
          break; // One finding per pattern
        }
      }
    }
  }
  
  return findings;
}

export { batchedPatterns41 };
export const BATCH_41_COUNT = batchedPatterns41.length; // 70 patterns
