/**
 * Batch 71: February 2026 Latest Security Patterns (Part 2)
 * Based on: DEV.to "15 Critical Solana Vulnerabilities" (Feb 2026)
 *           Step Finance $30M Hack Details (Jan 31, 2026)
 *           CertiK January 2026 Stats ($400M+ in losses)
 *           OKX/Phantom Phishing Alert (Jan 7, 2026)
 * Patterns: SOL3201-SOL3275
 */

import type { PatternInput, Finding } from './index.js';

function createFinding(
  id: string,
  title: string,
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info',
  description: string,
  location: { file: string; line?: number },
  recommendation?: string
): Finding {
  return { id, title, severity, description, location, recommendation };
}

/**
 * SOL3201-3205: Missing Signer Check Patterns (DEV.to #1)
 * Real Exploit: Solend Aug 2021 - $2M attempted theft via admin bypass
 */
function checkMissingSignerCheck(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  
  const content = input.rust.content;
  const lines = content.split('\n');
  
  // SOL3201: Using AccountInfo without signer check
  if (content.includes('AccountInfo') && !content.includes('Signer<')) {
    if ((content.includes('authority') || content.includes('admin') || content.includes('owner')) &&
        !content.includes('.is_signer') && !content.includes('is_signer()')) {
      findings.push(createFinding(
        'SOL3201',
        'AccountInfo Without Signer Verification (Solend Pattern)',
        'critical',
        'Using AccountInfo for authority without is_signer check. Solend Aug 2021: attacker passed admin pubkey without signing, nearly stole $2M.',
        { file: input.path },
        'Use Signer<\'info> in Anchor, or verify: if !authority.is_signer() { return Err(ProgramError::MissingRequiredSignature); }'
      ));
    }
  }
  
  // SOL3202: Withdrawal without signer verification
  lines.forEach((line, idx) => {
    if ((line.includes('withdraw') || line.includes('transfer_from')) && 
        !content.includes('require_signer') && !content.includes('Signer<')) {
      if (line.includes('authority') || line.includes('from')) {
        findings.push(createFinding(
          'SOL3202',
          'Withdrawal Operation Missing Signer Check',
          'critical',
          'Fund withdrawal operations must verify the signer. Pattern: attacker passes pubkey without owning private key.',
          { file: input.path, line: idx + 1 },
          'Add explicit signer requirement: pub authority: Signer<\'info>'
        ));
      }
    }
  });
  
  // SOL3203: Admin functions without signer
  if ((content.includes('update_config') || content.includes('set_param') || content.includes('admin_')) &&
      !content.includes('Signer<') && !content.includes('is_signer')) {
    findings.push(createFinding(
      'SOL3203',
      'Admin Function Without Signer Verification',
      'critical',
      'Administrative functions must verify signer ownership. Attackers can call admin functions by just knowing the admin pubkey.',
      { file: input.path },
      'All admin functions need: #[access_control(admin_check(...))] or Signer<\'info>'
    ));
  }
  
  // SOL3204: Conditional signer check (insufficient)
  if (content.includes('if authority.key() ==') && !content.includes('is_signer')) {
    findings.push(createFinding(
      'SOL3204',
      'Key Comparison Without Signer Check',
      'critical',
      'Checking key equality is not enough - anyone can pass any pubkey. Must also verify is_signer.',
      { file: input.path },
      'Always combine: authority.key() == expected_key && authority.is_signer()'
    ));
  }
  
  // SOL3205: Anchor Signer missing in struct
  const structMatches = content.match(/pub struct \w+<'info>\s*\{[^}]+\}/g);
  if (structMatches) {
    structMatches.forEach(struct => {
      if ((struct.includes('authority') || struct.includes('admin') || struct.includes('payer')) &&
          !struct.includes('Signer<\'info>')) {
        findings.push(createFinding(
          'SOL3205',
          'Account Struct Authority Without Signer Type',
          'high',
          'Authority/admin accounts in instruction context should use Signer<\'info> type for automatic verification.',
          { file: input.path },
          'Change: pub authority: AccountInfo<\'info> → pub authority: Signer<\'info>'
        ));
      }
    });
  }
  
  return findings;
}

/**
 * SOL3206-3210: Missing Owner Check Patterns (DEV.to #2)
 * Real Exploits: Solend Aug 2021, Crema Finance Jul 2022 ($8.8M)
 */
function checkMissingOwnerCheck(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  
  const content = input.rust.content;
  
  // SOL3206: AccountInfo without owner verification
  if (content.includes('AccountInfo') && !content.includes('Account<')) {
    if (!content.includes('.owner') && !content.includes('owner()') && 
        !content.includes('owner ==') && !content.includes('owner !=')) {
      if (content.includes('data') || content.includes('deserialize') || content.includes('try_from_slice')) {
        findings.push(createFinding(
          'SOL3206',
          'Account Data Read Without Owner Verification (Crema Pattern)',
          'critical',
          'Reading account data without verifying owner. Crema Finance ($8.8M): attacker created fake tick accounts with false price data.',
          { file: input.path },
          'Verify owner: if account.owner() != program_id { return Err(ProgramError::IllegalOwner); }'
        ));
      }
    }
  }
  
  // SOL3207: UncheckedAccount usage
  if (content.includes('UncheckedAccount') || content.includes('/// CHECK:')) {
    findings.push(createFinding(
      'SOL3207',
      'UncheckedAccount May Skip Owner Validation',
      'high',
      'UncheckedAccount bypasses Anchor\'s automatic owner checks. Manual verification required.',
      { file: input.path },
      'If using UncheckedAccount, add explicit owner check: require!(account.owner == &expected_program)'
    ));
  }
  
  // SOL3208: Oracle/price feed without owner check
  if (content.includes('price') || content.includes('oracle') || content.includes('feed')) {
    if (!content.includes('owner ==') && !content.includes('pyth') && !content.includes('switchboard')) {
      findings.push(createFinding(
        'SOL3208',
        'Price/Oracle Account Without Owner Verification',
        'critical',
        'Oracle accounts must verify owner is the expected oracle program. Attackers can create fake oracle accounts with manipulated prices.',
        { file: input.path },
        'Verify: price_account.owner == &pyth_program_id OR use verified oracle libraries'
      ));
    }
  }
  
  // SOL3209: Token account owner confusion
  if (content.includes('TokenAccount') || content.includes('token::Token')) {
    if (content.includes('owner') && !content.includes('token_account.owner')) {
      findings.push(createFinding(
        'SOL3209',
        'Token Account Owner Field Confusion',
        'medium',
        'Token accounts have both an account owner (Token Program) and a data owner field. Ensure you\'re checking the right one.',
        { file: input.path },
        'Account owner = Token Program; Data owner = wallet that controls tokens. Verify both as needed.'
      ));
    }
  }
  
  // SOL3210: SystemProgram account misuse
  if (content.includes('system_program') && content.includes('transfer')) {
    if (!content.includes('Account<') && content.includes('AccountInfo')) {
      findings.push(createFinding(
        'SOL3210',
        'SystemProgram Transfer Without Type Safety',
        'high',
        'System program operations should use typed accounts. Raw AccountInfo can accept fake system-owned accounts.',
        { file: input.path },
        'Use: pub system_program: Program<\'info, System> instead of AccountInfo'
      ));
    }
  }
  
  return findings;
}

/**
 * SOL3211-3215: Account Data Matching Patterns (DEV.to #3)
 * Real Exploit: Solend Oracle Manipulation Nov 2022 ($1.26M)
 */
function checkAccountDataMatching(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  
  const content = input.rust.content;
  
  // SOL3211: Token account without mint constraint
  if (content.includes('TokenAccount') || content.includes('token_account')) {
    if (!content.includes('constraint = ') && !content.includes('.mint ==') && !content.includes('mint ==')) {
      if (!content.includes('mint =')) {
        findings.push(createFinding(
          'SOL3211',
          'Token Account Without Mint Constraint (Solend Pattern)',
          'critical',
          'Token account accepted without verifying mint. Solend Nov 2022: attacker substituted manipulatable USDH pool, inflated price from $1 to $8.80.',
          { file: input.path },
          'Add constraint: #[account(constraint = token_account.mint == expected_mint)]'
        ));
      }
    }
  }
  
  // SOL3212: Missing relationship validation
  if (content.includes('pool') && content.includes('token')) {
    if (!content.includes('pool.token_account') && !content.includes('token_account == pool')) {
      findings.push(createFinding(
        'SOL3212',
        'Pool-Token Account Relationship Not Verified',
        'high',
        'Pool and token account relationship must be validated. Attackers can substitute their own controlled accounts.',
        { file: input.path },
        'Validate: require!(user_token.key() == pool.token_account)'
      ));
    }
  }
  
  // SOL3213: Oracle source not validated
  if (content.includes('oracle') || content.includes('price_feed')) {
    if (!content.includes('has_one') && !content.includes('constraint =') && 
        !content.includes('feed_id') && !content.includes('price_feed ==')) {
      findings.push(createFinding(
        'SOL3213',
        'Oracle Feed Source Not Validated',
        'critical',
        'Oracle feed must be the specific expected feed, not just any valid oracle account.',
        { file: input.path },
        'Add: #[account(constraint = oracle.key() == expected_oracle_pubkey)]'
      ));
    }
  }
  
  // SOL3214: User relationship validation
  if (content.includes('user') && (content.includes('vault') || content.includes('position'))) {
    if (!content.includes('has_one = user') && !content.includes('user.key()')) {
      findings.push(createFinding(
        'SOL3214',
        'User-Owned Account Relationship Not Verified',
        'high',
        'User\'s vault/position must verify the user relationship. Attackers may access other users\' accounts.',
        { file: input.path },
        'Add: #[account(has_one = user)] or constraint = vault.owner == user.key()'
      ));
    }
  }
  
  // SOL3215: Multiple price sources
  if (content.includes('price') && !content.includes('twap') && !content.includes('aggregate')) {
    if (content.match(/oracle|price_feed/gi)?.length === 1) {
      findings.push(createFinding(
        'SOL3215',
        'Single Oracle Price Source',
        'high',
        'Using single price source is vulnerable to manipulation. Solend attack used single Saber pool while keeping Orca price stable.',
        { file: input.path },
        'Use multiple price sources: aggregate(pyth_price, switchboard_price) or implement TWAP'
      ));
    }
  }
  
  return findings;
}

/**
 * SOL3216-3220: Type Cosplay Patterns (DEV.to #4)
 * Vulnerability: Passing one account type where another is expected
 */
function checkTypeCosplay(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  
  const content = input.rust.content;
  
  // SOL3216: Missing discriminator in manual deserialization
  if (content.includes('try_from_slice') || content.includes('deserialize')) {
    if (!content.includes('discriminator') && !content.includes('[0..8]')) {
      findings.push(createFinding(
        'SOL3216',
        'Manual Deserialization Without Discriminator Check',
        'critical',
        'Deserializing account data without checking discriminator. Attacker can pass different account type with aligned fields.',
        { file: input.path },
        'Check first 8 bytes: if &data[0..8] != EXPECTED_DISCRIMINATOR { return Err(...) }'
      ));
    }
  }
  
  // SOL3217: AccountInfo casting without type verification
  if (content.includes('AccountInfo') && content.includes('as *const')) {
    findings.push(createFinding(
      'SOL3217',
      'Unsafe AccountInfo Casting',
      'critical',
      'Casting AccountInfo data directly is dangerous. Different account types may have overlapping memory layouts.',
      { file: input.path },
      'Use Anchor Account<\'info, T> or verify discriminator before casting'
    ));
  }
  
  // SOL3218: Multiple account types with similar layouts
  const structDefs = content.match(/#\[account\]\s*pub struct \w+ \{[^}]+\}/g);
  if (structDefs && structDefs.length >= 2) {
    // Check for similar field patterns
    const patterns = structDefs.map(s => {
      const fields = s.match(/pub \w+: (Pubkey|u64|u8|bool)/g);
      return fields?.join(',');
    });
    if (new Set(patterns).size < patterns.length) {
      findings.push(createFinding(
        'SOL3218',
        'Account Types With Similar Layouts (Cosplay Risk)',
        'medium',
        'Multiple account types have similar field layouts. Ensure discriminators are unique and always checked.',
        { file: input.path },
        'Anchor automatically adds discriminators, but verify custom types have unique first 8 bytes'
      ));
    }
  }
  
  // SOL3219: Raw account without Anchor
  if (content.includes('AccountInfo') && !content.includes('#[derive(Accounts)]')) {
    if (content.includes('borrow_mut') || content.includes('borrow()')) {
      findings.push(createFinding(
        'SOL3219',
        'Raw Account Access Without Framework Protection',
        'high',
        'Accessing account data without Anchor\'s type system increases type cosplay risk.',
        { file: input.path },
        'Use Account<\'info, T> or implement discriminator checks manually'
      ));
    }
  }
  
  // SOL3220: Zero discriminator check
  if (content.includes('[0u8; 8]') || content.includes('== [0, 0, 0')) {
    findings.push(createFinding(
      'SOL3220',
      'Zero Discriminator May Allow Uninitialized Accounts',
      'high',
      'Checking for zero discriminator may accept uninitialized accounts.',
      { file: input.path },
      'Use non-zero discriminators and check for initialization flag separately'
    ));
  }
  
  return findings;
}

/**
 * SOL3221-3225: PDA Bump Seed Canonicalization (DEV.to #5)
 */
function checkBumpCanonicalization(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  
  const content = input.rust.content;
  
  // SOL3221: User-provided bump without validation
  if (content.includes('bump') && content.includes('instruction_data')) {
    if (!content.includes('find_program_address') && !content.includes('canonical')) {
      findings.push(createFinding(
        'SOL3221',
        'User-Provided Bump Without Canonicalization',
        'critical',
        'Accepting bump from user input allows creation of shadow PDAs at different addresses.',
        { file: input.path },
        'Always use find_program_address to get canonical bump, or store and verify bump in account'
      ));
    }
  }
  
  // SOL3222: Bump not stored in account
  if (content.includes('create_program_address') || content.includes('pda')) {
    if (content.includes('seeds') && !content.includes('bump') && !content.includes('nonce')) {
      findings.push(createFinding(
        'SOL3222',
        'PDA Bump Not Stored For Verification',
        'high',
        'Without storing canonical bump, subsequent operations may accept non-canonical PDAs.',
        { file: input.path },
        'Store bump in account: pub bump: u8, and verify on access: seeds = [..., &[account.bump]]'
      ));
    }
  }
  
  // SOL3223: Using create_program_address without verification
  if (content.includes('create_program_address') && !content.includes('find_program_address')) {
    findings.push(createFinding(
      'SOL3223',
      'create_program_address Without find_program_address',
      'medium',
      'create_program_address can succeed with non-canonical bumps. Use find_program_address to get canonical bump first.',
      { file: input.path },
      'Use find_program_address for initialization, store bump, verify with create_program_address'
    ));
  }
  
  // SOL3224: Anchor bump constraint missing
  if (content.includes('#[account(') && content.includes('seeds =')) {
    if (!content.includes('bump')) {
      findings.push(createFinding(
        'SOL3224',
        'Anchor Seeds Without Bump Constraint',
        'medium',
        'PDA seeds should include bump constraint for verification. Anchor will use canonical bump.',
        { file: input.path },
        'Add bump constraint: seeds = [...], bump or seeds = [...], bump = account.bump'
      ));
    }
  }
  
  // SOL3225: Shadow PDA creation risk
  if (content.includes('init') && content.includes('pda')) {
    if (content.includes('bump =') && content.includes('ctx.bumps')) {
      // Good pattern - using ctx.bumps
    } else if (!content.includes('bump')) {
      findings.push(createFinding(
        'SOL3225',
        'PDA Initialization Without Canonical Bump',
        'high',
        'PDA initialization should use canonical bump from ctx.bumps to prevent shadow accounts.',
        { file: input.path },
        'Use: bump = ctx.bumps.account_name in Anchor'
      ));
    }
  }
  
  return findings;
}

/**
 * SOL3226-3230: Account Reinitialization (DEV.to #6)
 */
function checkReinitialization(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  
  const content = input.rust.content;
  
  // SOL3226: Initialize without existence check
  if (content.includes('initialize') || content.includes('init_')) {
    if (!content.includes('init,') && !content.includes('init_if_needed')) {
      if (!content.includes('is_initialized') && !content.includes('discriminator')) {
        findings.push(createFinding(
          'SOL3226',
          'Initialize Function Without Existence Check',
          'critical',
          'Initialize can be called on existing accounts, overwriting data. Attacker can reset authority to themselves.',
          { file: input.path },
          'Use Anchor init (fails if exists) or check: if account.is_initialized { return Err(...) }'
        ));
      }
    }
  }
  
  // SOL3227: init_if_needed race condition
  if (content.includes('init_if_needed')) {
    findings.push(createFinding(
      'SOL3227',
      'init_if_needed Has Race Condition Risk',
      'high',
      'init_if_needed can race between check and initialize. Prefer explicit two-phase: check + init.',
      { file: input.path },
      'Consider separate initialize instruction with proper checks, or use careful constraint ordering'
    ));
  }
  
  // SOL3228: Close and reinitialize pattern
  if (content.includes('close') && content.includes('init')) {
    findings.push(createFinding(
      'SOL3228',
      'Close-Reinitialize Pattern May Allow Account Resurrection',
      'high',
      'If same account can be closed and reinitialized in same transaction, attacker may resurrect with modified data.',
      { file: input.path },
      'Add delay between close and reinitialize, or use different PDA seeds after close'
    ));
  }
  
  // SOL3229: Zero discriminator as uninitialized check
  if (content.includes('[0; 8]') && content.includes('discriminator')) {
    findings.push(createFinding(
      'SOL3229',
      'Zero Discriminator as Initialization Check',
      'medium',
      'Relying on zero discriminator is fragile. Accounts can be partially written.',
      { file: input.path },
      'Use explicit is_initialized field: pub is_initialized: bool'
    ));
  }
  
  // SOL3230: Reinitialization via deserialization
  if (content.includes('try_from_slice') && !content.includes('Initialized')) {
    if (content.includes('write') || content.includes('serialize_into')) {
      findings.push(createFinding(
        'SOL3230',
        'Deserialization Without Initialization Guard',
        'high',
        'Deserializing and writing without checking initialization allows overwrite attacks.',
        { file: input.path },
        'Check initialization before any write: require!(account.data_is_empty() || !is_initialized)'
      ));
    }
  }
  
  return findings;
}

/**
 * SOL3231-3235: Arbitrary CPI Patterns (DEV.to #7)
 */
function checkArbitraryCPI(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  
  const content = input.rust.content;
  
  // SOL3231: User-provided program ID for CPI
  if (content.includes('invoke') || content.includes('invoke_signed')) {
    if (content.includes('program_id') && !content.includes('token::ID') && 
        !content.includes('system_program::ID') && !content.includes('::id()')) {
      findings.push(createFinding(
        'SOL3231',
        'CPI With Potentially User-Controlled Program ID',
        'critical',
        'Invoking a program ID from user input allows attacker to redirect calls to malicious program.',
        { file: input.path },
        'Hardcode expected program IDs: invoke(&ix, accounts, &token::ID)'
      ));
    }
  }
  
  // SOL3232: CPI without program verification
  if (content.includes('CpiContext') || content.includes('cpi::')) {
    if (content.includes('AccountInfo') && !content.includes('Program<')) {
      findings.push(createFinding(
        'SOL3232',
        'CPI Program Account Not Type-Verified',
        'high',
        'CPI target program should use Program<\'info, T> for automatic ID verification.',
        { file: input.path },
        'Use: pub token_program: Program<\'info, Token> instead of AccountInfo'
      ));
    }
  }
  
  // SOL3233: Token transfer CPI vulnerability
  if (content.includes('transfer') && content.includes('token')) {
    if (!content.includes('anchor_spl::token') && !content.includes('spl_token::')) {
      if (content.includes('invoke')) {
        findings.push(createFinding(
          'SOL3233',
          'Token Transfer CPI Without SPL Token Verification',
          'critical',
          'Token transfer must verify it\'s invoking the real SPL Token program.',
          { file: input.path },
          'Use anchor_spl::token::transfer or verify: program.key() == &spl_token::ID'
        ));
      }
    }
  }
  
  // SOL3234: CPI with user seeds
  if (content.includes('invoke_signed') && content.includes('seeds')) {
    if (!content.includes('b"') && content.includes('instruction_data')) {
      findings.push(createFinding(
        'SOL3234',
        'CPI Seeds May Include User-Controlled Data',
        'high',
        'CPI signer seeds should be deterministic. User-controlled seeds may authorize unintended accounts.',
        { file: input.path },
        'Use fixed seeds or validate user-provided seed components strictly'
      ));
    }
  }
  
  // SOL3235: CPI account ordering attack
  if (content.includes('accounts') && content.includes('invoke')) {
    if (!content.includes('verify_account_order') && !content.includes('key() ==')) {
      findings.push(createFinding(
        'SOL3235',
        'CPI Account Order May Be Manipulated',
        'medium',
        'CPI account ordering should be explicit. Attackers may reorder accounts to exploit index-based access.',
        { file: input.path },
        'Verify account keys explicitly before CPI, or use named accounts in Anchor'
      ));
    }
  }
  
  return findings;
}

/**
 * SOL3236-3245: Step Finance Attack Patterns (Jan 31, 2026)
 * $30M stolen via treasury wallet key compromise + Monero conversion
 */
function checkStepFinancePatterns(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  
  const content = input.rust.content;
  
  // SOL3236: Centralized treasury without multisig
  if (content.includes('treasury') && (content.includes('withdraw') || content.includes('transfer'))) {
    if (!content.includes('multisig') && !content.includes('threshold') && !content.includes('signatures')) {
      findings.push(createFinding(
        'SOL3236',
        'Centralized Treasury (Step Finance Attack Vector)',
        'critical',
        'Step Finance Jan 2026: $30M stolen via single key compromise. Treasury had no multisig.',
        { file: input.path },
        'Implement multisig: require minimum 2-of-3 or 3-of-5 signatures for treasury operations'
      ));
    }
  }
  
  // SOL3237: Commission fund access pattern
  if (content.includes('commission') || content.includes('fee_vault')) {
    if (!content.includes('timelock') && !content.includes('delay')) {
      findings.push(createFinding(
        'SOL3237',
        'Commission Fund Without Withdrawal Delay',
        'high',
        'Step Finance: commission funds were drained instantly. Add timelock for large withdrawals.',
        { file: input.path },
        'Add withdrawal delay: require!(current_time >= request_time + WITHDRAWAL_DELAY)'
      ));
    }
  }
  
  // SOL3238: Unstaking without restrictions
  if (content.includes('unstake') && content.includes('authority')) {
    if (!content.includes('cooldown') && !content.includes('epoch')) {
      findings.push(createFinding(
        'SOL3238',
        'Unstaking Without Cooldown Period',
        'high',
        'Step Finance: attackers unstaked all SOL immediately. Add cooldown/unbonding period.',
        { file: input.path },
        'Implement unbonding: stake cannot be withdrawn until cooldown_end timestamp'
      ));
    }
  }
  
  // SOL3239: Large withdrawal without limits
  if ((content.includes('withdraw') || content.includes('transfer')) && content.includes('amount')) {
    if (!content.includes('max_withdrawal') && !content.includes('daily_limit') && !content.includes('withdrawal_limit')) {
      findings.push(createFinding(
        'SOL3239',
        'Unlimited Withdrawal Amount',
        'high',
        'No withdrawal limits allows complete fund drainage in single transaction.',
        { file: input.path },
        'Add limits: require!(amount <= MAX_SINGLE_WITHDRAWAL); track daily/weekly limits'
      ));
    }
  }
  
  // SOL3240: Key storage recommendations
  if (content.includes('authority') && content.includes('Pubkey')) {
    if (content.includes('// TODO') || content.includes('hot wallet') || content.includes('hot_wallet')) {
      findings.push(createFinding(
        'SOL3240',
        'Hot Wallet Authority (Key Compromise Risk)',
        'critical',
        'Using hot wallet for treasury authority. Step Finance lost $30M via hot key compromise.',
        { file: input.path },
        'Use hardware wallet (Ledger/Trezor) or MPC solution for treasury authorities'
      ));
    }
  }
  
  // SOL3241: Emergency pause mechanism
  if (content.includes('withdraw') || content.includes('transfer')) {
    if (!content.includes('paused') && !content.includes('frozen') && !content.includes('emergency')) {
      findings.push(createFinding(
        'SOL3241',
        'No Emergency Pause Mechanism',
        'high',
        'Cannot pause operations during attack. Step Finance couldn\'t stop drainage.',
        { file: input.path },
        'Add emergency pause: require!(!state.is_paused, "Protocol paused")'
      ));
    }
  }
  
  // SOL3242: Anomaly detection hooks
  if (content.includes('treasury') && !content.includes('monitor') && !content.includes('alert')) {
    findings.push(createFinding(
      'SOL3242',
      'No Anomaly Detection for Treasury Operations',
      'medium',
      'Large treasury movements should trigger alerts. Step Finance attack was detected hours later.',
      { file: input.path },
      'Implement monitoring: emit event with size flags for off-chain alerting'
    ));
  }
  
  // SOL3243: Fund tracking for anti-laundering
  if (content.includes('transfer') && !content.includes('destination_check')) {
    findings.push(createFinding(
      'SOL3243',
      'No Destination Validation for Large Transfers',
      'medium',
      'Step Finance: funds were converted to Monero to complicate tracking. Known mixer addresses can be blacklisted.',
      { file: input.path },
      'Consider destination allowlists for large treasury transfers'
    ));
  }
  
  // SOL3244: Recovery mechanism
  if (content.includes('treasury') && !content.includes('recovery') && !content.includes('backup')) {
    findings.push(createFinding(
      'SOL3244',
      'No Treasury Recovery Mechanism',
      'medium',
      'Step Finance had no recovery option. Consider time-delayed recovery keys.',
      { file: input.path },
      'Implement: backup authority that can recover after extended timelock (e.g., 7 days)'
    ));
  }
  
  // SOL3245: Audit trail
  if (content.includes('treasury') && !content.includes('emit!') && !content.includes('msg!')) {
    findings.push(createFinding(
      'SOL3245',
      'Treasury Operations Without Audit Trail',
      'medium',
      'All treasury operations should emit events for forensic analysis.',
      { file: input.path },
      'Add: emit!(TreasuryOperation { action, amount, authority, timestamp })'
    ));
  }
  
  return findings;
}

/**
 * SOL3246-3255: January 2026 Phishing Campaign Patterns
 * OKX/Phantom Alert Jan 7, 2026 - Owner permission exploitation
 */
function checkJan2026PhishingPatterns(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  
  const content = input.rust.content;
  
  // SOL3246: SetAuthority without confirmation
  if (content.includes('SetAuthority') || content.includes('set_authority')) {
    if (!content.includes('confirm') && !content.includes('two_step') && !content.includes('pending')) {
      findings.push(createFinding(
        'SOL3246',
        'SetAuthority Without Two-Step Confirmation (Jan 2026 Phishing)',
        'critical',
        'Jan 7, 2026 OKX/Phantom alert: Attackers used silent owner transfers via SetAuthority in phishing transactions.',
        { file: input.path },
        'Implement: 1) propose_authority(new) 2) accept_authority() - new owner must actively confirm'
      ));
    }
  }
  
  // SOL3247: Owner field manipulation
  if (content.includes('owner') && (content.includes('update') || content.includes('change'))) {
    if (!content.includes('emit!') && !content.includes('OwnerChanged')) {
      findings.push(createFinding(
        'SOL3247',
        'Owner Change Without Event Emission',
        'high',
        'Silent owner changes make phishing attacks hard to detect. Wallets scan for authority events.',
        { file: input.path },
        'Emit event: emit!(OwnerChanged { account, old_owner, new_owner })'
      ));
    }
  }
  
  // SOL3248: Transaction simulation bypass
  if (content.includes('owner') || content.includes('authority')) {
    // This pattern uses instruction sysvar to evade simulation
    if (content.includes('Instructions') && content.includes('sysvar')) {
      findings.push(createFinding(
        'SOL3248',
        'Instruction Sysvar May Enable Simulation Bypass',
        'high',
        'Attackers use instruction sysvar to detect simulation and change behavior.',
        { file: input.path },
        'Don\'t change behavior based on simulation detection - be consistent'
      ));
    }
  }
  
  // SOL3249: Delegate authority abuse
  if (content.includes('delegate') && content.includes('authority')) {
    if (!content.includes('revoke') && !content.includes('expiry')) {
      findings.push(createFinding(
        'SOL3249',
        'Delegate Authority Without Revocation/Expiry',
        'high',
        'Delegated authority should be revocable and/or time-limited. Phishing can trick users into permanent delegation.',
        { file: input.path },
        'Add: delegate_expiry timestamp, require!(current_time < delegate_expiry)'
      ));
    }
  }
  
  // SOL3250: Approval amount unlimited
  if (content.includes('approve') && content.includes('u64::MAX')) {
    findings.push(createFinding(
      'SOL3250',
      'Unlimited Token Approval (Phishing Vector)',
      'critical',
      'Unlimited approvals let attackers drain all tokens once approved. Jan 2026 phishing used this pattern.',
      { file: input.path },
      'Request minimum necessary approval. Warn users about unlimited approvals.'
    ));
  }
  
  // SOL3251: Memo-based phishing vector
  if (content.includes('memo') || content.includes('Memo')) {
    findings.push(createFinding(
      'SOL3251',
      'Memo Program May Be Used for Phishing',
      'low',
      'Attackers use memo field for phishing URLs. Don\'t render memo content as clickable links.',
      { file: input.path },
      'Sanitize memo content in UI: never render as HTML or clickable URLs'
    ));
  }
  
  // SOL3252: Fake airdrop claim pattern
  if (content.includes('claim') && content.includes('airdrop')) {
    if (!content.includes('merkle') && !content.includes('whitelist')) {
      findings.push(createFinding(
        'SOL3252',
        'Airdrop Claim Without Verification',
        'medium',
        'Fake airdrops are common phishing vector. Verify eligibility via merkle proof.',
        { file: input.path },
        'Use merkle proof for airdrop eligibility verification'
      ));
    }
  }
  
  // SOL3253: Blind signing risk
  if (content.includes('sign') && !content.includes('verify') && !content.includes('display')) {
    findings.push(createFinding(
      'SOL3253',
      'Transaction May Enable Blind Signing Attack',
      'medium',
      'Users signing transactions they don\'t understand. Ensure clear transaction display.',
      { file: input.path },
      'Implement clear transaction preview showing all state changes'
    ));
  }
  
  // SOL3254: Session key vulnerability
  if (content.includes('session') && content.includes('key')) {
    if (!content.includes('expiry') && !content.includes('scope')) {
      findings.push(createFinding(
        'SOL3254',
        'Session Key Without Expiry/Scope Limits',
        'high',
        'Session keys should have limited lifetime and action scope to minimize phishing impact.',
        { file: input.path },
        'Add: session_expiry, allowed_actions[], max_amount per session'
      ));
    }
  }
  
  // SOL3255: Connected dApp permissions
  if (content.includes('connect') || content.includes('approval')) {
    findings.push(createFinding(
      'SOL3255',
      'DApp Connection Permissions Review',
      'info',
      'Users should regularly review and revoke connected dApp permissions. Common phishing recovery step.',
      { file: input.path },
      'Implement permission review UI and easy revocation'
    ));
  }
  
  return findings;
}

/**
 * SOL3256-3265: Integer Overflow and Arithmetic Patterns (DEV.to #7-8)
 */
function checkArithmeticPatterns(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  
  const content = input.rust.content;
  
  // SOL3256: Arithmetic without checked operations
  if ((content.includes('+ ') || content.includes('- ') || content.includes('* ')) &&
      !content.includes('checked_') && !content.includes('saturating_') && 
      !content.includes('require_') && !content.includes('.unwrap_or')) {
    
    // Check if it's in a sensitive context
    if (content.includes('balance') || content.includes('amount') || content.includes('fee')) {
      findings.push(createFinding(
        'SOL3256',
        'Unchecked Arithmetic on Financial Values',
        'critical',
        'Arithmetic on balances/amounts without overflow checks. In release mode, Rust wraps instead of panicking.',
        { file: input.path },
        'Use checked arithmetic: balance.checked_add(amount).ok_or(ProgramError::ArithmeticOverflow)?'
      ));
    }
  }
  
  // SOL3257: u128 to u64 truncation
  if (content.includes('as u64') && content.includes('u128')) {
    findings.push(createFinding(
      'SOL3257',
      'u128 to u64 Truncation Risk',
      'high',
      'Casting u128 to u64 silently truncates. High bits are lost, potentially reducing large values.',
      { file: input.path },
      'Use try_into() with error handling: amount.try_into().map_err(|_| TruncationError)?'
    ));
  }
  
  // SOL3258: Division before multiplication
  if (content.match(/\/.*\*/)) {
    findings.push(createFinding(
      'SOL3258',
      'Division Before Multiplication (Precision Loss)',
      'high',
      'Dividing before multiplying causes precision loss. a/b*c != a*c/b in integer math.',
      { file: input.path },
      'Reorder: (a * c) / b instead of (a / b) * c'
    ));
  }
  
  // SOL3259: Fee calculation overflow
  if (content.includes('fee') && content.includes('*') && content.includes('/')) {
    if (!content.includes('checked') && !content.includes('u128')) {
      findings.push(createFinding(
        'SOL3259',
        'Fee Calculation May Overflow',
        'high',
        'fee = amount * fee_rate / 10000 can overflow before division. Cast to u128 first.',
        { file: input.path },
        'Use: fee = (amount as u128 * fee_rate as u128 / 10000) as u64'
      ));
    }
  }
  
  // SOL3260: Share calculation rounding
  if (content.includes('share') || content.includes('ratio')) {
    if (content.includes('/') && !content.includes('ceil') && !content.includes('round')) {
      findings.push(createFinding(
        'SOL3260',
        'Share Calculation Uses Floor Division',
        'medium',
        'Integer division always floors. For deposits, ceil is fairer; for withdrawals, floor is fairer.',
        { file: input.path },
        'Choose rounding direction carefully: (a + b - 1) / b for ceiling division'
      ));
    }
  }
  
  // SOL3261: Interest rate spike
  if (content.includes('interest') && content.includes('rate')) {
    if (!content.includes('max_rate') && !content.includes('cap')) {
      findings.push(createFinding(
        'SOL3261',
        'Interest Rate Without Maximum Cap',
        'high',
        'Uncapped interest rates can spike to extreme values during utilization spikes.',
        { file: input.path },
        'Add: rate = min(calculated_rate, MAX_INTEREST_RATE)'
      ));
    }
  }
  
  // SOL3262: Price calculation precision
  if (content.includes('price') && (content.includes('*') || content.includes('/'))) {
    if (!content.includes('PRECISION') && !content.includes('decimals') && !content.includes('1e')) {
      findings.push(createFinding(
        'SOL3262',
        'Price Calculation Without Precision Handling',
        'high',
        'Price calculations need proper decimal handling. Different tokens have different decimals.',
        { file: input.path },
        'Normalize: price * 10^(target_decimals - source_decimals)'
      ));
    }
  }
  
  // SOL3263: Timestamp overflow (year 2038)
  if (content.includes('timestamp') && content.includes('i32')) {
    findings.push(createFinding(
      'SOL3263',
      'Timestamp Using i32 (Year 2038 Problem)',
      'medium',
      'i32 timestamps overflow in 2038. Use i64 or u64 for timestamps.',
      { file: input.path },
      'Use i64 for timestamps: let timestamp: i64 = clock.unix_timestamp;'
    ));
  }
  
  // SOL3264: Subtraction underflow
  if (content.includes('- ') && (content.includes('balance') || content.includes('amount'))) {
    if (!content.includes('checked_sub') && !content.includes('saturating_sub') && !content.includes('require!(')) {
      findings.push(createFinding(
        'SOL3264',
        'Subtraction Without Underflow Check',
        'critical',
        'Subtracting more than available causes underflow/wrap in release mode.',
        { file: input.path },
        'Use: balance.checked_sub(amount).ok_or(InsufficientFunds)?'
      ));
    }
  }
  
  // SOL3265: Supply manipulation via overflow
  if (content.includes('supply') && content.includes('+')) {
    if (!content.includes('MAX_SUPPLY') && !content.includes('checked_add')) {
      findings.push(createFinding(
        'SOL3265',
        'Token Supply Addition Without Max Check',
        'critical',
        'Unchecked supply addition enables infinite mint via overflow.',
        { file: input.path },
        'Add: require!(new_supply <= MAX_SUPPLY); use checked arithmetic'
      ));
    }
  }
  
  return findings;
}

/**
 * SOL3266-3275: CertiK January 2026 Statistics-Driven Patterns
 * Based on: $400M+ total losses, major attack categories
 */
function checkCertik2026Patterns(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  
  const content = input.rust.content;
  
  // SOL3266: Private key exposure (top attack vector Jan 2026)
  if (content.includes('private') || content.includes('secret') || content.includes('seed')) {
    if (content.includes('log') || content.includes('print') || content.includes('msg!')) {
      findings.push(createFinding(
        'SOL3266',
        'Potential Private Key/Seed Logging',
        'critical',
        'CertiK Jan 2026: Key exposure was #1 attack vector. Never log secrets.',
        { file: input.path },
        'Remove ALL logging of private keys, seeds, or secrets. Use environment variables.'
      ));
    }
  }
  
  // SOL3267: Access control bypass (major category)
  if (content.includes('admin') || content.includes('owner')) {
    if (!content.includes('require!') && !content.includes('constraint')) {
      findings.push(createFinding(
        'SOL3267',
        'Admin/Owner Check May Be Missing',
        'critical',
        'CertiK reports access control bypass as major 2026 attack category.',
        { file: input.path },
        'Add: require!(ctx.accounts.authority.key() == state.admin)'
      ));
    }
  }
  
  // SOL3268: Exit scam indicators
  if (content.includes('withdraw_all') || content.includes('drain') || content.includes('emergency_withdraw')) {
    if (!content.includes('multisig') && !content.includes('timelock')) {
      findings.push(createFinding(
        'SOL3268',
        'Potential Exit Scam Function (Drain All)',
        'critical',
        'Functions that drain all funds should require multisig + timelock.',
        { file: input.path },
        'Add multisig requirement and 24-48hr timelock for drain functions'
      ));
    }
  }
  
  // SOL3269: Bridge vulnerability patterns
  if (content.includes('bridge') || content.includes('cross_chain')) {
    if (!content.includes('merkle') && !content.includes('guardian') && !content.includes('relayer')) {
      findings.push(createFinding(
        'SOL3269',
        'Bridge Without Multi-Party Verification',
        'critical',
        'Bridge exploits caused massive losses. Require multiple verifiers.',
        { file: input.path },
        'Implement: merkle proofs + guardian signatures + relayer confirmation'
      ));
    }
  }
  
  // SOL3270: Flash loan detection
  if ((content.includes('borrow') && content.includes('repay')) || content.includes('flash')) {
    if (!content.includes('callback') && !content.includes('reentrancy')) {
      findings.push(createFinding(
        'SOL3270',
        'Flash Loan Implementation Without Reentrancy Guard',
        'high',
        'Flash loans require careful reentrancy protection.',
        { file: input.path },
        'Add reentrancy guard: set flag before callback, check after'
      ));
    }
  }
  
  // SOL3271: Liquidity pool manipulation
  if (content.includes('pool') && content.includes('swap')) {
    if (!content.includes('slippage') && !content.includes('min_out')) {
      findings.push(createFinding(
        'SOL3271',
        'Pool Swap Without Slippage Protection',
        'high',
        'Swaps without slippage protection are vulnerable to sandwich attacks.',
        { file: input.path },
        'Add: require!(amount_out >= min_amount_out)'
      ));
    }
  }
  
  // SOL3272: Governance attack vector
  if (content.includes('governance') || content.includes('proposal')) {
    if (!content.includes('voting_period') && !content.includes('execution_delay')) {
      findings.push(createFinding(
        'SOL3272',
        'Governance Without Time Delays',
        'high',
        'Flash loan governance attacks use instant voting. Add delays.',
        { file: input.path },
        'Add: voting_period >= 3 days, execution_delay >= 24 hours'
      ));
    }
  }
  
  // SOL3273: Oracle dependency
  if (content.includes('price') || content.includes('oracle')) {
    if (!content.includes('fallback') && !content.includes('secondary')) {
      findings.push(createFinding(
        'SOL3273',
        'Single Oracle Without Fallback',
        'high',
        'Oracle failures/manipulations caused major losses. Have fallback.',
        { file: input.path },
        'Implement fallback: if (primary_oracle_stale) use secondary_oracle'
      ));
    }
  }
  
  // SOL3274: Upgrade mechanism
  if (content.includes('upgrade') || content.includes('migrate')) {
    if (!content.includes('timelock') && !content.includes('multisig')) {
      findings.push(createFinding(
        'SOL3274',
        'Program Upgrade Without Protection',
        'critical',
        'Instant upgrades enable backdoor deployment. Add timelock.',
        { file: input.path },
        'Use upgrade authority with: multisig + 48hr timelock + announcement'
      ));
    }
  }
  
  // SOL3275: Insurance/reserve fund
  if (content.includes('protocol') || content.includes('lending') || content.includes('pool')) {
    if (!content.includes('insurance') && !content.includes('reserve') && !content.includes('backstop')) {
      findings.push(createFinding(
        'SOL3275',
        'Protocol Without Insurance/Reserve Fund',
        'medium',
        'DeFi protocols should maintain reserve fund for bad debt/exploits.',
        { file: input.path },
        'Allocate portion of fees to insurance fund for user protection'
      ));
    }
  }
  
  return findings;
}

// Export all check functions
export function checkBatch71Patterns(input: PatternInput): Finding[] {
  return [
    ...checkMissingSignerCheck(input),
    ...checkMissingOwnerCheck(input),
    ...checkAccountDataMatching(input),
    ...checkTypeCosplay(input),
    ...checkBumpCanonicalization(input),
    ...checkReinitialization(input),
    ...checkArbitraryCPI(input),
    ...checkStepFinancePatterns(input),
    ...checkJan2026PhishingPatterns(input),
    ...checkArithmeticPatterns(input),
    ...checkCertik2026Patterns(input),
  ];
}

export default checkBatch71Patterns;
