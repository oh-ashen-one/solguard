/**
 * Batch 110: Zealynx 45-Check Deep Dive + Pinocchio Native Safety + 2025-2026 Advanced Attack Vectors
 * 
 * Sources:
 * - Zealynx Security Blog: 45 Critical Checks for Anchor & Native Programs (Jan 2026)
 * - DEV.to: Solana Vulnerabilities Every Developer Should Know (Jan 2026)
 * - NoOnes $8M Bridge Exploit (Jan 2025)
 * - DEXX $30M Private Key Leak (Nov 2024)
 * - CertiK 2026 Threat Landscape
 * - Pinocchio Framework Security Patterns
 * 
 * Patterns: SOL7526-SOL7555 (30 patterns)
 * Focus: Transfer Hook Reentrancy, Pinocchio Native Signer Validation, 
 *        Two-Step Authority Transfer, Anchor init_if_needed Risks,
 *        Account Data Matching, Cross-Instance Replay, NoOnes Bridge Logic
 */

import type { PatternInput, Finding } from './index.js';

const BATCH_110_PATTERNS: {
  id: string;
  name: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  pattern: RegExp;
  description: string;
  recommendation: string;
}[] = [
  // === TRANSFER HOOK REENTRANCY (Token-2022) ===
  {
    id: 'SOL7526',
    name: 'Transfer Hook State Mutation Before Completion',
    severity: 'critical',
    pattern: /transfer_hook[\s\S]{0,300}(?:state|balance|amount)[\s\S]{0,50}(?:=|\+=|-=)[\s\S]{0,200}(?![\s\S]{0,100}require![\s\S]{0,50}transfer_complete)/i,
    description: 'Transfer hook modifies protocol state before the transfer is finalized. Attackers can exploit partial execution to corrupt state if the outer transfer reverts.',
    recommendation: 'In transfer hooks, validate the transfer completed successfully before mutating any protocol state. Use post-transfer callbacks or verify token balances changed as expected.'
  },
  {
    id: 'SOL7527',
    name: 'Transfer Hook Missing Program ID Validation',
    severity: 'critical',
    pattern: /execute[\s\S]{0,100}transfer_hook[\s\S]{0,300}(?![\s\S]{0,200}program_id\s*==|[\s\S]{0,200}spl_transfer_hook_interface)/i,
    description: 'Transfer hook handler does not verify it was called by the expected Token-2022 program. Attackers can invoke the hook directly, bypassing the transfer flow.',
    recommendation: 'Verify the calling program is the Token-2022 program by checking the instruction sysvar or enforcing that only the token program can invoke the hook.'
  },
  {
    id: 'SOL7528',
    name: 'Transfer Hook Recursive Invocation Risk',
    severity: 'high',
    pattern: /transfer_hook[\s\S]{0,400}(?:transfer_checked|transfer|spl_token[\s\S]{0,50}invoke)/i,
    description: 'Transfer hook initiates another token transfer, risking recursive hook invocations. This can lead to reentrancy-like attacks or CPI depth exhaustion.',
    recommendation: 'Avoid initiating token transfers within transfer hooks. If necessary, use a flag to prevent recursive hook execution and validate CPI depth limits.'
  },

  // === PINOCCHIO / NATIVE PROGRAM SAFETY ===
  {
    id: 'SOL7529',
    name: 'Pinocchio Missing Manual Signer Verification',
    severity: 'critical',
    pattern: /(?:AccountInfo|account_info)[\s\S]{0,200}(?:key|pubkey)[\s\S]{0,100}==[\s\S]{0,200}(?![\s\S]{0,100}is_signer\(\)|[\s\S]{0,100}Signer)/i,
    description: 'Native/Pinocchio program checks pubkey match without verifying is_signer(). The Solend 2021 attack exploited this exact pattern — anyone can pass any pubkey without the private key.',
    recommendation: 'In native programs, always check account.is_signer() BEFORE comparing pubkeys: if !authority.is_signer() { return Err(ProgramError::MissingRequiredSignature); }'
  },
  {
    id: 'SOL7530',
    name: 'Native Program Missing Account Owner Validation',
    severity: 'critical',
    pattern: /(?:next_account_info|AccountInfo)[\s\S]{0,300}(?:try_borrow_data|data\(\)|lamports)[\s\S]{0,200}(?![\s\S]{0,100}owner\s*==|[\s\S]{0,100}check_program_account)/i,
    description: 'Native program reads or modifies account data/lamports without verifying the account is owned by the expected program. Attackers can pass accounts owned by malicious programs with crafted data.',
    recommendation: 'Verify account.owner == &expected_program_id before accessing account data. In Anchor, use Account<T> which validates ownership automatically.'
  },
  {
    id: 'SOL7531',
    name: 'Native Unsafe Borsh Deserialization Without Discriminator',
    severity: 'high',
    pattern: /try_from_slice|deserialize[\s\S]{0,100}(?:data|account_data)[\s\S]{0,200}(?![\s\S]{0,100}discriminator|[\s\S]{0,100}DISCRIMINATOR|[\s\S]{0,100}account_type)/i,
    description: 'Deserializing account data in native program without checking a discriminator/type tag first. An attacker can pass an account of a different type with matching byte layout to confuse the program.',
    recommendation: 'Prefix all account data with an 8-byte discriminator. Validate the discriminator matches the expected account type before deserializing.'
  },
  {
    id: 'SOL7532',
    name: 'Native Manual PDA Derivation Without Canonical Bump',
    severity: 'high',
    pattern: /create_program_address[\s\S]{0,200}(?![\s\S]{0,100}find_program_address|[\s\S]{0,100}canonical_bump|[\s\S]{0,100}bump\s*=\s*(?:stored|saved|expected))/i,
    description: 'Using create_program_address with a user-supplied bump instead of the canonical bump from find_program_address. Non-canonical bumps can create different valid PDAs for the same seeds.',
    recommendation: 'Always use find_program_address to derive the canonical bump, store it, and verify it on subsequent calls. Never accept bump values from user input.'
  },

  // === TWO-STEP AUTHORITY TRANSFER ===
  {
    id: 'SOL7533',
    name: 'Single-Step Authority Transfer Without Acceptance',
    severity: 'high',
    pattern: /(?:authority|admin|owner)\s*=\s*(?:new_authority|new_admin|new_owner|ctx\.accounts\.new)[\s\S]{0,200}(?![\s\S]{0,200}pending_authority|[\s\S]{0,200}nominate|[\s\S]{0,200}accept_authority)/i,
    description: 'Authority is transferred in a single step without requiring the new authority to accept. Transferring to a wrong address permanently locks the protocol.',
    recommendation: 'Implement a two-step nominate → accept pattern: current authority nominates, new authority must call accept. Include a cancellation mechanism.'
  },
  {
    id: 'SOL7534',
    name: 'Authority Transfer to Zero/Default Address',
    severity: 'critical',
    pattern: /(?:authority|admin|owner)\s*=[\s\S]{0,100}(?![\s\S]{0,100}!=\s*(?:Pubkey::default|system_program|zero|0))/i,
    description: 'Authority transfer does not validate the new address is non-zero/non-default. Setting authority to the zero address permanently locks the protocol without any recovery path.',
    recommendation: 'Reject authority transfers to Pubkey::default(), system_program, or known burn addresses. Add explicit validation: require!(new_authority.key() != Pubkey::default()).'
  },

  // === ANCHOR init_if_needed RISKS ===
  {
    id: 'SOL7535',
    name: 'Anchor init_if_needed Without Ownership Constraint',
    severity: 'critical',
    pattern: /init_if_needed[\s\S]{0,200}(?![\s\S]{0,100}has_one|[\s\S]{0,100}constraint\s*=|[\s\S]{0,100}owner\s*=)/i,
    description: 'Using init_if_needed without ownership constraints allows an attacker to front-run initialization with their own values, setting themselves as authority before the legitimate user.',
    recommendation: 'Avoid init_if_needed unless absolutely necessary. If used, pair with has_one or constraint checks to verify the initializer is authorized. Prefer separate init instructions with explicit access control.'
  },
  {
    id: 'SOL7536',
    name: 'Initialization Without Deployer Authority Check',
    severity: 'critical',
    pattern: /(?:initialize|init)[\s\S]{0,300}(?:authority|admin)\s*:[\s\S]{0,200}(?![\s\S]{0,100}upgrade_authority|[\s\S]{0,100}deployer|[\s\S]{0,100}hardcoded)/i,
    description: 'Program initialization sets authority from an unconstrained input account. First caller can set themselves as admin. Zealynx: "Restrict initializers to program upgrade authority or hardcoded deployer."',
    recommendation: 'Verify the initializer is the program upgrade authority via program_data.upgrade_authority_address, or use a hardcoded deployer pubkey.'
  },

  // === ACCOUNT DATA MATCHING (Zealynx Critical Check) ===
  {
    id: 'SOL7537',
    name: 'State Modification Before Authority Validation',
    severity: 'critical',
    pattern: /(?:try_borrow_mut_data|serialize|save|store)[\s\S]{0,300}(?:require!|constraint|has_one)[\s\S]{0,100}(?:authority|admin|owner)/i,
    description: 'Account state is modified before checking authority. If the authority check fails after state mutation, the transaction reverts but an attacker can observe the partial state via simulation.',
    recommendation: 'Always validate authority BEFORE any state changes. Order matters: (1) deserialize, (2) check authority, (3) modify state, (4) serialize.'
  },
  {
    id: 'SOL7538',
    name: 'Missing Account Data Matching Constraint',
    severity: 'high',
    pattern: /(?:vault|pool|config)[\s\S]{0,100}Account[\s\S]{0,200}(?:authority|admin)[\s\S]{0,100}(?:Signer|AccountInfo)[\s\S]{0,200}(?![\s\S]{0,100}has_one\s*=\s*authority|[\s\S]{0,100}constraint\s*=[\s\S]{0,50}\.authority\s*==)/i,
    description: 'Privileged function has separate vault/pool and authority accounts but no constraint linking them. Attacker can pass a valid signer with an unrelated vault to drain it.',
    recommendation: 'Use has_one = authority on the vault/pool account, or add constraint = vault.authority == authority.key().'
  },

  // === CROSS-INSTANCE / REPLAY ATTACKS ===
  {
    id: 'SOL7539',
    name: 'Missing Program Instance Isolation in PDA Seeds',
    severity: 'high',
    pattern: /seeds\s*=\s*\[[\s\S]{0,200}\][\s\S]{0,200}(?![\s\S]{0,100}program_id|[\s\S]{0,100}instance_id|[\s\S]{0,100}config\.key)/i,
    description: 'PDA seeds do not include a program instance identifier. If the program is deployed to multiple addresses, PDAs from one instance could be used in another.',
    recommendation: 'Include the program_id or a unique instance identifier in PDA seeds to prevent cross-instance account confusion.'
  },
  {
    id: 'SOL7540',
    name: 'Instruction Replay Without Nonce or Sequence Number',
    severity: 'high',
    pattern: /(?:process_instruction|handler)[\s\S]{0,500}(?:transfer|withdraw|claim|execute)[\s\S]{0,500}(?![\s\S]{0,200}nonce|[\s\S]{0,200}sequence|[\s\S]{0,200}already_processed|[\s\S]{0,200}claimed)/i,
    description: 'Instruction can be replayed because there is no nonce, sequence number, or processed flag. An attacker can submit the same signed transaction data multiple times.',
    recommendation: 'Implement replay protection: use a monotonically increasing sequence number, a nonce account, or a "processed" flag in the target account.'
  },

  // === BRIDGE / CROSS-CHAIN (NoOnes $8M Pattern) ===
  {
    id: 'SOL7541',
    name: 'Bridge Message Validation Without Chain ID',
    severity: 'critical',
    pattern: /(?:bridge|relay|cross_chain)[\s\S]{0,300}(?:verify|validate|check)[\s\S]{0,300}(?![\s\S]{0,200}chain_id|[\s\S]{0,200}source_chain|[\s\S]{0,200}domain)/i,
    description: 'Bridge message validation does not include source chain ID. The NoOnes bridge exploit siphoned $8M by replaying messages across chains. Without chain ID verification, messages from one chain are valid on another.',
    recommendation: 'Include chain ID in bridge message hashing and verification. Validate source_chain matches expected origin. Use domain separators in signature schemes.'
  },
  {
    id: 'SOL7542',
    name: 'Bridge Withdrawal Without Rate Limiting',
    severity: 'high',
    pattern: /(?:bridge|relay)[\s\S]{0,300}(?:withdraw|release|unlock|mint)[\s\S]{0,400}(?![\s\S]{0,200}rate_limit|[\s\S]{0,200}cooldown|[\s\S]{0,200}max_per_tx|[\s\S]{0,200}daily_limit)/i,
    description: 'Bridge withdrawal has no rate limiting or per-transaction caps. A single exploit can drain the entire bridge in one transaction.',
    recommendation: 'Implement rate limiting: per-transaction caps, daily withdrawal limits, and time-based cooldowns. Use circuit breakers that pause withdrawals when thresholds are exceeded.'
  },

  // === ADVANCED CPI SAFETY (Zealynx Domain 3) ===
  {
    id: 'SOL7543',
    name: 'CPI Forwarding Signer to Untrusted Program',
    severity: 'critical',
    pattern: /invoke(?:_signed)?[\s\S]{0,100}(?:signer_seeds|signers)[\s\S]{0,200}(?:remaining_accounts|ctx\.remaining|unchecked|AccountInfo)[\s\S]{0,200}(?![\s\S]{0,100}program_id\s*==)/i,
    description: 'CPI forwards user signer authority to a program loaded from remaining_accounts or an unchecked source. Attackers substitute a malicious program that steals the forwarded signer authority.',
    recommendation: 'Hardcode target program IDs for all CPIs. Never allow the target program to come from user input or remaining_accounts. Validate program_id before invoke.'
  },
  {
    id: 'SOL7544',
    name: 'CPI Return Data Manipulation',
    severity: 'high',
    pattern: /get_return_data|sol_get_return_data[\s\S]{0,200}(?![\s\S]{0,100}program_id\s*==|[\s\S]{0,100}verify_program)/i,
    description: 'Reading CPI return data without verifying which program set it. A malicious program in the CPI chain can overwrite return data with crafted values.',
    recommendation: 'Always verify the program_id returned by get_return_data() matches the expected callee before trusting the returned bytes.'
  },

  // === MATH & PRECISION (Zealynx Domain 4) ===
  {
    id: 'SOL7545',
    name: 'Release Build Arithmetic Overflow (No checked_math)',
    severity: 'high',
    pattern: /(?:amount|balance|supply|total|price|rate)\s*(?:\+|-|\*)\s*(?:amount|balance|supply|total|price|rate)[\s\S]{0,100}(?![\s\S]{0,50}checked_|[\s\S]{0,50}saturating_|[\s\S]{0,50}overflow-checks\s*=\s*true)/i,
    description: 'Arithmetic on financial values without checked math. Rust release builds disable overflow checks by default — what panics in debug silently wraps in production.',
    recommendation: 'Use checked_add/checked_sub/checked_mul for all financial math. Or set overflow-checks = true in Cargo.toml [profile.release].'
  },
  {
    id: 'SOL7546',
    name: 'Lossy U128 to U64 Truncation in Token Amount',
    severity: 'high',
    pattern: /as\s+u64[\s\S]{0,50}(?:amount|balance|lamports|supply)[\s\S]{0,100}(?![\s\S]{0,50}try_into|[\s\S]{0,50}try_from|[\s\S]{0,50}checked)/i,
    description: 'Casting u128 to u64 with "as u64" silently truncates values exceeding u64::MAX. In DeFi, intermediate calculations often exceed u64 range.',
    recommendation: 'Use u64::try_from(value).map_err(|_| error) instead of "as u64". This catches truncation and returns an explicit error.'
  },

  // === TOKEN OPERATIONS (Zealynx Domain 5) ===
  {
    id: 'SOL7547',
    name: 'Token Account Mint Mismatch Not Validated',
    severity: 'critical',
    pattern: /(?:token_account|source|destination)[\s\S]{0,200}(?:transfer|burn|mint_to)[\s\S]{0,300}(?![\s\S]{0,100}\.mint\s*==|[\s\S]{0,100}constraint[\s\S]{0,50}mint)/i,
    description: 'Token operation proceeds without verifying the token account belongs to the expected mint. Attackers can pass a token account for a worthless mint and receive valuable tokens in return.',
    recommendation: 'Validate token_account.mint == expected_mint before any transfer, burn, or mint operation. Use Anchor constraints: #[account(token::mint = expected_mint)].'
  },
  {
    id: 'SOL7548',
    name: 'Token Decimal Mismatch in Cross-Mint Operations',
    severity: 'high',
    pattern: /(?:price|rate|ratio|exchange)[\s\S]{0,200}(?:mint_a|mint_b|token_a|token_b)[\s\S]{0,200}(?![\s\S]{0,100}decimals|[\s\S]{0,100}10_u64\.pow)/i,
    description: 'Cross-mint token calculation does not account for different decimal places between mints (e.g., USDC has 6, wSOL has 9). This creates exploitable pricing errors.',
    recommendation: 'Always normalize token amounts to a common decimal base before price calculations. Query mint.decimals and adjust: normalized = amount * 10^(target_decimals - mint.decimals).'
  },

  // === EDGE CASES & PITFALLS (Zealynx Domain 7) ===
  {
    id: 'SOL7549',
    name: 'Account Close Without Data Zeroing Allows Revival',
    severity: 'critical',
    pattern: /(?:close|close_account)[\s\S]{0,200}(?:lamports|sol)[\s\S]{0,100}(?:=\s*0|\*\*\s*=\s*0)[\s\S]{0,200}(?![\s\S]{0,100}(?:data|account_data)[\s\S]{0,50}(?:fill|copy_from|iter\(\)\.for_each|=\s*\[0))/i,
    description: 'Account is closed by draining lamports but data is not zeroed. Within the same transaction, another instruction can re-fund the account (sending lamports back), reviving it with stale data.',
    recommendation: 'After closing: (1) zero all account data, (2) drain lamports, (3) assign owner to system program. Use Anchor close = target which handles all three.'
  },
  {
    id: 'SOL7550',
    name: 'Missing Realloc Zero-Init on Account Expansion',
    severity: 'medium',
    pattern: /realloc[\s\S]{0,200}(?![\s\S]{0,100}zero_init|[\s\S]{0,100}realloc::zero_init|[\s\S]{0,100}zero\s*=\s*true)/i,
    description: 'Account reallocation expands data space without zero-initializing the new bytes. Stale data from previous account occupants could leak into the new space.',
    recommendation: 'Use realloc::zero_init = true in Anchor, or manually zero the expanded region after realloc in native programs.'
  },

  // === ADVANCED ISSUES (Zealynx Domain 8) ===
  {
    id: 'SOL7551',
    name: 'Lookup Table Account Without Deactivation Check',
    severity: 'medium',
    pattern: /(?:address_lookup_table|lookup_table)[\s\S]{0,300}(?![\s\S]{0,200}deactivation_slot|[\s\S]{0,200}is_active|[\s\S]{0,200}status)/i,
    description: 'Program accepts address lookup table accounts without checking deactivation status. Deactivated tables can be closed and their addresses recycled, leading to account confusion.',
    recommendation: 'Verify the lookup table is still active by checking deactivation_slot == u64::MAX before trusting any addresses it contains.'
  },
  {
    id: 'SOL7552',
    name: 'Permissionless Crank Without Incentive Alignment',
    severity: 'medium',
    pattern: /(?:crank|keeper|liquidat)[\s\S]{0,300}(?![\s\S]{0,200}reward|[\s\S]{0,200}incentive|[\s\S]{0,200}tip|[\s\S]{0,200}fee.*crank)/i,
    description: 'Protocol relies on permissionless cranking (liquidation, settlement) but provides no economic incentive for crankers. Critical operations may not execute when gas costs exceed rewards.',
    recommendation: 'Provide cranker incentives (tip, fee share, or keeper reward) proportional to the gas cost. Implement fallback mechanisms for when no external cranker executes.'
  },
  {
    id: 'SOL7553',
    name: 'Slot-Based Timing Without Clock Sysvar',
    severity: 'medium',
    pattern: /Clock::get\(\)[\s\S]{0,50}slot[\s\S]{0,200}(?:expire|timeout|deadline|lock|unlock)[\s\S]{0,200}(?![\s\S]{0,100}unix_timestamp)/i,
    description: 'Using slot numbers for time-based logic (expirations, locks). Slot times vary from 400ms to multi-seconds during network congestion, making slot-based timing unreliable.',
    recommendation: 'Use Clock::get()?.unix_timestamp for time-sensitive logic instead of slot numbers. Slots are useful for ordering but not for measuring real-world time intervals.'
  },
  {
    id: 'SOL7554',
    name: 'Governance Proposal Without Execution Timelock',
    severity: 'high',
    pattern: /(?:proposal|vote)[\s\S]{0,300}(?:execute|enact|apply)[\s\S]{0,300}(?![\s\S]{0,200}timelock|[\s\S]{0,200}delay|[\s\S]{0,200}grace_period|[\s\S]{0,200}eta)/i,
    description: 'Governance proposals can be executed immediately after passing quorum, with no timelock delay. Malicious proposals can drain treasury before stakeholders react.',
    recommendation: 'Implement a timelock (24-72h) between proposal passage and execution. This gives stakeholders time to review, veto, or exit before potentially harmful changes take effect.'
  },
  {
    id: 'SOL7555',
    name: 'Emergency Pause Without Unpause Mechanism',
    severity: 'high',
    pattern: /(?:pause|freeze|halt|emergency_stop)[\s\S]{0,400}(?![\s\S]{0,300}unpause|[\s\S]{0,300}resume|[\s\S]{0,300}unfreeze|[\s\S]{0,300}thaw)/i,
    description: 'Protocol implements emergency pause but has no corresponding unpause function or governance-based recovery path. A paused protocol becomes permanently frozen.',
    recommendation: 'Always pair pause with unpause. Implement a governance-based unpause mechanism with a minimum timelock. Consider automatic unpause after a safety period.'
  },
];

export function checkBatch110Patterns(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';
  
  for (const pattern of BATCH_110_PATTERNS) {
    if (pattern.pattern.test(content)) {
      findings.push({
        id: pattern.id,
        title: pattern.name,
        severity: pattern.severity,
        description: pattern.description,
        location: { file: input.path },
        recommendation: pattern.recommendation,
      });
    }
  }
  
  return findings;
}

export { BATCH_110_PATTERNS };
