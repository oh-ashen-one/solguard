/**
 * Batch 112: Feb 2026 — Token Extensions Exploits, Confidential Transfers, ZK Proof Abuse
 * 
 * Sources:
 * - Solana Token-2022 Extension Audit Findings (Zellic, OtterSec 2025)
 * - Confidential Transfer extension bypass patterns (Sec3 2025)
 * - ZK ElGamal proof manipulation in token extensions
 * - Cross-program token extension interaction vulnerabilities
 * - Recent SPL Token transfer hook abuse patterns
 * 
 * Patterns: SOL7616-SOL7645 (30 patterns)
 * Focus: Token extensions (transfer hooks, confidential transfers, transfer fees),
 *        ZK proof validation, metadata pointer abuse, group/member pointer exploits
 */

import type { PatternInput, Finding } from './index.js';

const BATCH_112_PATTERNS: {
  id: string;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  pattern: RegExp;
  description: string;
  recommendation: string;
}[] = [
  // === TRANSFER HOOK ABUSE ===
  {
    id: 'SOL7616',
    title: 'Transfer Hook Without Program Validation',
    severity: 'critical',
    pattern: /transfer_hook|TransferHook/,
    description: 'Transfer hook configured without validating the hook program ID. Attacker can set a malicious transfer hook that drains tokens on every transfer or blocks transfers entirely (DoS).',
    recommendation: 'Validate transfer hook program ID against a known allowlist. Verify hook program is immutable or controlled by trusted authority.',
  },
  {
    id: 'SOL7617',
    title: 'Transfer Hook Reentrancy via CPI',
    severity: 'critical',
    pattern: /transfer_hook[\s\S]{0,500}invoke|execute[\s\S]{0,200}transfer_hook/,
    description: 'Transfer hook executes CPI back into the calling program, enabling reentrancy. Hook program can re-enter mid-transfer to manipulate balances or state.',
    recommendation: 'Add reentrancy guards before triggering transfers with hooks. Ensure state is finalized before the transfer CPI.',
  },
  {
    id: 'SOL7618',
    title: 'Transfer Hook State Manipulation',
    severity: 'high',
    pattern: /transfer_hook[\s\S]{0,300}(mut|write|set_data)/,
    description: 'Transfer hook modifies external state during transfer execution. Malicious hooks can alter protocol state, update oracles, or manipulate accounting during transfers.',
    recommendation: 'Treat transfer hook execution as untrusted. Re-validate all state after transfers complete. Never rely on pre-transfer state assumptions post-hook.',
  },
  {
    id: 'SOL7619',
    title: 'Missing Transfer Hook Extra Account Validation',
    severity: 'high',
    pattern: /ExtraAccountMeta|extra_account_metas/,
    description: 'Transfer hooks can require extra accounts (ExtraAccountMeta) that are not validated by the caller. Attacker can substitute malicious accounts in the extra accounts list.',
    recommendation: 'Validate all ExtraAccountMeta accounts against expected seeds and programs. Never pass unvalidated remaining_accounts to transfer hooks.',
  },
  // === CONFIDENTIAL TRANSFERS ===
  {
    id: 'SOL7620',
    title: 'Confidential Transfer Without Auditor',
    severity: 'high',
    pattern: /confidential_transfer[\s\S]{0,200}(?!auditor)/,
    description: 'Confidential transfer extension enabled without configuring an auditor ElGamal key. Without an auditor, there is no way to verify transfer amounts for compliance or detect infinite mint exploits hidden behind encryption.',
    recommendation: 'Always configure an auditor public key for confidential transfer mints. Implement periodic auditor decryption to verify supply integrity.',
  },
  {
    id: 'SOL7621',
    title: 'Confidential Transfer Pending Balance Overflow',
    severity: 'critical',
    pattern: /pending_balance|apply_pending_balance/,
    description: 'Pending confidential balance not applied before subsequent operations. Encrypted pending amounts can accumulate and overflow when applied, creating tokens from nothing.',
    recommendation: 'Force apply_pending_balance before any withdrawal or transfer. Validate decrypted pending amounts against expected ranges before applying.',
  },
  {
    id: 'SOL7622',
    title: 'ElGamal Proof Verification Skip',
    severity: 'critical',
    pattern: /verify_proof|ProofVerification|ZkElGamal/,
    description: 'ZK ElGamal proofs not properly verified before processing confidential transfers. Skipping proof verification allows attackers to forge transfer amounts or create tokens out of thin air.',
    recommendation: 'Always verify all ZK proofs (range proofs, equality proofs, validity proofs) before processing. Use SPL proof verification program, never custom verification.',
  },
  {
    id: 'SOL7623',
    title: 'Confidential Transfer Range Proof Missing',
    severity: 'critical',
    pattern: /confidential[\s\S]{0,300}transfer[\s\S]{0,200}(?!range_proof|RangeProof)/,
    description: 'Confidential transfer without range proof allows negative or overflow amounts. Attacker can transfer negative values, effectively minting tokens on the receiving end.',
    recommendation: 'Require Bulletproof range proofs for all confidential transfer amounts. Verify proof covers the correct bit range (typically 64-bit).',
  },
  // === TRANSFER FEE EXPLOITS ===
  {
    id: 'SOL7624',
    title: 'Transfer Fee Calculation Bypass',
    severity: 'high',
    pattern: /transfer_fee|TransferFee[\s\S]{0,200}(calculate|compute|amount)/,
    description: 'Transfer fee calculation can be bypassed by splitting transfers into amounts below the fee threshold, or by using confidential transfers where fee calculation on encrypted amounts is incorrect.',
    recommendation: 'Enforce minimum transfer amounts. Validate fee calculation on confidential transfers separately. Use withheld fee harvesting to collect accumulated fees.',
  },
  {
    id: 'SOL7625',
    title: 'Withheld Transfer Fee Theft',
    severity: 'high',
    pattern: /withheld|harvest_withheld|withdraw_withheld/,
    description: 'Withheld transfer fees can be harvested by unauthorized parties if the withdraw_withheld_authority is not properly set or validated.',
    recommendation: 'Set withdraw_withheld_authority to a secure multisig. Validate authority on all fee withdrawal instructions.',
  },
  // === METADATA POINTER ABUSE ===
  {
    id: 'SOL7626',
    title: 'Metadata Pointer to External Account',
    severity: 'high',
    pattern: /metadata_pointer|MetadataPointer/,
    description: 'Metadata pointer extension pointing to an external mutable account. Attacker who controls the metadata account can change token name/symbol/URI to impersonate legitimate tokens for phishing.',
    recommendation: 'Point metadata to the mint itself (self-referencing) when possible. If external, ensure metadata account is immutable or controlled by trusted authority.',
  },
  {
    id: 'SOL7627',
    title: 'Group Pointer Authority Hijack',
    severity: 'high',
    pattern: /group_pointer|GroupPointer|group_authority/,
    description: 'Token group pointer authority not properly secured. Attacker can modify group membership, adding malicious tokens to trusted groups or removing legitimate ones.',
    recommendation: 'Set group authority to a multisig or PDA. Validate group membership on-chain before trusting token groupings.',
  },
  {
    id: 'SOL7628',
    title: 'Member Pointer Spoofing',
    severity: 'medium',
    pattern: /member_pointer|MemberPointer|group_member/,
    description: 'Group member pointer can be set to claim membership in any group. Programs that check group membership without verifying bidirectional group<->member relationship can be spoofed.',
    recommendation: 'Verify both group->member and member->group pointers match. Check group authority signed the membership addition.',
  },
  // === PERMANENT DELEGATE EXPLOITS ===
  {
    id: 'SOL7629',
    title: 'Permanent Delegate Token Drain',
    severity: 'critical',
    pattern: /permanent_delegate|PermanentDelegate/,
    description: 'Token mint with permanent delegate extension allows the delegate to transfer or burn tokens from ANY account holding that mint, at any time, without holder approval. Users receiving these tokens can lose them instantly.',
    recommendation: 'Warn users about permanent delegate mints. Never accept tokens with permanent delegate from untrusted sources. Check for this extension before any token swap.',
  },
  {
    id: 'SOL7630',
    title: 'Non-Transferable Token Bypass via Delegate',
    severity: 'high',
    pattern: /non_transferable|NonTransferable[\s\S]{0,200}delegate/,
    description: 'Non-transferable tokens can still be burned by permanent delegate, effectively enabling value extraction. Soulbound token implementations must account for delegate burn capability.',
    recommendation: 'For true soulbound tokens, ensure no permanent delegate is set. Validate both non-transferable AND no-delegate properties.',
  },
  // === INTEREST-BEARING TOKEN EXPLOITS ===
  {
    id: 'SOL7631',
    title: 'Interest-Bearing Token Rate Manipulation',
    severity: 'high',
    pattern: /interest_bearing|InterestBearing|rate_authority/,
    description: 'Interest-bearing token rate authority can change interest rate arbitrarily. Malicious rate authority can set extreme rates to inflate token values before selling, or negative rates to drain holder value.',
    recommendation: 'Implement rate change timelock. Set maximum rate bounds. Use multisig for rate authority. Monitor rate changes on-chain.',
  },
  {
    id: 'SOL7632',
    title: 'Interest Calculation Timestamp Gaming',
    severity: 'medium',
    pattern: /interest[\s\S]{0,200}(timestamp|clock|slot|unix_timestamp)/,
    description: 'Interest calculations based on Solana clock can be gamed. Validators can manipulate slot timestamps within bounds, affecting interest accrual in lending protocols using interest-bearing tokens.',
    recommendation: 'Use slot-based intervals instead of unix timestamps for interest. Implement maximum interest accrual per period caps.',
  },
  // === CPI GUARD BYPASS ===
  {
    id: 'SOL7633',
    title: 'CPI Guard Disabled Before Malicious CPI',
    severity: 'critical',
    pattern: /disable_cpi_guard|cpi_guard[\s\S]{0,100}disable/,
    description: 'CPI guard intentionally disabled before cross-program invocation. Programs that convince users to disable CPI guard can then drain tokens via delegated transfer within CPI.',
    recommendation: 'Never disable CPI guard in user-facing instructions. Warn users about any transaction that includes disable_cpi_guard. Treat guard-disabling as high-risk.',
  },
  {
    id: 'SOL7634',
    title: 'CPI Guard Bypass via Wrapped SOL',
    severity: 'high',
    pattern: /cpi_guard[\s\S]{0,300}(native|wrapped|wsol|So11111)/,
    description: 'CPI guard does not protect native SOL transfers (only SPL tokens). Attacker can bypass CPI guard by unwrapping to native SOL then transferring via system program within CPI.',
    recommendation: 'Monitor both SPL token and native SOL flows in CPI contexts. Implement additional checks for wrapped SOL unwrap+transfer patterns.',
  },
  // === DEFAULT ACCOUNT STATE EXPLOITS ===
  {
    id: 'SOL7635',
    title: 'Default Account State Frozen Without Thaw Path',
    severity: 'medium',
    pattern: /default_account_state|DefaultAccountState[\s\S]{0,100}frozen/,
    description: 'Mint with default frozen account state but no clear thaw authority path. Users create token accounts that are immediately frozen with no way to unfreeze, permanently locking received tokens.',
    recommendation: 'When using default frozen state, implement clear thaw instructions. Document the thaw process. Ensure freeze authority is accessible and responsive.',
  },
  // === CLOSE AUTHORITY EXPLOITS ===
  {
    id: 'SOL7636',
    title: 'Mint Close Authority Token Supply Attack',
    severity: 'critical',
    pattern: /close_authority|MintCloseAuthority/,
    description: 'Mint with close authority can be closed while tokens still exist in accounts. If mint is closed and recreated at same address (via seed manipulation), token supply accounting is corrupted.',
    recommendation: 'Verify mint supply is zero before allowing close. Never trust token amounts from mints that have close authority without verifying mint account is still active.',
  },
  // === TOKEN EXTENSIONS INTERACTION PATTERNS ===
  {
    id: 'SOL7637',
    title: 'Multiple Extension Interaction Conflict',
    severity: 'high',
    pattern: /get_extension|ExtensionType[\s\S]{0,200}(transfer_hook|confidential|transfer_fee)/,
    description: 'Multiple token extensions interacting can create unexpected behaviors. Transfer hooks + confidential transfers can leak information. Transfer fees + hooks can double-charge or skip fees.',
    recommendation: 'Test all extension combinations thoroughly. Document expected behavior for multi-extension tokens. Add integration tests for every extension pair.',
  },
  {
    id: 'SOL7638',
    title: 'Extension Type Length Overflow',
    severity: 'high',
    pattern: /get_extension_types|ExtensionType.*len|extension.*size/,
    description: 'Token accounts with many extensions can exceed expected account size. Programs that allocate fixed-size buffers for token account data may truncate extension data or overflow.',
    recommendation: 'Use get_account_len_for_extensions() for dynamic sizing. Never assume fixed token account size when extensions are possible.',
  },
  {
    id: 'SOL7639',
    title: 'Immutable Owner Bypass via Program Upgrade',
    severity: 'medium',
    pattern: /immutable_owner|ImmutableOwner/,
    description: 'Immutable owner extension prevents owner changes but the token program itself could be upgraded (if using proxied/wrapped token program). Ensure immutability assumptions hold across program upgrades.',
    recommendation: 'Verify token program is the canonical SPL Token-2022 program. Do not trust immutable_owner from custom or upgradeable token programs.',
  },
  // === REQUIRED MEMO BYPASS ===
  {
    id: 'SOL7640',
    title: 'Required Memo Bypass via CPI',
    severity: 'medium',
    pattern: /memo_transfer|MemoTransfer|required_memo/,
    description: 'Required memo extension can be bypassed when transfers are initiated via CPI. Programs performing transfers on behalf of users may not include memo, bypassing compliance requirements.',
    recommendation: 'Enforce memo requirement at the program level, not just token extension level. Validate memo presence in transfer hook if compliance is critical.',
  },
  // === REALLOCATE EXPLOITS ===
  {
    id: 'SOL7641',
    title: 'Token Account Reallocate Extension Injection',
    severity: 'high',
    pattern: /reallocate|Reallocate[\s\S]{0,200}extension/,
    description: 'Reallocate instruction adds extensions to existing token accounts. Attacker can add transfer_hook or permanent_delegate extensions to existing accounts if they control the account owner.',
    recommendation: 'Monitor for unexpected reallocate instructions on token accounts. Validate extension set after any interaction with accounts that may have been reallocated.',
  },
  // === CONFIDENTIAL TRANSFER FEE ===
  {
    id: 'SOL7642',
    title: 'Confidential Transfer Fee Decryption Oracle',
    severity: 'high',
    pattern: /confidential[\s\S]{0,200}(fee|withheld)[\s\S]{0,200}(decrypt|ElGamal)/,
    description: 'Confidential transfer fees require separate decryption by fee authority. If fee decryption key is leaked or fee authority is compromised, all historical fee amounts (and by extension transfer amounts) are revealed.',
    recommendation: 'Rotate fee decryption keys periodically. Use HSM for fee authority keys. Implement key rotation mechanism without disrupting fee collection.',
  },
  {
    id: 'SOL7643',
    title: 'Sigma Proof Forgery in Confidential Transfer',
    severity: 'critical',
    pattern: /sigma_proof|equality_proof|validity_proof|CiphertextCommitmentEquality/,
    description: 'Sigma proofs (equality proofs, validity proofs) in confidential transfers must be verified against the correct public keys and ciphertexts. Reusing proofs across different contexts enables forgery.',
    recommendation: 'Bind proofs to specific transaction context (accounts, amounts, nonces). Never accept proofs generated for a different instruction or account set.',
  },
  {
    id: 'SOL7644',
    title: 'Confidential Mint Supply Inflation',
    severity: 'critical',
    pattern: /confidential[\s\S]{0,200}mint[\s\S]{0,200}(supply|amount)/,
    description: 'Confidential minting can hide supply inflation if the mint authority is compromised. Since amounts are encrypted, standard supply checks cannot detect unauthorized minting.',
    recommendation: 'Implement regular auditor-based supply verification. Publish zero-knowledge proofs of supply consistency. Use multi-party computation for mint authority.',
  },
  {
    id: 'SOL7645',
    title: 'Token Extension Account Confusion Attack',
    severity: 'high',
    pattern: /Token-2022|spl_token_2022[\s\S]{0,300}(spl_token|TokenkegQ)/,
    description: 'Programs that support both SPL Token and Token-2022 can be confused by passing Token-2022 accounts to SPL Token instructions or vice versa. Extension data is invisible to the old program, enabling bypasses.',
    recommendation: 'Always check token program ID matches the token account owner. Route to correct program based on mint program ownership. Never mix token program versions in a single instruction.',
  },
];

export function checkBatch112Patterns(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content ?? '';

  for (const p of BATCH_112_PATTERNS) {
    if (p.pattern.test(content)) {
      findings.push({
        id: p.id,
        title: p.title,
        severity: p.severity,
        description: p.description,
        recommendation: p.recommendation,
        location: { file: input.path },
      });
    }
  }

  return findings;
}
