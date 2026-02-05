import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

// SOL785-SOL804: Token-2022 Advanced Security & Extension Patterns (Feb 5 2026 5:30AM)
// Source: Token-2022 Program Documentation, Known Vulnerabilities

function createFinding(id: string, name: string, severity: Finding['severity'], file: string, line: number, details: string): Finding {
  return { id, name, severity, file, line, details };
}

// SOL785: Token-2022 Confidential Transfer Decryption Attack
export function checkConfidentialTransferDecryption(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.sourceCode;

  if (/confidential_transfer/i.test(content) || /ConfidentialTransfer/.test(content)) {
    // Check for proper encryption key management
    if (!/elgamal/.test(content) && !/encryption_key/.test(content)) {
      findings.push(createFinding(
        'SOL785',
        'Confidential Transfer Key Management Missing',
        'high',
        input.filePath,
        1,
        'Confidential transfer without proper ElGamal key management could leak amounts.'
      ));
    }
  }

  return findings;
}

// SOL786: Token-2022 Transfer Fee Bypass
export function checkTransferFeeBypass(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.sourceCode;

  if (/transfer_fee/i.test(content) || /TransferFee/.test(content)) {
    // Check for fee exemption abuse
    if (!/fee_exempt/.test(content) || !/verify_exemption/.test(content)) {
      if (/exempt/i.test(content)) {
        findings.push(createFinding(
          'SOL786',
          'Transfer Fee Exemption Not Verified',
          'high',
          input.filePath,
          1,
          'Transfer fee exemption without proper verification could be bypassed.'
        ));
      }
    }
  }

  return findings;
}

// SOL787: Token-2022 Interest Bearing Token Manipulation
export function checkInterestBearingManipulation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.sourceCode;

  if (/interest_bearing/i.test(content) || /InterestBearing/.test(content)) {
    // Check for rate manipulation protection
    if (!/rate_authority/.test(content)) {
      findings.push(createFinding(
        'SOL787',
        'Interest Bearing Rate Authority Not Validated',
        'high',
        input.filePath,
        1,
        'Interest bearing token without rate authority check allows rate manipulation.'
      ));
    }
  }

  return findings;
}

// SOL788: Token-2022 Permanent Delegate Abuse
export function checkPermanentDelegateAbuse(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.sourceCode;

  if (/permanent_delegate/i.test(content) || /PermanentDelegate/.test(content)) {
    findings.push(createFinding(
      'SOL788',
      'Permanent Delegate Extension Used',
      'medium',
      input.filePath,
      1,
      'Permanent delegate extension allows unrestricted transfers. Ensure this is intended behavior.'
    ));
  }

  return findings;
}

// SOL789: Token-2022 Non-Transferable Token Bypass
export function checkNonTransferableBypass(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.sourceCode;

  if (/non_transferable/i.test(content) || /NonTransferable/.test(content)) {
    // Check if burn is still allowed (could be used for value extraction)
    if (/burn/i.test(content) && !/burn_disabled/.test(content)) {
      findings.push(createFinding(
        'SOL789',
        'Non-Transferable Token Burn Not Disabled',
        'medium',
        input.filePath,
        1,
        'Non-transferable token can still be burned. Consider if this is intended.'
      ));
    }
  }

  return findings;
}

// SOL790: Token-2022 Default Account State Exploitation
export function checkDefaultAccountStateExploit(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.sourceCode;

  if (/default_account_state/i.test(content) || /DefaultAccountState/.test(content)) {
    // Check for frozen by default without proper thaw mechanism
    if (/frozen/i.test(content) && !/thaw/.test(content)) {
      findings.push(createFinding(
        'SOL790',
        'Default Frozen State Without Thaw Mechanism',
        'high',
        input.filePath,
        1,
        'Token defaults to frozen but no thaw mechanism found. Tokens may be permanently locked.'
      ));
    }
  }

  return findings;
}

// SOL791: Token-2022 Metadata Pointer Spoofing
export function checkMetadataPointerSpoofing(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.sourceCode;

  if (/metadata_pointer/i.test(content) || /MetadataPointer/.test(content)) {
    // Check for metadata validation
    if (!/verify_metadata/.test(content) && !/metadata_authority/.test(content)) {
      findings.push(createFinding(
        'SOL791',
        'Metadata Pointer Authority Not Validated',
        'medium',
        input.filePath,
        1,
        'Metadata pointer without authority validation could point to malicious metadata.'
      ));
    }
  }

  return findings;
}

// SOL792: Token-2022 Group Pointer Manipulation
export function checkGroupPointerManipulation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.sourceCode;

  if (/group_pointer/i.test(content) || /GroupPointer/.test(content)) {
    if (!/group_authority/.test(content)) {
      findings.push(createFinding(
        'SOL792',
        'Group Pointer Authority Not Validated',
        'medium',
        input.filePath,
        1,
        'Group pointer manipulation without authority check could misclassify tokens.'
      ));
    }
  }

  return findings;
}

// SOL793: Token-2022 Member Pointer Manipulation
export function checkMemberPointerManipulation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.sourceCode;

  if (/member_pointer/i.test(content) || /MemberPointer/.test(content)) {
    if (!/member_authority/.test(content)) {
      findings.push(createFinding(
        'SOL793',
        'Member Pointer Authority Not Validated',
        'medium',
        input.filePath,
        1,
        'Member pointer manipulation without authority check could affect group membership.'
      ));
    }
  }

  return findings;
}

// SOL794: Token-2022 CPI Guard Bypass
export function checkToken2022CpiGuardBypass(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.sourceCode;

  if (/cpi_guard/i.test(content) || /CpiGuard/.test(content)) {
    // Check for proper CPI restriction enforcement
    if (/invoke/i.test(content) && !/cpi_guard_enabled/.test(content)) {
      findings.push(createFinding(
        'SOL794',
        'CPI Guard Status Not Checked Before Invoke',
        'high',
        input.filePath,
        1,
        'CPI invocation without checking CPI guard status could bypass user protections.'
      ));
    }
  }

  return findings;
}

// SOL795: Token-2022 Memo Required Bypass
export function checkMemoRequiredBypass(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.sourceCode;

  if (/memo_required/i.test(content) || /MemoRequired/.test(content)) {
    // Check if memo is actually validated
    if (/transfer/i.test(content) && !/memo/.test(content)) {
      findings.push(createFinding(
        'SOL795',
        'Memo Required But Not Validated',
        'medium',
        input.filePath,
        1,
        'Transfer with memo required extension but memo not validated in instruction.'
      ));
    }
  }

  return findings;
}

// SOL796: Token-2022 Reallocate Extension Attack
export function checkReallocateExtensionAttack(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.sourceCode;

  if (/reallocate/i.test(content) && /extension/i.test(content)) {
    // Check for extension type validation during reallocation
    if (!/ExtensionType/.test(content)) {
      findings.push(createFinding(
        'SOL796',
        'Extension Reallocation Type Not Validated',
        'high',
        input.filePath,
        1,
        'Account reallocation without extension type validation could add malicious extensions.'
      ));
    }
  }

  return findings;
}

// SOL797: Token-2022 Immutable Owner Bypass via CPI
export function checkImmutableOwnerBypass(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.sourceCode;

  if (/immutable_owner/i.test(content) || /ImmutableOwner/.test(content)) {
    // This extension should prevent owner changes via CPI
    if (/set_authority/i.test(content) && /invoke/i.test(content)) {
      findings.push(createFinding(
        'SOL797',
        'Immutable Owner CPI Authority Change Attempt',
        'high',
        input.filePath,
        1,
        'Attempting authority change via CPI on immutable owner account will fail. Review logic.'
      ));
    }
  }

  return findings;
}

// SOL798: Token-2022 Close Authority Drain
export function checkCloseAuthorityDrain(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.sourceCode;

  if (/close_authority/i.test(content)) {
    // Check for proper balance handling before close
    if (/close_account/i.test(content) && !/balance.*==.*0/.test(content) && !/empty/.test(content)) {
      findings.push(createFinding(
        'SOL798',
        'Close Authority Without Balance Check',
        'high',
        input.filePath,
        1,
        'Account close without balance verification could drain remaining tokens.'
      ));
    }
  }

  return findings;
}

// SOL799: Token-2022 Multiple Extension Conflict
export function checkMultipleExtensionConflict(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.sourceCode;

  const conflictingExtensions = [
    ['confidential_transfer', 'transfer_fee'],
    ['non_transferable', 'transfer_hook'],
    ['permanent_delegate', 'cpi_guard'],
  ];

  for (const [ext1, ext2] of conflictingExtensions) {
    const hasExt1 = new RegExp(ext1, 'i').test(content);
    const hasExt2 = new RegExp(ext2, 'i').test(content);
    
    if (hasExt1 && hasExt2) {
      findings.push(createFinding(
        'SOL799',
        'Potentially Conflicting Token Extensions',
        'medium',
        input.filePath,
        1,
        `Extensions ${ext1} and ${ext2} used together may have unexpected interactions.`
      ));
    }
  }

  return findings;
}

// SOL800: Token-2022 Withheld Tokens Drain
export function checkWithheldTokensDrain(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.sourceCode;

  if (/withheld/i.test(content) && /transfer_fee/i.test(content)) {
    // Check for proper withheld amount handling
    if (!/harvest_withheld/.test(content) && !/withdraw_withheld/.test(content)) {
      findings.push(createFinding(
        'SOL800',
        'Withheld Tokens Not Properly Managed',
        'medium',
        input.filePath,
        1,
        'Transfer fee withheld tokens exist but no harvest/withdraw mechanism found.'
      ));
    }
  }

  return findings;
}

// SOL801: Token-2022 Account State Transition Attack
export function checkAccountStateTransition(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.sourceCode;
  const lines = content.split('\n');

  // Check for state transitions without proper validation
  const statePatterns = [
    /AccountState::Frozen/,
    /AccountState::Initialized/,
    /AccountState::Uninitialized/,
  ];

  lines.forEach((line, idx) => {
    for (const pattern of statePatterns) {
      if (pattern.test(line)) {
        const contextEnd = Math.min(lines.length, idx + 10);
        const context = lines.slice(idx, contextEnd).join('\n');
        
        if (!/verify/.test(context) && !/check/.test(context) && !/require/.test(context)) {
          findings.push(createFinding(
            'SOL801',
            'Account State Transition Not Validated',
            'medium',
            input.filePath,
            idx + 1,
            'Account state transition without validation could allow unauthorized state changes.'
          ));
        }
        break;
      }
    }
  });

  return findings;
}

// SOL802: Token-2022 Mint Close Authority Exploit
export function checkMintCloseAuthorityExploit(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.sourceCode;

  if (/mint_close_authority/i.test(content) || /MintCloseAuthority/.test(content)) {
    // This is a powerful extension - ensure it's properly guarded
    if (!/timelock/.test(content) && !/multisig/.test(content)) {
      findings.push(createFinding(
        'SOL802',
        'Mint Close Authority Without Protection',
        'high',
        input.filePath,
        1,
        'Mint close authority without timelock/multisig allows instant token destruction.'
      ));
    }
  }

  return findings;
}

// SOL803: Token-2022 Extension Data Overflow
export function checkExtensionDataOverflow(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.sourceCode;

  if (/get_extension_data/i.test(content) || /extension_data/i.test(content)) {
    // Check for proper bounds checking
    if (!/len\(\)/.test(content) && !/size/.test(content)) {
      findings.push(createFinding(
        'SOL803',
        'Extension Data Read Without Bounds Check',
        'high',
        input.filePath,
        1,
        'Extension data access without bounds checking could cause overflow.'
      ));
    }
  }

  return findings;
}

// SOL804: Token-2022 Required Memo Length Attack
export function checkMemoLengthAttack(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.sourceCode;

  if (/memo/i.test(content)) {
    // Check for memo length validation
    if (!/max_memo_len/.test(content) && !/memo_length/.test(content) && /memo.*len/.test(content)) {
      // Has some length check, but verify it's a max check
      if (!/<=/.test(content) && !/<\s*\d+/.test(content)) {
        findings.push(createFinding(
          'SOL804',
          'Memo Length Not Properly Limited',
          'low',
          input.filePath,
          1,
          'Memo without maximum length limit could be used for DoS via large data.'
        ));
      }
    }
  }

  return findings;
}

export const batchedPatterns28 = [
  { id: 'SOL785', name: 'Confidential Transfer Key Management Missing', severity: 'high' as const, run: checkConfidentialTransferDecryption },
  { id: 'SOL786', name: 'Transfer Fee Exemption Not Verified', severity: 'high' as const, run: checkTransferFeeBypass },
  { id: 'SOL787', name: 'Interest Bearing Rate Authority Not Validated', severity: 'high' as const, run: checkInterestBearingManipulation },
  { id: 'SOL788', name: 'Permanent Delegate Extension Used', severity: 'medium' as const, run: checkPermanentDelegateAbuse },
  { id: 'SOL789', name: 'Non-Transferable Token Burn Not Disabled', severity: 'medium' as const, run: checkNonTransferableBypass },
  { id: 'SOL790', name: 'Default Frozen State Without Thaw Mechanism', severity: 'high' as const, run: checkDefaultAccountStateExploit },
  { id: 'SOL791', name: 'Metadata Pointer Authority Not Validated', severity: 'medium' as const, run: checkMetadataPointerSpoofing },
  { id: 'SOL792', name: 'Group Pointer Authority Not Validated', severity: 'medium' as const, run: checkGroupPointerManipulation },
  { id: 'SOL793', name: 'Member Pointer Authority Not Validated', severity: 'medium' as const, run: checkMemberPointerManipulation },
  { id: 'SOL794', name: 'CPI Guard Status Not Checked Before Invoke', severity: 'high' as const, run: checkToken2022CpiGuardBypass },
  { id: 'SOL795', name: 'Memo Required But Not Validated', severity: 'medium' as const, run: checkMemoRequiredBypass },
  { id: 'SOL796', name: 'Extension Reallocation Type Not Validated', severity: 'high' as const, run: checkReallocateExtensionAttack },
  { id: 'SOL797', name: 'Immutable Owner CPI Authority Change Attempt', severity: 'high' as const, run: checkImmutableOwnerBypass },
  { id: 'SOL798', name: 'Close Authority Without Balance Check', severity: 'high' as const, run: checkCloseAuthorityDrain },
  { id: 'SOL799', name: 'Potentially Conflicting Token Extensions', severity: 'medium' as const, run: checkMultipleExtensionConflict },
  { id: 'SOL800', name: 'Withheld Tokens Not Properly Managed', severity: 'medium' as const, run: checkWithheldTokensDrain },
  { id: 'SOL801', name: 'Account State Transition Not Validated', severity: 'medium' as const, run: checkAccountStateTransition },
  { id: 'SOL802', name: 'Mint Close Authority Without Protection', severity: 'high' as const, run: checkMintCloseAuthorityExploit },
  { id: 'SOL803', name: 'Extension Data Read Without Bounds Check', severity: 'high' as const, run: checkExtensionDataOverflow },
  { id: 'SOL804', name: 'Memo Length Not Properly Limited', severity: 'low' as const, run: checkMemoLengthAttack },
];
