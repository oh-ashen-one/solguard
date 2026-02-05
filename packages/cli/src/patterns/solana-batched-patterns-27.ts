import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

// SOL765-SOL784: Infrastructure & Runtime Security Patterns (Feb 5 2026 5:30AM)
// Source: Solana Runtime Security, Validator Attacks, Recent 2025 Exploits

function createFinding(id: string, name: string, severity: Finding['severity'], file: string, line: number, details: string): Finding {
  return { id, name, severity, file, line, details };
}

// SOL765: Turbine Propagation Attack Vector
export function checkTurbinePropagationAttack(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.sourceCode;

  // Check for leader schedule manipulation
  if (/leader_schedule/i.test(content) || /slot_leader/i.test(content)) {
    if (!/verify_leader/.test(content)) {
      findings.push(createFinding(
        'SOL765',
        'Leader Schedule Verification Missing',
        'medium',
        input.filePath,
        1,
        'Leader schedule used without verification. Could be vulnerable to turbine propagation attacks.'
      ));
    }
  }

  return findings;
}

// SOL766: Validator Stake Concentration Risk
export function checkValidatorStakeConcentration(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.sourceCode;

  if (/validator/i.test(content) && /stake/i.test(content)) {
    if (!/stake_concentration/.test(content) && !/max_stake_per_validator/.test(content)) {
      findings.push(createFinding(
        'SOL766',
        'Validator Stake Concentration Not Checked',
        'medium',
        input.filePath,
        1,
        'Stake operations without concentration checks could centralize network control.'
      ));
    }
  }

  return findings;
}

// SOL767: Durable Nonce Replay Attack
export function checkDurableNonceReplay(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.sourceCode;
  const lines = content.split('\n');

  if (/durable_nonce/i.test(content) || /advance_nonce/i.test(content)) {
    // Check for nonce authority validation
    if (!/nonce_authority/.test(content)) {
      findings.push(createFinding(
        'SOL767',
        'Durable Nonce Authority Not Validated',
        'high',
        input.filePath,
        1,
        'Durable nonce used without authority validation. Could allow transaction replay.'
      ));
    }
  }

  return findings;
}

// SOL768: Address Lookup Table Poisoning
export function checkLookupTablePoisoning(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.sourceCode;
  const lines = content.split('\n');

  if (/lookup_table/i.test(content) || /AddressLookupTable/.test(content)) {
    // Check for table authority validation
    if (!/table_authority/.test(content) && !/verify_table/.test(content)) {
      findings.push(createFinding(
        'SOL768',
        'Address Lookup Table Authority Not Verified',
        'high',
        input.filePath,
        1,
        'Address lookup table used without verifying authority. Malicious tables could redirect transactions.'
      ));
    }
  }

  return findings;
}

// SOL769: Compute Budget Griefing
export function checkComputeBudgetGriefing(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.sourceCode;
  const lines = content.split('\n');

  // Check for unbounded loops that could exhaust compute
  const unboundedPatterns = [
    /while\s+true/,
    /loop\s*\{/,
    /for\s+\w+\s+in\s+0\.\./,
  ];

  lines.forEach((line, idx) => {
    for (const pattern of unboundedPatterns) {
      if (pattern.test(line)) {
        const contextEnd = Math.min(lines.length, idx + 10);
        const context = lines.slice(idx, contextEnd).join('\n');
        
        // Check for iteration limits
        if (!/max_iterations/.test(context) && !/break/.test(context) && !/return/.test(context)) {
          findings.push(createFinding(
            'SOL769',
            'Unbounded Loop Compute Griefing',
            'high',
            input.filePath,
            idx + 1,
            'Unbounded loop could exhaust compute budget. Add iteration limits.'
          ));
        }
        break;
      }
    }
  });

  return findings;
}

// SOL770: Priority Fee Manipulation
export function checkPriorityFeeManipulation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.sourceCode;

  if (/priority_fee/i.test(content) || /compute_unit_price/i.test(content)) {
    // Check for fee validation
    if (!/max_priority_fee/.test(content) && !/fee_cap/.test(content)) {
      findings.push(createFinding(
        'SOL770',
        'Priority Fee Cap Missing',
        'low',
        input.filePath,
        1,
        'Priority fee without cap could lead to excessive fees during congestion.'
      ));
    }
  }

  return findings;
}

// SOL771: Jito Bundle Manipulation
export function checkJitoBundleManipulation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.sourceCode;

  if (/jito/i.test(content) || /bundle/i.test(content)) {
    // Check for bundle tip validation
    if (!/tip_account/.test(content) && !/verify_bundle/.test(content)) {
      findings.push(createFinding(
        'SOL771',
        'Jito Bundle Tip Validation Missing',
        'medium',
        input.filePath,
        1,
        'Jito bundle operations without proper tip validation could be front-run.'
      ));
    }
  }

  return findings;
}

// SOL772: BPF Loader Exploit (Historical Reference)
export function checkBpfLoaderExploit(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.sourceCode;

  // Check for direct BPF loader interactions
  if (/BPFLoader/i.test(content) || /bpf_loader/i.test(content)) {
    if (/invoke/i.test(content)) {
      findings.push(createFinding(
        'SOL772',
        'Direct BPF Loader Invocation',
        'info',
        input.filePath,
        1,
        'Direct BPF loader invocation detected. Ensure using latest loader version for security patches.'
      ));
    }
  }

  return findings;
}

// SOL773: Syscall Abuse via invoke_signed
export function checkSyscallAbuse(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.sourceCode;
  const lines = content.split('\n');

  lines.forEach((line, idx) => {
    if (/invoke_signed/.test(line)) {
      const contextEnd = Math.min(lines.length, idx + 15);
      const context = lines.slice(idx, contextEnd).join('\n');
      
      // Check for proper seed validation
      if (!/seeds/.test(context) && !/signer_seeds/.test(context)) {
        findings.push(createFinding(
          'SOL773',
          'invoke_signed Without Proper Seeds',
          'critical',
          input.filePath,
          idx + 1,
          'invoke_signed called without visible signer seeds. Verify PDA signing is correct.'
        ));
      }
    }
  });

  return findings;
}

// SOL774: Program Cache Invalidation Attack
export function checkProgramCacheAttack(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.sourceCode;

  // Check for program upgrades without cache consideration
  if (/upgrade/i.test(content) && /program/i.test(content)) {
    if (!/set_buffer/.test(content) && !/close_buffer/.test(content)) {
      findings.push(createFinding(
        'SOL774',
        'Program Upgrade Cache Consideration',
        'info',
        input.filePath,
        1,
        'Program upgrade detected. Ensure proper buffer management to avoid cache issues.'
      ));
    }
  }

  return findings;
}

// SOL775: ELF Binary Alignment Attack
export function checkElfAlignmentAttack(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.sourceCode;

  // Check for custom serialization that could cause alignment issues
  if (/unsafe/i.test(content) && (/ptr/.test(content) || /raw/.test(content))) {
    findings.push(createFinding(
      'SOL775',
      'Unsafe Memory Access Alignment Risk',
      'high',
      input.filePath,
      1,
      'Unsafe memory access could cause ELF alignment issues. Use safe serialization methods.'
    ));
  }

  return findings;
}

// SOL776: Epoch Schedule Exploitation
export function checkEpochScheduleExploit(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.sourceCode;

  if (/epoch/i.test(content) && /schedule/i.test(content)) {
    if (!/get_epoch/.test(content) && !/EpochSchedule/.test(content)) {
      findings.push(createFinding(
        'SOL776',
        'Epoch Schedule Not Properly Queried',
        'low',
        input.filePath,
        1,
        'Epoch-related logic without proper schedule query could have timing issues.'
      ));
    }
  }

  return findings;
}

// SOL777: Rent Collection Attack
export function checkRentCollectionAttack(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.sourceCode;
  const lines = content.split('\n');

  // Check for rent-exempt validation
  if (/rent/i.test(content)) {
    if (!/rent_exempt/i.test(content) && !/is_exempt/.test(content)) {
      findings.push(createFinding(
        'SOL777',
        'Rent Exemption Not Validated',
        'medium',
        input.filePath,
        1,
        'Account rent status not validated. Non-exempt accounts could be garbage collected.'
      ));
    }
  }

  return findings;
}

// SOL778: Transaction Versioning Bypass
export function checkTransactionVersioningBypass(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.sourceCode;

  if (/versioned_transaction/i.test(content) || /v0_message/i.test(content)) {
    if (!/version/.test(content) && !/message_version/.test(content)) {
      findings.push(createFinding(
        'SOL778',
        'Transaction Version Not Validated',
        'low',
        input.filePath,
        1,
        'Versioned transaction without version validation could have compatibility issues.'
      ));
    }
  }

  return findings;
}

// SOL779: Slot Hashes Manipulation
export function checkSlotHashesManipulation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.sourceCode;

  if (/slot_hashes/i.test(content) || /SlotHashes/.test(content)) {
    findings.push(createFinding(
      'SOL779',
      'Slot Hashes Sysvar Usage',
      'info',
      input.filePath,
      1,
      'SlotHashes sysvar used. Ensure proper validation as it can be influenced by validators.'
    ));
  }

  return findings;
}

// SOL780: Stake History Manipulation
export function checkStakeHistoryManipulation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.sourceCode;

  if (/stake_history/i.test(content) || /StakeHistory/.test(content)) {
    if (!/verify/.test(content)) {
      findings.push(createFinding(
        'SOL780',
        'Stake History Not Verified',
        'medium',
        input.filePath,
        1,
        'Stake history sysvar used without verification. Historical data could be manipulated.'
      ));
    }
  }

  return findings;
}

// SOL781: Instructions Sysvar Introspection Attack
export function checkInstructionsSysvarAttack(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.sourceCode;
  const lines = content.split('\n');

  if (/instructions_sysvar/i.test(content) || /get_instruction_relative/i.test(content)) {
    // Check for proper instruction validation
    lines.forEach((line, idx) => {
      if (/load_instruction_at/.test(line) || /get_instruction/.test(line)) {
        const contextEnd = Math.min(lines.length, idx + 10);
        const context = lines.slice(idx, contextEnd).join('\n');
        
        if (!/program_id/.test(context)) {
          findings.push(createFinding(
            'SOL781',
            'Instructions Sysvar Without Program ID Check',
            'high',
            input.filePath,
            idx + 1,
            'Instruction introspection without program ID validation. Attacker could inject malicious instructions.'
          ));
        }
      }
    });
  }

  return findings;
}

// SOL782: Recent Blockhashes Attack
export function checkRecentBlockhashesAttack(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.sourceCode;

  if (/recent_blockhash/i.test(content) || /RecentBlockhashes/.test(content)) {
    if (!/verify_blockhash/.test(content) && !/is_valid_blockhash/.test(content)) {
      findings.push(createFinding(
        'SOL782',
        'Recent Blockhash Not Verified',
        'medium',
        input.filePath,
        1,
        'Recent blockhash used without verification. Could allow transaction replay within window.'
      ));
    }
  }

  return findings;
}

// SOL783: Vote Program Exploit Patterns
export function checkVoteProgramExploit(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.sourceCode;

  if (/vote_program/i.test(content) || /VoteState/.test(content)) {
    if (/invoke/i.test(content)) {
      findings.push(createFinding(
        'SOL783',
        'Vote Program Direct Invocation',
        'info',
        input.filePath,
        1,
        'Direct vote program invocation. Ensure proper authorization and state validation.'
      ));
    }
  }

  return findings;
}

// SOL784: Config Program State Manipulation
export function checkConfigProgramManipulation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.sourceCode;

  if (/config_program/i.test(content) || /ConfigState/.test(content)) {
    if (!/verify_config/.test(content) && !/config_authority/.test(content)) {
      findings.push(createFinding(
        'SOL784',
        'Config Program Authority Not Verified',
        'medium',
        input.filePath,
        1,
        'Config program state accessed without authority verification.'
      ));
    }
  }

  return findings;
}

export const batchedPatterns27 = [
  { id: 'SOL765', name: 'Leader Schedule Verification Missing', severity: 'medium' as const, run: checkTurbinePropagationAttack },
  { id: 'SOL766', name: 'Validator Stake Concentration Not Checked', severity: 'medium' as const, run: checkValidatorStakeConcentration },
  { id: 'SOL767', name: 'Durable Nonce Authority Not Validated', severity: 'high' as const, run: checkDurableNonceReplay },
  { id: 'SOL768', name: 'Address Lookup Table Authority Not Verified', severity: 'high' as const, run: checkLookupTablePoisoning },
  { id: 'SOL769', name: 'Unbounded Loop Compute Griefing', severity: 'high' as const, run: checkComputeBudgetGriefing },
  { id: 'SOL770', name: 'Priority Fee Cap Missing', severity: 'low' as const, run: checkPriorityFeeManipulation },
  { id: 'SOL771', name: 'Jito Bundle Tip Validation Missing', severity: 'medium' as const, run: checkJitoBundleManipulation },
  { id: 'SOL772', name: 'Direct BPF Loader Invocation', severity: 'info' as const, run: checkBpfLoaderExploit },
  { id: 'SOL773', name: 'invoke_signed Without Proper Seeds', severity: 'critical' as const, run: checkSyscallAbuse },
  { id: 'SOL774', name: 'Program Upgrade Cache Consideration', severity: 'info' as const, run: checkProgramCacheAttack },
  { id: 'SOL775', name: 'Unsafe Memory Access Alignment Risk', severity: 'high' as const, run: checkElfAlignmentAttack },
  { id: 'SOL776', name: 'Epoch Schedule Not Properly Queried', severity: 'low' as const, run: checkEpochScheduleExploit },
  { id: 'SOL777', name: 'Rent Exemption Not Validated', severity: 'medium' as const, run: checkRentCollectionAttack },
  { id: 'SOL778', name: 'Transaction Version Not Validated', severity: 'low' as const, run: checkTransactionVersioningBypass },
  { id: 'SOL779', name: 'Slot Hashes Sysvar Usage', severity: 'info' as const, run: checkSlotHashesManipulation },
  { id: 'SOL780', name: 'Stake History Not Verified', severity: 'medium' as const, run: checkStakeHistoryManipulation },
  { id: 'SOL781', name: 'Instructions Sysvar Without Program ID Check', severity: 'high' as const, run: checkInstructionsSysvarAttack },
  { id: 'SOL782', name: 'Recent Blockhash Not Verified', severity: 'medium' as const, run: checkRecentBlockhashesAttack },
  { id: 'SOL783', name: 'Vote Program Direct Invocation', severity: 'info' as const, run: checkVoteProgramExploit },
  { id: 'SOL784', name: 'Config Program Authority Not Verified', severity: 'medium' as const, run: checkConfigProgramManipulation },
];
