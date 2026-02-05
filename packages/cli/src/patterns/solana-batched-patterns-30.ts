import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

// SOL825-SOL844: Advanced Runtime & Protocol Security (Feb 5 2026 8:00AM)
// Sources: Solana Runtime Internals, ThreeSigma Rust Memory Safety Research
//          Loopscale RateX PT Token Exploit ($5.8M - April 2025)

function createFinding(id: string, name: string, severity: Finding['severity'], file: string, line: number, details: string): Finding {
  return { id, name, severity, file, line, details };
}

// SOL825: Loopscale RateX PT Token Calculation Flaw ($5.8M)
// Incorrect token value calculation in DeFi protocols
export function checkTokenValueCalculationFlaw(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.sourceCode;
  const lines = content.split('\n');

  if (/value|worth|price|calculate.*amount/i.test(content)) {
    // Check for external token value calculations
    lines.forEach((line, idx) => {
      if (/calculate.*value|get.*price|token.*worth/i.test(line)) {
        const context = lines.slice(Math.max(0, idx - 10), idx + 10).join('\n');
        // Check for proper validation of external token values
        if (!/validate|verify|check.*rate|sanity.*check/i.test(context)) {
          findings.push(createFinding(
            'SOL825',
            'External Token Value Not Validated',
            'critical',
            input.filePath,
            idx + 1,
            'Token value calculation without validation. Loopscale lost $5.8M due to flawed RateX PT token value calculation.'
          ));
        }
      }
    });
  }

  return findings;
}

// SOL826: Rust Memory Safety - Unsafe Block Misuse
// Unsafe code can introduce memory vulnerabilities even in Rust
export function checkUnsafeBlockMisuse(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.sourceCode;
  const lines = content.split('\n');

  lines.forEach((line, idx) => {
    if (/unsafe\s*{/.test(line) || /unsafe\s+fn/.test(line)) {
      // Check for raw pointer operations
      const context = lines.slice(idx, Math.min(lines.length, idx + 20)).join('\n');
      if (/\*mut|\*const|as\s+\*|from_raw|into_raw/i.test(context)) {
        findings.push(createFinding(
          'SOL826',
          'Unsafe Raw Pointer Operation',
          'high',
          input.filePath,
          idx + 1,
          'Unsafe block with raw pointer operations. Memory safety guarantees bypassed - review carefully.'
        ));
      }
      
      // Check for transmute
      if (/transmute/.test(context)) {
        findings.push(createFinding(
          'SOL826',
          'Unsafe Transmute Operation',
          'critical',
          input.filePath,
          idx + 1,
          'std::mem::transmute bypasses type safety. Can cause undefined behavior if types are incompatible.'
        ));
      }
    }
  });

  return findings;
}

// SOL827: BPF Loader Exploit Patterns
// Malicious program loading vulnerabilities
export function checkBPFLoaderExploits(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.sourceCode;
  const lines = content.split('\n');

  lines.forEach((line, idx) => {
    // Check for BPF loader interactions
    if (/bpf.*loader|loader.*v[234]|upgradeable.*loader/i.test(line)) {
      const context = lines.slice(Math.max(0, idx - 5), idx + 5).join('\n');
      // Ensure proper authority validation
      if (!/upgrade.*authority|program.*authority|verify.*authority/i.test(context)) {
        findings.push(createFinding(
          'SOL827',
          'BPF Loader Without Authority Check',
          'high',
          input.filePath,
          idx + 1,
          'BPF loader interaction without authority validation. Malicious upgrades could replace program.'
        ));
      }
    }
  });

  return findings;
}

// SOL828: ELF Alignment Attacks
// Malformed ELF can cause runtime issues
export function checkELFAlignmentIssues(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.sourceCode;
  const lines = content.split('\n');

  // Check for alignment assumptions
  lines.forEach((line, idx) => {
    if (/align|offset|padding|struct.*repr/i.test(line)) {
      if (!/repr\s*\(\s*C\s*\)|repr\s*\(\s*packed\s*\)|align\s*\(\s*\d+\s*\)/i.test(line)) {
        // Check for potential alignment issues in structs
        if (/struct\s+\w+/.test(line)) {
          findings.push(createFinding(
            'SOL828',
            'Struct Without Explicit Alignment',
            'low',
            input.filePath,
            idx + 1,
            'Struct without repr(C) or explicit alignment. May cause issues with cross-platform serialization.'
          ));
        }
      }
    }
  });

  return findings;
}

// SOL829: Epoch Schedule Exploitation
// Timing attacks based on epoch transitions
export function checkEpochScheduleExploitation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.sourceCode;
  const lines = content.split('\n');

  if (/epoch|slot.*schedule|leader.*schedule/i.test(content)) {
    lines.forEach((line, idx) => {
      if (/epoch.*boundary|slot.*transition|leader.*change/i.test(line)) {
        const context = lines.slice(Math.max(0, idx - 10), idx + 10).join('\n');
        if (!/verify.*epoch|check.*transition|atomic/i.test(context)) {
          findings.push(createFinding(
            'SOL829',
            'Epoch Boundary Not Handled Safely',
            'medium',
            input.filePath,
            idx + 1,
            'Epoch/slot boundary operations without safety checks. State may be inconsistent across transitions.'
          ));
        }
      }
    });
  }

  return findings;
}

// SOL830: Rent Collection Attack Patterns
// Exploiting rent mechanics for griefing
export function checkRentCollectionAttack(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.sourceCode;
  const lines = content.split('\n');

  lines.forEach((line, idx) => {
    // Check for rent-related operations
    if (/rent.*collect|collect.*rent|lamports.*drain/i.test(line)) {
      const context = lines.slice(Math.max(0, idx - 5), idx + 5).join('\n');
      if (!/owner.*check|authority.*check|verify/i.test(context)) {
        findings.push(createFinding(
          'SOL830',
          'Rent Collection Without Authorization',
          'high',
          input.filePath,
          idx + 1,
          'Rent collection without proper authorization. Attacker could drain lamports from accounts.'
        ));
      }
    }
  });

  return findings;
}

// SOL831: Transaction Versioning Bypass
// Legacy vs versioned transaction confusion
export function checkTransactionVersioningBypass(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.sourceCode;
  const lines = content.split('\n');

  if (/transaction|message|instruction/i.test(content)) {
    // Check for version-aware transaction handling
    if (/VersionedTransaction|MessageV0|v0.*message/i.test(content)) {
      if (!/version.*check|is.*legacy|message.*version/i.test(content)) {
        findings.push(createFinding(
          'SOL831',
          'Transaction Version Not Validated',
          'medium',
          input.filePath,
          1,
          'Versioned transaction handling without version check. Legacy/v0 confusion could cause issues.'
        ));
      }
    }
  }

  return findings;
}

// SOL832: Address Lookup Table Poisoning
// Malicious ALT entries
export function checkALTPoisoning(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.sourceCode;
  const lines = content.split('\n');

  if (/lookup.*table|AddressLookupTable|ALT/i.test(content)) {
    lines.forEach((line, idx) => {
      if (/extend.*lookup|add.*address.*table|create.*lookup/i.test(line)) {
        const context = lines.slice(Math.max(0, idx - 10), idx + 10).join('\n');
        if (!/verify.*address|whitelist|validate.*entry/i.test(context)) {
          findings.push(createFinding(
            'SOL832',
            'Address Lookup Table Entry Not Validated',
            'high',
            input.filePath,
            idx + 1,
            'ALT entries added without validation. Malicious addresses could be injected for later use.'
          ));
        }
      }
    });
  }

  return findings;
}

// SOL833: Priority Fee Manipulation
// Exploiting priority fees for MEV
export function checkPriorityFeeManipulation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.sourceCode;
  const lines = content.split('\n');

  if (/priority.*fee|compute.*unit.*price|set.*compute/i.test(content)) {
    lines.forEach((line, idx) => {
      if (/set.*priority|compute.*budget/i.test(line)) {
        const context = lines.slice(Math.max(0, idx - 5), idx + 5).join('\n');
        if (!/max.*fee|fee.*cap|limit.*priority/i.test(context)) {
          findings.push(createFinding(
            'SOL833',
            'Priority Fee Not Bounded',
            'low',
            input.filePath,
            idx + 1,
            'Priority fee without upper bound. Users could pay excessive fees in congestion.'
          ));
        }
      }
    });
  }

  return findings;
}

// SOL834: Jito Bundle Manipulation
// MEV bundle ordering attacks
export function checkJitoBundleManipulation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.sourceCode;
  const lines = content.split('\n');

  if (/jito|bundle|mev|searcher/i.test(content)) {
    lines.forEach((line, idx) => {
      if (/bundle.*submit|send.*bundle|jito.*tip/i.test(line)) {
        findings.push(createFinding(
          'SOL834',
          'Jito Bundle Usage Detected',
          'info',
          input.filePath,
          idx + 1,
          'Jito bundle submission detected. Ensure bundle atomicity and proper tip handling to prevent extraction.'
        ));
      }
    });
    
    // Check for bundle ordering assumptions
    if (!/atomic|all.*or.*none|revert.*bundle/i.test(content)) {
      findings.push(createFinding(
        'SOL834',
        'Bundle Atomicity Not Guaranteed',
        'medium',
        input.filePath,
        1,
        'MEV bundle without explicit atomicity. Partial execution could lead to losses.'
      ));
    }
  }

  return findings;
}

// SOL835: Compute Budget Griefing
// Attackers exhausting compute units
export function checkComputeBudgetGriefing(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.sourceCode;
  const lines = content.split('\n');

  // Check for unbounded loops
  lines.forEach((line, idx) => {
    if (/for\s+.*\s+in\s+|while\s+|loop\s*{/.test(line)) {
      const context = lines.slice(idx, Math.min(lines.length, idx + 15)).join('\n');
      // Check for iteration limits
      if (!/\.take\s*\(|limit|max.*iter|break.*if|counter.*</.test(context)) {
        findings.push(createFinding(
          'SOL835',
          'Unbounded Loop May Exhaust Compute',
          'high',
          input.filePath,
          idx + 1,
          'Loop without explicit bound could exhaust compute budget. Attacker can cause transaction failure.'
        ));
      }
    }
  });

  return findings;
}

// SOL836: Durable Nonce Replay Attack
// Reusing durable nonces improperly
export function checkDurableNonceReplay(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.sourceCode;
  const lines = content.split('\n');

  if (/durable.*nonce|nonce.*account|advance.*nonce/i.test(content)) {
    lines.forEach((line, idx) => {
      if (/use.*nonce|nonce.*instruction/i.test(line)) {
        const context = lines.slice(Math.max(0, idx - 10), idx + 10).join('\n');
        if (!/advance.*nonce|nonce.*advance|check.*nonce.*used/i.test(context)) {
          findings.push(createFinding(
            'SOL836',
            'Durable Nonce Not Advanced',
            'high',
            input.filePath,
            idx + 1,
            'Durable nonce used without advancement. Same nonce can be replayed for duplicate transactions.'
          ));
        }
      }
    });
  }

  return findings;
}

// SOL837: Slot Hashes Manipulation
// Using slot hashes for randomness
export function checkSlotHashesRandomness(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.sourceCode;
  const lines = content.split('\n');

  lines.forEach((line, idx) => {
    if (/slot.*hash|SlotHashes|recent.*hash/i.test(line)) {
      // Check if used for randomness
      const context = lines.slice(idx, Math.min(lines.length, idx + 10)).join('\n');
      if (/random|seed|entropy|lottery|raffle/i.test(context)) {
        findings.push(createFinding(
          'SOL837',
          'Slot Hashes Used for Randomness',
          'critical',
          input.filePath,
          idx + 1,
          'Slot hashes are predictable and should not be used for randomness. Use VRF (e.g., Switchboard) instead.'
        ));
      }
    }
  });

  return findings;
}

// SOL838: Stake History Manipulation
// Exploiting stake distribution data
export function checkStakeHistoryExploitation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.sourceCode;
  const lines = content.split('\n');

  if (/stake.*history|StakeHistory|delegation.*history/i.test(content)) {
    lines.forEach((line, idx) => {
      if (/get.*stake|stake.*amount|delegation.*info/i.test(line)) {
        const context = lines.slice(Math.max(0, idx - 5), idx + 5).join('\n');
        if (!/current.*epoch|verify.*epoch|fresh.*data/i.test(context)) {
          findings.push(createFinding(
            'SOL838',
            'Stake History Freshness Not Verified',
            'medium',
            input.filePath,
            idx + 1,
            'Stake history data used without epoch verification. Stale data could lead to incorrect calculations.'
          ));
        }
      }
    });
  }

  return findings;
}

// SOL839: Vote Program Exploits
// Manipulating validator voting
export function checkVoteProgramExploits(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.sourceCode;
  const lines = content.split('\n');

  if (/vote.*program|VoteState|voter.*authority/i.test(content)) {
    lines.forEach((line, idx) => {
      if (/cast.*vote|vote.*instruction|authorized.*voter/i.test(line)) {
        const context = lines.slice(Math.max(0, idx - 10), idx + 10).join('\n');
        if (!/verify.*authority|check.*authorized|validate.*voter/i.test(context)) {
          findings.push(createFinding(
            'SOL839',
            'Vote Authority Not Verified',
            'critical',
            input.filePath,
            idx + 1,
            'Vote operation without authority verification. Unauthorized voting could affect consensus.'
          ));
        }
      }
    });
  }

  return findings;
}

// SOL840: Config Program Manipulation
// Exploiting on-chain configuration
export function checkConfigProgramManipulation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.sourceCode;
  const lines = content.split('\n');

  if (/config.*program|ConfigKeys|on.*chain.*config/i.test(content)) {
    lines.forEach((line, idx) => {
      if (/update.*config|set.*config|store.*config/i.test(line)) {
        const context = lines.slice(Math.max(0, idx - 10), idx + 10).join('\n');
        if (!/admin.*only|owner.*check|authority.*required/i.test(context)) {
          findings.push(createFinding(
            'SOL840',
            'Config Update Without Authorization',
            'high',
            input.filePath,
            idx + 1,
            'Configuration update without proper authorization. Attacker could modify protocol settings.'
          ));
        }
      }
    });
  }

  return findings;
}

// SOL841: Recent Blockhashes Attack
// Using stale blockhashes
export function checkRecentBlockhashesAttack(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.sourceCode;
  const lines = content.split('\n');

  if (/recent.*blockhash|getLatestBlockhash|blockhash.*cache/i.test(content)) {
    // Check for blockhash freshness
    if (!/refresh.*blockhash|new.*blockhash|fresh.*hash/i.test(content)) {
      lines.forEach((line, idx) => {
        if (/blockhash/i.test(line)) {
          findings.push(createFinding(
            'SOL841',
            'Blockhash May Be Stale',
            'medium',
            input.filePath,
            idx + 1,
            'Blockhash used without freshness check. Stale blockhashes cause transaction failures after ~2 minutes.'
          ));
        }
      });
    }
  }

  return findings;
}

// SOL842: Instructions Sysvar Attack
// Malicious instruction introspection
export function checkInstructionsSysvarAttack(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.sourceCode;
  const lines = content.split('\n');

  if (/instructions.*sysvar|get_instruction|load_instruction/i.test(content)) {
    lines.forEach((line, idx) => {
      if (/load.*instruction|get.*current.*instruction/i.test(line)) {
        const context = lines.slice(idx, Math.min(lines.length, idx + 15)).join('\n');
        // Check for proper validation
        if (!/verify.*program.*id|check.*instruction.*data|validate.*caller/i.test(context)) {
          findings.push(createFinding(
            'SOL842',
            'Instruction Introspection Without Validation',
            'high',
            input.filePath,
            idx + 1,
            'Instruction sysvar read without validation. Attacker could craft malicious surrounding instructions.'
          ));
        }
      }
    });
  }

  return findings;
}

// SOL843: Turbine Propagation Attack
// Block propagation timing attacks
export function checkTurbinePropagationAttack(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.sourceCode;
  const lines = content.split('\n');

  // Check for timing-sensitive operations
  if (/confirmation|finality|commit.*level/i.test(content)) {
    lines.forEach((line, idx) => {
      if (/await.*confirm|wait.*finality|check.*commit/i.test(line)) {
        const context = lines.slice(Math.max(0, idx - 5), idx + 5).join('\n');
        if (!/finalized|max.*confirmations|retry.*logic/i.test(context)) {
          findings.push(createFinding(
            'SOL843',
            'Transaction Confirmation Not Finalized',
            'medium',
            input.filePath,
            idx + 1,
            'Transaction checked before finalization. Block reorgs during propagation could invalidate state.'
          ));
        }
      }
    });
  }

  return findings;
}

// SOL844: Validator Stake Concentration
// Centralization risk in stake delegation
export function checkValidatorStakeConcentration(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.sourceCode;
  const lines = content.split('\n');

  if (/delegate.*stake|stake.*pool|validator.*selection/i.test(content)) {
    // Check for stake distribution logic
    if (!/distribute|multiple.*validator|diversif|max.*stake.*per/i.test(content)) {
      lines.forEach((line, idx) => {
        if (/delegate|stake.*to/i.test(line)) {
          findings.push(createFinding(
            'SOL844',
            'Stake Delegation Not Diversified',
            'medium',
            input.filePath,
            idx + 1,
            'Stake delegation without distribution logic. Single validator concentration increases network risk.'
          ));
        }
      });
    }
  }

  return findings;
}

// Export all pattern checks
export const batchPatterns30 = [
  checkTokenValueCalculationFlaw,      // SOL825
  checkUnsafeBlockMisuse,              // SOL826
  checkBPFLoaderExploits,              // SOL827
  checkELFAlignmentIssues,             // SOL828
  checkEpochScheduleExploitation,      // SOL829
  checkRentCollectionAttack,           // SOL830
  checkTransactionVersioningBypass,    // SOL831
  checkALTPoisoning,                   // SOL832
  checkPriorityFeeManipulation,        // SOL833
  checkJitoBundleManipulation,         // SOL834
  checkComputeBudgetGriefing,          // SOL835
  checkDurableNonceReplay,             // SOL836
  checkSlotHashesRandomness,           // SOL837
  checkStakeHistoryExploitation,       // SOL838
  checkVoteProgramExploits,            // SOL839
  checkConfigProgramManipulation,      // SOL840
  checkRecentBlockhashesAttack,        // SOL841
  checkInstructionsSysvarAttack,       // SOL842
  checkTurbinePropagationAttack,       // SOL843
  checkValidatorStakeConcentration,    // SOL844
];
