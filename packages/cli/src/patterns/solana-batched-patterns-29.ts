import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

// SOL805-SOL824: Academic & Supply Chain Security Patterns (Feb 5 2026 8:00AM)
// Sources: arXiv:2504.07419 "Exploring Vulnerabilities in Solana Smart Contracts"
//          Sept 2025 NPM Supply Chain Attack (Palo Alto, OX Security)
//          Sec3 2025 Solana Security Ecosystem Review

function createFinding(id: string, name: string, severity: Finding['severity'], file: string, line: number, details: string): Finding {
  return { id, name, severity, file, line, details };
}

// SOL805: Missing Signer Check (arXiv 3.1.1)
// Classic vulnerability - attacker can pass admin account without proving they own it
export function checkMissingSignerValidation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.sourceCode;
  const lines = content.split('\n');

  lines.forEach((line, idx) => {
    // Look for admin/authority updates without signer checks
    if (/update.*admin|set.*authority|change.*owner/i.test(line)) {
      // Check surrounding context for signer validation
      const context = lines.slice(Math.max(0, idx - 10), idx + 10).join('\n');
      if (!/is_signer/.test(context) && !/\.signer\s*=/.test(context) && !/#\[account\([^)]*signer/.test(context)) {
        findings.push(createFinding(
          'SOL805',
          'Missing Signer Check on Authority Update',
          'critical',
          input.filePath,
          idx + 1,
          'Authority update without signer verification allows unauthorized admin changes. Attacker can pass admin pubkey without proving ownership.'
        ));
      }
    }
  });

  return findings;
}

// SOL806: Missing Ownership Check (arXiv 3.1.2)
// Accounts not verified as owned by expected program
export function checkMissingOwnershipValidation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.sourceCode;
  const lines = content.split('\n');

  // Check for account unpacking without owner validation
  if (/AccountInfo|next_account_info/i.test(content)) {
    if (!/\.owner\s*==/.test(content) && !/owner_check/.test(content) && !/#\[account\([^)]*owner/.test(content)) {
      // Find lines with account access
      lines.forEach((line, idx) => {
        if (/unpack|deserialize|try_from_slice/.test(line) && /account|info/i.test(line)) {
          findings.push(createFinding(
            'SOL806',
            'Account Owner Not Verified',
            'critical',
            input.filePath,
            idx + 1,
            'Account data deserialized without owner verification. Attacker can pass forged account with arbitrary data.'
          ));
        }
      });
    }
  }

  return findings;
}

// SOL807: Missing Rent Exemption Check (arXiv 3.1.3)
// Accounts without sufficient SOL may fail to load or be evicted
export function checkRentExemptionValidation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.sourceCode;
  const lines = content.split('\n');

  // Look for account creation without rent exemption validation
  if (/create_account|init|initialize/i.test(content) && /Account|Mint|Multisig/i.test(content)) {
    if (!/rent_exempt|minimum_balance|Rent::get/.test(content)) {
      lines.forEach((line, idx) => {
        if (/create_account|\.init\(|initialize_account/i.test(line)) {
          findings.push(createFinding(
            'SOL807',
            'Rent Exemption Not Verified on Account Creation',
            'medium',
            input.filePath,
            idx + 1,
            'Account created without rent exemption check. Account may be evicted if lamports are insufficient.'
          ));
        }
      });
    }
  }

  return findings;
}

// SOL808: Solana Account Type Confusion (arXiv 3.2.1)
// Different account types mistakenly used interchangeably
export function checkAccountTypeConfusion(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.sourceCode;
  const lines = content.split('\n');

  // Check for multiple account types without discriminator validation
  if (/Account|Vault|Config|State|Pool/.test(content)) {
    if (!/discriminator|account_type|AccountType|enum\s+\w+\s*{/.test(content)) {
      // Check for deserialization of account data
      lines.forEach((line, idx) => {
        if (/try_from_slice|deserialize|unpack/.test(line)) {
          findings.push(createFinding(
            'SOL808',
            'Account Type Not Discriminated',
            'high',
            input.filePath,
            idx + 1,
            'Multiple account types without discriminator allow type confusion attacks. Attacker can pass wrong account type.'
          ));
        }
      });
    }
  }

  return findings;
}

// SOL809: Cross-Instance Re-initialization Attack (arXiv 3.2.2)
// Contract can be re-initialized without clearing state
export function checkCrossInstanceReinitAttack(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.sourceCode;
  const lines = content.split('\n');

  lines.forEach((line, idx) => {
    // Look for initialize functions
    if (/fn\s+initialize|fn\s+init\s*\(|pub\s+fn\s+new/.test(line)) {
      // Check if there's protection against re-initialization
      const context = lines.slice(idx, Math.min(lines.length, idx + 30)).join('\n');
      if (!/is_initialized|already.*initialized|require.*!.*initialized|#\[constraint.*initialized/.test(context)) {
        findings.push(createFinding(
          'SOL809',
          'Re-initialization Attack Possible',
          'critical',
          input.filePath,
          idx + 1,
          'Initialize function without re-initialization check. Attacker can re-initialize with malicious state from another instance.'
        ));
      }
    }
  });

  return findings;
}

// SOL810: NPM Supply Chain - Address Swapping (Sept 2025 Attack)
// Malicious packages swap recipient addresses in transactions
export function checkSupplyChainAddressSwap(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.sourceCode;
  const lines = content.split('\n');

  // Look for hardcoded addresses that could be swapped
  lines.forEach((line, idx) => {
    // Check for suspicious address patterns
    if (/pubkey.*=.*"[A-HJ-NP-Za-km-z1-9]{32,44}"/.test(line) || /new\s+PublicKey\s*\(\s*["'][A-HJ-NP-Za-km-z1-9]+["']\s*\)/.test(line)) {
      // Check if it's a well-known program (OK) or unknown (suspicious)
      if (!/11111111111111111111111111111111|Token|Associated|System|Rent/.test(line)) {
        findings.push(createFinding(
          'SOL810',
          'Hardcoded Address May Be Supply Chain Target',
          'medium',
          input.filePath,
          idx + 1,
          'Hardcoded addresses in dependency-loaded code could be swapped by malicious packages. Verify address origin.'
        ));
      }
    }
  });

  return findings;
}

// SOL811: NPM Supply Chain - Transaction Hijacking
// Malicious code modifies transaction parameters before signing
export function checkTransactionHijacking(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.sourceCode;
  const lines = content.split('\n');

  // Look for transaction construction patterns
  lines.forEach((line, idx) => {
    if (/Transaction\s*\(|new\s+Transaction|buildTransaction/.test(line)) {
      // Check if transaction is modified after construction
      const after = lines.slice(idx, Math.min(lines.length, idx + 20)).join('\n');
      if (/\.add\(|\.instructions\s*=|\.keys\s*=|push.*instruction/.test(after)) {
        // Check if there's signature verification
        if (!/verify|validate.*instruction|whitelist/i.test(after)) {
          findings.push(createFinding(
            'SOL811',
            'Transaction May Be Modified Before Signing',
            'high',
            input.filePath,
            idx + 1,
            'Transaction constructed then modified. Supply chain attack could inject malicious instructions before signing.'
          ));
        }
      }
    }
  });

  return findings;
}

// SOL812: Solend Oracle Attack Pattern (Table 1 - $1.26M)
// Oracle can report stale or manipulated prices
export function checkOracleAttackPattern(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.sourceCode;
  const lines = content.split('\n');

  if (/oracle|price.*feed|pyth|switchboard|chainlink/i.test(content)) {
    // Check for staleness validation
    if (!/stale|fresh|timestamp|last_update|valid_slot/i.test(content)) {
      lines.forEach((line, idx) => {
        if (/get.*price|fetch.*price|oracle.*price|price.*oracle/i.test(line)) {
          findings.push(createFinding(
            'SOL812',
            'Oracle Price Staleness Not Checked',
            'critical',
            input.filePath,
            idx + 1,
            'Oracle price used without staleness check. Solend lost $1.26M to oracle attack in Nov 2022.'
          ));
        }
      });
    }
    
    // Check for confidence interval validation
    if (!/confidence|deviation|spread/i.test(content)) {
      findings.push(createFinding(
        'SOL812',
        'Oracle Price Confidence Not Validated',
        'high',
        input.filePath,
        1,
        'Oracle price without confidence interval check. Wide spreads can be exploited for manipulation.'
      ));
    }
  }

  return findings;
}

// SOL813: Mango Markets Flash Loan Pattern (Table 1 - $100M)
// Flash loan used to manipulate oracle prices
export function checkFlashLoanOracleManipulation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.sourceCode;
  const lines = content.split('\n');

  if (/flash.*loan|borrow.*repay.*same|atomic.*borrow/i.test(content)) {
    // Check for TWAP or multi-block price validation
    if (!/twap|time.*weighted|multiple.*blocks|average.*price/i.test(content)) {
      lines.forEach((line, idx) => {
        if (/flash|borrow/i.test(line)) {
          findings.push(createFinding(
            'SOL813',
            'Flash Loan Without TWAP Protection',
            'critical',
            input.filePath,
            idx + 1,
            'Flash loan pattern without TWAP oracle. Mango Markets lost $100M+ to flash loan oracle manipulation.'
          ));
        }
      });
    }
  }

  return findings;
}

// SOL814: Cashio Root-of-Trust Bypass (Table 1 - $52M)
// Unverified account passed as collateral root
export function checkCollateralRootTrustBypass(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.sourceCode;
  const lines = content.split('\n');

  if (/collateral|backing|reserve|mint.*auth/i.test(content)) {
    // Look for collateral validation
    lines.forEach((line, idx) => {
      if (/mint_collateral|add_collateral|deposit_collateral/i.test(line)) {
        const context = lines.slice(Math.max(0, idx - 15), idx + 15).join('\n');
        if (!/verify.*mint|check.*backing|validate.*collateral|whitelist/i.test(context)) {
          findings.push(createFinding(
            'SOL814',
            'Collateral Mint Not Verified',
            'critical',
            input.filePath,
            idx + 1,
            'Collateral mint accepted without verification. Cashio lost $52M when attacker used unverified collateral.'
          ));
        }
      }
    });
  }

  return findings;
}

// SOL815: Wormhole Signature Fabrication (Table 1 - 120K ETH)
// Deprecated function enabled forged signatures
export function checkDeprecatedCryptoFunction(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.sourceCode;
  const lines = content.split('\n');

  lines.forEach((line, idx) => {
    // Check for deprecated or unsafe crypto functions
    if (/load_instruction_at|deprecated|unsafe.*verify|old.*signature/i.test(line)) {
      findings.push(createFinding(
        'SOL815',
        'Deprecated Cryptographic Function',
        'critical',
        input.filePath,
        idx + 1,
        'Deprecated function may enable signature bypass. Wormhole lost $326M via deprecated load_instruction_at.'
      ));
    }
    
    // Check for improper guardian/validator verification
    if (/guardian|validator.*set|signature.*set/i.test(line)) {
      const context = lines.slice(Math.max(0, idx - 10), idx + 10).join('\n');
      if (!/quorum|threshold|minimum.*sign|verify.*all/i.test(context)) {
        findings.push(createFinding(
          'SOL815',
          'Guardian Quorum Not Enforced',
          'critical',
          input.filePath,
          idx + 1,
          'Guardian/validator set without quorum check. Multi-sig bridges must verify sufficient signatures.'
        ));
      }
    }
  });

  return findings;
}

// SOL816: Tulip Protocol Dependency Attack (Table 1 - $2.5M)
// Vulnerable to upstream protocol exploits (Mango attack cascade)
export function checkCrossProtocolDependency(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.sourceCode;
  const lines = content.split('\n');

  // Look for external protocol integrations
  const externalProtocols = /mango|tulip|orca|raydium|serum|marinade|solend|drift|jupiter/i;
  
  if (externalProtocols.test(content)) {
    // Check for circuit breakers or dependency health checks
    if (!/circuit.*breaker|health.*check|pause|emergency.*stop/i.test(content)) {
      lines.forEach((line, idx) => {
        if (externalProtocols.test(line)) {
          findings.push(createFinding(
            'SOL816',
            'External Protocol Dependency Without Circuit Breaker',
            'high',
            input.filePath,
            idx + 1,
            'External protocol integration without circuit breaker. Tulip lost $2.5M due to upstream Mango attack cascade.'
          ));
        }
      });
    }
  }

  return findings;
}

// SOL817: Nirvana Flash Loan Attack (Table 1 - $3.5M)
// AMM curve manipulation via flash loan
export function checkAMMCurveManipulation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.sourceCode;
  const lines = content.split('\n');

  if (/amm|swap|curve|pool|liquidity/i.test(content)) {
    // Check for curve invariant validation
    if (!/invariant|k\s*=|constant.*product|balance.*check/i.test(content)) {
      lines.forEach((line, idx) => {
        if (/swap|trade|exchange/i.test(line)) {
          findings.push(createFinding(
            'SOL817',
            'AMM Invariant Not Validated',
            'high',
            input.filePath,
            idx + 1,
            'AMM swap without invariant check. Nirvana lost $3.5M to flash loan curve manipulation.'
          ));
        }
      });
    }
    
    // Check for flash loan same-block protection
    if (!/same.*block|slot.*check|block.*number/i.test(content)) {
      findings.push(createFinding(
        'SOL817',
        'Flash Loan Same-Block Attack Possible',
        'high',
        input.filePath,
        1,
        'No same-block protection. Flash loans can manipulate prices within single transaction.'
      ));
    }
  }

  return findings;
}

// SOL818: Crema Finance Flash Loan (Table 1 - $1.68M)
// Tick manipulation in concentrated liquidity
export function checkConcentratedLiquidityManipulation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.sourceCode;
  const lines = content.split('\n');

  if (/tick|concentrated.*liquidity|clmm|whirlpool|position.*range/i.test(content)) {
    // Check for tick array manipulation protection
    if (!/tick.*validation|price.*range.*check|liquidity.*bounds/i.test(content)) {
      lines.forEach((line, idx) => {
        if (/tick|swap.*tick|position/i.test(line)) {
          findings.push(createFinding(
            'SOL818',
            'Concentrated Liquidity Tick Not Protected',
            'high',
            input.filePath,
            idx + 1,
            'CLMM tick without manipulation protection. Crema lost $1.68M to tick manipulation via flash loan.'
          ));
        }
      });
    }
  }

  return findings;
}

// SOL819: Jet Protocol Undisclosed Vulnerability (Table 1)
// Generic lending protocol security check
export function checkLendingProtocolSecurity(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.sourceCode;
  const lines = content.split('\n');

  if (/lending|borrow|collateral|liquidat/i.test(content)) {
    // Check for liquidation threshold safety
    if (!/liquidation.*threshold|health.*factor|collateral.*ratio/i.test(content)) {
      lines.forEach((line, idx) => {
        if (/liquidat/i.test(line)) {
          findings.push(createFinding(
            'SOL819',
            'Liquidation Threshold Not Defined',
            'high',
            input.filePath,
            idx + 1,
            'Lending protocol without explicit liquidation thresholds. Critical for protocol solvency.'
          ));
        }
      });
    }
    
    // Check for interest rate bounds
    if (!/max.*rate|rate.*cap|interest.*limit/i.test(content)) {
      findings.push(createFinding(
        'SOL819',
        'Interest Rate Not Bounded',
        'medium',
        input.filePath,
        1,
        'Lending protocol without interest rate caps. Extreme rates could destabilize protocol.'
      ));
    }
  }

  return findings;
}

// SOL820: Cargo Audit - Vulnerable Dependencies
// Check for known vulnerable crate patterns
export function checkVulnerableDependencies(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.sourceCode;
  const lines = content.split('\n');

  // Known vulnerable version patterns
  const vulnerablePatterns = [
    { pattern: /solana-program\s*=\s*["']1\.[0-8]\./, cve: 'CVE-2022-XXXXX', version: '< 1.9.0' },
    { pattern: /anchor-lang\s*=\s*["']0\.(1[0-9]|[0-9])\./, cve: 'init_if_needed', version: '< 0.20.0' },
    { pattern: /spl-token\s*=\s*["'][0-2]\./, cve: 'token validation', version: '< 3.0.0' },
  ];

  lines.forEach((line, idx) => {
    vulnerablePatterns.forEach(({ pattern, cve, version }) => {
      if (pattern.test(line)) {
        findings.push(createFinding(
          'SOL820',
          'Potentially Vulnerable Dependency Version',
          'medium',
          input.filePath,
          idx + 1,
          `Dependency version ${version} may have known vulnerabilities (${cve}). Run cargo audit.`
        ));
      }
    });
  });

  return findings;
}

// SOL821: UXD Protocol Mango Cascade (Table 1 - $20M)
// Stablecoin backed by exploited protocol
export function checkStablecoinBackingExposure(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.sourceCode;
  const lines = content.split('\n');

  if (/stablecoin|stable.*coin|peg|backing|reserve/i.test(content)) {
    // Check for diversified backing
    if (!/multiple.*collateral|diversif|backup.*reserve/i.test(content)) {
      lines.forEach((line, idx) => {
        if (/backing|collateral.*type|reserve.*source/i.test(line)) {
          findings.push(createFinding(
            'SOL821',
            'Stablecoin Single Collateral Dependency',
            'high',
            input.filePath,
            idx + 1,
            'Stablecoin with single collateral source. UXD lost $20M when Mango (backing) was exploited.'
          ));
        }
      });
    }
  }

  return findings;
}

// SOL822: OptiFi Operational Error (Table 1 - $661K USDC)
// Program accidentally closed with funds locked
export function checkProgramCloseWithFunds(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.sourceCode;
  const lines = content.split('\n');

  lines.forEach((line, idx) => {
    // Check for program close/upgrade patterns
    if (/close.*program|upgrade.*program|set.*authority.*none/i.test(line)) {
      const context = lines.slice(Math.max(0, idx - 10), idx + 10).join('\n');
      // Check for balance validation before close
      if (!/balance.*==.*0|empty|drain.*first|withdraw.*all/i.test(context)) {
        findings.push(createFinding(
          'SOL822',
          'Program Close Without Balance Check',
          'critical',
          input.filePath,
          idx + 1,
          'Program close without checking for remaining funds. OptiFi locked $661K USDC by accidentally closing program.'
        ));
      }
    }
  });

  return findings;
}

// SOL823: Syscall Security - invoke_signed abuse
// Improper CPI can bypass security checks
export function checkSyscallSecurityAbuse(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.sourceCode;
  const lines = content.split('\n');

  lines.forEach((line, idx) => {
    // Check for invoke_signed without proper validation
    if (/invoke_signed|invoke\s*\(/.test(line)) {
      const context = lines.slice(Math.max(0, idx - 5), idx + 5).join('\n');
      // Check for instruction validation
      if (!/validate.*instruction|check.*program_id|whitelist.*program/i.test(context)) {
        findings.push(createFinding(
          'SOL823',
          'CPI invoke Without Instruction Validation',
          'high',
          input.filePath,
          idx + 1,
          'invoke_signed without instruction validation. Arbitrary CPI can bypass program security.'
        ));
      }
    }
  });

  return findings;
}

// SOL824: Web3.js Supply Chain Attack ($164K - Jan 2025)
// Malicious npm package exfiltrating keys
export function checkKeyExfiltrationPatterns(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.sourceCode;
  const lines = content.split('\n');

  lines.forEach((line, idx) => {
    // Check for suspicious key handling
    if (/secret.*key|private.*key|keypair|seed.*phrase|mnemonic/i.test(line)) {
      // Check for network transmission
      if (/fetch|http|axios|request|send|post|socket|webhook/i.test(line)) {
        findings.push(createFinding(
          'SOL824',
          'Private Key Near Network Operation',
          'critical',
          input.filePath,
          idx + 1,
          'Private key handling near network code. Web3.js supply chain attack exfiltrated $164K via Gmail SMTP.'
        ));
      }
      
      // Check for logging
      if (/console|log|print|debug|trace/i.test(line)) {
        findings.push(createFinding(
          'SOL824',
          'Private Key May Be Logged',
          'critical',
          input.filePath,
          idx + 1,
          'Private key near logging statement. Keys should never be logged or exposed.'
        ));
      }
    }
  });

  return findings;
}

// Export all pattern checks
export const batchPatterns29 = [
  checkMissingSignerValidation,      // SOL805
  checkMissingOwnershipValidation,   // SOL806
  checkRentExemptionValidation,      // SOL807
  checkAccountTypeConfusion,         // SOL808
  checkCrossInstanceReinitAttack,    // SOL809
  checkSupplyChainAddressSwap,       // SOL810
  checkTransactionHijacking,         // SOL811
  checkOracleAttackPattern,          // SOL812
  checkFlashLoanOracleManipulation,  // SOL813
  checkCollateralRootTrustBypass,    // SOL814
  checkDeprecatedCryptoFunction,     // SOL815
  checkCrossProtocolDependency,      // SOL816
  checkAMMCurveManipulation,         // SOL817
  checkConcentratedLiquidityManipulation, // SOL818
  checkLendingProtocolSecurity,      // SOL819
  checkVulnerableDependencies,       // SOL820
  checkStablecoinBackingExposure,    // SOL821
  checkProgramCloseWithFunds,        // SOL822
  checkSyscallSecurityAbuse,         // SOL823
  checkKeyExfiltrationPatterns,      // SOL824
];
