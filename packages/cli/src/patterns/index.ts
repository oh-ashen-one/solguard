import type { Finding } from '../commands/audit.js';
import type { ParsedIdl } from '../parsers/idl.js';
import type { ParsedRust } from '../parsers/rust.js';
import { checkMissingOwner } from './owner-check.js';
import { checkMissingSigner } from './signer-check.js';
import { checkIntegerOverflow } from './overflow.js';
import { checkPdaValidation } from './pda-validation.js';
import { checkAuthorityBypass } from './authority-bypass.js';
import { checkMissingInitCheck } from './init-check.js';
import { checkCpiVulnerabilities } from './cpi-check.js';
import { checkRoundingErrors } from './rounding.js';
import { checkAccountConfusion } from './account-confusion.js';
import { checkClosingVulnerabilities } from './closing-account.js';
import { checkReentrancyRisk } from './reentrancy.js';
import { checkArbitraryCpi } from './arbitrary-cpi.js';
import { checkDuplicateMutable } from './duplicate-mutable.js';
import { checkRentExemption } from './rent-check.js';
import { checkTypeCosplay } from './type-cosplay.js';
import { checkBumpSeed } from './bump-seed.js';
import { checkFreezeAuthority } from './freeze-authority.js';
import { checkOracleManipulation } from './oracle-manipulation.js';
import { checkFlashLoan } from './flash-loan.js';
import { checkUnsafeMath } from './unsafe-math.js';
import { checkSysvarManipulation } from './sysvar-manipulation.js';
import { checkUpgradeAuthority } from './upgrade-authority.js';
import { checkTokenValidation } from './token-validation.js';
import { checkCrossProgramState } from './cross-program-state.js';
import { checkLamportBalance } from './lamport-balance.js';
import { checkSeededAccount } from './seeded-account.js';
import { checkErrorHandling } from './error-handling.js';
import { checkEventEmission } from './event-emission.js';
import { checkInstructionIntrospection } from './instruction-introspection.js';
import { checkAnchorMacros } from './anchor-macros.js';
import { checkAccessControl } from './access-control.js';
import { checkTimeLock } from './time-lock.js';
import { checkSignatureReplay } from './signature-replay.js';
import { checkStorageCollision } from './storage-collision.js';
import { checkDenialOfService } from './denial-of-service.js';
import { checkInputValidation } from './input-validation.js';
import { checkStateInitialization } from './state-initialization.js';
import { checkToken2022 } from './token-2022.js';
import { checkMemoLogging } from './memo-logging.js';
import { checkCpiGuard } from './cpi-guard.js';
import { checkGovernance } from './governance.js';
import { checkNftSecurity } from './nft-security.js';
import { checkStaking } from './staking.js';
import { checkAmm } from './amm.js';
import { checkLending } from './lending.js';
import { checkBridge } from './bridge.js';
import { checkVault } from './vault.js';
import { checkMerkle } from './merkle.js';
import { checkCompression } from './compression.js';
import { checkProgramDerived } from './program-derived.js';
import { checkAccountSize } from './account-size.js';
import { checkClockDependency } from './clock-dependency.js';
import { checkAccountOrder } from './account-order.js';
import { checkSerialization } from './serialization.js';
import { checkProgramId } from './program-id.js';

export interface PatternInput {
  idl: ParsedIdl | null;
  rust: ParsedRust | null;
  path: string;
}

export interface Pattern {
  id: string;
  name: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  run: (input: PatternInput) => Finding[];
}

// Pattern registry
const patterns: Pattern[] = [
  {
    id: 'SOL001',
    name: 'Missing Owner Check',
    severity: 'critical',
    run: checkMissingOwner,
  },
  {
    id: 'SOL002', 
    name: 'Missing Signer Check',
    severity: 'critical',
    run: checkMissingSigner,
  },
  {
    id: 'SOL003',
    name: 'Integer Overflow',
    severity: 'high',
    run: checkIntegerOverflow,
  },
  {
    id: 'SOL004',
    name: 'PDA Validation Gap',
    severity: 'high',
    run: checkPdaValidation,
  },
  {
    id: 'SOL005',
    name: 'Authority Bypass',
    severity: 'critical',
    run: checkAuthorityBypass,
  },
  {
    id: 'SOL006',
    name: 'Missing Initialization Check',
    severity: 'critical',
    run: checkMissingInitCheck,
  },
  {
    id: 'SOL007',
    name: 'CPI Vulnerability',
    severity: 'high',
    run: checkCpiVulnerabilities,
  },
  {
    id: 'SOL008',
    name: 'Rounding Error',
    severity: 'medium',
    run: checkRoundingErrors,
  },
  {
    id: 'SOL009',
    name: 'Account Confusion',
    severity: 'high',
    run: checkAccountConfusion,
  },
  {
    id: 'SOL010',
    name: 'Account Closing Vulnerability',
    severity: 'critical',
    run: checkClosingVulnerabilities,
  },
  {
    id: 'SOL011',
    name: 'Cross-Program Reentrancy',
    severity: 'high',
    run: checkReentrancyRisk,
  },
  {
    id: 'SOL012',
    name: 'Arbitrary CPI',
    severity: 'critical',
    run: checkArbitraryCpi,
  },
  {
    id: 'SOL013',
    name: 'Duplicate Mutable Accounts',
    severity: 'high',
    run: checkDuplicateMutable,
  },
  {
    id: 'SOL014',
    name: 'Missing Rent Exemption',
    severity: 'medium',
    run: checkRentExemption,
  },
  {
    id: 'SOL015',
    name: 'Type Cosplay',
    severity: 'critical',
    run: checkTypeCosplay,
  },
  {
    id: 'SOL016',
    name: 'Bump Seed Canonicalization',
    severity: 'high',
    run: checkBumpSeed,
  },
  {
    id: 'SOL017',
    name: 'Missing Freeze Authority Check',
    severity: 'medium',
    run: checkFreezeAuthority,
  },
  {
    id: 'SOL018',
    name: 'Oracle Manipulation Risk',
    severity: 'high',
    run: checkOracleManipulation,
  },
  {
    id: 'SOL019',
    name: 'Flash Loan Vulnerability',
    severity: 'critical',
    run: checkFlashLoan,
  },
  {
    id: 'SOL020',
    name: 'Unsafe Arithmetic',
    severity: 'high',
    run: checkUnsafeMath,
  },
  {
    id: 'SOL021',
    name: 'Sysvar Manipulation Risk',
    severity: 'critical',
    run: checkSysvarManipulation,
  },
  {
    id: 'SOL022',
    name: 'Program Upgrade Authority Risk',
    severity: 'medium',
    run: checkUpgradeAuthority,
  },
  {
    id: 'SOL023',
    name: 'Token Account Validation',
    severity: 'high',
    run: checkTokenValidation,
  },
  {
    id: 'SOL024',
    name: 'Cross-Program State Dependency',
    severity: 'high',
    run: checkCrossProgramState,
  },
  {
    id: 'SOL025',
    name: 'Lamport Balance Vulnerability',
    severity: 'high',
    run: checkLamportBalance,
  },
  {
    id: 'SOL026',
    name: 'Seeded Account Vulnerability',
    severity: 'medium',
    run: checkSeededAccount,
  },
  {
    id: 'SOL027',
    name: 'Inadequate Error Handling',
    severity: 'medium',
    run: checkErrorHandling,
  },
  {
    id: 'SOL028',
    name: 'Event Emission Issues',
    severity: 'low',
    run: checkEventEmission,
  },
  {
    id: 'SOL029',
    name: 'Instruction Introspection Issues',
    severity: 'high',
    run: checkInstructionIntrospection,
  },
  {
    id: 'SOL030',
    name: 'Anchor Macro Misuse',
    severity: 'medium',
    run: checkAnchorMacros,
  },
  {
    id: 'SOL031',
    name: 'Access Control Vulnerability',
    severity: 'critical',
    run: checkAccessControl,
  },
  {
    id: 'SOL032',
    name: 'Missing Time Lock',
    severity: 'medium',
    run: checkTimeLock,
  },
  {
    id: 'SOL033',
    name: 'Signature Replay Vulnerability',
    severity: 'critical',
    run: checkSignatureReplay,
  },
  {
    id: 'SOL034',
    name: 'Storage/Discriminator Collision',
    severity: 'high',
    run: checkStorageCollision,
  },
  {
    id: 'SOL035',
    name: 'Denial of Service',
    severity: 'high',
    run: checkDenialOfService,
  },
  {
    id: 'SOL036',
    name: 'Input Validation Issues',
    severity: 'medium',
    run: checkInputValidation,
  },
  {
    id: 'SOL037',
    name: 'State Initialization Issues',
    severity: 'medium',
    run: checkStateInitialization,
  },
  {
    id: 'SOL038',
    name: 'Token-2022 Compatibility',
    severity: 'medium',
    run: checkToken2022,
  },
  {
    id: 'SOL039',
    name: 'Memo and Logging Issues',
    severity: 'medium',
    run: checkMemoLogging,
  },
  {
    id: 'SOL040',
    name: 'CPI Guard Vulnerability',
    severity: 'high',
    run: checkCpiGuard,
  },
  {
    id: 'SOL041',
    name: 'Governance Vulnerability',
    severity: 'critical',
    run: checkGovernance,
  },
  {
    id: 'SOL042',
    name: 'NFT Security Issue',
    severity: 'high',
    run: checkNftSecurity,
  },
  {
    id: 'SOL043',
    name: 'Staking Vulnerability',
    severity: 'high',
    run: checkStaking,
  },
  {
    id: 'SOL044',
    name: 'AMM/DEX Vulnerability',
    severity: 'critical',
    run: checkAmm,
  },
  {
    id: 'SOL045',
    name: 'Lending Protocol Vulnerability',
    severity: 'critical',
    run: checkLending,
  },
  {
    id: 'SOL046',
    name: 'Bridge Vulnerability',
    severity: 'critical',
    run: checkBridge,
  },
  {
    id: 'SOL047',
    name: 'Vault Vulnerability',
    severity: 'high',
    run: checkVault,
  },
  {
    id: 'SOL048',
    name: 'Merkle Vulnerability',
    severity: 'critical',
    run: checkMerkle,
  },
  {
    id: 'SOL049',
    name: 'Compression Vulnerability',
    severity: 'medium',
    run: checkCompression,
  },
  {
    id: 'SOL050',
    name: 'Program-Derived Signing Issue',
    severity: 'high',
    run: checkProgramDerived,
  },
  {
    id: 'SOL051',
    name: 'Account Size Vulnerability',
    severity: 'medium',
    run: checkAccountSize,
  },
  {
    id: 'SOL052',
    name: 'Clock Dependency Issue',
    severity: 'medium',
    run: checkClockDependency,
  },
  {
    id: 'SOL053',
    name: 'Account Order Dependency',
    severity: 'medium',
    run: checkAccountOrder,
  },
  {
    id: 'SOL054',
    name: 'Serialization Vulnerability',
    severity: 'medium',
    run: checkSerialization,
  },
  {
    id: 'SOL055',
    name: 'Program ID Vulnerability',
    severity: 'critical',
    run: checkProgramId,
  },
];

export async function runPatterns(input: PatternInput): Promise<Finding[]> {
  const findings: Finding[] = [];
  
  for (const pattern of patterns) {
    try {
      const patternFindings = pattern.run(input);
      findings.push(...patternFindings);
    } catch (error) {
      console.warn(`Pattern ${pattern.id} failed: ${error}`);
    }
  }
  
  // Sort by severity
  const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  findings.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);
  
  return findings;
}

export function getPatternById(id: string): Pattern | undefined {
  return patterns.find(p => p.id === id);
}

export function listPatterns(): Pattern[] {
  return patterns;
}
