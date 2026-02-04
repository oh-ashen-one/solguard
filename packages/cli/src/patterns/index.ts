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
import { checkAuthorityTransfer } from './authority-transfer.js';
import { checkFeeHandling } from './fee-handling.js';
import { checkPauseMechanism } from './pause-mechanism.js';
import { checkWithdrawPattern } from './withdraw-pattern.js';
import { checkInitializationFrontrun } from './initialization-frontrun.js';
import { checkDataValidation } from './data-validation.js';
import { checkComputeBudget } from './compute-budget.js';
import { checkPrivilegeEscalation } from './privilege-escalation.js';
import { checkSandwichAttack } from './sandwich-attack.js';
import { checkSupplyManipulation } from './supply-manipulation.js';
import { checkAccountBorrowing } from './account-borrowing.js';
import { checkRemainingAccounts } from './remaining-accounts.js';
import { checkConstraintValidation } from './constraint-validation.js';
import { checkRentDrain } from './rent-drain.js';
import { checkPdaCollision } from './pda-collision.js';
import { checkMetaplexSecurity } from './metaplex-security.js';
import { checkAtaSecurity } from './ata-security.js';
import { checkSystemProgramAbuse } from './system-program-abuse.js';
import { checkWrappedSol } from './wrapped-sol.js';
import { checkAccountRevival } from './account-revival.js';
import { checkCrossInstance } from './cross-instance.js';
import { checkProgramDataAuthority } from './program-data-authority.js';
import { checkMintAuthority } from './mint-authority.js';
import { checkDiscriminator } from './discriminator.js';
import { checkTimestampManipulation } from './timestamp-manipulation.js';
import { checkAnchorAccountInit } from './anchor-account-init.js';
import { checkTokenOwnership } from './token-ownership.js';
import { checkPdaSignerSeeds } from './pda-signer-seeds.js';
import { checkConstraintOrder } from './constraint-order.js';
import { checkCpiReturnData } from './cpi-return-data.js';
import { checkAccountLifetime } from './account-lifetime.js';
import { checkArithmeticPrecision } from './arithmetic-precision.js';
import { checkEventOrdering } from './event-ordering.js';
import { checkAccountTypeSafety } from './account-type-safety.js';
import { checkSyscallSecurity } from './syscall-security.js';
import { checkSplGovernance } from './spl-governance.js';
import { checkTokenExtensions } from './token-extensions.js';
import { checkLookupTable } from './lookup-table.js';
import { checkPriorityFee } from './priority-fee.js';
import { checkSlotManipulation } from './slot-manipulation.js';
import { checkCrossChain } from './cross-chain.js';
import { checkMultisig } from './multisig.js';
import { checkVersioning } from './versioning.js';
import { checkAtomicOperations } from './atomic-operations.js';
import { checkInitializationOrder } from './initialization-order.js';
import { checkProgramCache } from './program-cache.js';
import { checkInstructionData } from './instruction-data.js';
import { checkAnchorCpiSafety } from './anchor-cpi-safety.js';
import { checkAuthorityScope } from './authority-scope.js';
import { checkErrorPropagation } from './error-propagation.js';
import { checkAccountKeyDerivation } from './account-key-derivation.js';
import { checkTokenBurnSafety } from './token-burn-safety.js';
import { checkAssociatedProgram } from './associated-program.js';
import { checkSignerSeedsValidation } from './signer-seeds-validation.js';
import { checkAccountReallocation } from './account-reallocation.js';
import { checkAccountDiscriminatorCheck } from './account-discriminator-check.js';
import { checkTokenApproval } from './token-approval.js';
import { checkRentCollection } from './rent-collection.js';
import { checkInstructionSysvar } from './instruction-sysvar.js';
import { checkStateTransition } from './state-transition.js';
import { checkAccountDataMatch } from './account-data-match.js';
import { checkTokenFreeze } from './token-freeze.js';
import { checkZeroCopyAccount } from './zero-copy-account.js';
import { checkProgramUpgrade } from './program-upgrade.js';
import { checkAccountConstraintCombo } from './account-constraint-combo.js';
import { checkCpiDepth } from './cpi-depth.js';
import { checkAccountCloseDestination } from './account-close-destination.js';
import { checkTokenAccountClosure } from './token-account-closure.js';
import { checkAccountDataInit } from './account-data-init.js';
import { checkProgramSigner } from './program-signer.js';
import { checkAccountLamportCheck } from './account-lamport-check.js';
import { checkInstructionSize } from './instruction-size.js';
import { checkAccountSeedLength } from './account-seed-length.js';
import { checkTokenDecimalHandling } from './token-decimal-handling.js';
import { checkAccountPdaBumpStorage } from './account-pda-bump-storage.js';
// New patterns based on real-world exploits (SOL131-SOL142)
import { checkTickAccountSpoofing } from './tick-account-spoofing.js';
import { checkGovernanceInjection } from './governance-injection.js';
import { checkBondingCurveManipulation } from './bonding-curve-manipulation.js';
import { checkInfiniteMint } from './infinite-mint.js';
import { checkLiquidationManipulation } from './liquidation-manipulation.js';
import { checkSupplyChainAttack } from './supply-chain-attack.js';
import { checkPrivateKeyExposure } from './private-key-exposure.js';
import { checkInsiderThreat } from './insider-threat.js';
import { checkTreasuryDrain } from './treasury-drain.js';
import { checkClmmExploit } from './clmm-exploit.js';
import { checkBotCompromise } from './bot-compromise.js';
import { checkSignatureBypass } from './signature-bypass.js';

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
  {
    id: 'SOL056',
    name: 'Authority Transfer Vulnerability',
    severity: 'medium',
    run: checkAuthorityTransfer,
  },
  {
    id: 'SOL057',
    name: 'Fee Handling Vulnerability',
    severity: 'high',
    run: checkFeeHandling,
  },
  {
    id: 'SOL058',
    name: 'Pause Mechanism Issue',
    severity: 'medium',
    run: checkPauseMechanism,
  },
  {
    id: 'SOL059',
    name: 'Withdrawal Pattern Issue',
    severity: 'critical',
    run: checkWithdrawPattern,
  },
  {
    id: 'SOL060',
    name: 'Initialization Frontrunning',
    severity: 'critical',
    run: checkInitializationFrontrun,
  },
  {
    id: 'SOL061',
    name: 'Data Validation Issue',
    severity: 'high',
    run: checkDataValidation,
  },
  {
    id: 'SOL062',
    name: 'Compute Budget Issue',
    severity: 'high',
    run: checkComputeBudget,
  },
  {
    id: 'SOL063',
    name: 'Privilege Escalation',
    severity: 'critical',
    run: checkPrivilegeEscalation,
  },
  {
    id: 'SOL064',
    name: 'Sandwich Attack Vulnerability',
    severity: 'high',
    run: checkSandwichAttack,
  },
  {
    id: 'SOL065',
    name: 'Supply Manipulation',
    severity: 'high',
    run: checkSupplyManipulation,
  },
  {
    id: 'SOL066',
    name: 'Account Data Borrowing Vulnerability',
    severity: 'high',
    run: checkAccountBorrowing,
  },
  {
    id: 'SOL067',
    name: 'Remaining Accounts Security',
    severity: 'critical',
    run: checkRemainingAccounts,
  },
  {
    id: 'SOL068',
    name: 'Anchor Constraint Validation',
    severity: 'high',
    run: checkConstraintValidation,
  },
  {
    id: 'SOL069',
    name: 'Rent Drain Attack',
    severity: 'high',
    run: checkRentDrain,
  },
  {
    id: 'SOL070',
    name: 'PDA Seed Collision',
    severity: 'high',
    run: checkPdaCollision,
  },
  {
    id: 'SOL071',
    name: 'Metaplex/NFT Metadata Security',
    severity: 'high',
    run: checkMetaplexSecurity,
  },
  {
    id: 'SOL072',
    name: 'Associated Token Account Security',
    severity: 'high',
    run: checkAtaSecurity,
  },
  {
    id: 'SOL073',
    name: 'System Program Abuse',
    severity: 'critical',
    run: checkSystemProgramAbuse,
  },
  {
    id: 'SOL074',
    name: 'Wrapped SOL Security',
    severity: 'high',
    run: checkWrappedSol,
  },
  {
    id: 'SOL075',
    name: 'Account Revival Attack',
    severity: 'critical',
    run: checkAccountRevival,
  },
  {
    id: 'SOL076',
    name: 'Cross-Instance Confusion',
    severity: 'medium',
    run: checkCrossInstance,
  },
  {
    id: 'SOL077',
    name: 'Program Data Authority',
    severity: 'critical',
    run: checkProgramDataAuthority,
  },
  {
    id: 'SOL078',
    name: 'Token Mint Authority Security',
    severity: 'critical',
    run: checkMintAuthority,
  },
  {
    id: 'SOL079',
    name: 'Account Discriminator Security',
    severity: 'critical',
    run: checkDiscriminator,
  },
  {
    id: 'SOL080',
    name: 'Timestamp Manipulation',
    severity: 'high',
    run: checkTimestampManipulation,
  },
  {
    id: 'SOL081',
    name: 'Anchor Account Initialization',
    severity: 'medium',
    run: checkAnchorAccountInit,
  },
  {
    id: 'SOL082',
    name: 'Token Account Ownership',
    severity: 'critical',
    run: checkTokenOwnership,
  },
  {
    id: 'SOL083',
    name: 'PDA Signer Seeds Mismatch',
    severity: 'critical',
    run: checkPdaSignerSeeds,
  },
  {
    id: 'SOL084',
    name: 'Account Constraints Order',
    severity: 'medium',
    run: checkConstraintOrder,
  },
  {
    id: 'SOL085',
    name: 'CPI Return Data Security',
    severity: 'high',
    run: checkCpiReturnData,
  },
  {
    id: 'SOL086',
    name: 'Account Lifetime Management',
    severity: 'medium',
    run: checkAccountLifetime,
  },
  {
    id: 'SOL087',
    name: 'Arithmetic Precision Issues',
    severity: 'high',
    run: checkArithmeticPrecision,
  },
  {
    id: 'SOL088',
    name: 'Event Ordering and Emission',
    severity: 'medium',
    run: checkEventOrdering,
  },
  {
    id: 'SOL089',
    name: 'Account Type Safety',
    severity: 'high',
    run: checkAccountTypeSafety,
  },
  {
    id: 'SOL090',
    name: 'Solana Syscall Security',
    severity: 'medium',
    run: checkSyscallSecurity,
  },
  {
    id: 'SOL091',
    name: 'SPL Governance Security',
    severity: 'high',
    run: checkSplGovernance,
  },
  {
    id: 'SOL092',
    name: 'Token Extensions Security',
    severity: 'high',
    run: checkTokenExtensions,
  },
  {
    id: 'SOL093',
    name: 'Address Lookup Table Security',
    severity: 'high',
    run: checkLookupTable,
  },
  {
    id: 'SOL094',
    name: 'Priority Fee Handling',
    severity: 'medium',
    run: checkPriorityFee,
  },
  {
    id: 'SOL095',
    name: 'Slot Number Manipulation',
    severity: 'high',
    run: checkSlotManipulation,
  },
  {
    id: 'SOL096',
    name: 'Cross-Chain Bridge Security',
    severity: 'critical',
    run: checkCrossChain,
  },
  {
    id: 'SOL097',
    name: 'Multisig Security',
    severity: 'critical',
    run: checkMultisig,
  },
  {
    id: 'SOL098',
    name: 'Account Versioning',
    severity: 'medium',
    run: checkVersioning,
  },
  {
    id: 'SOL099',
    name: 'Atomic Operations',
    severity: 'high',
    run: checkAtomicOperations,
  },
  {
    id: 'SOL100',
    name: 'Initialization Order Dependencies',
    severity: 'high',
    run: checkInitializationOrder,
  },
  {
    id: 'SOL101',
    name: 'Program Cache Considerations',
    severity: 'low',
    run: checkProgramCache,
  },
  {
    id: 'SOL102',
    name: 'Instruction Data Handling',
    severity: 'high',
    run: checkInstructionData,
  },
  {
    id: 'SOL103',
    name: 'Anchor CPI Safety',
    severity: 'high',
    run: checkAnchorCpiSafety,
  },
  {
    id: 'SOL104',
    name: 'Authority Scope',
    severity: 'medium',
    run: checkAuthorityScope,
  },
  {
    id: 'SOL105',
    name: 'Error Propagation',
    severity: 'medium',
    run: checkErrorPropagation,
  },
  {
    id: 'SOL106',
    name: 'Account Key Derivation',
    severity: 'high',
    run: checkAccountKeyDerivation,
  },
  {
    id: 'SOL107',
    name: 'Token Burn Safety',
    severity: 'critical',
    run: checkTokenBurnSafety,
  },
  {
    id: 'SOL108',
    name: 'Associated Program Security',
    severity: 'high',
    run: checkAssociatedProgram,
  },
  {
    id: 'SOL109',
    name: 'Signer Seeds Validation',
    severity: 'high',
    run: checkSignerSeedsValidation,
  },
  {
    id: 'SOL110',
    name: 'Account Reallocation',
    severity: 'high',
    run: checkAccountReallocation,
  },
  {
    id: 'SOL111',
    name: 'Account Discriminator Validation',
    severity: 'critical',
    run: checkAccountDiscriminatorCheck,
  },
  {
    id: 'SOL112',
    name: 'Token Approval/Delegation',
    severity: 'high',
    run: checkTokenApproval,
  },
  {
    id: 'SOL113',
    name: 'Rent Collection Security',
    severity: 'high',
    run: checkRentCollection,
  },
  {
    id: 'SOL114',
    name: 'Instruction Sysvar Usage',
    severity: 'medium',
    run: checkInstructionSysvar,
  },
  {
    id: 'SOL115',
    name: 'State Transition Validation',
    severity: 'high',
    run: checkStateTransition,
  },
  {
    id: 'SOL116',
    name: 'Account Data Matching',
    severity: 'high',
    run: checkAccountDataMatch,
  },
  {
    id: 'SOL117',
    name: 'Token Freeze Operations',
    severity: 'critical',
    run: checkTokenFreeze,
  },
  {
    id: 'SOL118',
    name: 'Zero-Copy Account Handling',
    severity: 'high',
    run: checkZeroCopyAccount,
  },
  {
    id: 'SOL119',
    name: 'Program Upgrade Security',
    severity: 'critical',
    run: checkProgramUpgrade,
  },
  {
    id: 'SOL120',
    name: 'Account Constraint Combinations',
    severity: 'high',
    run: checkAccountConstraintCombo,
  },
  {
    id: 'SOL121',
    name: 'CPI Depth Management',
    severity: 'medium',
    run: checkCpiDepth,
  },
  {
    id: 'SOL122',
    name: 'Account Close Destination',
    severity: 'high',
    run: checkAccountCloseDestination,
  },
  {
    id: 'SOL123',
    name: 'Token Account Closure',
    severity: 'high',
    run: checkTokenAccountClosure,
  },
  {
    id: 'SOL124',
    name: 'Account Data Initialization',
    severity: 'high',
    run: checkAccountDataInit,
  },
  {
    id: 'SOL125',
    name: 'Program as Signer',
    severity: 'medium',
    run: checkProgramSigner,
  },
  {
    id: 'SOL126',
    name: 'Account Lamport Checks',
    severity: 'high',
    run: checkAccountLamportCheck,
  },
  {
    id: 'SOL127',
    name: 'Instruction Size Limits',
    severity: 'medium',
    run: checkInstructionSize,
  },
  {
    id: 'SOL128',
    name: 'Account Seed Length',
    severity: 'medium',
    run: checkAccountSeedLength,
  },
  {
    id: 'SOL129',
    name: 'Token Decimal Handling',
    severity: 'medium',
    run: checkTokenDecimalHandling,
  },
  {
    id: 'SOL130',
    name: 'PDA Bump Storage',
    severity: 'low',
    run: checkAccountPdaBumpStorage,
  },
  // New patterns based on real-world exploits (2022-2025)
  {
    id: 'SOL131',
    name: 'Tick Account Spoofing (Crema)',
    severity: 'critical',
    run: checkTickAccountSpoofing,
  },
  {
    id: 'SOL132',
    name: 'Governance Proposal Injection (Audius)',
    severity: 'critical',
    run: checkGovernanceInjection,
  },
  {
    id: 'SOL133',
    name: 'Bonding Curve Manipulation (Nirvana)',
    severity: 'critical',
    run: checkBondingCurveManipulation,
  },
  {
    id: 'SOL134',
    name: 'Infinite Mint Vulnerability (Cashio)',
    severity: 'critical',
    run: checkInfiniteMint,
  },
  {
    id: 'SOL135',
    name: 'Liquidation Threshold Manipulation (Solend)',
    severity: 'critical',
    run: checkLiquidationManipulation,
  },
  {
    id: 'SOL136',
    name: 'Supply Chain Attack Vector (Web3.js)',
    severity: 'critical',
    run: checkSupplyChainAttack,
  },
  {
    id: 'SOL137',
    name: 'Private Key Exposure (Slope/DEXX)',
    severity: 'critical',
    run: checkPrivateKeyExposure,
  },
  {
    id: 'SOL138',
    name: 'Insider Threat Vector (Pump.fun)',
    severity: 'high',
    run: checkInsiderThreat,
  },
  {
    id: 'SOL139',
    name: 'Treasury Drain Attack',
    severity: 'critical',
    run: checkTreasuryDrain,
  },
  {
    id: 'SOL140',
    name: 'CLMM/AMM Exploit (Crema/Raydium)',
    severity: 'critical',
    run: checkClmmExploit,
  },
  {
    id: 'SOL141',
    name: 'Bot/Automation Compromise (Banana Gun)',
    severity: 'high',
    run: checkBotCompromise,
  },
  {
    id: 'SOL142',
    name: 'Signature Verification Bypass (Wormhole)',
    severity: 'critical',
    run: checkSignatureBypass,
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
