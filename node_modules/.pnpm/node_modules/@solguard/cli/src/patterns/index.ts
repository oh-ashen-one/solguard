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
import { checkDeprecatedFunction } from './deprecated-function.js';
import { checkStaleData } from './stale-data.js';
import { checkFrontRunning } from './front-running.js';
import { checkMissingConstraint } from './missing-constraint.js';
import { checkUnsafeDeserialization } from './unsafe-deserialization.js';
import { checkRewardDistribution } from './reward-distribution.js';
import { checkCollateralValidation } from './collateral-validation.js';
import { checkFeeExtraction } from './fee-extraction.js';
import { checkNftRoyalty } from './nft-royalty.js';
import { checkLiquidityPool } from './liquidity-pool.js';
import { checkAccountOwnership } from './account-ownership.js';
import { checkInstructionGuard } from './instruction-guard.js';
import { checkDelegationAttack } from './delegation-attack.js';
import { checkOracleSafety } from './oracle-safety.js';
import { checkEscrowSafety } from './escrow-safety.js';
import { checkBorrowRate } from './borrow-rate.js';
import { checkVoteManipulation } from './vote-manipulation.js';
import { checkEmergencyWithdraw } from './emergency-withdraw.js';
import { checkPermitSecurity } from './permit-security.js';
import { checkCallbackAttack } from './callback-attack.js';
import { checkPositionManagement } from './position-management.js';
import { checkTokenStandard } from './token-standard.js';
import { checkClockExploit } from './clock-exploit.js';
import { checkSeedCollision } from './seed-collision.js';
import { checkCalculationPrecision } from './calculation-precision.js';
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
import { checkTickAccountSpoofing } from './tick-account-spoofing.js';
import { checkGovernanceProposalInjection } from './governance-proposal-injection.js';
import { checkBondingCurveManipulation } from './bonding-curve-manipulation.js';
import { checkInfiniteMint } from './infinite-mint.js';
import { checkLiquidationManipulation } from './liquidation-manipulation.js';
import { checkSupplyChainAttack } from './supply-chain-attack.js';
import { checkPrivateKeyExposure } from './private-key-exposure.js';
import { checkInsiderThreat } from './insider-threat.js';
import { checkTreasuryDrain } from './treasury-drain.js';
import { checkClmmExploit } from './clmm-exploit.js';
import { checkBotCompromise } from './bot-compromise.js';
import { checkSignatureVerificationBypass } from './signature-verification-bypass.js';
import { checkLpTokenOracle } from './lp-token-oracle.js';
import { checkUncheckedAccountCpi } from './unchecked-account-cpi.js';
import { checkBreakLogicBug } from './break-logic-bug.js';
import { checkSimulationDetection } from './simulation-detection.js';
import { checkRootOfTrust } from './root-of-trust.js';
import { checkSplLendingRounding } from './spl-lending-rounding.js';
import { checkAnchorUncheckedAccount } from './anchor-unchecked-account.js';
import { checkCrossProgamInvocationSafety } from './cross-program-invocation-check.js';

// New patterns SOL176-SOL300 (Real-world exploits and advanced checks)
import { checkMongodbInjection } from './mongodb-injection.js';
import { checkSessionTokenSecurity } from './session-token-security.js';
import { checkBondingCurveExploit } from './bonding-curve-exploit.js';
import { checkAdminAuthenticationBypass } from './admin-authentication-bypass.js';
import { checkFlashLoanAttack } from './flash-loan-attack.js';
import { checkGuardianValidation } from './guardian-validation.js';
import { checkWalletKeyExposure } from './wallet-key-exposure.js';
import { checkLiquidationThreshold } from './liquidation-threshold.js';
import { checkFakeCollateralMint } from './fake-collateral-mint.js';
import { checkEmployeeInsiderAttack } from './employee-insider-attack.js';
import { checkDaoProposalAttack } from './dao-proposal-attack.js';
import { checkPriceOracleTwap } from './price-oracle-twap.js';
import { checkTickAccountValidation } from './tick-account-validation.js';
import { checkNftMintingDos } from './nft-minting-dos.js';
import { checkDependencyHijacking } from './dependency-hijacking.js';
import { checkFrontendPhishing } from './frontend-phishing.js';
import { checkDdosProtection } from './ddos-protection.js';
import { checkJitCacheBug } from './jit-cache-bug.js';
import { checkDurableNonceSafety } from './durable-nonce-safety.js';
import { checkDuplicateBlockCheck } from './duplicate-block-check.js';
import { checkTurbinePropagation } from './turbine-propagation.js';
import { checkElfAlignment } from './elf-alignment.js';
import { checkTradingBotSecurity } from './trading-bot-security.js';
import { checkDexxExploit } from './dexx-exploit.js';
import { checkNoonesExploit } from './noones-exploit.js';
import { checkLoopscaleExploit } from './loopscale-exploit.js';
import { checkSolareumExploit } from './solareum-exploit.js';
import { checkOptifiLockup } from './optifi-lockup.js';
import { checkTulipExploit } from './tulip-exploit.js';
import { checkUxdExploit } from './uxd-exploit.js';
import { checkIoNetExploit } from './io-net-exploit.js';
import { checkAuroryExploit } from './aurory-exploit.js';
import { checkSvtTokenExploit } from './svt-token-exploit.js';
import { checkSagaDaoExploit } from './saga-dao-exploit.js';
import { checkThunderTerminal } from './thunder-terminal.js';
import { checkRaydiumExploit } from './raydium-exploit.js';
import { checkSolendV2Exploit } from './solend-v2-exploit.js';
import { checkCypherV2Exploit } from './cypher-v2-exploit.js';
import { checkSeedInjection } from './seed-injection.js';
import { checkAccountDusting } from './account-dusting.js';
import { checkPhantomDos } from './phantom-dos.js';
import { checkGrapeProtocol } from './grape-protocol.js';
import { checkIntegerTruncation } from './integer-truncation.js';
import { checkDivisionBeforeMultiplication } from './division-before-multiplication.js';
import { checkAccountDiscriminatorLength } from './account-discriminator-length.js';
import { checkMissingReturn } from './missing-return.js';
import { checkUnsafeUnwrap } from './unsafe-unwrap.js';
import { checkUnsafeExpect } from './unsafe-expect.js';
import { checkUncheckedReturn } from './unchecked-return.js';
import { checkUninitializedMemory } from './uninitialized-memory.js';
import { checkUnsafeSlice, checkHardcodedAddress, checkExcessiveAccounts, checkDeprecatedInstruction, checkMissingClose, checkDecimalMismatch, checkMissingSysvarClock, checkUnboundedString, checkVecNoCapacity, checkMissingRentCheck } from './solana-batched-patterns.js';
import { checkFloatingPoint, checkModuloBias, checkWeakRandomness, checkMagicNumber, checkUncheckedArrayIndex, checkEmptyErrorMessage, checkDeadCode, checkInfiniteLoopRisk, checkUnboundedRecursion, checkUncheckedArithmetic } from './solana-batched-patterns-2.js';
import { checkMissingBumpValidation, checkExcessiveGas, checkCloneInsteadCopy, checkMissingAuthorityRotation, checkUnprotectedInitialize, checkMissingProgramIdCheck, checkUnvalidatedAccountData, checkTimestampDrift, checkMissingInstructionSysvar, checkExcessiveNesting } from './solana-batched-patterns-3.js';
import { checkUnvalidatedTokenMint, checkMissingDelegateCheck, checkStaleAccountReference, checkMissingCloseAuthority, checkUnguardedStateTransition, checkMissingEventEmission, checkHardcodedFee, checkMissingSlippage, checkUnvalidatedPriceFeed, checkMissingPriceStaleness } from './solana-batched-patterns-4.js';
import { checkMissingBalanceCheck, checkUnsafeTokenBurn, checkMissingAnchorError, checkMissingAccessList, checkUncappedSupply, checkMissingPause, checkMissingUpgradeGuard, checkMissingReentrancyGuard, checkMissingDecimalNormalization, checkExposedInternalFunction } from './solana-batched-patterns-5.js';
import { checkUnsafeSignerSeeds, checkMissingValidationCombo, checkUnsafeLamportMath, checkMissingKeyDerivationSalt, checkImplicitTrust, checkMissingInstructionDataValidation, checkMissingAccountLengthCheck, checkUnsafeCastingFromBytes, checkMissingCpiProgramCheck, checkMissingWritableCheck } from './solana-batched-patterns-6.js';
import { checkTokenAccountState, checkMissingAssociatedTokenCheck, checkMissingMetadataValidation, checkMissingEditionCheck, checkMissingMasterEdition, checkMissingTokenRecord, checkUnsafeCompression, checkMissingCreatorVerification, checkMissingRoyaltyCheck, checkUnsafeCollectionUpdate, checkMissingDelegateAuthority, checkMissingLockCheck, checkMissingUseAuthority, checkExcessiveAccountRent, checkMissingReallocCheck } from './solana-batched-patterns-7.js';

// New patterns SOL233-SOL250 (Feb 2026 - Real-world exploits from research)
import { checkWeb3jsSupplyChain } from './web3js-supply-chain.js';
import { checkJitoDdos } from './jito-ddos.js';
import { checkParclFrontend } from './parcl-frontend.js';
import { checkMangoOracleExploit } from './mango-oracle-exploit.js';
import { checkSlopeWalletLeak } from './slope-wallet-leak.js';
import { checkPumpFunExploit } from './pump-fun-exploit.js';
import { checkWormholeGuardian } from './wormhole-guardian.js';
import { checkBananaGunExploit } from './banana-gun-exploit.js';
import { checkNirvanaBondingCurve } from './nirvana-bonding-curve.js';
import { checkAudiusGovernance } from './audius-governance.js';
import { checkTokenRevokeSafety } from './token-revoke-safety.js';
import { checkSynthetifyDao } from './synthetify-dao.js';

// New patterns SOL249-SOL300 (Feb 4 2026 - Build session patterns)
import { checkProgramCloseSafety } from './program-close-safety.js';
import { checkReserveConfigBypass } from './reserve-config-bypass.js';
import { checkCollateralMintValidation } from './collateral-mint-validation.js';
import { checkKeyLoggingExposure } from './key-logging-exposure.js';
import { checkGovernanceProposalTiming } from './governance-proposal-timing.js';
import { checkThirdPartyIntegrationSecurity } from './third-party-integration-security.js';
import { checkGamingNftExploits } from './gaming-nft-exploits.js';
import { checkValidatorStakingSecurity } from './validator-staking-security.js';
import { checkMevProtection } from './mev-protection.js';
import { checkRugPullDetection } from './rug-pull-detection.js';
import { checkAdvancedDefiPatterns } from './advanced-defi-patterns.js';
import { checkAccountValidationComprehensive } from './account-validation-comprehensive.js';

// New patterns SOL261-SOL275 (Feb 4 2026 - Evening build session batch 8)
import { checkPrivateKeyLogging, checkCentralizedLogging, checkTwapOracleManipulation, checkLeveragedPositionManipulation, checkFlashLoanOracleAttack, checkBondingCurveFlashLoan, checkGovernanceTimelockBypass, checkThirdPartyPoolDependency, checkNoSqlInjection, checkSessionTokenSecurity, checkInsiderAccessControl, checkGuardianValidationComprehensive, checkTradingBotSecurity, checkPrivateKeyManagement, checkNpmDependencyHijacking } from './solana-batched-patterns-8.js';

// New patterns SOL276-SOL290 (Feb 4 2026 - Evening build session batch 9)
import { checkOwnershipPhishing, checkProgramAccountConfusion, checkAmmPoolDrainExploit, checkInsiderExploitVectors, checkReserveConfigManipulation, checkRugPullVectors, checkDistributedNetworkExploit, checkGamingExploitVectors, checkCertiKAlertPatterns, checkHiddenMintingPatterns, checkDaoGovernanceAttack, checkP2pPlatformExploit, checkLoopscaleExploitPattern, checkNftMintingDosPattern, checkWalletDdosPattern } from './solana-batched-patterns-9.js';

// New patterns SOL291-SOL310 (Feb 4 2026 - Evening build session batch 10)
import { checkJitCacheVulnerability, checkDurableNonceMisuse, checkDuplicateBlockPattern, checkTurbinePropagation as checkTurbinePropagationV2, checkElfAlignment as checkElfAlignmentV2, checkCheckedMathEnforcement, checkSeedPredictability, checkCpiReturnInjection, checkAccountLifetime as checkAccountLifetimeV2, checkAnchorConstraintOrdering, checkMissingRentCheck as checkMissingRentCheckV2, checkSystemProgramInvocation, checkTokenProgramVersion, checkLookupTablePoisoning, checkComputeExhaustion, checkPriorityFeeManipulation, checkVersionedTransactionHandling, checkSignerSeedValidationComplete, checkAccountLamportDrain, checkInstructionSysvarSpoofing } from './solana-batched-patterns-10.js';

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
  {
    id: 'SOL131',
    name: 'Tick Account Spoofing',
    severity: 'critical',
    run: checkTickAccountSpoofing,
  },
  {
    id: 'SOL132',
    name: 'Governance Proposal Injection',
    severity: 'critical',
    run: checkGovernanceProposalInjection,
  },
  {
    id: 'SOL133',
    name: 'Bonding Curve Manipulation',
    severity: 'critical',
    run: checkBondingCurveManipulation,
  },
  {
    id: 'SOL134',
    name: 'Infinite Mint Vulnerability',
    severity: 'critical',
    run: checkInfiniteMint,
  },
  {
    id: 'SOL135',
    name: 'Liquidation Threshold Manipulation',
    severity: 'critical',
    run: checkLiquidationManipulation,
  },
  {
    id: 'SOL136',
    name: 'Supply Chain Attack Vector',
    severity: 'high',
    run: checkSupplyChainAttack,
  },
  {
    id: 'SOL137',
    name: 'Private Key Exposure',
    severity: 'critical',
    run: checkPrivateKeyExposure,
  },
  {
    id: 'SOL138',
    name: 'Insider Threat Vector',
    severity: 'critical',
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
    name: 'CLMM/AMM Exploit',
    severity: 'critical',
    run: checkClmmExploit,
  },
  {
    id: 'SOL141',
    name: 'Bot/Automation Compromise',
    severity: 'high',
    run: checkBotCompromise,
  },
  {
    id: 'SOL142',
    name: 'Signature Verification Bypass',
    severity: 'critical',
    run: checkSignatureVerificationBypass,
  },
  {
    id: 'SOL143',
    name: 'LP Token Oracle Manipulation',
    severity: 'critical',
    run: checkLpTokenOracle,
  },
  {
    id: 'SOL144',
    name: 'Unchecked Account in CPI',
    severity: 'critical',
    run: checkUncheckedAccountCpi,
  },
  {
    id: 'SOL145',
    name: 'Break Statement Logic Bug',
    severity: 'medium',
    run: checkBreakLogicBug,
  },
  {
    id: 'SOL146',
    name: 'Transaction Simulation Detection',
    severity: 'critical',
    run: checkSimulationDetection,
  },
  {
    id: 'SOL147',
    name: 'Root of Trust Establishment',
    severity: 'critical',
    run: checkRootOfTrust,
  },
  {
    id: 'SOL148',
    name: 'SPL Lending Rounding',
    severity: 'critical',
    run: checkSplLendingRounding,
  },
  {
    id: 'SOL149',
    name: 'Anchor Unchecked Account',
    severity: 'critical',
    run: checkAnchorUncheckedAccount,
  },
  {
    id: 'SOL150',
    name: 'Cross-Program Invocation Safety',
    severity: 'high',
    run: checkCrossProgamInvocationSafety,
  },
  {
    id: 'SOL151',
    name: 'Deprecated Function Usage',
    severity: 'critical',
    run: checkDeprecatedFunction,
  },
  {
    id: 'SOL152',
    name: 'Stale Data Vulnerability',
    severity: 'critical',
    run: checkStaleData,
  },
  {
    id: 'SOL153',
    name: 'Front-Running Attack Vector',
    severity: 'critical',
    run: checkFrontRunning,
  },
  {
    id: 'SOL154',
    name: 'Missing Anchor Constraints',
    severity: 'high',
    run: checkMissingConstraint,
  },
  {
    id: 'SOL155',
    name: 'Unsafe Deserialization',
    severity: 'critical',
    run: checkUnsafeDeserialization,
  },
  {
    id: 'SOL156',
    name: 'Reward Distribution Vulnerability',
    severity: 'high',
    run: checkRewardDistribution,
  },
  {
    id: 'SOL157',
    name: 'Collateral Validation Bypass',
    severity: 'critical',
    run: checkCollateralValidation,
  },
  {
    id: 'SOL158',
    name: 'Fee Extraction Attack',
    severity: 'high',
    run: checkFeeExtraction,
  },
  {
    id: 'SOL159',
    name: 'NFT Royalty Bypass',
    severity: 'high',
    run: checkNftRoyalty,
  },
  {
    id: 'SOL160',
    name: 'Liquidity Pool Manipulation',
    severity: 'critical',
    run: checkLiquidityPool,
  },
  {
    id: 'SOL161',
    name: 'Account Ownership Validation',
    severity: 'critical',
    run: checkAccountOwnership,
  },
  {
    id: 'SOL162',
    name: 'Instruction Guard Protection',
    severity: 'high',
    run: checkInstructionGuard,
  },
  {
    id: 'SOL163',
    name: 'Delegation Attack Vector',
    severity: 'high',
    run: checkDelegationAttack,
  },
  {
    id: 'SOL164',
    name: 'Oracle Safety Validation',
    severity: 'critical',
    run: checkOracleSafety,
  },
  {
    id: 'SOL165',
    name: 'Escrow Safety Check',
    severity: 'critical',
    run: checkEscrowSafety,
  },
  {
    id: 'SOL166',
    name: 'Borrow Rate Manipulation',
    severity: 'high',
    run: checkBorrowRate,
  },
  {
    id: 'SOL167',
    name: 'Vote Manipulation Attack',
    severity: 'critical',
    run: checkVoteManipulation,
  },
  {
    id: 'SOL168',
    name: 'Emergency Withdraw Safety',
    severity: 'high',
    run: checkEmergencyWithdraw,
  },
  {
    id: 'SOL169',
    name: 'Permit/Signature Security',
    severity: 'critical',
    run: checkPermitSecurity,
  },
  {
    id: 'SOL170',
    name: 'Callback Attack Vector',
    severity: 'critical',
    run: checkCallbackAttack,
  },
  {
    id: 'SOL171',
    name: 'Position Management Safety',
    severity: 'high',
    run: checkPositionManagement,
  },
  {
    id: 'SOL172',
    name: 'Token Standard Compliance',
    severity: 'high',
    run: checkTokenStandard,
  },
  {
    id: 'SOL173',
    name: 'Clock/Time Exploit',
    severity: 'high',
    run: checkClockExploit,
  },
  {
    id: 'SOL174',
    name: 'PDA Seed Collision',
    severity: 'high',
    run: checkSeedCollision,
  },
  {
    id: 'SOL175',
    name: 'Calculation Precision Loss',
    severity: 'high',
    run: checkCalculationPrecision,
  },
  // NEW PATTERNS SOL233-SOL250 (Feb 2026 - Real-world exploit research)
  {
    id: 'SOL233',
    name: 'Web3.js Supply Chain Attack',
    severity: 'critical',
    run: checkWeb3jsSupplyChain,
  },
  {
    id: 'SOL236',
    name: 'Jito/MEV DDoS Protection',
    severity: 'high',
    run: checkJitoDdos,
  },
  {
    id: 'SOL238',
    name: 'Parcl Frontend Security',
    severity: 'high',
    run: checkParclFrontend,
  },
  {
    id: 'SOL239',
    name: 'Mango Oracle Exploit',
    severity: 'critical',
    run: checkMangoOracleExploit,
  },
  {
    id: 'SOL240',
    name: 'Slope Wallet Key Leakage',
    severity: 'critical',
    run: checkSlopeWalletLeak,
  },
  {
    id: 'SOL241',
    name: 'Pump.fun Employee Exploit',
    severity: 'high',
    run: checkPumpFunExploit,
  },
  {
    id: 'SOL242',
    name: 'Wormhole Guardian Bypass',
    severity: 'critical',
    run: checkWormholeGuardian,
  },
  {
    id: 'SOL243',
    name: 'Banana Gun Bot Exploit',
    severity: 'high',
    run: checkBananaGunExploit,
  },
  {
    id: 'SOL245',
    name: 'Nirvana Bonding Curve Attack',
    severity: 'critical',
    run: checkNirvanaBondingCurve,
  },
  {
    id: 'SOL246',
    name: 'Audius Governance Exploit',
    severity: 'critical',
    run: checkAudiusGovernance,
  },
  {
    id: 'SOL247',
    name: 'Token Revoke Safety',
    severity: 'high',
    run: checkTokenRevokeSafety,
  },
  {
    id: 'SOL248',
    name: 'Synthetify DAO Hidden Proposal',
    severity: 'high',
    run: checkSynthetifyDao,
  },
  // New patterns SOL249-SOL260 (Feb 4 2026 - Build session)
  {
    id: 'SOL249',
    name: 'Program Close Safety',
    severity: 'critical',
    run: checkProgramCloseSafety,
  },
  {
    id: 'SOL250',
    name: 'Reserve Config Bypass (Solend-style)',
    severity: 'critical',
    run: checkReserveConfigBypass,
  },
  {
    id: 'SOL251',
    name: 'Collateral Mint Validation (Cashio-style)',
    severity: 'critical',
    run: checkCollateralMintValidation,
  },
  {
    id: 'SOL252',
    name: 'Key Logging Exposure (Slope-style)',
    severity: 'critical',
    run: checkKeyLoggingExposure,
  },
  {
    id: 'SOL253',
    name: 'Governance Proposal Timing Attack',
    severity: 'high',
    run: checkGovernanceProposalTiming,
  },
  {
    id: 'SOL254',
    name: 'Third-Party Integration Security',
    severity: 'high',
    run: checkThirdPartyIntegrationSecurity,
  },
  {
    id: 'SOL255',
    name: 'Gaming/NFT Exploit Patterns',
    severity: 'high',
    run: checkGamingNftExploits,
  },
  {
    id: 'SOL256',
    name: 'Validator/Staking Security',
    severity: 'high',
    run: checkValidatorStakingSecurity,
  },
  {
    id: 'SOL257',
    name: 'MEV Protection Patterns',
    severity: 'high',
    run: checkMevProtection,
  },
  {
    id: 'SOL258',
    name: 'Rug Pull Detection',
    severity: 'critical',
    run: checkRugPullDetection,
  },
  {
    id: 'SOL259',
    name: 'Advanced DeFi Patterns',
    severity: 'high',
    run: checkAdvancedDefiPatterns,
  },
  {
    id: 'SOL260',
    name: 'Comprehensive Account Validation',
    severity: 'critical',
    run: checkAccountValidationComprehensive,
  },
  // NEW PATTERNS SOL261-SOL310 (Feb 4 2026 - Evening build session)
  {
    id: 'SOL261',
    name: 'Private Key Logging (Slope-style)',
    severity: 'critical',
    run: checkPrivateKeyLogging,
  },
  {
    id: 'SOL262',
    name: 'Centralized Logging Security',
    severity: 'high',
    run: checkCentralizedLogging,
  },
  {
    id: 'SOL263',
    name: 'TWAP Oracle Manipulation',
    severity: 'high',
    run: checkTwapOracleManipulation,
  },
  {
    id: 'SOL264',
    name: 'Leveraged Position Manipulation (Mango-style)',
    severity: 'critical',
    run: checkLeveragedPositionManipulation,
  },
  {
    id: 'SOL265',
    name: 'Flash Loan Oracle Attack',
    severity: 'critical',
    run: checkFlashLoanOracleAttack,
  },
  {
    id: 'SOL266',
    name: 'Bonding Curve Flash Loan (Nirvana-style)',
    severity: 'critical',
    run: checkBondingCurveFlashLoan,
  },
  {
    id: 'SOL267',
    name: 'Governance Timelock Bypass (Audius-style)',
    severity: 'critical',
    run: checkGovernanceTimelockBypass,
  },
  {
    id: 'SOL268',
    name: 'Third-Party Pool Dependency (UXD/Tulip)',
    severity: 'high',
    run: checkThirdPartyPoolDependency,
  },
  {
    id: 'SOL269',
    name: 'NoSQL Injection (Thunder-style)',
    severity: 'critical',
    run: checkNoSqlInjection,
  },
  {
    id: 'SOL270',
    name: 'Session Token Security',
    severity: 'high',
    run: checkSessionTokenSecurity,
  },
  {
    id: 'SOL271',
    name: 'Insider Access Control (Pump.fun-style)',
    severity: 'critical',
    run: checkInsiderAccessControl,
  },
  {
    id: 'SOL272',
    name: 'Guardian Validation (Wormhole-style)',
    severity: 'critical',
    run: checkGuardianValidationComprehensive,
  },
  {
    id: 'SOL273',
    name: 'Trading Bot Security (Banana Gun)',
    severity: 'critical',
    run: checkTradingBotSecurity,
  },
  {
    id: 'SOL274',
    name: 'Private Key Management (DEXX-style)',
    severity: 'critical',
    run: checkPrivateKeyManagement,
  },
  {
    id: 'SOL275',
    name: 'NPM Dependency Hijacking (Web3.js)',
    severity: 'high',
    run: checkNpmDependencyHijacking,
  },
  {
    id: 'SOL276',
    name: 'Ownership Phishing (2025 Attacks)',
    severity: 'critical',
    run: checkOwnershipPhishing,
  },
  {
    id: 'SOL277',
    name: 'Program Account Confusion',
    severity: 'high',
    run: checkProgramAccountConfusion,
  },
  {
    id: 'SOL278',
    name: 'AMM Pool Drain (Raydium-style)',
    severity: 'critical',
    run: checkAmmPoolDrainExploit,
  },
  {
    id: 'SOL279',
    name: 'Insider Exploit (Cypher-style)',
    severity: 'critical',
    run: checkInsiderExploitVectors,
  },
  {
    id: 'SOL280',
    name: 'Reserve Config Manipulation (Solend)',
    severity: 'critical',
    run: checkReserveConfigManipulation,
  },
  {
    id: 'SOL281',
    name: 'Rug Pull Detection (Solareum)',
    severity: 'high',
    run: checkRugPullVectors,
  },
  {
    id: 'SOL282',
    name: 'Distributed Network Exploit (io.net)',
    severity: 'high',
    run: checkDistributedNetworkExploit,
  },
  {
    id: 'SOL283',
    name: 'Gaming Exploit (Aurory-style)',
    severity: 'high',
    run: checkGamingExploitVectors,
  },
  {
    id: 'SOL284',
    name: 'CertiK Alert Patterns (SVT Token)',
    severity: 'high',
    run: checkCertiKAlertPatterns,
  },
  {
    id: 'SOL285',
    name: 'Hidden Minting (Synthetify-style)',
    severity: 'critical',
    run: checkHiddenMintingPatterns,
  },
  {
    id: 'SOL286',
    name: 'DAO Governance Attack (Saga)',
    severity: 'high',
    run: checkDaoGovernanceAttack,
  },
  {
    id: 'SOL287',
    name: 'P2P Platform Exploit (NoOnes)',
    severity: 'high',
    run: checkP2pPlatformExploit,
  },
  {
    id: 'SOL288',
    name: 'Flash Loan Undercollateralized (Loopscale)',
    severity: 'critical',
    run: checkLoopscaleExploitPattern,
  },
  {
    id: 'SOL289',
    name: 'NFT Minting DoS (Candy Machine)',
    severity: 'medium',
    run: checkNftMintingDosPattern,
  },
  {
    id: 'SOL290',
    name: 'Wallet DDoS (Phantom)',
    severity: 'medium',
    run: checkWalletDdosPattern,
  },
  {
    id: 'SOL291',
    name: 'JIT Cache Vulnerability (Solana 2023)',
    severity: 'info',
    run: checkJitCacheVulnerability,
  },
  {
    id: 'SOL292',
    name: 'Durable Nonce Misuse',
    severity: 'high',
    run: checkDurableNonceMisuse,
  },
  {
    id: 'SOL293',
    name: 'Duplicate Block Pattern',
    severity: 'high',
    run: checkDuplicateBlockPattern,
  },
  {
    id: 'SOL294',
    name: 'Turbine Propagation Security',
    severity: 'high',
    run: checkTurbinePropagationV2,
  },
  {
    id: 'SOL295',
    name: 'ELF Alignment Vulnerability',
    severity: 'medium',
    run: checkElfAlignmentV2,
  },
  {
    id: 'SOL296',
    name: 'Checked Math Enforcement',
    severity: 'high',
    run: checkCheckedMathEnforcement,
  },
  {
    id: 'SOL297',
    name: 'Seed Derivation Predictability',
    severity: 'high',
    run: checkSeedPredictability,
  },
  {
    id: 'SOL298',
    name: 'CPI Return Data Injection',
    severity: 'critical',
    run: checkCpiReturnInjection,
  },
  {
    id: 'SOL299',
    name: 'Account Lifetime Issues',
    severity: 'high',
    run: checkAccountLifetimeV2,
  },
  {
    id: 'SOL300',
    name: 'Anchor Constraint Ordering',
    severity: 'medium',
    run: checkAnchorConstraintOrdering,
  },
  {
    id: 'SOL301',
    name: 'Missing Rent Check V2',
    severity: 'medium',
    run: checkMissingRentCheckV2,
  },
  {
    id: 'SOL302',
    name: 'System Program Invocation',
    severity: 'high',
    run: checkSystemProgramInvocation,
  },
  {
    id: 'SOL303',
    name: 'Token Program Version Mismatch',
    severity: 'high',
    run: checkTokenProgramVersion,
  },
  {
    id: 'SOL304',
    name: 'Lookup Table Poisoning',
    severity: 'high',
    run: checkLookupTablePoisoning,
  },
  {
    id: 'SOL305',
    name: 'Compute Unit Exhaustion',
    severity: 'high',
    run: checkComputeExhaustion,
  },
  {
    id: 'SOL306',
    name: 'Priority Fee Manipulation',
    severity: 'medium',
    run: checkPriorityFeeManipulation,
  },
  {
    id: 'SOL307',
    name: 'Versioned Transaction Handling',
    severity: 'low',
    run: checkVersionedTransactionHandling,
  },
  {
    id: 'SOL308',
    name: 'Signer Seed Validation Complete',
    severity: 'high',
    run: checkSignerSeedValidationComplete,
  },
  {
    id: 'SOL309',
    name: 'Account Lamport Drain',
    severity: 'high',
    run: checkAccountLamportDrain,
  },
  {
    id: 'SOL310',
    name: 'Instruction Sysvar Spoofing',
    severity: 'critical',
    run: checkInstructionSysvarSpoofing,
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
