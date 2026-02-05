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

// New patterns SOL311-SOL330 (Feb 4 2026 - Night build session batch 11)
import { checkPortMaxWithdrawBug, checkJetGovernanceVuln, checkSemanticInconsistency, checkTokenApproveRevocation, checkLpTokenFairPricing, checkSignatureSetFabrication, checkCandyMachineZeroAccount, checkRevertExploit, checkSimulationDetectionBypass, checkAuthorityDelegationChain, checkQuarryRewardDistribution, checkStableSwapInvariant, checkMarinadeStakePoolSecurity, checkWhirlpoolTickArraySecurity, checkPythOracleIntegration, checkDriftOracleGuardrails, checkSolidoLiquidStaking, checkSquadsMultisigReplay, checkStreamflowVestingSecurity, checkPhoenixOrderBookSecurity } from './solana-batched-patterns-11.js';

// New patterns SOL331-SOL350 (Feb 4 2026 - Night build session batch 12)
import { checkHedgeProtocolStability, checkMeanFinanceDCA, checkHubbleLendingIsolation, checkInvariantCLMM, checkLarixLiquidation, checkLightProtocolZK, checkFranciumLeverageVault, checkFriktionOptionsVault, checkGenopetsStakingDuration, checkGooseFXSwapInvariant, checkCropperAMMSecurity, checkParrotCollateralTypes, checkAldrinOrderMatching, checkAudiusStorageSlot, checkSwimCrossChainMessage, checkSynthetifySyntheticMinting, checkUXDRedeemablePeg, checkWormholeVAAParsing, checkDebridgeMessageVerification, checkCashmereMultisigThreshold } from './solana-batched-patterns-12.js';

// New patterns SOL351-SOL370 (Feb 4 2026 - Night build session batch 13)
import { checkAnchorInitIfNeeded, checkAccountCloseLamportDust, checkPdaSeedCollision, checkBorshDeserializationDoS, checkInvokeSignedSeedsMismatch, checkTokenAuthorityConfusion, checkWritableNotMutable, checkAccountCreationRentExemption, checkRecursiveCpiDepth, checkClockSysvarReliability, checkProgramLogSizeLimit, checkHeapMemoryExhaustion, checkAccountDataSizeChange, checkCpiAccountOrdering, checkProgramIdHardcoding, checkSysvarDeprecation, checkTokenAmountTruncation, checkNativeSolWrappedConfusion, checkToken2022TransferHook, checkMetadataUriValidation } from './solana-batched-patterns-13.js';

// New patterns SOL371-SOL395 (Feb 5 2026 - Night build session batch 14 - Advanced Protocol Patterns)
import { checkAldrinOrderBook, checkCrossChainReplay, checkOptionsVaultEpoch, checkLeverageVaultControls, checkSyntheticDebtTracking, checkZkProofVerification, checkCdpStability, checkDcaSecurity, checkLendingPoolIsolation, checkClmmFeeGrowth, checkLiquidationIncentive, checkNftStakingDuration, checkAmmInvariant, checkVestingContractSecurity, checkOrderBookDepth, checkPerpFundingRate, checkMultiCollateralRisk, checkStorageSlotAuth, checkVaaGuardianQuorum, checkDoubleClaimPrevention, checkMultisigThresholdBounds, checkStakePoolMechanics, checkTickArrayBoundary, checkPythConfidenceInterval, checkOracleGuardrails } from './solana-batched-patterns-14.js';

// New patterns SOL396-SOL500 (Feb 5 2026 - 500 patterns milestone)
import { checkBlinkActions } from './blink-actions.js';
import { checkToken2022Advanced } from './token-2022-advanced.js';
import { checkDexAggregator } from './dex-aggregator.js';
import { checkNftLending } from './nft-lending.js';
import { checkPerpetualDex } from './perpetual-dex.js';
import { checkCrossMargin } from './cross-margin.js';
import { checkPredictionMarket } from './prediction-market.js';
import { checkSocialFi } from './social-fi.js';
import { checkDaoTreasury } from './dao-treasury.js';
import { checkRestaking } from './restaking.js';
import { checkRealWorldAssets } from './real-world-assets.js';

// New patterns SOL501-SOL560 (Feb 5 2026 - Hackathon push to 500+)
import { checkPrivilegedKeyManagement, checkSinglePointAuthority, checkKeyRotationMechanism, checkInsecureUpgradeAuthority, checkHotWalletConcentration, checkMissingEmergencyPause, checkInsufficientEventLogging, checkSocialEngineeringAttackSurface, checkPhishingVulnerableApproval, checkDomainSpoofingVulnerability, checkMissingRateLimiting, checkUnprotectedConfigUpdate, checkImproperAccessControlHierarchy, checkUnverifiedExternalCallResult, checkMissingWithdrawalDelay, checkInsecureRandomNumberGeneration, checkCrossProgramStateInconsistency, checkUnprotectedInitialization, checkMissingSanityChecks, checkTimestampDependencyWithoutBounds } from './solana-batched-patterns-15.js';

import { checkFlashLoanReentrancy, checkPriceFeedStaleness, checkInsufficientLiquidityCheck, checkUnboundedLoopCriticalPath, checkMissingSlippageProtection, checkSandwichAttackVuln, checkImproperDecimalHandling, checkVaultShareManipulation, checkInterestRateManipulation, checkLiquidationThresholdBypass, checkRewardCalculationRounding, checkGovernanceQuorumManipulation, checkNftMetadataManipulation, checkRoyaltyBypassPattern, checkUnstakingCooldownBypass, checkFeeManipulationAttack, checkImproperTokenTransferValidation, checkMerkleProofManipulation, checkCrossMarginCollateralRisk, checkFundingRateManipulation } from './solana-batched-patterns-16.js';

import { checkUnprotectedAdminFunctions, checkMissingInputLengthValidation, checkAccountDataSizeMismatch, checkDeprecatedSolanaApiUsage, checkMissingProgramDeploymentCheck, checkUnsafeTypeCasting, checkMissingAccountOwnershipValidation, checkImproperBumpSeedValidation, checkInsufficientEntropyInSeeds, checkMissingCloseAccountCleanup, checkComputeBudgetExhaustion, checkUnsafeArithmeticTokenCalc, checkMissingAccountDiscriminator, checkImproperErrorHandlingCpi, checkReentrancyThroughCallback, checkMissingRentExemptionCheck, checkUnsafeDeserializationPattern, checkMissingTokenAccountFreezeCheck, checkImproperAuthorityDelegation, checkMissingStateMachineValidation } from './solana-batched-patterns-17.js';

// New patterns SOL301-SOL315 (Feb 5 2026 - Real-world exploit research session)
import { checkCandyMachineExploit } from './candy-machine-exploit.js';
import { checkMaliciousLendingMarket } from './malicious-lending-market.js';
import { checkTokenApprovalDrain } from './token-approval-drain.js';
import { checkSemanticInconsistency as checkSemanticInconsistencyV2 } from './semantic-inconsistency.js';
import { checkLpFairPricing } from './lp-fair-pricing.js';
import { checkRevertExploit as checkRevertExploitV2 } from './revert-exploit.js';
import { checkCheckedMathValidation } from './checked-math-validation.js';
import { checkCrossChainDelegation } from './cross-chain-delegation.js';
import { checkIncineratorAttack } from './incinerator-attack.js';
import { checkExploitChaining } from './exploit-chaining.js';
import { checkStakePoolSecurity } from './stake-pool-security.js';
import { checkProgramUpgradeSecurity } from './program-upgrade-security.js';
import { checkSimulationBypass } from './simulation-bypass.js';
import { checkOracleTwapManipulation } from './oracle-twap-manipulation.js';
import { checkNpmSupplyChain } from './npm-supply-chain.js';

// NEW PATTERNS SOL576-SOL600 (Feb 5 2026 2AM - Real-world exploit research patterns)
import { checkRevertingTransactionExploit } from './reverting-transaction-exploit.js';
import { checkTokenApprovalExploitation } from './token-approval-exploitation.js';
import { checkLpTokenFairPricing } from './lp-token-fair-pricing.js';
import { checkSignatureSetSpoofing } from './signature-set-spoofing.js';
import { checkRootOfTrustChain } from './root-of-trust-chain.js';
import { checkIncineratorNftAttack } from './incinerator-nft-attack.js';
import { checkCandyMachineSecurity } from './candy-machine-security.js';
import { checkCheckedMathRequired } from './checked-math-required.js';
import { checkJetBreakBug } from './jet-break-bug.js';
import { checkRoundingDirectionAttack } from './rounding-direction-attack.js';
import { checkSolendReserveBypass } from './solend-reserve-bypass.js';
import { checkKudelskiOwnershipCheck } from './kudelski-ownership-check.js';
import { checkSec3AuditPatterns } from './sec3-audit-patterns.js';
import { checkDriftOracleGuardrails } from './drift-oracle-guardrails.js';
import { checkMangoMarketsPatterns } from './mango-markets-patterns.js';
import { checkZellicAnchorPatterns } from './zellic-anchor-patterns.js';
import { checkOttersecAuditPatterns } from './ottersec-audit-patterns.js';

// New patterns SOL593-SOL612 (Feb 5 2026 2:30AM - Business Logic Patterns from Sec3 Report)
import { checkIncorrectStateMachine, checkMissingInvariantChecks, checkUnrestrictedParameterUpdate, checkIncorrectAccounting, checkMissingSettlementValidation, checkInconsistentFeeCalculation, checkMissingCooldownPeriod, checkIncorrectShareCalculation, checkMissingEpochBoundary, checkIncorrectOrderMatching, checkMissingPositionLimits, checkIncorrectLiquidationPriority, checkMissingPartialFillHandling, checkIncorrectUtilizationRate, checkMissingDustThreshold, checkIncorrectRebaseHandling, checkMissingCrossCollateralValidation, checkIncorrectInterestAccrual, checkMissingReserveFactor, checkIncorrectSlashingCondition } from './solana-batched-patterns-18.js';

// New patterns SOL613-SOL632 (Feb 5 2026 2:30AM - Access Control & Input Validation from Sec3 Report)
import { checkMissingRBAC, checkHardcodedAuthorityAddress, checkMissingMultisigRequirement, checkUnrestrictedDelegateAuthority, checkMissingAuthoritySeparation, checkInsufficientInputLengthValidation, checkMissingNumericBounds, checkUnvalidatedStringInput, checkMissingZeroAddressCheck, checkInsufficientArrayIndexValidation, checkMissingTimestampFutureValidation, checkUnvalidatedPercentageInput, checkMissingPubkeyValidation, checkTimelockBypassParameter, checkMissingReentrancyGuardStateChange, checkInsufficientMerkleProofValidation, checkMissingEnumExhaustiveness, checkMissingProgramIdValidationCpi, checkMissingAuthorityExpiry, checkUnsafeTypeConversion } from './solana-batched-patterns-19.js';

// New patterns SOL633-SOL652 (Feb 5 2026 2:30AM - Data Integrity & DoS from Sec3 Report)
import { checkUncheckedDivisionRemainder, checkMissingDataVersionCheck, checkInconsistentSerialization, checkMissingChecksumValidation, checkRaceConditionParallelUpdates, checkMissingAtomicUpdate, checkIncorrectBitManipulation, checkMissingDataMigration, checkComputeUnitExhaustion, checkAccountCreationDos, checkLogSpamAttack, checkMemoryAllocationDos, checkStackOverflowRecursion, checkBlockingOperationCriticalPath, checkQueueGriefingAttack, checkOracleLivenessDependency, checkInsufficientGasReserve, checkSignatureVerificationDos, checkIntegerUnderflowUnsigned, checkHashCollisionRisk } from './solana-batched-patterns-20.js';

// NEW PATTERNS SOL653-SOL656 (Feb 5 2026 3AM - Recent 2025 Exploits)
import { checkStepFinanceExploit } from './step-finance-exploit.js';
import { checkPhishingAccountTransfer } from './phishing-account-transfer.js';
import { checkLoopscaleAdminExploit } from './loopscale-admin-exploit.js';
import { checkNpmSupplyChain2025 } from './npm-supply-chain-2025.js';

// NEW PATTERNS SOL657-SOL676 (Feb 5 2026 3:30AM - Latest 2025 Exploits from Helius Research)
import { checkNoOnesPlatformExploit, checkDexxHotWalletExposure, checkBananaGunBotVulnerability, checkPumpFunInsiderThreat, checkThunderTerminalInjection, checkSolareumBotExploit, checkCypherInsiderTheft, checkIoNetSybilAttack, checkSvtTokenHoneypot, checkSagaDaoGovernanceAttack, checkAurorySyncSpaceExploit, checkTulipCrankManipulation, checkUxdStabilityFlaw, checkOptiFiCloseVulnerability, checkWeb3JsSupplyChainAttack, checkParclFrontendAttack, checkJitoDdosPattern, checkPhantomDdosPattern, checkGrapeProtocolDos, checkCandyMachineZeroAccount } from './solana-batched-patterns-21.js';

// NEW PATTERNS SOL677-SOL696 (Feb 5 2026 4AM - Sec3 2025 Report + sannykim/solsec Research)
import { checkNeodymeRoundingAttack, checkJetBreakStatementBug, checkCopeRouletteExploit, checkSimulationDetectionBypass, checkRootOfTrustChainValidation, checkUncheckedAccountDocumentation, checkLpTokenOracleManipulation, checkSignatureSetFabrication, checkIncineratorNftAttack, checkSemanticInconsistency as checkSemanticInconsistencyV2, checkTokenApprovalRevocation, checkCheckedMathNotUsed, checkDriftOracleGuardrails as checkDriftOracleGuardrailsV2, checkMangoMarketsPattern, checkSolendReserveBypass, checkKudelskiOwnershipPattern, checkSec3AuditCommonFindings, checkTrailOfBitsDefiPattern, checkZellicAnchorVulnerability, checkOttersecAuditPattern } from './solana-batched-patterns-22.js';

// NEW PATTERNS SOL697-SOL716 (Feb 5 2026 4AM - Input Validation & Data Hygiene)
import { checkInputLengthOverflow, checkNumericRangeValidation, checkPubkeyFormatValidation, checkArrayIndexBounds, checkTimestampFuturePastValidation, checkPercentageOverflow, checkEnumVariantExhaustiveness, checkMerkleProofDepth, checkProgramIdValidationCpi, checkDataVersionMigration, checkChecksumValidation, checkRaceConditionStateUpdate, checkAtomicUpdateGuarantee, checkBitManipulationCorrectness, checkComputeUnitExhaustionDos, checkMemoryAllocationDos, checkStackOverflowRecursionV2, checkLogSpamAttackV2, checkQueueGriefingAttackV2, checkOracleLivenessDependencyV2 } from './solana-batched-patterns-23.js';

// NEW PATTERNS SOL717-SOL736 (Feb 5 2026 4AM - Access Control & Authorization)
import { checkRoleBasedAccessControl, checkHardcodedAdminAddress, checkMissingMultisigCritical, checkAuthorityDelegationChainV2, checkMissingAuthorityExpiryV2, checkSignerBypassCpi, checkOwnerCheckDerivedAccount, checkPermissionEscalationInit, checkUnprotectedEmergencyFunctions, checkTimelockBypassParameterV2, checkCrossProgramAuthorityConfusion, checkPdaSignerSeedsMismatch, checkOwnershipTransferConfirmation, checkInsufficientPauseProtection, checkGovernanceQuorumManipulationV2, checkMissingFunctionSelectorValidation, checkReentrancyStateUpdateOrder, checkTokenAccountAuthorityValidation, checkUpgradeAuthorityRestriction, checkMissingEventAuthorityChange } from './solana-batched-patterns-24.js';

// NEW PATTERNS SOL737-SOL775 (Feb 5 2026 5AM - Helius Complete History + Recent Exploits)
import { checkAllBatch25Patterns } from './solana-batched-patterns-25.js';
import { checkPrivateKeySecurityPatterns } from './dexx-private-key-leak.js';
import { checkCremaStyleExploits } from './crema-tick-spoofing.js';
import { checkNirvanaStyleExploits } from './nirvana-bonding-curve-attack.js';
import { checkSolendStyleExploits } from './solend-auth-bypass-2021.js';
import { checkThunderStyleExploits } from './thunder-terminal-exploit.js';
import { checkOptiFiStyleBugs } from './optifi-close-bug.js';
import { checkCypherStyleInsiderThreats } from './cypher-insider-theft.js';

// NEW PATTERNS SOL745-SOL764 (Feb 5 2026 5:30AM - Advanced DeFi Protocol Security)
import { batchedPatterns26 } from './solana-batched-patterns-26.js';

// NEW PATTERNS SOL765-SOL784 (Feb 5 2026 5:30AM - Infrastructure & Runtime Security)
import { batchedPatterns27 } from './solana-batched-patterns-27.js';

// NEW PATTERNS SOL785-SOL804 (Feb 5 2026 5:30AM - Token-2022 Advanced Security)
import { batchedPatterns28 } from './solana-batched-patterns-28.js';

// NEW PATTERNS SOL805-SOL852 (Feb 5 2026 6AM - Sec3 2025 Report Categories)
import { batchedPatterns29 } from './solana-batched-patterns-29.js';
import { batchedPatterns30 } from './solana-batched-patterns-30.js';
import { batchedPatterns31 } from './solana-batched-patterns-31.js';

// NEW PATTERNS SOL853-SOL868 (Feb 5 2026 6:30AM - Helius Complete Exploit History Deep Dive)
import { batchedPatterns32 } from './solana-batched-patterns-32.js';

// NEW PATTERNS SOL869-SOL884 (Feb 5 2026 6:30AM - Network & Infrastructure Security)
import { batchedPatterns33 } from './solana-batched-patterns-33.js';

// NEW PATTERNS SOL885-SOL904 (Feb 5 2026 7AM - Feb 2026 Latest Exploits)
import { batchedPatterns34 } from './solana-batched-patterns-34.js';

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
  // NEW PATTERNS SOL311-SOL370 (Feb 4 2026 - Night build session)
  {
    id: 'SOL311',
    name: 'Port Max Withdraw Bug Pattern',
    severity: 'high',
    run: checkPortMaxWithdrawBug,
  },
  {
    id: 'SOL312',
    name: 'Jet Governance Vulnerability',
    severity: 'high',
    run: checkJetGovernanceVuln,
  },
  {
    id: 'SOL313',
    name: 'Semantic Inconsistency (Stake Pool)',
    severity: 'high',
    run: checkSemanticInconsistency,
  },
  {
    id: 'SOL314',
    name: 'Token Approval Revocation Missing',
    severity: 'medium',
    run: checkTokenApproveRevocation,
  },
  {
    id: 'SOL315',
    name: 'LP Token Fair Pricing ($200M Risk)',
    severity: 'critical',
    run: checkLpTokenFairPricing,
  },
  {
    id: 'SOL316',
    name: 'Signature Set Fabrication (Wormhole)',
    severity: 'critical',
    run: checkSignatureSetFabrication,
  },
  {
    id: 'SOL317',
    name: 'Candy Machine Zero Account Exploit',
    severity: 'high',
    run: checkCandyMachineZeroAccount,
  },
  {
    id: 'SOL318',
    name: 'Transaction Revert Exploit (Cope Roulette)',
    severity: 'high',
    run: checkRevertExploit,
  },
  {
    id: 'SOL319',
    name: 'Simulation Detection Bypass',
    severity: 'medium',
    run: checkSimulationDetectionBypass,
  },
  {
    id: 'SOL320',
    name: 'Authority Delegation Chain Vulnerability',
    severity: 'critical',
    run: checkAuthorityDelegationChain,
  },
  {
    id: 'SOL321',
    name: 'Quarry Reward Distribution Issue',
    severity: 'high',
    run: checkQuarryRewardDistribution,
  },
  {
    id: 'SOL322',
    name: 'Saber Stable Swap Invariant',
    severity: 'high',
    run: checkStableSwapInvariant,
  },
  {
    id: 'SOL323',
    name: 'Marinade Stake Pool Security',
    severity: 'high',
    run: checkMarinadeStakePoolSecurity,
  },
  {
    id: 'SOL324',
    name: 'Orca Whirlpool Tick Array Security',
    severity: 'high',
    run: checkWhirlpoolTickArraySecurity,
  },
  {
    id: 'SOL325',
    name: 'Pyth Oracle Confidence Check',
    severity: 'high',
    run: checkPythOracleIntegration,
  },
  {
    id: 'SOL326',
    name: 'Drift Protocol Oracle Guardrails',
    severity: 'high',
    run: checkDriftOracleGuardrails,
  },
  {
    id: 'SOL327',
    name: 'Solido Liquid Staking Security',
    severity: 'high',
    run: checkSolidoLiquidStaking,
  },
  {
    id: 'SOL328',
    name: 'Squads Multisig Replay Prevention',
    severity: 'critical',
    run: checkSquadsMultisigReplay,
  },
  {
    id: 'SOL329',
    name: 'Streamflow Vesting Security',
    severity: 'high',
    run: checkStreamflowVestingSecurity,
  },
  {
    id: 'SOL330',
    name: 'Phoenix Order Book Security',
    severity: 'high',
    run: checkPhoenixOrderBookSecurity,
  },
  {
    id: 'SOL331',
    name: 'Hedge Protocol CDP Stability',
    severity: 'critical',
    run: checkHedgeProtocolStability,
  },
  {
    id: 'SOL332',
    name: 'Mean Finance DCA Security',
    severity: 'high',
    run: checkMeanFinanceDCA,
  },
  {
    id: 'SOL333',
    name: 'Hubble Lending Pool Isolation',
    severity: 'high',
    run: checkHubbleLendingIsolation,
  },
  {
    id: 'SOL334',
    name: 'Invariant CLMM Fee Growth',
    severity: 'high',
    run: checkInvariantCLMM,
  },
  {
    id: 'SOL335',
    name: 'Larix Liquidation Incentive',
    severity: 'high',
    run: checkLarixLiquidation,
  },
  {
    id: 'SOL336',
    name: 'Light Protocol ZK Proof Verification',
    severity: 'critical',
    run: checkLightProtocolZK,
  },
  {
    id: 'SOL337',
    name: 'Francium Leverage Vault Controls',
    severity: 'high',
    run: checkFranciumLeverageVault,
  },
  {
    id: 'SOL338',
    name: 'Friktion Options Vault Epoch',
    severity: 'high',
    run: checkFriktionOptionsVault,
  },
  {
    id: 'SOL339',
    name: 'Genopets NFT Staking Duration',
    severity: 'medium',
    run: checkGenopetsStakingDuration,
  },
  {
    id: 'SOL340',
    name: 'GooseFX Swap Invariant Check',
    severity: 'high',
    run: checkGooseFXSwapInvariant,
  },
  {
    id: 'SOL341',
    name: 'Cropper AMM Fee Precision',
    severity: 'medium',
    run: checkCropperAMMSecurity,
  },
  {
    id: 'SOL342',
    name: 'Parrot Multi-Collateral Risk',
    severity: 'high',
    run: checkParrotCollateralTypes,
  },
  {
    id: 'SOL343',
    name: 'Aldrin DEX Order Partial Fill',
    severity: 'medium',
    run: checkAldrinOrderMatching,
  },
  {
    id: 'SOL344',
    name: 'Audius Storage Slot Authorization',
    severity: 'high',
    run: checkAudiusStorageSlot,
  },
  {
    id: 'SOL345',
    name: 'Swim Cross-Chain Message Validation',
    severity: 'critical',
    run: checkSwimCrossChainMessage,
  },
  {
    id: 'SOL346',
    name: 'Synthetify Debt Pool Tracking',
    severity: 'high',
    run: checkSynthetifySyntheticMinting,
  },
  {
    id: 'SOL347',
    name: 'UXD Redeemable Peg Mechanism',
    severity: 'high',
    run: checkUXDRedeemablePeg,
  },
  {
    id: 'SOL348',
    name: 'Wormhole VAA Guardian Quorum',
    severity: 'critical',
    run: checkWormholeVAAParsing,
  },
  {
    id: 'SOL349',
    name: 'Debridge Double-Claim Prevention',
    severity: 'critical',
    run: checkDebridgeMessageVerification,
  },
  {
    id: 'SOL350',
    name: 'Cashmere Multisig Threshold Bounds',
    severity: 'critical',
    run: checkCashmereMultisigThreshold,
  },
  {
    id: 'SOL351',
    name: 'Anchor init_if_needed Race Condition',
    severity: 'high',
    run: checkAnchorInitIfNeeded,
  },
  {
    id: 'SOL352',
    name: 'Account Close Lamport Dust',
    severity: 'medium',
    run: checkAccountCloseLamportDust,
  },
  {
    id: 'SOL353',
    name: 'PDA Seed Collision Risk',
    severity: 'high',
    run: checkPdaSeedCollision,
  },
  {
    id: 'SOL354',
    name: 'Borsh Deserialization DoS',
    severity: 'medium',
    run: checkBorshDeserializationDoS,
  },
  {
    id: 'SOL355',
    name: 'Invoke Signed Seeds Validation',
    severity: 'info',
    run: checkInvokeSignedSeedsMismatch,
  },
  {
    id: 'SOL356',
    name: 'Token Account Authority Confusion',
    severity: 'high',
    run: checkTokenAuthorityConfusion,
  },
  {
    id: 'SOL357',
    name: 'Writable Account Not Mutable',
    severity: 'high',
    run: checkWritableNotMutable,
  },
  {
    id: 'SOL358',
    name: 'Account Creation Rent Exemption',
    severity: 'medium',
    run: checkAccountCreationRentExemption,
  },
  {
    id: 'SOL359',
    name: 'Recursive CPI Depth Exhaustion',
    severity: 'medium',
    run: checkRecursiveCpiDepth,
  },
  {
    id: 'SOL360',
    name: 'Clock Sysvar Time Manipulation',
    severity: 'medium',
    run: checkClockSysvarReliability,
  },
  {
    id: 'SOL361',
    name: 'Excessive Program Logging',
    severity: 'low',
    run: checkProgramLogSizeLimit,
  },
  {
    id: 'SOL362',
    name: 'Heap Memory Exhaustion Risk',
    severity: 'medium',
    run: checkHeapMemoryExhaustion,
  },
  {
    id: 'SOL363',
    name: 'Account Data Size Without Realloc',
    severity: 'high',
    run: checkAccountDataSizeChange,
  },
  {
    id: 'SOL364',
    name: 'CPI Account Ordering Dependency',
    severity: 'info',
    run: checkCpiAccountOrdering,
  },
  {
    id: 'SOL365',
    name: 'Hardcoded Program IDs',
    severity: 'medium',
    run: checkProgramIdHardcoding,
  },
  {
    id: 'SOL366',
    name: 'Deprecated Sysvar Account Usage',
    severity: 'low',
    run: checkSysvarDeprecation,
  },
  {
    id: 'SOL367',
    name: 'Token Amount Truncation',
    severity: 'medium',
    run: checkTokenAmountTruncation,
  },
  {
    id: 'SOL368',
    name: 'Native SOL / Wrapped SOL Handling',
    severity: 'medium',
    run: checkNativeSolWrappedConfusion,
  },
  {
    id: 'SOL369',
    name: 'Token-2022 Transfer Hook Missing',
    severity: 'high',
    run: checkToken2022TransferHook,
  },
  {
    id: 'SOL370',
    name: 'Metadata URI Validation',
    severity: 'low',
    run: checkMetadataUriValidation,
  },
  // NEW PATTERNS SOL371-SOL395 (Feb 5 2026 - Night session batch 14)
  {
    id: 'SOL371',
    name: 'Aldrin Order Book Manipulation',
    severity: 'high',
    run: checkAldrinOrderBook,
  },
  {
    id: 'SOL372',
    name: 'Cross-Chain Message Replay',
    severity: 'critical',
    run: checkCrossChainReplay,
  },
  {
    id: 'SOL373',
    name: 'Options Vault Epoch Security',
    severity: 'high',
    run: checkOptionsVaultEpoch,
  },
  {
    id: 'SOL374',
    name: 'Leverage Vault Controls (Francium)',
    severity: 'critical',
    run: checkLeverageVaultControls,
  },
  {
    id: 'SOL375',
    name: 'Synthetic Debt Tracking (Synthetify)',
    severity: 'critical',
    run: checkSyntheticDebtTracking,
  },
  {
    id: 'SOL376',
    name: 'ZK Proof Verification (Light)',
    severity: 'critical',
    run: checkZkProofVerification,
  },
  {
    id: 'SOL377',
    name: 'CDP Stability Mechanism (Hedge)',
    severity: 'high',
    run: checkCdpStability,
  },
  {
    id: 'SOL378',
    name: 'DCA Security (Mean Finance)',
    severity: 'high',
    run: checkDcaSecurity,
  },
  {
    id: 'SOL379',
    name: 'Lending Pool Isolation (Hubble)',
    severity: 'high',
    run: checkLendingPoolIsolation,
  },
  {
    id: 'SOL380',
    name: 'CLMM Fee Growth Tracking (Invariant)',
    severity: 'high',
    run: checkClmmFeeGrowth,
  },
  {
    id: 'SOL381',
    name: 'Liquidation Incentive (Larix)',
    severity: 'high',
    run: checkLiquidationIncentive,
  },
  {
    id: 'SOL382',
    name: 'NFT Staking Duration (Genopets)',
    severity: 'medium',
    run: checkNftStakingDuration,
  },
  {
    id: 'SOL383',
    name: 'AMM Invariant Preservation',
    severity: 'critical',
    run: checkAmmInvariant,
  },
  {
    id: 'SOL384',
    name: 'Vesting Contract Security (Streamflow)',
    severity: 'critical',
    run: checkVestingContractSecurity,
  },
  {
    id: 'SOL385',
    name: 'Order Book Depth Protection (Phoenix)',
    severity: 'high',
    run: checkOrderBookDepth,
  },
  {
    id: 'SOL386',
    name: 'Perpetual Funding Rate Manipulation',
    severity: 'high',
    run: checkPerpFundingRate,
  },
  {
    id: 'SOL387',
    name: 'Multi-Collateral Type Risk (Parrot)',
    severity: 'high',
    run: checkMultiCollateralRisk,
  },
  {
    id: 'SOL388',
    name: 'Storage Slot Authorization (Audius)',
    severity: 'critical',
    run: checkStorageSlotAuth,
  },
  {
    id: 'SOL389',
    name: 'VAA Guardian Quorum (Wormhole Deep)',
    severity: 'critical',
    run: checkVaaGuardianQuorum,
  },
  {
    id: 'SOL390',
    name: 'Double-Claim Prevention (Debridge)',
    severity: 'critical',
    run: checkDoubleClaimPrevention,
  },
  {
    id: 'SOL391',
    name: 'Multisig Threshold Bounds (Cashmere)',
    severity: 'critical',
    run: checkMultisigThresholdBounds,
  },
  {
    id: 'SOL392',
    name: 'Stake Pool Mechanics (Marinade)',
    severity: 'medium',
    run: checkStakePoolMechanics,
  },
  {
    id: 'SOL393',
    name: 'Tick Array Boundary (Whirlpool)',
    severity: 'high',
    run: checkTickArrayBoundary,
  },
  {
    id: 'SOL394',
    name: 'Pyth Confidence Interval Check',
    severity: 'high',
    run: checkPythConfidenceInterval,
  },
  {
    id: 'SOL395',
    name: 'Oracle Guardrails (Drift)',
    severity: 'high',
    run: checkOracleGuardrails,
  },
  // SOL396-SOL500: New specialized patterns (Feb 5 2026)
  {
    id: 'SOL396-400',
    name: 'Blink/Actions Security (5 patterns)',
    severity: 'high',
    run: checkBlinkActions,
  },
  {
    id: 'SOL401-410',
    name: 'Token-2022 Advanced Security (10 patterns)',
    severity: 'critical',
    run: checkToken2022Advanced,
  },
  {
    id: 'SOL411-420',
    name: 'DEX Aggregator Security (10 patterns)',
    severity: 'critical',
    run: checkDexAggregator,
  },
  {
    id: 'SOL421-430',
    name: 'NFT Lending Security (10 patterns)',
    severity: 'critical',
    run: checkNftLending,
  },
  {
    id: 'SOL431-440',
    name: 'Perpetual DEX Security (10 patterns)',
    severity: 'critical',
    run: checkPerpetualDex,
  },
  {
    id: 'SOL441-450',
    name: 'Cross-Margin Security (10 patterns)',
    severity: 'critical',
    run: checkCrossMargin,
  },
  {
    id: 'SOL451-460',
    name: 'Prediction Market Security (10 patterns)',
    severity: 'high',
    run: checkPredictionMarket,
  },
  {
    id: 'SOL461-470',
    name: 'Social-Fi Security (10 patterns)',
    severity: 'high',
    run: checkSocialFi,
  },
  {
    id: 'SOL471-480',
    name: 'DAO/Treasury Security (10 patterns)',
    severity: 'critical',
    run: checkDaoTreasury,
  },
  {
    id: 'SOL481-490',
    name: 'Restaking Security (10 patterns)',
    severity: 'critical',
    run: checkRestaking,
  },
  {
    id: 'SOL491-500',
    name: 'Real World Asset Security (10 patterns)',
    severity: 'critical',
    run: checkRealWorldAssets,
  },
  // NEW PATTERNS SOL501-SOL560 (Feb 5 2026 - Hackathon 500+ push)
  { id: 'SOL501', name: 'Privileged Key Management', severity: 'critical', run: checkPrivilegedKeyManagement },
  { id: 'SOL502', name: 'Single Point of Failure Authority', severity: 'high', run: checkSinglePointAuthority },
  { id: 'SOL503', name: 'Missing Key Rotation Mechanism', severity: 'medium', run: checkKeyRotationMechanism },
  { id: 'SOL504', name: 'Insecure Upgrade Authority', severity: 'critical', run: checkInsecureUpgradeAuthority },
  { id: 'SOL505', name: 'Hot Wallet Concentration Risk', severity: 'high', run: checkHotWalletConcentration },
  { id: 'SOL506', name: 'Missing Emergency Pause', severity: 'high', run: checkMissingEmergencyPause },
  { id: 'SOL507', name: 'Insufficient Event Logging', severity: 'medium', run: checkInsufficientEventLogging },
  { id: 'SOL508', name: 'Social Engineering Attack Surface', severity: 'high', run: checkSocialEngineeringAttackSurface },
  { id: 'SOL509', name: 'Phishing-Vulnerable Approval Pattern', severity: 'high', run: checkPhishingVulnerableApproval },
  { id: 'SOL510', name: 'Domain Spoofing Vulnerability', severity: 'medium', run: checkDomainSpoofingVulnerability },
  { id: 'SOL511', name: 'Missing Rate Limiting', severity: 'medium', run: checkMissingRateLimiting },
  { id: 'SOL512', name: 'Unprotected Configuration Update', severity: 'high', run: checkUnprotectedConfigUpdate },
  { id: 'SOL513', name: 'Improper Access Control Hierarchy', severity: 'medium', run: checkImproperAccessControlHierarchy },
  { id: 'SOL514', name: 'Unverified External Call Result', severity: 'high', run: checkUnverifiedExternalCallResult },
  { id: 'SOL515', name: 'Missing Withdrawal Delay', severity: 'medium', run: checkMissingWithdrawalDelay },
  { id: 'SOL516', name: 'Insecure Random Number Generation', severity: 'critical', run: checkInsecureRandomNumberGeneration },
  { id: 'SOL517', name: 'Cross-Program State Inconsistency', severity: 'high', run: checkCrossProgramStateInconsistency },
  { id: 'SOL518', name: 'Unprotected Initialization', severity: 'critical', run: checkUnprotectedInitialization },
  { id: 'SOL519', name: 'Missing Sanity Checks on Inputs', severity: 'medium', run: checkMissingSanityChecks },
  { id: 'SOL520', name: 'Timestamp Dependency Without Bounds', severity: 'medium', run: checkTimestampDependencyWithoutBounds },
  { id: 'SOL521', name: 'Flash Loan Re-entrancy Risk', severity: 'critical', run: checkFlashLoanReentrancy },
  { id: 'SOL522', name: 'Price Feed Staleness Not Checked', severity: 'high', run: checkPriceFeedStaleness },
  { id: 'SOL523', name: 'Insufficient Liquidity Check', severity: 'high', run: checkInsufficientLiquidityCheck },
  { id: 'SOL524', name: 'Unbounded Loop in Critical Path', severity: 'high', run: checkUnboundedLoopCriticalPath },
  { id: 'SOL525', name: 'Missing Slippage Protection', severity: 'high', run: checkMissingSlippageProtection },
  { id: 'SOL526', name: 'Sandwich Attack Vulnerability', severity: 'high', run: checkSandwichAttackVuln },
  { id: 'SOL527', name: 'Improper Decimal Handling', severity: 'high', run: checkImproperDecimalHandling },
  { id: 'SOL528', name: 'Vault Share Manipulation Risk', severity: 'critical', run: checkVaultShareManipulation },
  { id: 'SOL529', name: 'Interest Rate Manipulation Risk', severity: 'high', run: checkInterestRateManipulation },
  { id: 'SOL530', name: 'Liquidation Threshold Bypass Risk', severity: 'critical', run: checkLiquidationThresholdBypass },
  { id: 'SOL531', name: 'Reward Calculation Rounding Issues', severity: 'medium', run: checkRewardCalculationRounding },
  { id: 'SOL532', name: 'Governance Quorum Manipulation', severity: 'high', run: checkGovernanceQuorumManipulation },
  { id: 'SOL533', name: 'NFT Metadata Manipulation Risk', severity: 'medium', run: checkNftMetadataManipulation },
  { id: 'SOL534', name: 'Royalty Bypass Pattern', severity: 'medium', run: checkRoyaltyBypassPattern },
  { id: 'SOL535', name: 'Unstaking Cooldown Bypass', severity: 'medium', run: checkUnstakingCooldownBypass },
  { id: 'SOL536', name: 'Fee Manipulation Attack Vector', severity: 'high', run: checkFeeManipulationAttack },
  { id: 'SOL537', name: 'Improper Token Transfer Validation', severity: 'high', run: checkImproperTokenTransferValidation },
  { id: 'SOL538', name: 'Merkle Proof Manipulation Risk', severity: 'high', run: checkMerkleProofManipulation },
  { id: 'SOL539', name: 'Cross-Margin Collateral Risk', severity: 'high', run: checkCrossMarginCollateralRisk },
  { id: 'SOL540', name: 'Funding Rate Manipulation', severity: 'high', run: checkFundingRateManipulation },
  { id: 'SOL541', name: 'Unprotected Admin Functions', severity: 'critical', run: checkUnprotectedAdminFunctions },
  { id: 'SOL542', name: 'Missing Input Length Validation', severity: 'medium', run: checkMissingInputLengthValidation },
  { id: 'SOL543', name: 'Account Data Size Mismatch', severity: 'high', run: checkAccountDataSizeMismatch },
  { id: 'SOL544', name: 'Deprecated Solana API Usage', severity: 'low', run: checkDeprecatedSolanaApiUsage },
  { id: 'SOL545', name: 'Missing Program Deployment Check', severity: 'high', run: checkMissingProgramDeploymentCheck },
  { id: 'SOL546', name: 'Unsafe Type Casting', severity: 'high', run: checkUnsafeTypeCasting },
  { id: 'SOL547', name: 'Missing Account Ownership Validation', severity: 'critical', run: checkMissingAccountOwnershipValidation },
  { id: 'SOL548', name: 'Improper Bump Seed Validation', severity: 'high', run: checkImproperBumpSeedValidation },
  { id: 'SOL549', name: 'Insufficient Entropy in PDA Seeds', severity: 'medium', run: checkInsufficientEntropyInSeeds },
  { id: 'SOL550', name: 'Missing Close Account Data Cleanup', severity: 'medium', run: checkMissingCloseAccountCleanup },
  { id: 'SOL551', name: 'Vulnerable to Compute Budget Exhaustion', severity: 'medium', run: checkComputeBudgetExhaustion },
  { id: 'SOL552', name: 'Unsafe Arithmetic in Token Calculations', severity: 'high', run: checkUnsafeArithmeticTokenCalc },
  { id: 'SOL553', name: 'Missing Account Discriminator', severity: 'high', run: checkMissingAccountDiscriminator },
  { id: 'SOL554', name: 'Improper Error Handling in CPI', severity: 'high', run: checkImproperErrorHandlingCpi },
  { id: 'SOL555', name: 'Reentrancy Through CPI Callback', severity: 'critical', run: checkReentrancyThroughCallback },
  { id: 'SOL556', name: 'Missing Rent Exemption Check', severity: 'medium', run: checkMissingRentExemptionCheck },
  { id: 'SOL557', name: 'Unsafe Deserialization Pattern', severity: 'high', run: checkUnsafeDeserializationPattern },
  { id: 'SOL558', name: 'Missing Token Account Freeze Check', severity: 'medium', run: checkMissingTokenAccountFreezeCheck },
  { id: 'SOL559', name: 'Improper Authority Delegation', severity: 'high', run: checkImproperAuthorityDelegation },
  { id: 'SOL560', name: 'Missing State Machine Validation', severity: 'high', run: checkMissingStateMachineValidation },
  
  // NEW PATTERNS SOL561-SOL575 (Feb 5 2026 - Real-world exploit research session)
  { id: 'SOL561', name: 'Candy Machine Exploit Pattern', severity: 'critical', run: checkCandyMachineExploit },
  { id: 'SOL562', name: 'Malicious Lending Market Creation', severity: 'critical', run: checkMaliciousLendingMarket },
  { id: 'SOL563', name: 'Token Approval Drain Attack', severity: 'high', run: checkTokenApprovalDrain },
  { id: 'SOL564', name: 'Semantic Inconsistency Detection V2', severity: 'critical', run: checkSemanticInconsistencyV2 },
  { id: 'SOL565', name: 'LP Token Fair Pricing Vulnerability', severity: 'critical', run: checkLpFairPricing },
  { id: 'SOL566', name: 'Reverting Transaction Exploit V2', severity: 'critical', run: checkRevertExploitV2 },
  { id: 'SOL567', name: 'Checked Math Validation Comprehensive', severity: 'critical', run: checkCheckedMathValidation },
  { id: 'SOL568', name: 'Cross-Chain Delegation Verification', severity: 'critical', run: checkCrossChainDelegation },
  { id: 'SOL569', name: 'Incinerator/Burn Attack Detection', severity: 'high', run: checkIncineratorAttack },
  { id: 'SOL570', name: 'Exploit Chaining Detection', severity: 'critical', run: checkExploitChaining },
  { id: 'SOL571', name: 'Stake Pool Security Comprehensive', severity: 'critical', run: checkStakePoolSecurity },
  { id: 'SOL572', name: 'Program Upgrade Security', severity: 'critical', run: checkProgramUpgradeSecurity },
  { id: 'SOL573', name: 'Simulation Bypass Detection', severity: 'critical', run: checkSimulationBypass },
  { id: 'SOL574', name: 'Oracle TWAP Manipulation', severity: 'critical', run: checkOracleTwapManipulation },
  { id: 'SOL575', name: 'NPM Supply Chain Attack Detection', severity: 'critical', run: checkNpmSupplyChain },
  
  // NEW PATTERNS SOL576-SOL600 (Feb 5 2026 2AM - Real-world exploit research patterns)
  { id: 'SOL576', name: 'Reverting Transaction Exploit (Cope Roulette)', severity: 'critical', run: checkRevertingTransactionExploit },
  { id: 'SOL577', name: 'Token Approval Exploitation Patterns', severity: 'high', run: checkTokenApprovalExploitation },
  { id: 'SOL578', name: 'LP Token Fair Pricing Vulnerability', severity: 'critical', run: checkLpTokenFairPricing },
  { id: 'SOL579', name: 'Signature Set Spoofing (Wormhole)', severity: 'critical', run: checkSignatureSetSpoofing },
  { id: 'SOL580', name: 'Root of Trust Chain (Cashio)', severity: 'critical', run: checkRootOfTrustChain },
  { id: 'SOL581', name: 'Incinerator NFT Attack (Schrodinger)', severity: 'high', run: checkIncineratorNftAttack },
  { id: 'SOL582', name: 'Candy Machine Security', severity: 'critical', run: checkCandyMachineSecurity },
  { id: 'SOL583', name: 'Checked Math Required (BlockSec)', severity: 'high', run: checkCheckedMathRequired },
  { id: 'SOL584', name: 'Jet Break Statement Bug', severity: 'high', run: checkJetBreakBug },
  { id: 'SOL585', name: 'Rounding Direction Attack (Neodyme SPL)', severity: 'critical', run: checkRoundingDirectionAttack },
  { id: 'SOL586', name: 'Solend Reserve Bypass', severity: 'critical', run: checkSolendReserveBypass },
  { id: 'SOL587', name: 'Kudelski Ownership Check Patterns', severity: 'critical', run: checkKudelskiOwnershipCheck },
  { id: 'SOL588', name: 'Sec3 Audit Methodology Patterns', severity: 'high', run: checkSec3AuditPatterns },
  { id: 'SOL589', name: 'Drift Oracle Guardrails', severity: 'high', run: checkDriftOracleGuardrails },
  { id: 'SOL590', name: 'Mango Markets Exploit Patterns', severity: 'critical', run: checkMangoMarketsPatterns },
  { id: 'SOL591', name: 'Zellic Anchor Vulnerability Patterns', severity: 'critical', run: checkZellicAnchorPatterns },
  { id: 'SOL592', name: 'OtterSec Audit Methodology Patterns', severity: 'high', run: checkOttersecAuditPatterns },
  
  // NEW PATTERNS SOL593-SOL612 (Feb 5 2026 2:30AM - Business Logic Patterns from Sec3 2025 Report)
  { id: 'SOL593', name: 'Incorrect State Machine Transitions', severity: 'high', run: checkIncorrectStateMachine },
  { id: 'SOL594', name: 'Missing Invariant Checks', severity: 'critical', run: checkMissingInvariantChecks },
  { id: 'SOL595', name: 'Unrestricted Protocol Parameter Updates', severity: 'high', run: checkUnrestrictedParameterUpdate },
  { id: 'SOL596', name: 'Incorrect Accounting Updates', severity: 'critical', run: checkIncorrectAccounting },
  { id: 'SOL597', name: 'Missing Settlement Validation', severity: 'high', run: checkMissingSettlementValidation },
  { id: 'SOL598', name: 'Inconsistent Fee Calculation', severity: 'medium', run: checkInconsistentFeeCalculation },
  { id: 'SOL599', name: 'Missing Cooldown Period', severity: 'medium', run: checkMissingCooldownPeriod },
  { id: 'SOL600', name: 'Incorrect Share Calculation', severity: 'critical', run: checkIncorrectShareCalculation },
  { id: 'SOL601', name: 'Missing Epoch Boundary Handling', severity: 'medium', run: checkMissingEpochBoundary },
  { id: 'SOL602', name: 'Incorrect Order Matching Logic', severity: 'high', run: checkIncorrectOrderMatching },
  { id: 'SOL603', name: 'Missing Position Size Limits', severity: 'high', run: checkMissingPositionLimits },
  { id: 'SOL604', name: 'Incorrect Liquidation Priority', severity: 'high', run: checkIncorrectLiquidationPriority },
  { id: 'SOL605', name: 'Missing Partial Fill Handling', severity: 'medium', run: checkMissingPartialFillHandling },
  { id: 'SOL606', name: 'Incorrect Utilization Rate Calculation', severity: 'high', run: checkIncorrectUtilizationRate },
  { id: 'SOL607', name: 'Missing Dust Threshold Handling', severity: 'low', run: checkMissingDustThreshold },
  { id: 'SOL608', name: 'Incorrect Rebase Token Handling', severity: 'high', run: checkIncorrectRebaseHandling },
  { id: 'SOL609', name: 'Missing Cross-Collateral Validation', severity: 'high', run: checkMissingCrossCollateralValidation },
  { id: 'SOL610', name: 'Incorrect Interest Accrual', severity: 'high', run: checkIncorrectInterestAccrual },
  { id: 'SOL611', name: 'Missing Reserve Factor Application', severity: 'medium', run: checkMissingReserveFactor },
  { id: 'SOL612', name: 'Incorrect Slashing Condition', severity: 'critical', run: checkIncorrectSlashingCondition },
  
  // NEW PATTERNS SOL613-SOL632 (Feb 5 2026 2:30AM - Access Control & Input Validation from Sec3 Report)
  { id: 'SOL613', name: 'Missing Role-Based Access Control', severity: 'high', run: checkMissingRBAC },
  { id: 'SOL614', name: 'Hardcoded Authority Address', severity: 'medium', run: checkHardcodedAuthorityAddress },
  { id: 'SOL615', name: 'Missing Multi-Signature Requirement', severity: 'high', run: checkMissingMultisigRequirement },
  { id: 'SOL616', name: 'Unrestricted Delegate Authority', severity: 'medium', run: checkUnrestrictedDelegateAuthority },
  { id: 'SOL617', name: 'Missing Authority Separation', severity: 'medium', run: checkMissingAuthoritySeparation },
  { id: 'SOL618', name: 'Insufficient Input Length Validation', severity: 'high', run: checkInsufficientInputLengthValidation },
  { id: 'SOL619', name: 'Missing Numeric Bounds Validation', severity: 'medium', run: checkMissingNumericBounds },
  { id: 'SOL620', name: 'Unvalidated String Input', severity: 'medium', run: checkUnvalidatedStringInput },
  { id: 'SOL621', name: 'Missing Zero Address Check', severity: 'high', run: checkMissingZeroAddressCheck },
  { id: 'SOL622', name: 'Insufficient Array Index Validation', severity: 'high', run: checkInsufficientArrayIndexValidation },
  { id: 'SOL623', name: 'Missing Timestamp Future Validation', severity: 'medium', run: checkMissingTimestampFutureValidation },
  { id: 'SOL624', name: 'Unvalidated Percentage Input', severity: 'medium', run: checkUnvalidatedPercentageInput },
  { id: 'SOL625', name: 'Missing Pubkey Format Validation', severity: 'medium', run: checkMissingPubkeyValidation },
  { id: 'SOL626', name: 'Timelock Bypass via Parameter', severity: 'critical', run: checkTimelockBypassParameter },
  { id: 'SOL627', name: 'Missing Reentrancy Guard on State Changes', severity: 'high', run: checkMissingReentrancyGuardStateChange },
  { id: 'SOL628', name: 'Insufficient Merkle Proof Validation', severity: 'high', run: checkInsufficientMerkleProofValidation },
  { id: 'SOL629', name: 'Missing Enum Variant Exhaustiveness', severity: 'medium', run: checkMissingEnumExhaustiveness },
  { id: 'SOL630', name: 'Missing Program ID Validation in CPIs', severity: 'critical', run: checkMissingProgramIdValidationCpi },
  { id: 'SOL631', name: 'Missing Authority Expiry Check', severity: 'medium', run: checkMissingAuthorityExpiry },
  { id: 'SOL632', name: 'Unsafe Type Conversion', severity: 'high', run: checkUnsafeTypeConversion },
  
  // NEW PATTERNS SOL633-SOL652 (Feb 5 2026 2:30AM - Data Integrity & DoS from Sec3 Report)
  { id: 'SOL633', name: 'Unchecked Division Remainder', severity: 'medium', run: checkUncheckedDivisionRemainder },
  { id: 'SOL634', name: 'Missing Data Version Check', severity: 'medium', run: checkMissingDataVersionCheck },
  { id: 'SOL635', name: 'Inconsistent Serialization Format', severity: 'medium', run: checkInconsistentSerialization },
  { id: 'SOL636', name: 'Missing Checksum Validation', severity: 'medium', run: checkMissingChecksumValidation },
  { id: 'SOL637', name: 'Race Condition in Parallel Updates', severity: 'high', run: checkRaceConditionParallelUpdates },
  { id: 'SOL638', name: 'Missing Atomic Update Guarantee', severity: 'high', run: checkMissingAtomicUpdate },
  { id: 'SOL639', name: 'Incorrect Bit Manipulation', severity: 'medium', run: checkIncorrectBitManipulation },
  { id: 'SOL640', name: 'Missing Data Migration Path', severity: 'medium', run: checkMissingDataMigration },
  { id: 'SOL641', name: 'Compute Unit Exhaustion', severity: 'high', run: checkComputeUnitExhaustion },
  { id: 'SOL642', name: 'Account Creation DoS', severity: 'medium', run: checkAccountCreationDos },
  { id: 'SOL643', name: 'Log Spam Attack', severity: 'low', run: checkLogSpamAttack },
  { id: 'SOL644', name: 'Memory Allocation DoS', severity: 'high', run: checkMemoryAllocationDos },
  { id: 'SOL645', name: 'Stack Overflow via Recursion', severity: 'high', run: checkStackOverflowRecursion },
  { id: 'SOL646', name: 'Blocking Operation in Critical Path', severity: 'medium', run: checkBlockingOperationCriticalPath },
  { id: 'SOL647', name: 'Queue Griefing Attack', severity: 'medium', run: checkQueueGriefingAttack },
  { id: 'SOL648', name: 'Oracle Liveness Dependency', severity: 'high', run: checkOracleLivenessDependency },
  { id: 'SOL649', name: 'Insufficient Gas Reserve', severity: 'medium', run: checkInsufficientGasReserve },
  { id: 'SOL650', name: 'Signature Verification DoS', severity: 'high', run: checkSignatureVerificationDos },
  { id: 'SOL651', name: 'Integer Underflow on Unsigned', severity: 'critical', run: checkIntegerUnderflowUnsigned },
  { id: 'SOL652', name: 'Hash Collision Risk', severity: 'medium', run: checkHashCollisionRisk },
  
  // NEW PATTERNS SOL653-SOL656 (Feb 5 2026 3AM - Recent 2025 Exploits)
  { id: 'SOL653', name: 'Step Finance Treasury Exploit (Jan 2025)', severity: 'critical', run: checkStepFinanceExploit },
  { id: 'SOL654', name: 'Phishing Account Transfer Attack', severity: 'critical', run: checkPhishingAccountTransfer },
  { id: 'SOL655', name: 'Loopscale Admin Wallet Exploit (Apr 2025)', severity: 'critical', run: checkLoopscaleAdminExploit },
  { id: 'SOL656', name: 'NPM Supply Chain Attack 2025', severity: 'high', run: checkNpmSupplyChain2025 },
  
  // NEW PATTERNS SOL657-SOL676 (Feb 5 2026 3:30AM - Latest 2025 Exploits from Helius Research)
  { id: 'SOL657', name: 'NoOnes P2P Platform Hot Wallet Exploit ($4M)', severity: 'critical', run: checkNoOnesPlatformExploit },
  { id: 'SOL658', name: 'DEXX Hot Wallet Key Exposure ($30M)', severity: 'critical', run: checkDexxHotWalletExposure },
  { id: 'SOL659', name: 'Banana Gun Trading Bot Vulnerability ($1.4M)', severity: 'high', run: checkBananaGunBotVulnerability },
  { id: 'SOL660', name: 'Pump.fun Insider Employee Exploit ($1.9M)', severity: 'critical', run: checkPumpFunInsiderThreat },
  { id: 'SOL661', name: 'Thunder Terminal MongoDB Injection ($240K)', severity: 'high', run: checkThunderTerminalInjection },
  { id: 'SOL662', name: 'Solareum Bot Payment Exploit ($500K+)', severity: 'high', run: checkSolareumBotExploit },
  { id: 'SOL663', name: 'Cypher Protocol Insider Theft ($1.35M)', severity: 'critical', run: checkCypherInsiderTheft },
  { id: 'SOL664', name: 'io.net Sybil Attack (Fake GPUs)', severity: 'medium', run: checkIoNetSybilAttack },
  { id: 'SOL665', name: 'SVT Token Honeypot Pattern', severity: 'critical', run: checkSvtTokenHoneypot },
  { id: 'SOL666', name: 'Saga DAO Governance Attack ($230K)', severity: 'critical', run: checkSagaDaoGovernanceAttack },
  { id: 'SOL667', name: 'Aurory SyncSpace Gaming Exploit', severity: 'medium', run: checkAurorySyncSpaceExploit },
  { id: 'SOL668', name: 'Tulip Protocol Crank Manipulation', severity: 'medium', run: checkTulipCrankManipulation },
  { id: 'SOL669', name: 'UXD Protocol Stability Mechanism Flaw', severity: 'high', run: checkUxdStabilityFlaw },
  { id: 'SOL670', name: 'OptiFi Program Close Lockup ($661K)', severity: 'critical', run: checkOptiFiCloseVulnerability },
  { id: 'SOL671', name: 'Web3.js Supply Chain Attack ($164K)', severity: 'high', run: checkWeb3JsSupplyChainAttack },
  { id: 'SOL672', name: 'Parcl Frontend Phishing Attack', severity: 'info', run: checkParclFrontendAttack },
  { id: 'SOL673', name: 'Jito DDoS Attack Pattern', severity: 'medium', run: checkJitoDdosPattern },
  { id: 'SOL674', name: 'Phantom Wallet Spam/DDoS', severity: 'low', run: checkPhantomDdosPattern },
  { id: 'SOL675', name: 'Grape Protocol Network DoS', severity: 'high', run: checkGrapeProtocolDos },
  { id: 'SOL676', name: 'Candy Machine Zero-Account DoS', severity: 'medium', run: checkCandyMachineZeroAccount },
  
  // NEW PATTERNS SOL677-SOL696 (Feb 5 2026 4AM - Sec3 2025 Report + sannykim/solsec Research)
  { id: 'SOL677', name: 'Neodyme Rounding Attack Vector ($2.6B risk)', severity: 'critical', run: checkNeodymeRoundingAttack },
  { id: 'SOL678', name: 'Jet Protocol Break Statement Bug', severity: 'high', run: checkJetBreakStatementBug },
  { id: 'SOL679', name: 'Cope Roulette Revert Exploit Pattern', severity: 'critical', run: checkCopeRouletteExploit },
  { id: 'SOL680', name: 'Simulation Detection Bypass Risk', severity: 'medium', run: checkSimulationDetectionBypass },
  { id: 'SOL681', name: 'Missing Root of Trust Chain (Cashio)', severity: 'critical', run: checkRootOfTrustChainValidation },
  { id: 'SOL682', name: 'Unchecked Account Without Documentation', severity: 'high', run: checkUncheckedAccountDocumentation },
  { id: 'SOL683', name: 'LP Token Oracle Manipulation ($200M risk)', severity: 'critical', run: checkLpTokenOracleManipulation },
  { id: 'SOL684', name: 'Signature Set Fabrication (Wormhole $326M)', severity: 'critical', run: checkSignatureSetFabrication },
  { id: 'SOL685', name: 'Incinerator NFT Attack (Schrodingers NFT)', severity: 'high', run: checkIncineratorNftAttack },
  { id: 'SOL686', name: 'Semantic Inconsistency (Stake Pool)', severity: 'high', run: checkSemanticInconsistencyV2 },
  { id: 'SOL687', name: 'Missing Token Approval Revocation', severity: 'medium', run: checkTokenApprovalRevocation },
  { id: 'SOL688', name: 'Checked Math Not Used (BlockSec Pattern)', severity: 'high', run: checkCheckedMathNotUsed },
  { id: 'SOL689', name: 'Missing Oracle Guardrails (Drift Pattern)', severity: 'high', run: checkDriftOracleGuardrailsV2 },
  { id: 'SOL690', name: 'Mango Markets Price Manipulation ($116M)', severity: 'critical', run: checkMangoMarketsPattern },
  { id: 'SOL691', name: 'Solend Reserve Config Bypass', severity: 'critical', run: checkSolendReserveBypass },
  { id: 'SOL692', name: 'Missing Ownership Check (Kudelski)', severity: 'critical', run: checkKudelskiOwnershipPattern },
  { id: 'SOL693', name: 'Business Logic Flaw (Sec3 38.5%)', severity: 'high', run: checkSec3AuditCommonFindings },
  { id: 'SOL694', name: 'DeFi Security Anti-Pattern (Trail of Bits)', severity: 'high', run: checkTrailOfBitsDefiPattern },
  { id: 'SOL695', name: 'Zellic Anchor Vulnerability Pattern', severity: 'high', run: checkZellicAnchorVulnerability },
  { id: 'SOL696', name: 'OtterSec Audit Pattern Finding', severity: 'medium', run: checkOttersecAuditPattern },
  
  // NEW PATTERNS SOL697-SOL716 (Feb 5 2026 4AM - Input Validation & Data Hygiene 25%)
  { id: 'SOL697', name: 'Input Length Overflow Attack Vector', severity: 'high', run: checkInputLengthOverflow },
  { id: 'SOL698', name: 'Missing Numeric Range Validation', severity: 'medium', run: checkNumericRangeValidation },
  { id: 'SOL699', name: 'Pubkey Format Validation Missing', severity: 'medium', run: checkPubkeyFormatValidation },
  { id: 'SOL700', name: 'Array Index Bounds Not Checked', severity: 'high', run: checkArrayIndexBounds },
  { id: 'SOL701', name: 'Timestamp Future/Past Validation Missing', severity: 'medium', run: checkTimestampFuturePastValidation },
  { id: 'SOL702', name: 'Percentage/Basis Points Overflow Risk', severity: 'high', run: checkPercentageOverflow },
  { id: 'SOL703', name: 'Non-Exhaustive Enum Match', severity: 'medium', run: checkEnumVariantExhaustiveness },
  { id: 'SOL704', name: 'Merkle Proof Depth Not Limited', severity: 'high', run: checkMerkleProofDepth },
  { id: 'SOL705', name: 'Missing Program ID Validation in CPI', severity: 'critical', run: checkProgramIdValidationCpi },
  { id: 'SOL706', name: 'Missing Data Version Field', severity: 'low', run: checkDataVersionMigration },
  { id: 'SOL707', name: 'Missing Checksum Validation', severity: 'medium', run: checkChecksumValidation },
  { id: 'SOL708', name: 'Race Condition in State Update', severity: 'high', run: checkRaceConditionStateUpdate },
  { id: 'SOL709', name: 'Non-Atomic Multi-Account Update', severity: 'high', run: checkAtomicUpdateGuarantee },
  { id: 'SOL710', name: 'Bit Shift Overflow Risk', severity: 'medium', run: checkBitManipulationCorrectness },
  { id: 'SOL711', name: 'Compute Unit Exhaustion DoS Risk', severity: 'high', run: checkComputeUnitExhaustionDos },
  { id: 'SOL712', name: 'Memory Allocation DoS Risk', severity: 'high', run: checkMemoryAllocationDos },
  { id: 'SOL713', name: 'Stack Overflow via Recursion Risk', severity: 'high', run: checkStackOverflowRecursionV2 },
  { id: 'SOL714', name: 'Log Spam Attack Vector', severity: 'low', run: checkLogSpamAttackV2 },
  { id: 'SOL715', name: 'Queue Griefing Attack Risk', severity: 'medium', run: checkQueueGriefingAttackV2 },
  { id: 'SOL716', name: 'Oracle Liveness Dependency', severity: 'high', run: checkOracleLivenessDependencyV2 },
  
  // NEW PATTERNS SOL717-SOL736 (Feb 5 2026 4AM - Access Control & Authorization 19%)
  { id: 'SOL717', name: 'Missing Role-Based Access Control', severity: 'high', run: checkRoleBasedAccessControl },
  { id: 'SOL718', name: 'Hardcoded Admin Address', severity: 'medium', run: checkHardcodedAdminAddress },
  { id: 'SOL719', name: 'Missing Multisig for Critical Operation', severity: 'high', run: checkMissingMultisigCritical },
  { id: 'SOL720', name: 'Authority Delegation Chain Depth Risk', severity: 'medium', run: checkAuthorityDelegationChainV2 },
  { id: 'SOL721', name: 'Authority Grant Without Expiry', severity: 'medium', run: checkMissingAuthorityExpiryV2 },
  { id: 'SOL722', name: 'Signer Check Bypass via CPI', severity: 'high', run: checkSignerBypassCpi },
  { id: 'SOL723', name: 'Missing Owner Check on PDA', severity: 'critical', run: checkOwnerCheckDerivedAccount },
  { id: 'SOL724', name: 'Permission Escalation via Reinitialization', severity: 'critical', run: checkPermissionEscalationInit },
  { id: 'SOL725', name: 'Unprotected Emergency Function', severity: 'critical', run: checkUnprotectedEmergencyFunctions },
  { id: 'SOL726', name: 'Timelock Bypass via Zero Delay', severity: 'critical', run: checkTimelockBypassParameterV2 },
  { id: 'SOL727', name: 'Cross-Program Authority Confusion', severity: 'high', run: checkCrossProgramAuthorityConfusion },
  { id: 'SOL728', name: 'PDA Signer Seeds Validation Missing', severity: 'high', run: checkPdaSignerSeedsMismatch },
  { id: 'SOL729', name: 'Ownership Transfer Without Confirmation', severity: 'high', run: checkOwnershipTransferConfirmation },
  { id: 'SOL730', name: 'Incomplete Pause Protection', severity: 'medium', run: checkInsufficientPauseProtection },
  { id: 'SOL731', name: 'Governance Quorum Manipulation Risk', severity: 'high', run: checkGovernanceQuorumManipulationV2 },
  { id: 'SOL732', name: 'Missing Instruction Discriminator Validation', severity: 'high', run: checkMissingFunctionSelectorValidation },
  { id: 'SOL733', name: 'Reentrancy via CPI Before State Update', severity: 'critical', run: checkReentrancyStateUpdateOrder },
  { id: 'SOL734', name: 'Token Account Authority Not Validated', severity: 'high', run: checkTokenAccountAuthorityValidation },
  { id: 'SOL735', name: 'Upgrade Authority Not Restricted', severity: 'high', run: checkUpgradeAuthorityRestriction },
  { id: 'SOL736', name: 'Missing Event on Authority Change', severity: 'medium', run: checkMissingEventAuthorityChange },
  
  // NEW PATTERNS SOL737-SOL775 (Feb 5 2026 5AM - Helius Complete Exploit History)
  { id: 'SOL737', name: 'DEXX Private Key Leak Pattern ($30M)', severity: 'critical', run: checkPrivateKeySecurityPatterns },
  { id: 'SOL738', name: 'Crema Finance CLMM Tick Spoofing ($8.8M)', severity: 'critical', run: checkCremaStyleExploits },
  { id: 'SOL739', name: 'Nirvana Bonding Curve Flash Loan ($3.5M)', severity: 'critical', run: checkNirvanaStyleExploits },
  { id: 'SOL740', name: 'Solend Auth Bypass Pattern ($2M risk)', severity: 'critical', run: checkSolendStyleExploits },
  { id: 'SOL741', name: 'Thunder Terminal MongoDB Injection ($240K)', severity: 'high', run: checkThunderStyleExploits },
  { id: 'SOL742', name: 'OptiFi Program Close Lockup ($661K)', severity: 'critical', run: checkOptiFiStyleBugs },
  { id: 'SOL743', name: 'Cypher Insider Theft Pattern ($317K)', severity: 'critical', run: checkCypherStyleInsiderThreats },
  { id: 'SOL744', name: 'Helius Batch 25 Patterns (38 patterns)', severity: 'high', run: checkAllBatch25Patterns },
  
  // NEW PATTERNS SOL745-SOL764 (Feb 5 2026 5:30AM - Advanced DeFi Protocol Security)
  ...batchedPatterns26,
  
  // NEW PATTERNS SOL765-SOL784 (Feb 5 2026 5:30AM - Infrastructure & Runtime Security)
  ...batchedPatterns27,
  
  // NEW PATTERNS SOL785-SOL804 (Feb 5 2026 5:30AM - Token-2022 Advanced Security)
  ...batchedPatterns28,
  
  // NEW PATTERNS SOL805-SOL820 (Feb 5 2026 6AM - Business Logic from Sec3 2025)
  { id: 'SOL805', name: 'Missing Protocol Fee Accrual', severity: 'high', run: batchedPatterns29.checkMissingFeeAccrual },
  { id: 'SOL806', name: 'Incorrect Reward Rate Calculation', severity: 'high', run: batchedPatterns29.checkIncorrectRewardRate },
  { id: 'SOL807', name: 'Missing Withdrawal Queue Processing', severity: 'medium', run: batchedPatterns29.checkMissingWithdrawalQueue },
  { id: 'SOL808', name: 'First Depositor Attack (Vault Shares)', severity: 'critical', run: batchedPatterns29.checkVaultShareCalculation },
  { id: 'SOL809', name: 'Missing Borrow Capacity Check', severity: 'high', run: batchedPatterns29.checkMissingBorrowCapacity },
  { id: 'SOL810', name: 'Incorrect Liquidation Incentive', severity: 'high', run: batchedPatterns29.checkLiquidationIncentiveCalc },
  { id: 'SOL811', name: 'Missing Position Health Update', severity: 'high', run: batchedPatterns29.checkMissingHealthUpdate },
  { id: 'SOL812', name: 'Missing Interest Rate Model Kink', severity: 'medium', run: batchedPatterns29.checkInterestRateModel },
  { id: 'SOL813', name: 'Missing Debt Token Tracking', severity: 'high', run: batchedPatterns29.checkMissingDebtTracking },
  { id: 'SOL814', name: 'Missing Collateral Factor Bounds', severity: 'medium', run: batchedPatterns29.checkCollateralFactorApplication },
  { id: 'SOL815', name: 'Missing Oracle Fallback Mechanism', severity: 'high', run: batchedPatterns29.checkMissingOracleFallback },
  { id: 'SOL816', name: 'Missing AMM Invariant Verification', severity: 'critical', run: batchedPatterns29.checkAmmInvariantMaintenance },
  { id: 'SOL817', name: 'Missing Slippage Protection in Swap', severity: 'high', run: batchedPatterns29.checkSwapSlippageProtection },
  { id: 'SOL818', name: 'Missing Fee-on-Transfer Handling', severity: 'high', run: batchedPatterns29.checkFeeOnTransferHandling },
  { id: 'SOL819', name: 'Missing Epoch Boundary Handling', severity: 'medium', run: batchedPatterns29.checkEpochBoundaryHandling },
  { id: 'SOL820', name: 'Missing Time-Weighted Voting Power', severity: 'medium', run: batchedPatterns29.checkVotingPowerCalculation },
  
  // NEW PATTERNS SOL821-SOL836 (Feb 5 2026 6AM - Input Validation from Sec3 2025)
  { id: 'SOL821', name: 'Missing Account Data Size Validation', severity: 'high', run: batchedPatterns30.checkAccountDataSizeValidation },
  { id: 'SOL822', name: 'Unsafe String Input Handling', severity: 'medium', run: batchedPatterns30.checkUnsafeStringInput },
  { id: 'SOL823', name: 'Missing Pubkey Format Validation', severity: 'medium', run: batchedPatterns30.checkPubkeyFormatValidation },
  { id: 'SOL824', name: 'Unchecked Array Bounds Access', severity: 'high', run: batchedPatterns30.checkUncheckedArrayBounds },
  { id: 'SOL825', name: 'Missing Timestamp Range Validation', severity: 'medium', run: batchedPatterns30.checkTimestampRangeValidation },
  { id: 'SOL826', name: 'Missing BPS/Percentage Bounds', severity: 'high', run: batchedPatterns30.checkPercentageValidation },
  { id: 'SOL827', name: 'Missing Decimal Precision Handling', severity: 'high', run: batchedPatterns30.checkDecimalPrecisionHandling },
  { id: 'SOL828', name: 'Unsafe Borsh Deserialization', severity: 'high', run: batchedPatterns30.checkUnsafeBorshDeserialization },
  { id: 'SOL829', name: 'Non-Exhaustive Enum Matching', severity: 'medium', run: batchedPatterns30.checkEnumVariantValidation },
  { id: 'SOL830', name: 'Missing Negative Number Check', severity: 'high', run: batchedPatterns30.checkNegativeNumberCheck },
  { id: 'SOL831', name: 'Missing Instruction Discriminator', severity: 'high', run: batchedPatterns30.checkInstructionDiscriminatorValidation },
  { id: 'SOL832', name: 'Missing Remaining Data Check', severity: 'low', run: batchedPatterns30.checkRemainingDataCheck },
  { id: 'SOL833', name: 'Missing Account Lamport Validation', severity: 'medium', run: batchedPatterns30.checkAccountLamportValidation },
  { id: 'SOL834', name: 'Unsafe Vec Capacity Allocation', severity: 'high', run: batchedPatterns30.checkUnsafeVecCapacity },
  { id: 'SOL835', name: 'Missing Seed Length Validation', severity: 'medium', run: batchedPatterns30.checkSeedLengthValidation },
  { id: 'SOL836', name: 'Missing Account Executable Check', severity: 'high', run: batchedPatterns30.checkAccountExecutableCheck },
  
  // NEW PATTERNS SOL837-SOL852 (Feb 5 2026 6AM - Access Control from Sec3 2025)
  { id: 'SOL837', name: 'Missing Operator Role Validation', severity: 'high', run: batchedPatterns31.checkOperatorRoleValidation },
  { id: 'SOL838', name: 'Missing Governance Timelock', severity: 'high', run: batchedPatterns31.checkGovernanceTimelock },
  { id: 'SOL839', name: 'Missing Two-Step Ownership Transfer', severity: 'medium', run: batchedPatterns31.checkTwoStepOwnershipTransfer },
  { id: 'SOL840', name: 'Missing Guardian/Emergency Admin', severity: 'medium', run: batchedPatterns31.checkEmergencyAdmin },
  { id: 'SOL841', name: 'Missing Function Access Control', severity: 'high', run: batchedPatterns31.checkFunctionAccessModifier },
  { id: 'SOL842', name: 'Missing Upgrade Authority Renunciation', severity: 'medium', run: batchedPatterns31.checkUpgradeAuthorityRenunciation },
  { id: 'SOL843', name: 'Missing Rate Limiting', severity: 'medium', run: batchedPatterns31.checkMissingRateLimiting },
  { id: 'SOL844', name: 'Missing CPI Caller Validation', severity: 'high', run: batchedPatterns31.checkCpiCallerValidation },
  { id: 'SOL845', name: 'Missing PDA Authority Derivation', severity: 'critical', run: batchedPatterns31.checkPdaAuthorityDerivation },
  { id: 'SOL846', name: 'Missing Token Whitelist Check', severity: 'high', run: batchedPatterns31.checkWhitelistCheck },
  { id: 'SOL847', name: 'Missing Delegate Revocation', severity: 'medium', run: batchedPatterns31.checkDelegateRevocation },
  { id: 'SOL848', name: 'Missing Config Update Authorization', severity: 'critical', run: batchedPatterns31.checkConfigUpdateAuth },
  { id: 'SOL849', name: 'Missing Proposal Threshold', severity: 'medium', run: batchedPatterns31.checkProposalThreshold },
  { id: 'SOL850', name: 'Missing Execution Delay', severity: 'medium', run: batchedPatterns31.checkExecutionDelay },
  { id: 'SOL851', name: 'Missing Quorum Validation', severity: 'high', run: batchedPatterns31.checkQuorumValidation },
  { id: 'SOL852', name: 'Missing Vote Weight Snapshot', severity: 'high', run: batchedPatterns31.checkVoteWeightSnapshot },
  
  // NEW PATTERNS SOL853-SOL868 (Feb 5 2026 6:30AM - Helius Complete Exploit History)
  { id: 'SOL853', name: 'Audius-Style Governance Configuration Attack ($6.1M)', severity: 'critical', run: batchedPatterns32.checkAudiusStyleGovernanceAttack },
  { id: 'SOL854', name: 'OptiFi-Style Program Close Lockup ($661K)', severity: 'critical', run: batchedPatterns32.checkOptiFiStyleProgramClose },
  { id: 'SOL855', name: 'Mango-Style Oracle Price Manipulation ($116M)', severity: 'critical', run: batchedPatterns32.checkMangoStyleOracleManipulation },
  { id: 'SOL856', name: 'Slope-Style Private Key Exposure ($8M)', severity: 'critical', run: batchedPatterns32.checkSlopeStyleKeyExposure },
  { id: 'SOL857', name: 'Supply Chain NPM Dependency Attack', severity: 'high', run: batchedPatterns32.checkSupplyChainDependencyAttack },
  { id: 'SOL858', name: 'Pump.fun-Style Insider Exploitation ($1.9M)', severity: 'high', run: batchedPatterns32.checkInsiderExploitationRisk },
  { id: 'SOL859', name: 'Banana Gun-Style Bot Compromise ($1.4M)', severity: 'critical', run: batchedPatterns32.checkBotCompromiseRisk },
  { id: 'SOL860', name: 'DEXX-Style Centralized Key Management ($30M)', severity: 'critical', run: batchedPatterns32.checkDEXXStyleCentralizedKeys },
  { id: 'SOL861', name: 'Thunder Terminal-Style Database Injection ($240K)', severity: 'high', run: batchedPatterns32.checkThunderStyleDatabaseInjection },
  { id: 'SOL862', name: 'Raydium-Style Pool Admin Drain ($4.4M)', severity: 'critical', run: batchedPatterns32.checkRaydiumStylePoolDrain },
  { id: 'SOL863', name: 'Cypher-Style Insider Fund Theft ($317K)', severity: 'high', run: batchedPatterns32.checkCypherStyleInsiderTheft },
  { id: 'SOL864', name: 'Solareum-Style Rug Pull Detection', severity: 'critical', run: batchedPatterns32.checkSolareumStyleRugPull },
  { id: 'SOL865', name: 'Synthetify-Style DAO Treasury Heist ($230K)', severity: 'critical', run: batchedPatterns32.checkSynthetifyStyleDAOHeist },
  { id: 'SOL866', name: 'NoOnes-Style Withdrawal Verification Missing', severity: 'high', run: batchedPatterns32.checkNoOnesStyleWithdrawalExploit },
  { id: 'SOL867', name: 'Loopscale-Style Admin Wallet Takeover ($5.8M)', severity: 'critical', run: batchedPatterns32.checkLoopscaleAdminTakeover },
  { id: 'SOL868', name: 'Saga DAO-Style Insider Attack ($1.5M)', severity: 'high', run: batchedPatterns32.checkSagaDAOInsiderAttack },
  
  // NEW PATTERNS SOL869-SOL884 (Feb 5 2026 6:30AM - Network & Infrastructure Security)
  { id: 'SOL869', name: 'Network Congestion Attack Vulnerability', severity: 'medium', run: batchedPatterns33.checkNetworkCongestionAttack },
  { id: 'SOL870', name: 'Candy Machine-Style Minting DoS Risk', severity: 'high', run: batchedPatterns33.checkMintingDoSVulnerability },
  { id: 'SOL871', name: 'Jito-Style Bundle Spam DoS Risk', severity: 'medium', run: batchedPatterns33.checkBundleSpamDoS },
  { id: 'SOL872', name: 'Phantom-Style Wallet DoS via Malformed Data', severity: 'medium', run: batchedPatterns33.checkWalletDoSVulnerability },
  { id: 'SOL873', name: 'Turbine-Style Propagation Failure Risk', severity: 'high', run: batchedPatterns33.checkTurbinePropagationRisk },
  { id: 'SOL874', name: 'Durable Nonce Expiry Vulnerability', severity: 'medium', run: batchedPatterns33.checkDurableNonceExpiry },
  { id: 'SOL875', name: 'Duplicate Block Handling Vulnerability', severity: 'high', run: batchedPatterns33.checkDuplicateBlockHandling },
  { id: 'SOL876', name: 'JIT Cache Corruption Risk', severity: 'high', run: batchedPatterns33.checkJITCacheCorruption },
  { id: 'SOL877', name: 'ELF Address Alignment Vulnerability', severity: 'medium', run: batchedPatterns33.checkELFAlignmentExploit },
  { id: 'SOL878', name: 'Front-End Phishing Attack Risk (Parcl-style)', severity: 'high', run: batchedPatterns33.checkFrontEndPhishingRisk },
  { id: 'SOL879', name: 'Tulip-Style Flash Loan Vault Vulnerability', severity: 'critical', run: batchedPatterns33.checkTulipStyleFlashLoan },
  { id: 'SOL880', name: 'UXD-Style Stablecoin Depeg Risk', severity: 'high', run: batchedPatterns33.checkUXDStyleDepegRisk },
  { id: 'SOL881', name: 'SVT-Style Unclaimed Token Vulnerability', severity: 'medium', run: batchedPatterns33.checkSVTStyleUnclaimedVuln },
  { id: 'SOL882', name: 'io.net-Style API Key Exposure Risk', severity: 'high', run: batchedPatterns33.checkAPIKeyExposureRisk },
  { id: 'SOL883', name: 'Aurory-Style Game Marketplace Exploit', severity: 'high', run: batchedPatterns33.checkAuroryStyleExploit },
  { id: 'SOL884', name: 'Cross-Chain Message Verification Weakness', severity: 'critical', run: batchedPatterns33.checkCrossChainMessageVerification },
  
  // NEW PATTERNS SOL885-SOL904 (Feb 5 2026 7AM - Feb 2026 Latest Exploits & Security Research)
  { id: 'SOL885', name: 'Owner Permission Phishing Attack (Jan 2026)', severity: 'critical', run: batchedPatterns34.checkOwnerPermissionPhishing },
  { id: 'SOL886', name: 'Centralized Wallet Key Exposure (Step Finance $40M)', severity: 'critical', run: batchedPatterns34.checkCentralizedWalletStorage },
  { id: 'SOL887', name: 'Transaction Simulation Bypass Risk', severity: 'high', run: batchedPatterns34.checkSimulationBypassRisk },
  { id: 'SOL888', name: 'Hidden Authority Transfer Attack', severity: 'critical', run: batchedPatterns34.checkHiddenAuthorityTransfer },
  { id: 'SOL889', name: 'Withdrawal Verification Missing (NoOnes $8.5M)', severity: 'critical', run: batchedPatterns34.checkWithdrawalVerificationMissing },
  { id: 'SOL890', name: 'Social Engineering Attack Surface', severity: 'high', run: batchedPatterns34.checkSocialEngineeringAttackSurface },
  { id: 'SOL891', name: 'Key Equality Without Signer Verification', severity: 'critical', run: batchedPatterns34.checkMissingSignerPattern },
  { id: 'SOL892', name: 'Missing Account Data Relationship Validation', severity: 'high', run: batchedPatterns34.checkMissingAccountDataMatching },
  { id: 'SOL893', name: 'Non-Canonical PDA Bump Risk', severity: 'high', run: batchedPatterns34.checkNonCanonicalBump },
  { id: 'SOL894', name: 'Type Cosplay via Missing Discriminator', severity: 'critical', run: batchedPatterns34.checkMissingDiscriminatorCheck },
  { id: 'SOL895', name: 'Arithmetic Overflow Risk (Unchecked Math)', severity: 'high', run: batchedPatterns34.checkArithmeticOverflowRisk },
  { id: 'SOL896', name: 'Rent Exemption Not Verified', severity: 'medium', run: batchedPatterns34.checkRentExemptionNotVerified },
  { id: 'SOL897', name: 'Account Close to Unverified Destination', severity: 'high', run: batchedPatterns34.checkClosingAccountDestination },
  { id: 'SOL898', name: 'Arbitrary CPI Without Program Verification', severity: 'critical', run: batchedPatterns34.checkCpiProgramIdVerification },
  { id: 'SOL899', name: 'Account Revival Attack Vector', severity: 'high', run: batchedPatterns34.checkAccountRevivalVector },
  { id: 'SOL900', name: 'Flash Loan Oracle Manipulation (Mango $116M)', severity: 'critical', run: batchedPatterns34.checkFlashLoanOracleManipulation },
  { id: 'SOL901', name: 'Fund Obfuscation Risk (No Rate Limiting)', severity: 'high', run: batchedPatterns34.checkFundObfuscationPattern },
  { id: 'SOL902', name: 'Missing Emergency Pause Mechanism', severity: 'medium', run: batchedPatterns34.checkMissingEmergencyPause },
  { id: 'SOL903', name: 'Insufficient Event Logging for Forensics', severity: 'low', run: batchedPatterns34.checkInsufficientEventLogging },
  { id: 'SOL904', name: 'Cross-Program Reentrancy via CPI', severity: 'critical', run: batchedPatterns34.checkReentrancyViaCpi },
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
