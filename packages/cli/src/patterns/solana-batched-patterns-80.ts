/**
 * Batch 80: Helius Complete Exploit History + 2024-2025 Emerging Threats
 * Source: helius.dev/blog/solana-hacks, arxiv papers, security firm reports
 * Added: Feb 6, 2026 2:00 AM
 * Patterns: SOL4026-SOL4150
 */

import type { Finding } from './index.js';

interface ParsedRust {
  content: string;
  functions: Array<{ name: string; body: string; line: number }>;
  structs: Array<{ name: string; fields: string[]; line: number }>;
  impl_blocks: Array<{ name: string; methods: string[]; line: number }>;
  uses: string[];
  attributes: Array<{ name: string; line: number }>;
}

export function checkBatch80Patterns(parsed: ParsedRust, filePath: string): Finding[] {
  const findings: Finding[] = [];
  const content = parsed.content;
  const lines = content.split('\n');

  // === HELIUS COMPLETE HISTORY PATTERNS ===

  // SOL4026: Wormhole - verify_signatures Delegation Chain
  const hasVerifySignatures = /verify.*signature|signature.*verify/i.test(content);
  const hasDelegation = /delegate|call_signed|invoke.*signed/i.test(content);
  if (hasVerifySignatures && hasDelegation) {
    findings.push({
      id: 'SOL4026',
      title: 'Wormhole Pattern - Signature Verification Delegation Chain',
      severity: 'critical',
      description: '$320M Wormhole exploit: verify_signatures used deprecated Sysvar API allowing delegation bypass. Always verify complete signature chain.',
      location: { file: filePath, line: 1 },
      recommendation: 'Use current secp256k1 instruction for verification. Never trust delegated verification without complete chain validation.'
    });
  }

  // SOL4027: Cashio - Infinite Mint via Fake Bank
  const hasBankAccount = /bank|collateral_bank|backing_bank/i.test(content);
  const hasMintOperation = /mint_to|mint.*token/i.test(content);
  if (hasBankAccount && hasMintOperation) {
    const hasNoAccountValidation = !/validate.*bank|bank.*owner|trusted.*bank/i.test(content);
    if (hasNoAccountValidation) {
      findings.push({
        id: 'SOL4027',
        title: 'Cashio Pattern - Fake Bank Infinite Mint',
        severity: 'critical',
        description: '$52M Cashio exploit: attacker provided fake bank account to mint unlimited tokens. Validate all collateral account authenticity.',
        location: { file: filePath, line: 1 },
        recommendation: 'Validate bank/collateral accounts against known mints. Use PDA derivation for trusted accounts. Implement allowlists.'
      });
    }
  }

  // SOL4028: Mango Markets - Oracle Manipulation for Liquidation
  const hasOracleManipulation = /oracle|price_feed|pyth|switchboard/i.test(content);
  const hasBorrowOrLeverage = /borrow|leverage|collateral_ratio/i.test(content);
  if (hasOracleManipulation && hasBorrowOrLeverage) {
    const hasNoCircuitBreaker = !/circuit_breaker|max_deviation|price_limit/i.test(content);
    if (hasNoCircuitBreaker) {
      findings.push({
        id: 'SOL4028',
        title: 'Mango Markets Pattern - Oracle Price Manipulation',
        severity: 'critical',
        description: '$114M Mango exploit: Attacker manipulated illiquid token price via spot market to inflate collateral value and drain protocol.',
        location: { file: filePath, line: 1 },
        recommendation: 'Implement oracle deviation limits. Use TWAP not spot price. Add per-market borrow caps. Verify liquidity depth.'
      });
    }
  }

  // SOL4029: Crema Finance - Tick Account Spoofing
  const hasTickAccount = /tick|tick_array|position_tick/i.test(content);
  const hasLiquidityCalc = /liquidity|sqrt_price|amount.*token/i.test(content);
  if (hasTickAccount && hasLiquidityCalc) {
    const hasNoTickValidation = !/validate.*tick|tick.*owner|check.*tick/i.test(content);
    if (hasNoTickValidation) {
      findings.push({
        id: 'SOL4029',
        title: 'Crema Finance Pattern - Tick Account Spoofing',
        severity: 'critical',
        description: '$8.78M Crema exploit: Flash loaned to create fake tick accounts with inflated fee values for bogus fee claims.',
        location: { file: filePath, line: 1 },
        recommendation: 'Validate tick account ownership and derivation. Verify tick accounts are created through proper protocol flow.'
      });
    }
  }

  // SOL4030: Slope Wallet - Private Key Telemetry Leak
  const hasKeyLogging = /log|debug|console|telemetry/i.test(content);
  const hasPrivateKey = /private_key|secret_key|seed_phrase|mnemonic/i.test(content);
  if (hasKeyLogging && hasPrivateKey) {
    findings.push({
      id: 'SOL4030',
      title: 'Slope Wallet Pattern - Private Key Logging',
      severity: 'critical',
      description: '$8M Slope exploit: Wallet logged seed phrases in plaintext to centralized server. Never log sensitive key material.',
      location: { file: filePath, line: 1 },
      recommendation: 'Never log private keys, seeds, or mnemonics. Use secure enclaves. Audit all logging paths. Sanitize debug output.'
    });
  }

  // SOL4031: Cypher Protocol - Insider Access Abuse
  const hasAdminAccess = /admin|owner|authority/i.test(content);
  const hasTreasuryAccess = /treasury|vault|withdraw_all/i.test(content);
  if (hasAdminAccess && hasTreasuryAccess) {
    const hasNoTimelock = !/timelock|delay|multi_sig/i.test(content);
    if (hasNoTimelock) {
      findings.push({
        id: 'SOL4031',
        title: 'Cypher Protocol Pattern - Insider Treasury Access',
        severity: 'high',
        description: '$1.04M Cypher exploit: Rogue developer accessed treasury keys. Implement timelocks and multisig for admin actions.',
        location: { file: filePath, line: 1 },
        recommendation: 'Use multisig for all admin operations. Implement timelock on treasury withdrawals. Separate hot/cold key management.'
      });
    }
  }

  // SOL4032: OptiFi - Close Authority Missing Check
  const hasCloseAccount = /close|close_account|delete_account/i.test(content);
  const hasTvlAtRisk = /tvl|total_value|locked|staked/i.test(content);
  if (hasCloseAccount && hasTvlAtRisk) {
    const hasNoCloseCheck = !/can_close|is_empty|balance.*==.*0/i.test(content);
    if (hasNoCloseCheck) {
      findings.push({
        id: 'SOL4032',
        title: 'OptiFi Pattern - Unchecked Account Close',
        severity: 'critical',
        description: '$661K OptiFi lockup: Account closed while containing user funds. Always verify accounts are empty before closing.',
        location: { file: filePath, line: 1 },
        recommendation: 'Verify zero balance before close. Implement recovery mechanisms. Use drain-then-close pattern.'
      });
    }
  }

  // SOL4033: Synthetify DAO - Governance Proposal Attack
  const hasGovernanceProposal = /proposal|governance|vote/i.test(content);
  const hasQuorum = /quorum|threshold|minimum_votes/i.test(content);
  if (hasGovernanceProposal && hasQuorum) {
    const hasNoReviewPeriod = !/review_period|voting_period|delay/i.test(content);
    if (hasNoReviewPeriod) {
      findings.push({
        id: 'SOL4033',
        title: 'Synthetify DAO Pattern - Rushed Proposal Attack',
        severity: 'high',
        description: '$230K Synthetify: Malicious proposal executed before community review. Implement mandatory review periods.',
        location: { file: filePath, line: 1 },
        recommendation: 'Enforce minimum review period (24-72h). Implement proposal visibility requirements. Add grace period for execution.'
      });
    }
  }

  // SOL4034: Nirvana Finance - Bonding Curve Drain
  const hasBondingCurve = /bonding_curve|curve|price.*formula/i.test(content);
  const hasFlashLoan = /flash.*loan|borrow.*repay/i.test(content);
  if (hasBondingCurve && hasFlashLoan) {
    findings.push({
      id: 'SOL4034',
      title: 'Nirvana Finance Pattern - Bonding Curve Flash Loan Attack',
      severity: 'critical',
      description: '$3.49M Nirvana exploit: Flash loan used to drain bonding curve by exploiting price formula. Implement flash loan guards.',
      location: { file: filePath, line: 1 },
      recommendation: 'Add same-block swap limits. Implement anti-flash-loan checks. Use TWAP for curve pricing.'
    });
  }

  // SOL4035: Solend - Malicious Reserve Configuration
  const hasReserve = /reserve|lending_market|pool/i.test(content);
  const hasConfig = /config|parameter|setting/i.test(content);
  if (hasReserve && hasConfig) {
    const hasNoConfigValidation = !/validate.*config|check.*config|config.*range/i.test(content);
    if (hasNoConfigValidation) {
      findings.push({
        id: 'SOL4035',
        title: 'Solend Pattern - Malicious Reserve Configuration',
        severity: 'high',
        description: 'Solend incident: Malicious actors could create lending markets with harmful parameters. Validate all configuration values.',
        location: { file: filePath, line: 1 },
        recommendation: 'Implement configuration value ranges. Require governance approval for new markets. Use allowlists for supported assets.'
      });
    }
  }

  // SOL4036: Tulip Protocol - Vault Strategy Exploit
  const hasVaultStrategy = /strategy|vault|yield/i.test(content);
  const hasExternalProtocol = /cpi|invoke|external/i.test(content);
  if (hasVaultStrategy && hasExternalProtocol) {
    findings.push({
      id: 'SOL4036',
      title: 'Tulip Protocol Pattern - Vault Strategy Manipulation',
      severity: 'high',
      description: 'Yield vault strategies interacting with external protocols are vulnerable to composability exploits.',
      location: { file: filePath, line: 1 },
      recommendation: 'Validate external protocol states. Implement slippage protection for all external calls. Add strategy timeout checks.'
    });
  }

  // SOL4037: Parcl - Frontend Hijack
  const hasFrontend = /frontend|url|domain/i.test(content);
  const hasSigningRequest = /sign|approve|transaction/i.test(content);
  if (hasFrontend || hasSigningRequest) {
    findings.push({
      id: 'SOL4037',
      title: 'Parcl Pattern - Frontend Compromise Risk',
      severity: 'high',
      description: 'Parcl frontend compromised to serve malicious transaction requests. Implement content security and verification.',
      location: { file: filePath, line: 1 },
      recommendation: 'Use CSP headers. Implement transaction simulation display. Sign and verify frontend assets. Use multiple mirrors.'
    });
  }

  // SOL4038: Raydium - Admin Key Compromise
  const hasAdminKey = /admin|owner_authority|upgrade_authority/i.test(content);
  const hasProtocolControl = /pool|vault|treasury/i.test(content);
  if (hasAdminKey && hasProtocolControl) {
    findings.push({
      id: 'SOL4038',
      title: 'Raydium Pattern - Admin Key Compromise Impact',
      severity: 'critical',
      description: 'Raydium admin key compromise led to pool draining. Minimize admin powers. Implement timelocks.',
      location: { file: filePath, line: 1 },
      recommendation: 'Use multisig for admin keys. Implement timelocks on critical actions. Separate operational keys from upgrade keys.'
    });
  }

  // SOL4039: Saber - Wrapped Token Accounting
  const hasWrappedToken = /wrapped|synthetic|receipt/i.test(content);
  const hasAccounting = /balance|total_supply|mint.*burn/i.test(content);
  if (hasWrappedToken && hasAccounting) {
    findings.push({
      id: 'SOL4039',
      title: 'Saber Pattern - Wrapped Token Accounting Mismatch',
      severity: 'high',
      description: 'Wrapped token protocols must maintain 1:1 backing. Accounting errors can cause insolvency.',
      location: { file: filePath, line: 1 },
      recommendation: 'Implement invariant checks on every mint/burn. Use separate accounting for wrapped vs underlying. Add proof of reserves.'
    });
  }

  // SOL4040: UXD - Delta Neutral Hedging Failure
  const hasDeltaNeutral = /delta|hedge|perpetual|derivative/i.test(content);
  const hasRebalancing = /rebalance|adjust|maintain/i.test(content);
  if (hasDeltaNeutral && hasRebalancing) {
    findings.push({
      id: 'SOL4040',
      title: 'UXD Pattern - Delta Neutral Hedging Exposure',
      severity: 'high',
      description: 'Delta neutral strategies can fail during extreme market conditions. UXD faced depeg risk during Mango exploit.',
      location: { file: filePath, line: 1 },
      recommendation: 'Implement circuit breakers for extreme volatility. Diversify hedging counterparties. Add insurance fund buffer.'
    });
  }

  // === 2024-2025 EMERGING PATTERNS ===

  // SOL4041: DEXX - Private Key Storage Attack
  const hasKeyStorage = /store.*key|key.*storage|save.*private/i.test(content);
  const hasServerSide = /server|backend|api/i.test(content);
  if (hasKeyStorage && hasServerSide) {
    findings.push({
      id: 'SOL4041',
      title: 'DEXX Pattern - Server-Side Key Storage Breach',
      severity: 'critical',
      description: '$21M DEXX exploit (Nov 2024): Private keys stored server-side were compromised. Never store user keys on servers.',
      location: { file: filePath, line: 1 },
      recommendation: 'Use client-side key generation only. Implement hardware wallet support. Consider MPC for custodial needs.'
    });
  }

  // SOL4042: Pump.fun - Bonding Curve Insider Attack
  const hasPumpMechanic = /bonding|launch|fair_launch/i.test(content);
  const hasEmployeeAccess = /admin|employee|internal/i.test(content);
  if (hasPumpMechanic && hasEmployeeAccess) {
    findings.push({
      id: 'SOL4042',
      title: 'Pump.fun Pattern - Insider Launch Attack',
      severity: 'high',
      description: '$1.9M Pump.fun (May 2024): Employee exploited privileged access to extract bonding curve funds. Implement zero-trust internally.',
      location: { file: filePath, line: 1 },
      recommendation: 'Minimize internal privileged access. Implement audit trails. Use hardware keys for employee access. Background checks.'
    });
  }

  // SOL4043: Loopscale - Admin Authority Exploit
  const hasAdminAuthority = /authority|admin|super/i.test(content);
  const hasNoSeparation = !/separation|isolated|sandboxed/i.test(content);
  if (hasAdminAuthority && hasNoSeparation) {
    findings.push({
      id: 'SOL4043',
      title: 'Loopscale Pattern - Unseparated Admin Authority',
      severity: 'critical',
      description: '$5.7M Loopscale (Apr 2025): Single admin authority controlled all protocol functions. Implement separation of duties.',
      location: { file: filePath, line: 1 },
      recommendation: 'Separate upgrade, treasury, and operational authorities. Use different multisig sets. Implement timelocks per function type.'
    });
  }

  // SOL4044: Thunder Terminal - Session Key Misuse
  const hasSessionKey = /session.*key|temporary.*auth|api.*key/i.test(content);
  const hasExpiry = /expire|ttl|valid_until/i.test(content);
  if (hasSessionKey && !hasExpiry) {
    findings.push({
      id: 'SOL4044',
      title: 'Thunder Terminal Pattern - Non-Expiring Session Keys',
      severity: 'high',
      description: '$240K Thunder Terminal (Dec 2023): Session keys without expiry can be leaked and abused indefinitely.',
      location: { file: filePath, line: 1 },
      recommendation: 'Implement short-lived session keys. Add refresh mechanisms. Allow key revocation. Monitor for unusual patterns.'
    });
  }

  // SOL4045: Step Finance - Smart Contract Calculation Bug
  const hasStepCalculation = /step|increment|accumulator/i.test(content);
  const hasRewardCalculation = /reward|emission|distribute/i.test(content);
  if (hasStepCalculation && hasRewardCalculation) {
    findings.push({
      id: 'SOL4045',
      title: 'Step Finance Pattern - Reward Calculation Error',
      severity: 'high',
      description: 'Step Finance had calculation bugs in reward distribution. Audit all mathematical formulas thoroughly.',
      location: { file: filePath, line: 1 },
      recommendation: 'Use symbolic testing for math. Implement invariant checks. Compare on-chain vs expected values in tests.'
    });
  }

  // SOL4046-SOL4060: Supply Chain and Dependency Attacks

  // SOL4046: @solana/web3.js Backdoor Pattern
  const hasSolanaWeb3 = /@solana\/web3|solana-web3|web3\.js/i.test(content);
  const hasVersionPin = /exact.*version|locked|pinned/i.test(content);
  if (hasSolanaWeb3) {
    findings.push({
      id: 'SOL4046',
      title: 'Supply Chain - @solana/web3.js Backdoor Risk',
      severity: 'critical',
      description: 'Dec 2024: Compromised @solana/web3.js versions contained key-stealing backdoor. Pin dependencies and verify integrity.',
      location: { file: filePath, line: 1 },
      recommendation: 'Use lockfiles. Verify package checksums. Pin exact versions. Monitor for security advisories. Use npm audit.'
    });
  }

  // SOL4047: NPM Typosquatting Attack
  const hasNpmPackage = /require|import.*from/i.test(content);
  if (hasNpmPackage) {
    findings.push({
      id: 'SOL4047',
      title: 'Supply Chain - NPM Typosquatting Risk',
      severity: 'high',
      description: 'Typosquatted packages like "soIana" (capital I) vs "solana" trick developers. Verify package names carefully.',
      location: { file: filePath, line: 1 },
      recommendation: 'Double-check package names. Use verified publisher badges. Audit new dependencies. Implement allowlists.'
    });
  }

  // SOL4048: Anchor Dependency Mismatch
  const hasAnchor = /anchor|#\[program\]|#\[derive\(Accounts\)\]/i.test(content);
  const hasVersionMismatch = /version|^0\.|^1\./i.test(content);
  if (hasAnchor) {
    findings.push({
      id: 'SOL4048',
      title: 'Build Risk - Anchor Version Mismatch',
      severity: 'medium',
      description: 'Anchor CLI and project version mismatches can cause silent build issues and unexpected behavior.',
      location: { file: filePath, line: 1 },
      recommendation: 'Pin Anchor versions in CI. Use anchor verify for deployment. Document version requirements clearly.'
    });
  }

  // SOL4049: Rust Crate Backdoor
  const hasCrateImport = /use\s+\w+::/i.test(content);
  if (hasCrateImport) {
    findings.push({
      id: 'SOL4049',
      title: 'Supply Chain - Rust Crate Backdoor Risk',
      severity: 'high',
      description: 'Malicious crates can be published to crates.io. Audit all dependencies, especially new or rarely-used ones.',
      location: { file: filePath, line: 1 },
      recommendation: 'Review crate source. Use cargo-crev for trust chains. Pin exact versions with Cargo.lock. Regular cargo audit.'
    });
  }

  // SOL4050: Build Reproducibility Attack
  const hasBuildScript = /build\.rs|build_script/i.test(content);
  if (hasBuildScript) {
    findings.push({
      id: 'SOL4050',
      title: 'Build Attack - Non-Reproducible Builds',
      severity: 'medium',
      description: 'Non-reproducible builds allow malicious binaries to differ from source. Use verifiable builds.',
      location: { file: filePath, line: 1 },
      recommendation: 'Use solana-verify or anchor verify. Document build environment. Use deterministic builds with docker.'
    });
  }

  // SOL4051-SOL4070: MEV and Economic Attack Patterns

  // SOL4051: Jito Bundle Sandwich Attack
  const hasSwapExecution = /swap|exchange|trade/i.test(content);
  const hasSlippage = /slippage|min.*out|max.*in/i.test(content);
  if (hasSwapExecution && hasSlippage) {
    findings.push({
      id: 'SOL4051',
      title: 'MEV - Jito Bundle Sandwich Attack',
      severity: 'high',
      description: 'Solana MEV via Jito bundles enables sophisticated sandwich attacks. Implement robust slippage protection.',
      location: { file: filePath, line: 1 },
      recommendation: 'Use tight slippage. Consider private transaction pools. Implement MEV-aware routing. Add bundle detection.'
    });
  }

  // SOL4052: CU Auction Front-Running
  const hasPriorityFee = /priority_fee|compute_unit_price/i.test(content);
  if (hasPriorityFee) {
    findings.push({
      id: 'SOL4052',
      title: 'MEV - Compute Unit Auction Front-Running',
      severity: 'medium',
      description: 'High priority fee transactions are visible in mempool and can be front-run with higher fees.',
      location: { file: filePath, line: 1 },
      recommendation: 'Use commit-reveal for order-sensitive operations. Consider Jito private transactions. Design order-independent logic.'
    });
  }

  // SOL4053: Liquidation Racing
  const hasLiquidation = /liquidat|underwater|bad_debt/i.test(content);
  const hasIncentive = /bonus|discount|incentive/i.test(content);
  if (hasLiquidation && hasIncentive) {
    findings.push({
      id: 'SOL4053',
      title: 'MEV - Liquidation Racing',
      severity: 'medium',
      description: 'Liquidation incentives create racing conditions where searchers compete aggressively, sometimes causing protocol issues.',
      location: { file: filePath, line: 1 },
      recommendation: 'Use Dutch auction for liquidation incentives. Implement gradual liquidations. Add keeper rotation.'
    });
  }

  // SOL4054: Oracle Update Front-Running
  const hasOracleUpdate = /update.*price|price.*update|push.*price/i.test(content);
  if (hasOracleUpdate) {
    findings.push({
      id: 'SOL4054',
      title: 'MEV - Oracle Update Front-Running',
      severity: 'high',
      description: 'Pending oracle updates can be detected and front-run to profit from price movements.',
      location: { file: filePath, line: 1 },
      recommendation: 'Use confidential oracle updates. Implement commit-reveal. Add randomized update timing.'
    });
  }

  // SOL4055: NFT Mint Sniping
  const hasNftMint = /mint|nft|collection/i.test(content);
  const hasPublicMint = /public|open|anyone/i.test(content);
  if (hasNftMint && hasPublicMint) {
    findings.push({
      id: 'SOL4055',
      title: 'MEV - NFT Mint Sniping',
      severity: 'medium',
      description: 'Public NFT mints are vulnerable to bot sniping of rare traits using simulation attacks.',
      location: { file: filePath, line: 1 },
      recommendation: 'Use reveal mechanism. Implement fair randomness. Add bot protection (captcha, rate limits). Consider allowlists.'
    });
  }

  // SOL4056-SOL4070: Advanced Protocol Security

  // SOL4056: Perp DEX Funding Rate Attack
  const hasPerpetual = /perpetual|perp|futures/i.test(content);
  const hasFunding = /funding|rate|premium/i.test(content);
  if (hasPerpetual && hasFunding) {
    findings.push({
      id: 'SOL4056',
      title: 'Perp DEX - Funding Rate Manipulation',
      severity: 'high',
      description: 'Perpetual funding rates based on mark-index spread can be manipulated via concentrated position placement.',
      location: { file: filePath, line: 1 },
      recommendation: 'Cap maximum funding rate. Use multi-source price feeds. Implement anti-manipulation delays. Monitor unusual activity.'
    });
  }

  // SOL4057: AMM Virtual Reserves Drain
  const hasVirtualReserve = /virtual|k_invariant|constant_product/i.test(content);
  const hasReserveDrain = /drain|extract|remove.*liquidity/i.test(content);
  if (hasVirtualReserve || hasReserveDrain) {
    findings.push({
      id: 'SOL4057',
      title: 'AMM - Virtual Reserves Drain Attack',
      severity: 'high',
      description: 'AMMs with virtual reserves can be drained if reserve calculations dont properly account for edge cases.',
      location: { file: filePath, line: 1 },
      recommendation: 'Implement minimum liquidity. Add withdrawal rate limits. Verify invariant after every operation.'
    });
  }

  // SOL4058: Stake Pool Rebasing Attack
  const hasStakePool = /stake.*pool|liquid.*staking|lst/i.test(content);
  const hasRebasing = /rebase|adjust.*supply|reward.*distribution/i.test(content);
  if (hasStakePool && hasRebasing) {
    findings.push({
      id: 'SOL4058',
      title: 'Stake Pool - Rebasing Attack Vector',
      severity: 'high',
      description: 'Rebasing stake tokens can be exploited if rebase timing is predictable or manipulable.',
      location: { file: filePath, line: 1 },
      recommendation: 'Use non-rebasing receipt tokens (exchange rate model). Make rebase timing unpredictable. Add rate limiters.'
    });
  }

  // SOL4059: Bridge Replay Attack
  const hasBridge = /bridge|cross.*chain|wormhole|layerzero/i.test(content);
  const hasNonce = /nonce|sequence|message_id/i.test(content);
  if (hasBridge && !hasNonce) {
    findings.push({
      id: 'SOL4059',
      title: 'Bridge - Message Replay Attack',
      severity: 'critical',
      description: 'Cross-chain messages without nonces can be replayed for double-spending across chains.',
      location: { file: filePath, line: 1 },
      recommendation: 'Include incrementing nonce in all bridge messages. Verify nonce progression. Implement replay protection per chain pair.'
    });
  }

  // SOL4060: Intent-Based Protocol Solver Collusion
  const hasIntent = /intent|order|rfq/i.test(content);
  const hasSolver = /solver|filler|market_maker/i.test(content);
  if (hasIntent && hasSolver) {
    findings.push({
      id: 'SOL4060',
      title: 'Intent Protocol - Solver Collusion Risk',
      severity: 'medium',
      description: 'Intent-based protocols can suffer from solver collusion to provide suboptimal fills.',
      location: { file: filePath, line: 1 },
      recommendation: 'Implement solver reputation system. Use competitive auctions. Add price benchmarks. Allow user price limits.'
    });
  }

  // SOL4061-SOL4080: Wallet and Client Security

  // SOL4061: Wallet Simulation Mismatch
  const hasSimulation = /simulat|preflight|dry_run/i.test(content);
  const hasExecution = /send|execute|submit/i.test(content);
  if (hasSimulation && hasExecution) {
    findings.push({
      id: 'SOL4061',
      title: 'Wallet - Simulation vs Execution Mismatch',
      severity: 'high',
      description: 'Transactions can produce different results between simulation and execution due to state changes.',
      location: { file: filePath, line: 1 },
      recommendation: 'Show simulation warnings to users. Use recent blockhash. Implement transaction preview verification.'
    });
  }

  // SOL4062: Blind Signing Attack
  const hasSignRequest = /sign|approve/i.test(content);
  const hasNoPreview = !/preview|display|show.*transaction/i.test(content);
  if (hasSignRequest && hasNoPreview) {
    findings.push({
      id: 'SOL4062',
      title: 'Wallet - Blind Signing Attack',
      severity: 'high',
      description: 'Users signing transactions without clear preview can be tricked into malicious approvals.',
      location: { file: filePath, line: 1 },
      recommendation: 'Always show transaction effects before signing. Implement human-readable transaction parsing. Add risk warnings.'
    });
  }

  // SOL4063: Connection Hijacking
  const hasWalletConnect = /connect|wallet.*connect|adapter/i.test(content);
  const hasSession = /session|connection|link/i.test(content);
  if (hasWalletConnect && hasSession) {
    findings.push({
      id: 'SOL4063',
      title: 'Wallet - Connection Hijacking',
      severity: 'medium',
      description: 'Wallet connections can be hijacked if session keys are exposed or connection is unencrypted.',
      location: { file: filePath, line: 1 },
      recommendation: 'Use encrypted connections. Implement session timeouts. Show connected apps clearly. Allow easy disconnection.'
    });
  }

  // SOL4064: Message Signing Phishing
  const hasMessageSign = /sign_message|personal_sign/i.test(content);
  if (hasMessageSign) {
    findings.push({
      id: 'SOL4064',
      title: 'Wallet - Message Signing Phishing',
      severity: 'medium',
      description: 'Signed messages can be used for off-chain authorization. Phishing sites can trick users into signing malicious messages.',
      location: { file: filePath, line: 1 },
      recommendation: 'Show clear message content before signing. Implement domain-specific prefixes. Warn on unusual messages.'
    });
  }

  // SOL4065: Multiple Wallet Confusion
  const hasMultiWallet = /wallet|account|keypair/i.test(content);
  const hasSelection = /select|choose|switch/i.test(content);
  if (hasMultiWallet && hasSelection) {
    findings.push({
      id: 'SOL4065',
      title: 'UX Security - Multiple Wallet Confusion',
      severity: 'low',
      description: 'Users with multiple wallets can accidentally sign with wrong wallet, sending from unintended accounts.',
      location: { file: filePath, line: 1 },
      recommendation: 'Display active wallet clearly. Confirm wallet selection before signing. Use visual wallet identifiers.'
    });
  }

  // SOL4066-SOL4080: DeFi Composability Risks

  // SOL4066: Flash Loan Arbitrage Loop
  const hasFlashLoan2 = /flash.*loan|flashloan/i.test(content);
  const hasArbitrage = /arbitrage|arb|profit/i.test(content);
  if (hasFlashLoan2 && hasArbitrage) {
    findings.push({
      id: 'SOL4066',
      title: 'DeFi Composability - Flash Loan Arbitrage Impact',
      severity: 'medium',
      description: 'Flash loan arbitrage can extract value from protocol inefficiencies, sometimes destabilizing pools.',
      location: { file: filePath, line: 1 },
      recommendation: 'Design arbitrage-resistant pricing. Implement gradual price updates. Consider MEV auction mechanisms.'
    });
  }

  // SOL4067: Composability Reentrancy
  const hasComposableCpi = /invoke|cpi|call/i.test(content);
  const hasStateUpdate = /state|account.*=|data\./i.test(content);
  if (hasComposableCpi && hasStateUpdate) {
    findings.push({
      id: 'SOL4067',
      title: 'DeFi Composability - Cross-Protocol Reentrancy',
      severity: 'high',
      description: 'CPI to external protocols can trigger callbacks that reenter your protocol in unexpected state.',
      location: { file: filePath, line: 1 },
      recommendation: 'Use checks-effects-interactions pattern. Implement reentrancy guards. Complete state updates before CPI.'
    });
  }

  // SOL4068: Collateral Factor Mismatch
  const hasCollateralFactor = /collateral.*factor|ltv|loan_to_value/i.test(content);
  const hasMultiAsset = /multi.*asset|mixed.*collateral/i.test(content);
  if (hasCollateralFactor && hasMultiAsset) {
    findings.push({
      id: 'SOL4068',
      title: 'Lending - Collateral Factor Correlation Risk',
      severity: 'high',
      description: 'Correlated assets used as collateral may crash together, making collateral factors insufficient.',
      location: { file: filePath, line: 1 },
      recommendation: 'Adjust LTV for correlated assets. Implement correlation monitoring. Use portfolio-based risk assessment.'
    });
  }

  // SOL4069: Protocol Fee Extraction
  const hasProtocolFee = /fee|protocol_fee|treasury_fee/i.test(content);
  const hasFeeCalculation = /calculate.*fee|fee.*percent/i.test(content);
  if (hasProtocolFee && hasFeeCalculation) {
    findings.push({
      id: 'SOL4069',
      title: 'DeFi - Protocol Fee Extraction Attack',
      severity: 'medium',
      description: 'Fee calculation edge cases can be exploited to minimize fees paid or maximize fees received.',
      location: { file: filePath, line: 1 },
      recommendation: 'Use fixed-point math for fees. Implement minimum fee thresholds. Audit fee paths for gaming.'
    });
  }

  // SOL4070: Liquidity Fragmentation Attack
  const hasLiquidity = /liquidity|pool|amm/i.test(content);
  const hasMultiPool = /pool.*pool|migrate|split/i.test(content);
  if (hasLiquidity && hasMultiPool) {
    findings.push({
      id: 'SOL4070',
      title: 'AMM - Liquidity Fragmentation Attack',
      severity: 'medium',
      description: 'Splitting liquidity across many pools can degrade trading efficiency and enable manipulation.',
      location: { file: filePath, line: 1 },
      recommendation: 'Implement pool routing aggregation. Add minimum liquidity requirements. Consider pool consolidation incentives.'
    });
  }

  // SOL4071-SOL4100: Advanced Patterns

  // SOL4071: Token-2022 Interest-Bearing Token Attack
  const hasInterestBearing = /interest|accrued|rate.*bearing/i.test(content);
  const hasToken2022 = /spl_token_2022|token.*extension/i.test(content);
  if (hasInterestBearing || hasToken2022) {
    findings.push({
      id: 'SOL4071',
      title: 'Token-2022 - Interest-Bearing Token Exploitation',
      severity: 'high',
      description: 'Interest-bearing tokens accumulate value over time. DeFi integrations must handle interest accrual correctly.',
      location: { file: filePath, line: 1 },
      recommendation: 'Query current amount including interest. Account for interest in pricing. Test with various interest rates.'
    });
  }

  // SOL4072: Permanent Delegate Abuse
  const hasPermanentDelegate = /permanent.*delegate|delegate.*permanent/i.test(content);
  if (hasPermanentDelegate) {
    findings.push({
      id: 'SOL4072',
      title: 'Token-2022 - Permanent Delegate Abuse',
      severity: 'critical',
      description: 'Permanent delegates can transfer any token amount without owner approval. Extremely dangerous if compromised.',
      location: { file: filePath, line: 1 },
      recommendation: 'Avoid permanent delegates for user tokens. Use for protocol-controlled tokens only. Document risks clearly.'
    });
  }

  // SOL4073: Non-Transferable Token Bypass
  const hasNonTransferable = /non.*transfer|soulbound|locked/i.test(content);
  const hasTransferCheck = /can.*transfer|is.*transferable/i.test(content);
  if (hasNonTransferable && !hasTransferCheck) {
    findings.push({
      id: 'SOL4073',
      title: 'Token-2022 - Non-Transferable Token Bypass',
      severity: 'medium',
      description: 'Non-transferable tokens should block all transfer paths including CPI. Missing checks allow bypasses.',
      location: { file: filePath, line: 1 },
      recommendation: 'Use token-2022 non-transferable extension. Verify no alternative transfer paths exist.'
    });
  }

  // SOL4074: Memo Required Validation Skip
  const hasMemoRequired = /memo.*required|require.*memo/i.test(content);
  if (hasMemoRequired) {
    findings.push({
      id: 'SOL4074',
      title: 'Token-2022 - Memo Requirement Bypass',
      severity: 'low',
      description: 'Memo-required tokens can have compliance issues if CPI transfers skip memo attachment.',
      location: { file: filePath, line: 1 },
      recommendation: 'Verify memo is attached in all transfer paths. Test CPI transfer compliance.'
    });
  }

  // SOL4075: Default Account State Exploitation
  const hasDefaultState = /default.*state|frozen|initial.*state/i.test(content);
  if (hasDefaultState) {
    findings.push({
      id: 'SOL4075',
      title: 'Token-2022 - Default Account State Issues',
      severity: 'medium',
      description: 'Default frozen state can cause UX issues. Protocols must handle thaw correctly.',
      location: { file: filePath, line: 1 },
      recommendation: 'Implement automatic thaw flow. Document frozen state handling. Test integration with frozen accounts.'
    });
  }

  // SOL4076-SOL4085: Governance and DAO Security

  // SOL4076: Proposal Griefing Attack
  const hasProposal = /proposal|vote|governance/i.test(content);
  const hasSpamProtection = /deposit|stake.*vote|cooldown/i.test(content);
  if (hasProposal && !hasSpamProtection) {
    findings.push({
      id: 'SOL4076',
      title: 'Governance - Proposal Griefing Attack',
      severity: 'medium',
      description: 'Without proposal costs, attackers can spam proposals to exhaust voter attention.',
      location: { file: filePath, line: 1 },
      recommendation: 'Require proposal deposit. Implement proposal limits. Add proposal quality thresholds.'
    });
  }

  // SOL4077: Vote Buying via Delegation
  const hasVoteDelegation = /delegate|delegation|voting_power/i.test(content);
  if (hasVoteDelegation) {
    findings.push({
      id: 'SOL4077',
      title: 'Governance - Vote Buying via Delegation',
      severity: 'medium',
      description: 'Delegation systems can enable vote buying through off-chain agreements for delegation.',
      location: { file: filePath, line: 1 },
      recommendation: 'Consider delegation lock periods. Implement transparent delegation tracking. Add anti-sybil measures.'
    });
  }

  // SOL4078: Emergency Action Abuse
  const hasEmergency = /emergency|urgent|immediate/i.test(content);
  const hasNoTimelock = !/timelock|delay|waiting/i.test(content);
  if (hasEmergency && hasNoTimelock) {
    findings.push({
      id: 'SOL4078',
      title: 'Governance - Emergency Action Abuse',
      severity: 'high',
      description: 'Emergency powers without limits can be abused to bypass normal governance.',
      location: { file: filePath, line: 1 },
      recommendation: 'Limit emergency actions scope. Require multi-party approval. Implement automatic expiry.'
    });
  }

  // SOL4079: Quorum Manipulation
  const hasGovQuorum = /quorum|threshold|minimum.*vote/i.test(content);
  const hasDynamicQuorum = /dynamic|adaptive|adjusted/i.test(content);
  if (hasGovQuorum && !hasDynamicQuorum) {
    findings.push({
      id: 'SOL4079',
      title: 'Governance - Static Quorum Manipulation',
      severity: 'medium',
      description: 'Static quorum can become too high (paralysis) or too low (attack) as participation changes.',
      location: { file: filePath, line: 1 },
      recommendation: 'Implement adaptive quorum. Track participation trends. Allow quorum updates via governance.'
    });
  }

  // SOL4080: Token Holder Snapshot Timing
  const hasSnapshot = /snapshot|checkpoint|at_block/i.test(content);
  if (hasSnapshot) {
    findings.push({
      id: 'SOL4080',
      title: 'Governance - Snapshot Timing Exploitation',
      severity: 'medium',
      description: 'Known snapshot times allow accumulating voting power just before snapshot, then selling after.',
      location: { file: filePath, line: 1 },
      recommendation: 'Use random snapshot delays. Implement time-weighted voting. Consider lock requirements.'
    });
  }

  // SOL4081-SOL4100: Emerging 2026 Patterns

  // SOL4081: AI Agent Transaction Injection
  const hasAiAgent = /agent|bot|automat/i.test(content);
  const hasTransactionBuild = /build.*tx|create.*transaction/i.test(content);
  if (hasAiAgent && hasTransactionBuild) {
    findings.push({
      id: 'SOL4081',
      title: '2026 Pattern - AI Agent Transaction Injection',
      severity: 'high',
      description: 'AI agents building transactions can be manipulated via prompt injection to create malicious transactions.',
      location: { file: filePath, line: 1 },
      recommendation: 'Validate all agent-built transactions. Implement spending limits. Use allowlist for transaction types.'
    });
  }

  // SOL4082: LLM Oracle Manipulation
  const hasLlmOracle = /llm|gpt|claude|ai.*oracle/i.test(content);
  if (hasLlmOracle) {
    findings.push({
      id: 'SOL4082',
      title: '2026 Pattern - LLM Oracle Manipulation',
      severity: 'critical',
      description: 'AI/LLM-based oracles can be manipulated via adversarial inputs or prompt injection.',
      location: { file: filePath, line: 1 },
      recommendation: 'Never use LLM output for financial decisions. Implement sanity checks. Use traditional oracles for prices.'
    });
  }

  // SOL4083: Modular Account Abstraction Exploit
  const hasAccountAbstraction = /account.*abstraction|smart.*account|module/i.test(content);
  if (hasAccountAbstraction) {
    findings.push({
      id: 'SOL4083',
      title: '2026 Pattern - Modular Account Exploit',
      severity: 'high',
      description: 'Modular smart accounts can have vulnerabilities in module interactions or permission systems.',
      location: { file: filePath, line: 1 },
      recommendation: 'Audit module interactions. Implement module allowlists. Use permission scoping. Test upgrade paths.'
    });
  }

  // SOL4084: Restaking Slashing Cascade
  const hasRestaking = /restaking|restake|shared.*security/i.test(content);
  const hasSlashing = /slash|penalty|punish/i.test(content);
  if (hasRestaking && hasSlashing) {
    findings.push({
      id: 'SOL4084',
      title: '2026 Pattern - Restaking Slashing Cascade',
      severity: 'high',
      description: 'Restaking across multiple protocols can cause cascade slashing if one protocol has an incident.',
      location: { file: filePath, line: 1 },
      recommendation: 'Implement slashing caps. Diversify restaking across uncorrelated protocols. Add circuit breakers.'
    });
  }

  // SOL4085: Intents MEV Extraction
  const hasIntents = /intent|order|user.*preference/i.test(content);
  const hasFiller = /filler|solver|executor/i.test(content);
  if (hasIntents && hasFiller) {
    findings.push({
      id: 'SOL4085',
      title: '2026 Pattern - Intent-Based MEV Extraction',
      severity: 'medium',
      description: 'Intent-based systems can leak MEV to fillers/solvers who have information advantage.',
      location: { file: filePath, line: 1 },
      recommendation: 'Implement fair ordering. Use encrypted intents. Add user-specified MEV protection.'
    });
  }

  // SOL4086: Points/Airdrop Gaming
  const hasPoints = /points|airdrop|reward.*distribution/i.test(content);
  const hasActivity = /activity|volume|interaction/i.test(content);
  if (hasPoints && hasActivity) {
    findings.push({
      id: 'SOL4086',
      title: '2026 Pattern - Points/Airdrop Gaming',
      severity: 'low',
      description: 'Points systems based on activity metrics can be gamed via wash trading or Sybil attacks.',
      location: { file: filePath, line: 1 },
      recommendation: 'Use Sybil-resistant metrics. Implement velocity limits. Consider proof-of-personhood.'
    });
  }

  // SOL4087: Compressed State Proof Attack
  const hasCompressedState = /compressed.*state|state.*compression|zk.*proof/i.test(content);
  if (hasCompressedState) {
    findings.push({
      id: 'SOL4087',
      title: '2026 Pattern - Compressed State Proof Attack',
      severity: 'high',
      description: 'State compression using ZK proofs can have vulnerabilities in proof generation or verification.',
      location: { file: filePath, line: 1 },
      recommendation: 'Use audited ZK circuits. Verify proofs on-chain. Implement fallback to uncompressed state.'
    });
  }

  // SOL4088: Cross-Rollup Message Attack
  const hasCrossRollup = /rollup|l2|svm/i.test(content);
  const hasMessage = /message|relay|bridge/i.test(content);
  if (hasCrossRollup && hasMessage) {
    findings.push({
      id: 'SOL4088',
      title: '2026 Pattern - Cross-Rollup Message Attack',
      severity: 'critical',
      description: 'Messages between Solana rollups/L2s can be forged or replayed if not properly secured.',
      location: { file: filePath, line: 1 },
      recommendation: 'Verify message authenticity via state proofs. Implement nonces per rollup pair. Add message expiry.'
    });
  }

  // SOL4089: Real-World Asset Tokenization Fraud
  const hasRwa = /rwa|real.*world.*asset|tokeniz/i.test(content);
  if (hasRwa) {
    findings.push({
      id: 'SOL4089',
      title: '2026 Pattern - RWA Tokenization Fraud Risk',
      severity: 'high',
      description: 'Real-world asset tokens depend on off-chain custody and verification which can be falsified.',
      location: { file: filePath, line: 1 },
      recommendation: 'Implement proof of reserves. Use trusted custodians. Add oracle-based verification. Consider insurance.'
    });
  }

  // SOL4090-SOL4100: Infrastructure Patterns

  // SOL4090: Validator Client Divergence
  const hasValidator = /validator|consensus|vote/i.test(content);
  if (hasValidator) {
    findings.push({
      id: 'SOL4090',
      title: 'Infrastructure - Validator Client Divergence Risk',
      severity: 'medium',
      description: 'Different validator clients may have subtle differences causing consensus issues.',
      location: { file: filePath, line: 1 },
      recommendation: 'Test against all major clients. Monitor client distribution. Participate in testnet.'
    });
  }

  // SOL4091: Compute Market Manipulation
  const hasComputeMarket = /compute|resource|allocation/i.test(content);
  const hasAuction = /auction|bid|priority/i.test(content);
  if (hasComputeMarket && hasAuction) {
    findings.push({
      id: 'SOL4091',
      title: 'Infrastructure - Compute Market Manipulation',
      severity: 'medium',
      description: 'Compute resource auctions can be manipulated to block legitimate transactions.',
      location: { file: filePath, line: 1 },
      recommendation: 'Implement fair scheduling. Add compute reservation. Monitor for manipulation patterns.'
    });
  }

  // SOL4092: Leader Schedule Exploitation
  const hasLeaderSchedule = /leader|slot.*schedule|producer/i.test(content);
  if (hasLeaderSchedule) {
    findings.push({
      id: 'SOL4092',
      title: 'Infrastructure - Leader Schedule Exploitation',
      severity: 'low',
      description: 'Known leader schedules allow timing attacks and targeted MEV strategies.',
      location: { file: filePath, line: 1 },
      recommendation: 'Design for worst-case leader behavior. Implement timeout handling. Use randomized submission.'
    });
  }

  // SOL4093: Turbine Propagation Attack
  const hasTurbine = /turbine|shred|propagation/i.test(content);
  if (hasTurbine) {
    findings.push({
      id: 'SOL4093',
      title: 'Infrastructure - Turbine Propagation Attack',
      severity: 'medium',
      description: 'Turbine block propagation can be disrupted by malicious nodes causing network delays.',
      location: { file: filePath, line: 1 },
      recommendation: 'Monitor propagation health. Implement fallback mechanisms. Diversify node connections.'
    });
  }

  // SOL4094: Gossip Network Poisoning
  const hasGossip = /gossip|peer|discovery/i.test(content);
  if (hasGossip) {
    findings.push({
      id: 'SOL4094',
      title: 'Infrastructure - Gossip Network Poisoning',
      severity: 'medium',
      description: 'Gossip protocol can be poisoned with malicious peer information.',
      location: { file: filePath, line: 1 },
      recommendation: 'Implement peer reputation. Use verified entry points. Monitor for anomalous peers.'
    });
  }

  // SOL4095: RPC Rate Limit Bypass
  const hasRpcRateLimit = /rate.*limit|throttle|limit.*request/i.test(content);
  if (hasRpcRateLimit) {
    findings.push({
      id: 'SOL4095',
      title: 'Infrastructure - RPC Rate Limit Bypass',
      severity: 'low',
      description: 'RPC rate limits can be bypassed using multiple endpoints or IP rotation.',
      location: { file: filePath, line: 1 },
      recommendation: 'Implement application-level rate limiting. Use authenticated RPC. Monitor usage patterns.'
    });
  }

  // SOL4096: Account Data Size DoS
  const hasAccountSize = /account.*size|data.*length|space/i.test(content);
  const hasUserInput = /user|input|external/i.test(content);
  if (hasAccountSize && hasUserInput) {
    findings.push({
      id: 'SOL4096',
      title: 'Infrastructure - Account Data Size DoS',
      severity: 'medium',
      description: 'Allowing users to control account data size can cause compute/rent issues.',
      location: { file: filePath, line: 1 },
      recommendation: 'Set maximum data sizes. Charge proportionally for storage. Implement size validation.'
    });
  }

  // SOL4097: Clock Drift Exploitation
  const hasClockUsage = /Clock::get|unix_timestamp|current_time/i.test(content);
  const hasTimeSensitive = /expire|deadline|valid_until/i.test(content);
  if (hasClockUsage && hasTimeSensitive) {
    findings.push({
      id: 'SOL4097',
      title: 'Infrastructure - Clock Drift Exploitation',
      severity: 'low',
      description: 'Clock sysvar can drift from real time. Time-sensitive logic must account for drift.',
      location: { file: filePath, line: 1 },
      recommendation: 'Add tolerance for clock drift. Use slots for ordering when possible. Avoid tight time constraints.'
    });
  }

  // SOL4098: Transaction Size Limit Gaming
  const hasTxSize = /transaction.*size|tx.*limit|instruction.*count/i.test(content);
  if (hasTxSize) {
    findings.push({
      id: 'SOL4098',
      title: 'Infrastructure - Transaction Size Limit Gaming',
      severity: 'low',
      description: 'Complex operations near transaction size limits may fail unexpectedly.',
      location: { file: filePath, line: 1 },
      recommendation: 'Design for worst-case transaction sizes. Implement batching for large operations. Use ALTs for address compression.'
    });
  }

  // SOL4099: Cross-Program Data Poisoning
  const hasCrossProgram = /cross.*program|cpi|invoke/i.test(content);
  const hasDataRead = /read|load|deserialize/i.test(content);
  if (hasCrossProgram && hasDataRead) {
    findings.push({
      id: 'SOL4099',
      title: 'Infrastructure - Cross-Program Data Poisoning',
      severity: 'high',
      description: 'Data read from cross-program accounts should be treated as untrusted until validated.',
      location: { file: filePath, line: 1 },
      recommendation: 'Validate all cross-program data. Verify account ownership before reading. Check discriminators.'
    });
  }

  // SOL4100: Program Deploy Race Condition
  const hasDeploy = /deploy|upgrade|buffer/i.test(content);
  const hasRace = /concurrent|parallel|simultaneous/i.test(content);
  if (hasDeploy || hasRace) {
    findings.push({
      id: 'SOL4100',
      title: 'Infrastructure - Program Deploy Race Condition',
      severity: 'medium',
      description: 'Program upgrades can create race conditions with in-flight transactions.',
      location: { file: filePath, line: 1 },
      recommendation: 'Coordinate upgrades with pause mechanism. Implement version checks. Use graceful migration patterns.'
    });
  }

  return findings;
}
