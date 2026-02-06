/**
 * Batch 69: February 2026 Deep Security Patterns
 * Enhanced patterns based on comprehensive exploit analysis
 * Patterns: SOL3076-SOL3150
 */

import type { PatternInput, Finding } from './index.js';

function createFinding(
  id: string,
  title: string,
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info',
  description: string,
  location: { file: string; line?: number },
  recommendation?: string
): Finding {
  return { id, title, severity, description, location, recommendation };
}

/**
 * SOL3076: Solend UpdateReserveConfig Authentication Bypass
 * Based on Aug 2021 Solend exploit - $2M at risk
 */
function checkSolendAuthBypass(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  
  const content = input.rust.content;
  
  // Check for lending market authority validation
  if (content.includes('update_reserve') || content.includes('UpdateReserveConfig')) {
    if (!content.includes('lending_market_authority') || 
        !content.includes('has_one = lending_market_owner')) {
      findings.push(createFinding(
        'SOL3076',
        'Lending Market Authority Bypass Risk',
        'critical',
        'UpdateReserveConfig without proper lending market authority validation. Attacker can create fake lending market and bypass admin checks.',
        { file: input.path },
        'Validate lending_market_owner against trusted lending_market account, not user-provided account'
      ));
    }
  }
  
  return findings;
}

/**
 * SOL3077: Liquidation Threshold Manipulation
 * Based on Solend attack - manipulated thresholds to force liquidations
 */
function checkLiquidationThresholdManipulation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  
  const content = input.rust.content;
  
  if (content.includes('liquidation_threshold') && content.includes('set') || content.includes('update')) {
    if (!content.includes('timelock') && !content.includes('delay')) {
      findings.push(createFinding(
        'SOL3077',
        'Liquidation Threshold Instant Update Risk',
        'high',
        'Liquidation threshold changes without timelock can instantly make user positions liquidatable.',
        { file: input.path },
        'Add timelock delay for liquidation threshold changes to give users time to adjust positions'
      ));
    }
  }
  
  return findings;
}

/**
 * SOL3078: Liquidation Bonus Inflation Attack
 * Based on Solend - attacker inflated bonus to 100% profit on liquidations
 */
function checkLiquidationBonusInflation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  
  const content = input.rust.content;
  
  if (content.includes('liquidation_bonus')) {
    // Check for max bounds
    if (!content.includes('max_liquidation_bonus') && !content.includes('MAX_BONUS')) {
      findings.push(createFinding(
        'SOL3078',
        'Unbounded Liquidation Bonus',
        'high',
        'Liquidation bonus without maximum cap can be inflated to extract excessive value from liquidated positions.',
        { file: input.path },
        'Set maximum liquidation bonus cap (typically 10-20%) and validate in update functions'
      ));
    }
  }
  
  return findings;
}

/**
 * SOL3079: Wormhole Guardian Signature Verification Bypass
 * Based on $326M Wormhole exploit - signature verification flaw
 */
function checkGuardianSignatureBypass(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  
  const content = input.rust.content;
  
  // Check for signature verification patterns
  if (content.includes('verify_signature') || content.includes('guardian')) {
    if (content.includes('external') || content.includes('unchecked') || 
        !content.includes('solana_program::secp256k1_recover')) {
      findings.push(createFinding(
        'SOL3079',
        'External Signature Verification Risk',
        'critical',
        'Signature verification using external contracts can be bypassed by forging inputs. Wormhole lost $326M due to this.',
        { file: input.path },
        'Use native Solana secp256k1 verification, not external contract calls that can be spoofed'
      ));
    }
  }
  
  return findings;
}

/**
 * SOL3080: VAA (Verifiable Action Approval) Spoofing
 * Based on Wormhole - attacker fabricated valid-looking VAAs
 */
function checkVAASpoofing(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  
  const content = input.rust.content;
  
  if (content.includes('vaa') || content.includes('VAA') || content.includes('message')) {
    // Check for proper guardian count validation
    if (!content.includes('guardian_set') || !content.includes('quorum')) {
      findings.push(createFinding(
        'SOL3080',
        'Cross-Chain Message Verification Missing',
        'critical',
        'Cross-chain messages (VAAs) must verify against guardian quorum. Missing validation enables message spoofing.',
        { file: input.path },
        'Verify message against current guardian set with proper quorum (2/3+ guardians)'
      ));
    }
  }
  
  return findings;
}

/**
 * SOL3081: Deprecated verify_signatures_address Function
 * Wormhole used deprecated function that could be bypassed
 */
function checkDeprecatedVerifySignatures(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  
  if (input.rust.content.includes('verify_signatures_address')) {
    findings.push(createFinding(
      'SOL3081',
      'Deprecated Signature Verification Function',
      'critical',
      'verify_signatures_address is deprecated and can be bypassed. Wormhole $326M exploit used this.',
      { file: input.path },
      'Use current Solana native signature verification methods instead of deprecated functions'
    ));
  }
  
  return findings;
}

/**
 * SOL3082: Infinite Mint via Collateral Validation Bypass (Cashio)
 * Based on $52.8M Cashio exploit
 */
function checkInfiniteMintCollateral(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  
  const content = input.rust.content;
  
  // Check for mint operations with collateral
  if ((content.includes('mint') || content.includes('Mint')) && 
      (content.includes('collateral') || content.includes('backing'))) {
    // Missing validation patterns
    if (!content.includes('validate_collateral') && 
        !content.includes('verify_backing') &&
        !content.includes('collateral_mint ==')) {
      findings.push(createFinding(
        'SOL3082',
        'Collateral Validation Missing on Mint',
        'critical',
        'Minting without proper collateral validation enables infinite mint attacks. Cashio lost $52.8M to this.',
        { file: input.path },
        'Validate collateral mint address and amount match expected backing before any mint operation'
      ));
    }
  }
  
  return findings;
}

/**
 * SOL3083: Nested Account Trust Chain Bypass
 * Cashio allowed fake accounts that referenced other fake accounts
 */
function checkNestedAccountTrust(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  
  const content = input.rust.content;
  
  // Check for LP token or nested collateral
  if (content.includes('lp_token') || content.includes('underlying') || content.includes('nested')) {
    if (!content.includes('root_of_trust') && !content.includes('trusted_program')) {
      findings.push(createFinding(
        'SOL3083',
        'Nested Account Trust Chain Vulnerability',
        'critical',
        'Nested account references (LP tokens, wrapped assets) need root of trust validation to prevent fake account chains.',
        { file: input.path },
        'Establish root of trust - verify all accounts in chain trace back to trusted program/mint'
      ));
    }
  }
  
  return findings;
}

/**
 * SOL3084: Saber LP Token Validation Bypass
 * Cashio failed to validate Saber LP token authenticity
 */
function checkLPTokenValidation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  
  const content = input.rust.content;
  
  if (content.includes('lp_token') || content.includes('LP') || content.includes('pool_token')) {
    if (!content.includes('pool_program') && !content.includes('amm_id') && 
        !content.includes('validate_lp_mint')) {
      findings.push(createFinding(
        'SOL3084',
        'LP Token Authenticity Not Verified',
        'critical',
        'LP tokens must be validated against their source AMM/pool program. Fake LP tokens can bypass collateral checks.',
        { file: input.path },
        'Verify LP token mint was created by the claimed AMM program and matches expected pool'
      ));
    }
  }
  
  return findings;
}

/**
 * SOL3085: Crema CLMM Fake Tick Account Attack
 * Based on $8.8M Crema exploit - fake tick accounts
 */
function checkFakeTickAccount(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  
  const content = input.rust.content;
  
  if (content.includes('tick') || content.includes('Tick') || content.includes('position')) {
    if (!content.includes('tick_account.owner') && !content.includes('validate_tick_owner')) {
      findings.push(createFinding(
        'SOL3085',
        'CLMM Tick Account Owner Not Verified',
        'critical',
        'Tick accounts in CLMM protocols must verify owner is the pool program. Fake tick accounts enabled Crema $8.8M exploit.',
        { file: input.path },
        'Verify tick account owner matches pool program ID before reading tick data'
      ));
    }
  }
  
  return findings;
}

/**
 * SOL3086: Fee Accumulator Manipulation
 * Crema exploit manipulated fee accumulator data
 */
function checkFeeAccumulatorManipulation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  
  const content = input.rust.content;
  
  if (content.includes('fee') && (content.includes('accumulator') || content.includes('growth'))) {
    if (!content.includes('validate_fee_source') && !content.includes('fee_account.owner')) {
      findings.push(createFinding(
        'SOL3086',
        'Fee Accumulator Source Not Validated',
        'high',
        'Fee accumulator data must come from verified accounts. Manipulated fee data enabled excessive fee claims.',
        { file: input.path },
        'Validate fee accumulator account ownership and derive from trusted pool state'
      ));
    }
  }
  
  return findings;
}

/**
 * SOL3087: Flash Loan Fee Claim Amplification
 * Crema attacker used flash loans to amplify fee claims
 */
function checkFlashLoanFeeClaim(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  
  const content = input.rust.content;
  
  if (content.includes('claim_fee') || content.includes('collect_fees')) {
    if (!content.includes('flash_loan_guard') && !content.includes('same_slot_check')) {
      findings.push(createFinding(
        'SOL3087',
        'Fee Claim Vulnerable to Flash Loan Attack',
        'high',
        'Fee claims without flash loan protection can be amplified using borrowed liquidity within same transaction.',
        { file: input.path },
        'Add flash loan guards - check position age, slot-based cooling periods, or cumulative claim limits'
      ));
    }
  }
  
  return findings;
}

/**
 * SOL3088: Mango Markets Self-Trading Oracle Manipulation
 * Based on $116M Mango exploit - self-trading to move oracle
 */
function checkSelfTradingOracle(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  
  const content = input.rust.content;
  
  if (content.includes('oracle') && (content.includes('perp') || content.includes('market'))) {
    if (!content.includes('twap') && !content.includes('external_oracle')) {
      findings.push(createFinding(
        'SOL3088',
        'On-Chain Oracle Vulnerable to Self-Trading',
        'critical',
        'On-chain oracles based on trade prices can be manipulated via self-trading. Mango lost $116M to this attack.',
        { file: input.path },
        'Use external oracles (Pyth, Switchboard) with TWAP, or implement trade-based manipulation detection'
      ));
    }
  }
  
  return findings;
}

/**
 * SOL3089: Unrealized PnL Collateral Exploit
 * Mango allowed unrealized PnL as collateral, enabling infinite leverage
 */
function checkUnrealizedPnLCollateral(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  
  const content = input.rust.content;
  
  if (content.includes('unrealized') || content.includes('pnl') || content.includes('PnL')) {
    if (content.includes('collateral') || content.includes('borrow')) {
      if (!content.includes('realized_only') && !content.includes('pnl_discount')) {
        findings.push(createFinding(
          'SOL3089',
          'Unrealized PnL Used as Full Collateral',
          'critical',
          'Unrealized PnL as full collateral enables infinite leverage via self-trading. Apply discount or require realization.',
          { file: input.path },
          'Discount unrealized PnL significantly (50%+) or exclude from borrowing power entirely'
        ));
      }
    }
  }
  
  return findings;
}

/**
 * SOL3090: Position Concentration Limit Missing
 * Mango had no limit on position size relative to market liquidity
 */
function checkPositionConcentration(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  
  const content = input.rust.content;
  
  if (content.includes('position') && (content.includes('open') || content.includes('increase'))) {
    if (!content.includes('max_position') && !content.includes('position_limit') && 
        !content.includes('concentration_limit')) {
      findings.push(createFinding(
        'SOL3090',
        'No Position Concentration Limits',
        'high',
        'Missing position limits allow single user to dominate market and manipulate prices. Implement position caps.',
        { file: input.path },
        'Add maximum position size relative to pool liquidity (e.g., max 10% of open interest)'
      ));
    }
  }
  
  return findings;
}

/**
 * SOL3091: Slope Wallet Seed Phrase Logging
 * Based on $8M Slope exploit - seed phrases sent to telemetry
 */
function checkSeedPhraseLogging(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  
  const content = input.rust.content;
  
  // Check for logging near sensitive key material
  if ((content.includes('seed') || content.includes('mnemonic') || content.includes('private_key')) &&
      (content.includes('log') || content.includes('println') || content.includes('msg!'))) {
    findings.push(createFinding(
      'SOL3091',
      'Potential Key Material Logging',
      'critical',
      'Logging near key material operations. Slope wallet leaked $8M by logging seed phrases to telemetry.',
      { file: input.path },
      'Never log or transmit seed phrases, private keys, or any key derivation material'
    ));
  }
  
  return findings;
}

/**
 * SOL3092: Unencrypted Key Storage
 * Slope stored keys unencrypted in Sentry
 */
function checkUnencryptedKeyStorage(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  
  const content = input.rust.content;
  
  if (content.includes('store') && (content.includes('key') || content.includes('secret'))) {
    if (!content.includes('encrypt') && !content.includes('cipher') && !content.includes('sealed')) {
      findings.push(createFinding(
        'SOL3092',
        'Key Storage Without Encryption',
        'critical',
        'Storing keys without encryption enables theft if storage is compromised. Always encrypt sensitive material.',
        { file: input.path },
        'Use authenticated encryption (ChaCha20-Poly1305, AES-GCM) for all key storage'
      ));
    }
  }
  
  return findings;
}

/**
 * SOL3093: Telemetry Including Sensitive Data
 * Slope sent sensitive data to Sentry
 */
function checkTelemetrySensitiveData(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  
  const content = input.rust.content;
  
  if (content.includes('sentry') || content.includes('telemetry') || content.includes('analytics')) {
    if (content.includes('user') || content.includes('account') || content.includes('wallet')) {
      findings.push(createFinding(
        'SOL3093',
        'Telemetry May Include Sensitive User Data',
        'high',
        'Telemetry services near user/wallet data can leak sensitive information. Slope leaked seeds via Sentry.',
        { file: input.path },
        'Strictly filter telemetry - never include keys, seeds, signatures, or user-identifying wallet data'
      ));
    }
  }
  
  return findings;
}

/**
 * SOL3094: Audius Governance Proposal Validation Bypass
 * Based on $6.1M Audius exploit
 */
function checkGovernanceProposalValidation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  
  const content = input.rust.content;
  
  if (content.includes('proposal') && (content.includes('execute') || content.includes('submit'))) {
    if (!content.includes('validate_proposal') && !content.includes('proposal_check')) {
      findings.push(createFinding(
        'SOL3094',
        'Governance Proposal Validation Missing',
        'critical',
        'Proposals without proper validation can execute malicious instructions. Audius lost $6.1M to this.',
        { file: input.path },
        'Validate proposal instructions against allowlist, check signer permissions, add execution delay'
      ));
    }
  }
  
  return findings;
}

/**
 * SOL3095: Treasury Permission Reconfiguration Attack
 * Audius attacker reconfigured treasury permissions
 */
function checkTreasuryPermissionChange(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  
  const content = input.rust.content;
  
  if (content.includes('treasury') && (content.includes('permission') || content.includes('authority'))) {
    if (!content.includes('timelock') && !content.includes('multi_sig')) {
      findings.push(createFinding(
        'SOL3095',
        'Treasury Permission Changes Without Timelock',
        'critical',
        'Treasury permission changes need timelocks and multisig. Instant changes enable governance attacks.',
        { file: input.path },
        'Require timelock (7+ days) and multisig for any treasury permission modifications'
      ));
    }
  }
  
  return findings;
}

/**
 * SOL3096: Nirvana Bonding Curve Flash Loan Attack
 * Based on $3.5M Nirvana exploit
 */
function checkBondingCurveFlashLoan(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  
  const content = input.rust.content;
  
  if (content.includes('bonding_curve') || content.includes('pricing_curve')) {
    if (!content.includes('flash_loan_protection') && !content.includes('cooldown')) {
      findings.push(createFinding(
        'SOL3096',
        'Bonding Curve Vulnerable to Flash Loan',
        'critical',
        'Bonding curves without flash loan protection can be exploited to mint at manipulated rates. Nirvana lost $3.5M.',
        { file: input.path },
        'Add time-based cooldowns between large buys/sells, or use TWAP-based pricing'
      ));
    }
  }
  
  return findings;
}

/**
 * SOL3097: OptiFi Program Close with Funds
 * Based on $661K OptiFi incident - accidental fund lockup
 */
function checkProgramCloseWithFunds(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  
  const content = input.rust.content;
  
  if (content.includes('close') && content.includes('program')) {
    if (!content.includes('withdraw_all') && !content.includes('funds_check')) {
      findings.push(createFinding(
        'SOL3097',
        'Program Close Without Fund Check',
        'critical',
        'Program close operations must verify all funds are withdrawn first. OptiFi locked $661K by closing with funds inside.',
        { file: input.path },
        'Require zero balance check or automatic withdrawal before any program/account closure'
      ));
    }
  }
  
  return findings;
}

/**
 * SOL3098: Irreversible Action Without Confirmation
 * OptiFi close was irreversible
 */
function checkIrreversibleAction(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  
  const content = input.rust.content;
  
  const irreversibleActions = ['close', 'destroy', 'terminate', 'delete', 'burn_all'];
  for (const action of irreversibleActions) {
    if (content.includes(action)) {
      if (!content.includes('confirmation') && !content.includes('two_step')) {
        findings.push(createFinding(
          'SOL3098',
          'Irreversible Action Without Safeguard',
          'high',
          `Irreversible action "${action}" without two-step confirmation. Add confirmation mechanism to prevent accidents.`,
          { file: input.path },
          'Implement two-step confirmation: initiate action, then confirm after delay'
        ));
        break;
      }
    }
  }
  
  return findings;
}

/**
 * SOL3099: DEXX Hot Wallet Key Exposure
 * Based on $30M DEXX exploit
 */
function checkHotWalletExposure(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  
  const content = input.rust.content;
  
  if (content.includes('hot_wallet') || content.includes('custodial')) {
    if (!content.includes('hsm') && !content.includes('mpc') && !content.includes('cold_storage')) {
      findings.push(createFinding(
        'SOL3099',
        'Hot Wallet Without HSM/MPC Protection',
        'critical',
        'Hot wallets storing significant funds need HSM or MPC protection. DEXX lost $30M via exposed hot wallet keys.',
        { file: input.path },
        'Use HSM for key storage, MPC for signing, and implement cold storage thresholds'
      ));
    }
  }
  
  return findings;
}

/**
 * SOL3100: Commingled User Funds
 * DEXX stored user funds in shared wallets
 */
function checkCommingledFunds(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  
  const content = input.rust.content;
  
  if (content.includes('deposit') && content.includes('user')) {
    if (!content.includes('user_account') && content.includes('pool') || content.includes('shared')) {
      findings.push(createFinding(
        'SOL3100',
        'User Funds May Be Commingled',
        'high',
        'User deposits into shared pools without individual accounting can lead to fund attribution issues and theft.',
        { file: input.path },
        'Use individual user accounts or precise share accounting for deposited funds'
      ));
    }
  }
  
  return findings;
}

/**
 * SOL3101: Pump.fun Insider Employee Exploit
 * Based on $1.9M Pump.fun incident
 */
function checkInsiderAccessControls(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  
  const content = input.rust.content;
  
  if (content.includes('admin') || content.includes('operator') || content.includes('employee')) {
    if (!content.includes('multi_sig') && !content.includes('time_lock')) {
      findings.push(createFinding(
        'SOL3101',
        'Privileged Role Without Multi-Sig',
        'high',
        'Privileged roles (admin/operator) without multi-sig enable insider attacks. Pump.fun lost $1.9M to employee.',
        { file: input.path },
        'Require multi-sig (2-of-3 minimum) for all privileged operations'
      ));
    }
  }
  
  return findings;
}

/**
 * SOL3102: Privileged Transaction Monitoring
 * Pump.fun had no monitoring for privileged txs
 */
function checkPrivilegedMonitoring(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  
  const content = input.rust.content;
  
  if (content.includes('admin') && (content.includes('withdraw') || content.includes('transfer'))) {
    if (!content.includes('emit!') && !content.includes('event')) {
      findings.push(createFinding(
        'SOL3102',
        'Privileged Operations Not Emitting Events',
        'medium',
        'Privileged operations should emit events for monitoring. Silent admin actions enable undetected insider abuse.',
        { file: input.path },
        'Emit events for all privileged operations to enable real-time monitoring and alerting'
      ));
    }
  }
  
  return findings;
}

/**
 * SOL3103: Thunder Terminal MongoDB Injection
 * Based on $240K Thunder Terminal exploit
 */
function checkDatabaseInjection(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  
  const content = input.rust.content;
  
  if (content.includes('query') || content.includes('database') || content.includes('db')) {
    if (!content.includes('sanitize') && !content.includes('parameterized')) {
      findings.push(createFinding(
        'SOL3103',
        'Database Query Without Sanitization',
        'high',
        'Database queries without input sanitization enable injection attacks. Thunder Terminal lost $240K to MongoDB injection.',
        { file: input.path },
        'Use parameterized queries and input sanitization for all database operations'
      ));
    }
  }
  
  return findings;
}

/**
 * SOL3104: Session Token Security
 * Thunder Terminal had session management issues
 */
function checkSessionTokenSecurity(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  
  const content = input.rust.content;
  
  if (content.includes('session') || content.includes('token') && content.includes('auth')) {
    if (!content.includes('expire') && !content.includes('rotate')) {
      findings.push(createFinding(
        'SOL3104',
        'Session Tokens Without Expiration/Rotation',
        'medium',
        'Session tokens need expiration and rotation. Long-lived tokens increase theft window.',
        { file: input.path },
        'Implement short session expiration (24h), automatic rotation, and invalidation on suspicious activity'
      ));
    }
  }
  
  return findings;
}

/**
 * SOL3105: Banana Gun Trading Bot Private Key Storage
 * Based on $1.4M Banana Gun exploit
 */
function checkTradingBotKeyStorage(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  
  const content = input.rust.content;
  
  if (content.includes('bot') && (content.includes('key') || content.includes('wallet'))) {
    if (!content.includes('encrypted') && !content.includes('secure_enclave')) {
      findings.push(createFinding(
        'SOL3105',
        'Trading Bot Keys Without Secure Storage',
        'critical',
        'Trading bot private keys need encrypted/enclave storage. Banana Gun lost $1.4M via exposed keys.',
        { file: input.path },
        'Use hardware enclaves or encrypted storage with access controls for bot signing keys'
      ));
    }
  }
  
  return findings;
}

/**
 * SOL3106: Solareum Bot Payment Exploit
 * Based on $500K+ Solareum incident
 */
function checkBotPaymentValidation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  
  const content = input.rust.content;
  
  if (content.includes('payment') && content.includes('bot')) {
    if (!content.includes('verify_payment') && !content.includes('receipt')) {
      findings.push(createFinding(
        'SOL3106',
        'Bot Payment Without Verification',
        'high',
        'Automated payments need verification before processing. Solareum lost $500K+ to payment exploitation.',
        { file: input.path },
        'Verify payment confirmation before executing any automated transactions'
      ));
    }
  }
  
  return findings;
}

/**
 * SOL3107: Cypher Protocol Sub-Account Isolation
 * Based on $1.35M Cypher insider theft
 */
function checkSubAccountIsolation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  
  const content = input.rust.content;
  
  if (content.includes('sub_account') || content.includes('subaccount')) {
    if (!content.includes('isolation') && !content.includes('access_control')) {
      findings.push(createFinding(
        'SOL3107',
        'Sub-Account Isolation Not Enforced',
        'high',
        'Sub-accounts need strict isolation and access controls. Cypher lost $1.35M via sub-account access bypass.',
        { file: input.path },
        'Enforce strict sub-account isolation with explicit permission grants per sub-account'
      ));
    }
  }
  
  return findings;
}

/**
 * SOL3108: io.net Sybil GPU Attack Pattern
 * Based on io.net fake GPU incident
 */
function checkSybilProtection(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  
  const content = input.rust.content;
  
  if (content.includes('node') || content.includes('provider') || content.includes('worker')) {
    if (!content.includes('stake') && !content.includes('verification') && !content.includes('proof')) {
      findings.push(createFinding(
        'SOL3108',
        'Node/Provider Without Sybil Protection',
        'high',
        'Node registration without stake or verification enables Sybil attacks. io.net was attacked with fake GPUs.',
        { file: input.path },
        'Require stake deposit, hardware verification, or proof-of-work for node registration'
      ));
    }
  }
  
  return findings;
}

/**
 * SOL3109: SVT Token Honeypot Pattern
 * CertiK detected SVT honeypot
 */
function checkHoneypotSellRestriction(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  
  const content = input.rust.content;
  
  // Check for asymmetric transfer restrictions
  if (content.includes('transfer') && content.includes('restrict')) {
    if (content.includes('buy') && !content.includes('sell_allowed')) {
      findings.push(createFinding(
        'SOL3109',
        'Potential Honeypot - Asymmetric Transfer Restrictions',
        'critical',
        'Transfer restrictions that allow buying but restrict selling indicate honeypot. SVT token used this pattern.',
        { file: input.path },
        'Ensure transfer restrictions apply equally to buys and sells, or flag for review'
      ));
    }
  }
  
  return findings;
}

/**
 * SOL3110: Saga DAO Governance Attack
 * Based on $230K Saga DAO incident
 */
function checkUnnoticedProposal(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  
  const content = input.rust.content;
  
  if (content.includes('proposal') && content.includes('execute')) {
    if (!content.includes('notice_period') && !content.includes('voting_period')) {
      findings.push(createFinding(
        'SOL3110',
        'Proposal Without Notice Period',
        'high',
        'Proposals need notice periods to allow community review. Saga DAO lost $230K to unnoticed attack proposal.',
        { file: input.path },
        'Implement minimum notice period (72h+) and voting duration before proposal execution'
      ));
    }
  }
  
  return findings;
}

/**
 * SOL3111: Web3.js Supply Chain Key Exfiltration
 * Based on $164K Web3.js compromise
 */
function checkSupplyChainKeyExfiltration(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  
  const content = input.rust.content;
  
  if (content.includes('import') || content.includes('require') || content.includes('dependency')) {
    if (content.includes('sign') || content.includes('key')) {
      findings.push(createFinding(
        'SOL3111',
        'External Dependency Near Signing Logic',
        'medium',
        'External dependencies near signing logic can be compromised. Web3.js supply chain attack stole $164K.',
        { file: input.path },
        'Audit dependencies near signing code, use lockfiles, verify package integrity'
      ));
    }
  }
  
  return findings;
}

/**
 * SOL3112: Parcl Front-End Phishing
 * CDN compromise enabled phishing
 */
function checkFrontendIntegrity(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  
  // This is more of a web security pattern but noting it
  const content = input.rust.content;
  
  if (content.includes('frontend') || content.includes('web') || content.includes('ui')) {
    findings.push(createFinding(
      'SOL3112',
      'Frontend Security Consideration',
      'info',
      'Frontend compromises (CDN, DNS) can redirect users to phishing sites. Parcl was affected by front-end attack.',
      { file: input.path },
      'Use Subresource Integrity (SRI), secure DNS (DNSSEC), and educate users to verify contract addresses'
    ));
  }
  
  return findings;
}

/**
 * SOL3113-3115: Network DoS Patterns (Jito, Phantom, Grape, Candy Machine)
 */
function checkNetworkDoSVulnerability(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  
  const content = input.rust.content;
  
  // Check for unbounded loops/iterations
  if (content.includes('loop') || content.includes('while') || content.includes('for')) {
    if (!content.includes('limit') && !content.includes('max_iterations')) {
      findings.push(createFinding(
        'SOL3113',
        'Unbounded Loop DoS Risk',
        'high',
        'Unbounded loops can be exploited for DoS attacks. Grape, Candy Machine saw network-level DoS from such patterns.',
        { file: input.path },
        'Add iteration limits and compute budget checks to prevent DoS via resource exhaustion'
      ));
    }
  }
  
  // Check for spam-able operations
  if (content.includes('create') || content.includes('mint') || content.includes('register')) {
    if (!content.includes('rate_limit') && !content.includes('fee')) {
      findings.push(createFinding(
        'SOL3114',
        'Spam-able Operation Without Rate Limiting',
        'medium',
        'Operations without rate limiting or meaningful fees can be spammed. Candy Machine zero-fee mints caused network issues.',
        { file: input.path },
        'Add rate limiting, minimum fees, or stake requirements for spam-able operations'
      ));
    }
  }
  
  return findings;
}

/**
 * SOL3115: Core Protocol - JIT Cache Bug Pattern
 */
function checkJITCacheVulnerability(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  
  const content = input.rust.content;
  
  if (content.includes('cache') && content.includes('jit') || content.includes('compiled')) {
    if (!content.includes('invalidate') && !content.includes('version_check')) {
      findings.push(createFinding(
        'SOL3115',
        'JIT/Cache Invalidation Missing',
        'high',
        'JIT compilation or caching without proper invalidation can cause state inconsistency. Solana had 5h outage from JIT cache bug.',
        { file: input.path },
        'Implement proper cache invalidation and version checking for compiled/cached code'
      ));
    }
  }
  
  return findings;
}

/**
 * SOL3116: Loopscale PT Token Pricing Flaw
 * Based on $5.8M Loopscale exploit (April 2025)
 */
function checkPTTokenPricing(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  
  const content = input.rust.content;
  
  if (content.includes('pt_token') || content.includes('principal_token') || content.includes('yield_token')) {
    if (!content.includes('validate_pricing') && !content.includes('oracle_check')) {
      findings.push(createFinding(
        'SOL3116',
        'Yield Token Pricing Validation Missing',
        'critical',
        'PT/YT token pricing must be validated against oracle. Loopscale lost $5.8M to PT token pricing manipulation.',
        { file: input.path },
        'Validate principal/yield token prices against external oracles with sanity bounds'
      ));
    }
  }
  
  return findings;
}

/**
 * SOL3117: Undercollateralization via Flash Loan
 * Loopscale attacker undercollateralized using flash loans
 */
function checkFlashLoanCollateralization(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  
  const content = input.rust.content;
  
  if (content.includes('collateral') && (content.includes('borrow') || content.includes('loan'))) {
    if (!content.includes('snapshot') && !content.includes('pre_flash')) {
      findings.push(createFinding(
        'SOL3117',
        'Collateralization Check Vulnerable to Flash Loan',
        'critical',
        'Collateral checks within single transaction can be bypassed with flash loans. Check collateral before flash loan context.',
        { file: input.path },
        'Take collateral snapshots before flash loan context or use time-delayed collateral verification'
      ));
    }
  }
  
  return findings;
}

/**
 * SOL3118: White Hat Recovery Capability
 * Loopscale successfully negotiated return of funds
 */
function checkWhiteHatRecovery(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  
  const content = input.rust.content;
  
  if (content.includes('admin') || content.includes('pause') || content.includes('emergency')) {
    // Check for recovery mechanisms
    if (!content.includes('recovery') && !content.includes('freeze')) {
      findings.push(createFinding(
        'SOL3118',
        'No Emergency Recovery Mechanism',
        'medium',
        'Emergency recovery mechanisms help negotiate with white hats. Loopscale recovered $5.8M through negotiation.',
        { file: input.path },
        'Implement pause/freeze capability and clear bounty communication channels for white hat recovery'
      ));
    }
  }
  
  return findings;
}

/**
 * SOL3119-3125: Additional Advanced Patterns
 */
function checkAdvancedSecurityPatterns(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;
  
  const content = input.rust.content;
  
  // SOL3119: Circuit Breaker Pattern
  if (content.includes('withdraw') || content.includes('transfer')) {
    if (!content.includes('circuit_breaker') && !content.includes('max_daily')) {
      findings.push(createFinding(
        'SOL3119',
        'No Circuit Breaker for Large Operations',
        'medium',
        'Large withdrawals/transfers should trigger circuit breakers. Implement daily limits and anomaly detection.',
        { file: input.path },
        'Add daily withdrawal limits and pause on anomalous activity'
      ));
    }
  }
  
  // SOL3120: Cross-Contract Reentrancy
  if (content.includes('invoke') && content.includes('callback')) {
    if (!content.includes('reentrancy_guard') && !content.includes('entered')) {
      findings.push(createFinding(
        'SOL3120',
        'Cross-Contract Reentrancy Risk',
        'high',
        'CPI invocations with callbacks can enable cross-contract reentrancy. Use reentrancy guards.',
        { file: input.path },
        'Implement reentrancy guard pattern: check-effects-interactions and state locks'
      ));
    }
  }
  
  // SOL3121: Arithmetic in Fee Calculations
  if (content.includes('fee') && (content.includes('/') || content.includes('div'))) {
    if (!content.includes('checked') && !content.includes('saturating')) {
      findings.push(createFinding(
        'SOL3121',
        'Unchecked Arithmetic in Fee Calculation',
        'high',
        'Fee calculations with division can truncate to zero on small amounts, causing fee bypass.',
        { file: input.path },
        'Use checked arithmetic and ensure minimum fees cannot be bypassed via small amounts'
      ));
    }
  }
  
  // SOL3122: Time-Based Access Control
  if (content.includes('time') && content.includes('access') || content.includes('unlock')) {
    if (!content.includes('clock::Clock') && content.includes('sysvar')) {
      findings.push(createFinding(
        'SOL3122',
        'Time-Based Logic Without Proper Clock Source',
        'medium',
        'Time-based logic should use Solana Clock sysvar, not custom timestamps that could be manipulated.',
        { file: input.path },
        'Use Clock::get()?.unix_timestamp for all time-based logic'
      ));
    }
  }
  
  // SOL3123: Versioned Transaction Compatibility
  if (content.includes('transaction') && content.includes('version')) {
    if (!content.includes('v0') && !content.includes('legacy_check')) {
      findings.push(createFinding(
        'SOL3123',
        'Transaction Version Handling',
        'low',
        'Ensure compatibility with both legacy and versioned (v0) transactions for wide client support.',
        { file: input.path },
        'Handle both legacy and versioned transaction formats appropriately'
      ));
    }
  }
  
  // SOL3124: Address Lookup Table Security
  if (content.includes('lookup_table') || content.includes('AddressLookupTable')) {
    if (!content.includes('validate_lookup') && !content.includes('trusted_table')) {
      findings.push(createFinding(
        'SOL3124',
        'Address Lookup Table Without Validation',
        'high',
        'Lookup tables can be poisoned with malicious addresses. Validate lookup table contents.',
        { file: input.path },
        'Verify lookup table ownership and validate resolved addresses against expected accounts'
      ));
    }
  }
  
  // SOL3125: Priority Fee Manipulation
  if (content.includes('priority') && content.includes('fee')) {
    findings.push(createFinding(
      'SOL3125',
      'Priority Fee Handling',
      'info',
      'Priority fees can be used for MEV extraction. Ensure users understand fee implications.',
      { file: input.path },
      'Document priority fee behavior and consider implementing fair ordering mechanisms'
    ));
  }
  
  return findings;
}

// Export all check functions
export function checkBatch69Patterns(input: PatternInput): Finding[] {
  return [
    ...checkSolendAuthBypass(input),
    ...checkLiquidationThresholdManipulation(input),
    ...checkLiquidationBonusInflation(input),
    ...checkGuardianSignatureBypass(input),
    ...checkVAASpoofing(input),
    ...checkDeprecatedVerifySignatures(input),
    ...checkInfiniteMintCollateral(input),
    ...checkNestedAccountTrust(input),
    ...checkLPTokenValidation(input),
    ...checkFakeTickAccount(input),
    ...checkFeeAccumulatorManipulation(input),
    ...checkFlashLoanFeeClaim(input),
    ...checkSelfTradingOracle(input),
    ...checkUnrealizedPnLCollateral(input),
    ...checkPositionConcentration(input),
    ...checkSeedPhraseLogging(input),
    ...checkUnencryptedKeyStorage(input),
    ...checkTelemetrySensitiveData(input),
    ...checkGovernanceProposalValidation(input),
    ...checkTreasuryPermissionChange(input),
    ...checkBondingCurveFlashLoan(input),
    ...checkProgramCloseWithFunds(input),
    ...checkIrreversibleAction(input),
    ...checkHotWalletExposure(input),
    ...checkCommingledFunds(input),
    ...checkInsiderAccessControls(input),
    ...checkPrivilegedMonitoring(input),
    ...checkDatabaseInjection(input),
    ...checkSessionTokenSecurity(input),
    ...checkTradingBotKeyStorage(input),
    ...checkBotPaymentValidation(input),
    ...checkSubAccountIsolation(input),
    ...checkSybilProtection(input),
    ...checkHoneypotSellRestriction(input),
    ...checkUnnoticedProposal(input),
    ...checkSupplyChainKeyExfiltration(input),
    ...checkFrontendIntegrity(input),
    ...checkNetworkDoSVulnerability(input),
    ...checkJITCacheVulnerability(input),
    ...checkPTTokenPricing(input),
    ...checkFlashLoanCollateralization(input),
    ...checkWhiteHatRecovery(input),
    ...checkAdvancedSecurityPatterns(input),
  ];
}

export default checkBatch69Patterns;
