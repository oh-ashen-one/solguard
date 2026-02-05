/**
 * SolGuard Batched Patterns 32 - Helius Exploit History Deep Dive
 * Based on comprehensive Helius research analyzing 38 verified security incidents
 * Feb 5, 2026 - 6:30 AM CST
 */

import type { Finding } from '../commands/audit.js';
import type { ParsedIdl } from '../parsers/idl.js';
import type { ParsedRust } from '../parsers/rust.js';

interface PatternInput {
  idl?: ParsedIdl;
  rust?: ParsedRust;
  content?: string;
  contractAddress?: string;
  network?: string;
}

// SOL853: Audius-Style Governance Configuration Attack
export function checkAudiusStyleGovernanceAttack(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || input.content || '';
  
  // Check for governance proposal systems without proper validation
  const hasGovernanceProposal = /proposal|governance|vote|execute_proposal/i.test(content);
  const hasConfigChange = /reconfigure|set_config|update_.*_permission|transfer_treasury/i.test(content);
  const hasMissingTimeLock = !/(timelock|delay|execute_after|waiting_period)/i.test(content);
  const hasMissingThreshold = !/(threshold|quorum|minimum_votes)/i.test(content);
  
  if (hasGovernanceProposal && hasConfigChange && (hasMissingTimeLock || hasMissingThreshold)) {
    findings.push({
      id: 'SOL853',
      title: 'Audius-Style Governance Configuration Attack',
      severity: 'critical',
      description: 'Governance proposal system may allow immediate execution of configuration changes without timelocks or quorum validation. Audius lost $6.1M when attacker submitted and executed malicious proposal to reconfigure treasury permissions.',
      location: 'governance_proposal_handler',
      recommendation: 'Add timelocks for governance actions (minimum 24-48 hours). Require minimum quorum threshold. Add proposal validation before execution. Implement guardian/veto capability.'
    });
  }
  
  return findings;
}

// SOL854: OptiFi-Style Program Close Lockup
export function checkOptiFiStyleProgramClose(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || input.content || '';
  
  // Check for program close functionality that could lock funds
  const hasProgramClose = /close_program|close_vault|close_market|set_close/i.test(content);
  const hasUserFundsInProgram = /user_balance|deposit|stake|vault|position/i.test(content);
  const hasMissingWithdrawCheck = !/(allow_withdraw|can_withdraw|withdrawal_enabled)/i.test(content);
  const hasMissingRefund = !/(refund|return_funds|emergency_withdraw)/i.test(content);
  
  if (hasProgramClose && hasUserFundsInProgram && (hasMissingWithdrawCheck || hasMissingRefund)) {
    findings.push({
      id: 'SOL854',
      title: 'OptiFi-Style Program Close Lockup Risk',
      severity: 'critical',
      description: 'Program close functionality may permanently lock user funds. OptiFi accidentally locked $661K when calling close-market without ensuring user positions were closed first. Close operation should verify all user funds are withdrawn.',
      location: 'program_close_handler',
      recommendation: 'Require all user positions to be closed before program close. Add emergency withdrawal mechanism. Implement grace period before final close. Add multi-sig requirement for close operations.'
    });
  }
  
  return findings;
}

// SOL855: Mango-Style Oracle Price Manipulation
export function checkMangoStyleOracleManipulation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || input.content || '';
  
  // Check for oracle usage in collateral/borrowing without manipulation protection
  const hasOraclePrice = /oracle.*price|get_price|price_feed|pyth|switchboard/i.test(content);
  const hasBorrowing = /borrow|collateral|leverage|margin|liquidat/i.test(content);
  const hasMissingBounds = !/(max_price_deviation|price_staleness|circuit_breaker)/i.test(content);
  const hasMissingTwap = !/(twap|time.*weighted|average_price)/i.test(content);
  
  if (hasOraclePrice && hasBorrowing && hasMissingBounds && hasMissingTwap) {
    findings.push({
      id: 'SOL855',
      title: 'Mango-Style Oracle Price Manipulation Risk ($116M)',
      severity: 'critical',
      description: 'Oracle prices used for borrowing/collateral without manipulation protection. Mango Markets lost $116M when attacker artificially inflated MNGO token price via market manipulation, then used it as collateral to drain treasury.',
      location: 'oracle_price_handler',
      recommendation: 'Use TWAP oracles instead of spot price. Add maximum position sizes relative to liquidity. Implement circuit breakers for unusual price movements. Add borrowing caps per collateral type.'
    });
  }
  
  return findings;
}

// SOL856: Slope-Style Private Key Exposure
export function checkSlopeStyleKeyExposure(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || input.content || '';
  
  // Check for private key handling patterns that could expose keys
  const hasPrivateKey = /private_key|secret_key|seed_phrase|mnemonic|keypair/i.test(content);
  const hasLogging = /log|console|print|debug|trace|sentry|analytics/i.test(content);
  const hasExternalTransmit = /http|api|send|upload|transmit|serialize/i.test(content);
  
  if (hasPrivateKey && (hasLogging || hasExternalTransmit)) {
    findings.push({
      id: 'SOL856',
      title: 'Slope-Style Private Key Exposure Risk ($8M)',
      severity: 'critical',
      description: 'Private key material may be logged or transmitted externally. Slope wallet logged seed phrases via Sentry crash reporting, exposing 9,231 wallets and causing $8M in losses.',
      location: 'key_handling',
      recommendation: 'Never log or transmit private key material. Use secure enclaves for key storage. Audit all logging and analytics integrations. Implement key material scrubbing in error handlers.'
    });
  }
  
  return findings;
}

// SOL857: Supply Chain NPM/Dependency Attack
export function checkSupplyChainDependencyAttack(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || input.content || '';
  
  // Check for patterns indicating dependency trust issues
  const hasExternalDep = /use\s+\w+::|extern\s+crate|import|require\(/i.test(content);
  const hasVersionPinning = !/(=\s*"\d+\.\d+\.\d+"|version\s*=\s*"=)/i.test(content);
  const hasCryptoOps = /sign|encrypt|decrypt|keypair|wallet|transfer/i.test(content);
  
  if (hasExternalDep && hasVersionPinning && hasCryptoOps) {
    findings.push({
      id: 'SOL857',
      title: 'Supply Chain Dependency Attack Risk (Web3.js incident)',
      severity: 'high',
      description: 'Dependencies may be compromised without version pinning. The @solana/web3.js npm package was compromised in December 2024 with a drain function affecting millions of downloads.',
      location: 'dependency_management',
      recommendation: 'Pin exact dependency versions. Use lockfiles. Audit dependencies regularly. Implement subresource integrity checks. Use private npm registry for critical packages.'
    });
  }
  
  return findings;
}

// SOL858: Pump.fun-Style Insider Exploitation
export function checkInsiderExploitationRisk(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || input.content || '';
  
  // Check for privileged access patterns that could enable insider abuse
  const hasPrivilegedAccess = /admin|owner|operator|maintainer|upgrade/i.test(content);
  const hasFlashLoan = /flash.*loan|borrow.*repay|instant.*loan/i.test(content);
  const hasBondingCurve = /bonding.*curve|curve_config|price_curve/i.test(content);
  const hasMissingMultiSig = !/(multi.*sig|threshold.*sign|n_of_m)/i.test(content);
  
  if (hasPrivilegedAccess && (hasFlashLoan || hasBondingCurve) && hasMissingMultiSig) {
    findings.push({
      id: 'SOL858',
      title: 'Pump.fun-Style Insider Exploitation Risk ($1.9M)',
      severity: 'high',
      description: 'Privileged access to bonding curves or flash loan functionality without multi-sig could enable insider exploitation. A Pump.fun employee exploited flash loan access to drain $1.9M from bonding curves.',
      location: 'privileged_access_handler',
      recommendation: 'Require multi-sig for all privileged operations. Implement access logging and monitoring. Add timelocks for configuration changes. Use cold storage for admin keys.'
    });
  }
  
  return findings;
}

// SOL859: Banana Gun-Style Bot Compromise
export function checkBotCompromiseRisk(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || input.content || '';
  
  // Check for trading bot patterns with security issues
  const hasTradingBot = /bot|sniper|swap.*auto|trade.*executor/i.test(content);
  const hasUserPrivateKey = /user.*key|delegated.*signer|session.*key/i.test(content);
  const hasMissingKeyIsolation = !/(isolated|enclave|secure.*storage|hardware.*wallet)/i.test(content);
  
  if (hasTradingBot && hasUserPrivateKey && hasMissingKeyIsolation) {
    findings.push({
      id: 'SOL859',
      title: 'Banana Gun-Style Bot Compromise Risk ($1.4M)',
      severity: 'critical',
      description: 'Trading bots storing user private keys without proper isolation are vulnerable to compromise. Banana Gun lost $1.4M when VM key storage was exploited. 11 users lost funds.',
      location: 'bot_key_storage',
      recommendation: 'Never store user private keys on servers. Use session keys with limited permissions. Implement hardware security modules. Add withdrawal limits and delays.'
    });
  }
  
  return findings;
}

// SOL860: DEXX-Style Centralized Key Management
export function checkDEXXStyleCentralizedKeys(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || input.content || '';
  
  // Check for centralized custodial patterns
  const hasCustodialKeys = /custodial|server.*wallet|platform.*key|master.*key/i.test(content);
  const hasUserFunds = /user.*balance|deposit|withdraw|transfer/i.test(content);
  const hasMissingSelfCustody = !/(non.*custodial|user.*sign|wallet.*connect)/i.test(content);
  
  if (hasCustodialKeys && hasUserFunds && hasMissingSelfCustody) {
    findings.push({
      id: 'SOL860',
      title: 'DEXX-Style Centralized Key Management Risk ($30M)',
      severity: 'critical',
      description: 'Centralized key management for user funds creates single point of failure. DEXX lost $30M when centralized private key system was compromised. Self-custody or MPC should be used.',
      location: 'key_management',
      recommendation: 'Implement non-custodial architecture. Use MPC (multi-party computation) for custody. Never store user private keys server-side. Use session keys with limited permissions.'
    });
  }
  
  return findings;
}

// SOL861: Thunder Terminal MongoDB Injection
export function checkThunderStyleDatabaseInjection(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || input.content || '';
  
  // Check for patterns indicating database/external service integration
  const hasDatabase = /database|mongodb|postgres|mysql|redis|query/i.test(content);
  const hasUserInput = /user_input|request|params|body|query_string/i.test(content);
  const hasMissingSanitization = !/(sanitize|escape|validate_input|prepared_statement)/i.test(content);
  
  if (hasDatabase && hasUserInput && hasMissingSanitization) {
    findings.push({
      id: 'SOL861',
      title: 'Thunder Terminal-Style Database Injection Risk ($240K)',
      severity: 'high',
      description: 'External database integration without input sanitization may enable injection attacks. Thunder Terminal lost $240K through MongoDB injection that exposed session tokens.',
      location: 'database_handler',
      recommendation: 'Sanitize all user inputs. Use parameterized queries. Implement WAF (Web Application Firewall). Add rate limiting and anomaly detection.'
    });
  }
  
  return findings;
}

// SOL862: Raydium-Style Pool Draining
export function checkRaydiumStylePoolDrain(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || input.content || '';
  
  // Check for liquidity pool admin patterns
  const hasPoolAdmin = /pool.*admin|withdraw_protocol_fee|admin_withdraw/i.test(content);
  const hasLpTokens = /lp_token|liquidity_pool|pool_balance/i.test(content);
  const hasMissingKeyProtection = !/(multi.*sig|timelock|cold.*storage)/i.test(content);
  
  if (hasPoolAdmin && hasLpTokens && hasMissingKeyProtection) {
    findings.push({
      id: 'SOL862',
      title: 'Raydium-Style Pool Admin Drain Risk ($4.4M)',
      severity: 'critical',
      description: 'Pool admin keys without proper protection could enable fund drainage. Raydium lost $4.4M when admin account private key was compromised, allowing attacker to drain fees and LPs.',
      location: 'pool_admin_handler',
      recommendation: 'Use multi-sig for admin operations. Store admin keys in cold storage. Implement timelocks on withdrawals. Add anomaly detection for large transfers.'
    });
  }
  
  return findings;
}

// SOL863: Cypher-Style Insider Fund Theft
export function checkCypherStyleInsiderTheft(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || input.content || '';
  
  // Check for treasury/vault patterns without oversight
  const hasTreasury = /treasury|vault|protocol_funds|collected_fees/i.test(content);
  const hasTeamAccess = /team|admin|operator|maintainer/i.test(content);
  const hasMissingOverSight = !/(multi.*sig|audit.*trail|external.*audit|dao.*vote)/i.test(content);
  
  if (hasTreasury && hasTeamAccess && hasMissingOverSight) {
    findings.push({
      id: 'SOL863',
      title: 'Cypher-Style Insider Fund Theft Risk ($317K)',
      severity: 'high',
      description: 'Treasury access by team members without multi-sig oversight creates insider theft risk. Cypher lost $317K when team member diverted protocol funds.',
      location: 'treasury_handler',
      recommendation: 'Require multi-sig for all treasury operations. Implement transparent on-chain accounting. Add external auditing and monitoring. Use DAO governance for fund allocation.'
    });
  }
  
  return findings;
}

// SOL864: Solareum-Style Rug Pull Detection
export function checkSolareumStyleRugPull(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || input.content || '';
  
  // Check for patterns that could enable rug pulls
  const hasUpgradeable = /upgrade.*authority|set_authority|program_data/i.test(content);
  const hasMintAuthority = /mint_authority|mint_to|create_mint/i.test(content);
  const hasLpControl = /withdraw_all|drain|emergency.*withdraw|admin.*transfer/i.test(content);
  const hasMissingRenounce = !/(renounce|revoke|immutable|frozen)/i.test(content);
  
  if ((hasUpgradeable || hasMintAuthority || hasLpControl) && hasMissingRenounce) {
    findings.push({
      id: 'SOL864',
      title: 'Solareum-Style Rug Pull Pattern Detected',
      severity: 'critical',
      description: 'Contract has rug pull characteristics: upgradeable, mint authority, or LP control without renunciation. Solareum owner drained $523K from trading bot wallets.',
      location: 'authority_controls',
      recommendation: 'Renounce mint authority for fair-launch tokens. Make contracts immutable after audit. Use time-locked LP with community oversight. Implement transparent tokenomics.'
    });
  }
  
  return findings;
}

// SOL865: Synthetify-Style DAO Treasury Heist
export function checkSynthetifyStyleDAOHeist(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || input.content || '';
  
  // Check for DAO/governance treasury access patterns
  const hasDAOTreasury = /dao.*treasury|governance.*vault|community.*funds/i.test(content);
  const hasProposalExecution = /execute_proposal|proposal.*passed|vote.*complete/i.test(content);
  const hasMissingValidation = !/(validate_executor|authorized_caller|proposal.*state)/i.test(content);
  
  if (hasDAOTreasury && hasProposalExecution && hasMissingValidation) {
    findings.push({
      id: 'SOL865',
      title: 'Synthetify-Style DAO Treasury Heist Risk ($230K)',
      severity: 'critical',
      description: 'DAO treasury may be exploited through governance manipulation. Synthetify lost $230K when governance proposals were exploited to drain DAO treasury.',
      location: 'dao_treasury_handler',
      recommendation: 'Add execution delays for governance actions. Implement guardian veto capability. Require minimum voting period. Add treasury withdrawal limits.'
    });
  }
  
  return findings;
}

// SOL866: NoOnes Platform Withdrawal Exploit
export function checkNoOnesStyleWithdrawalExploit(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || input.content || '';
  
  // Check for withdrawal/exchange patterns
  const hasWithdrawal = /withdraw|transfer_out|send_funds/i.test(content);
  const hasBalanceCheck = /balance|available_funds|can_withdraw/i.test(content);
  const hasMissingVerification = !/(verify_balance|atomic_check|double_spend)/i.test(content);
  
  if (hasWithdrawal && hasBalanceCheck && hasMissingVerification) {
    findings.push({
      id: 'SOL866',
      title: 'NoOnes-Style Withdrawal Verification Missing',
      severity: 'high',
      description: 'Withdrawal functionality may not properly verify balances atomically. NoOnes platform had $8.5M in fraudulent withdrawals through balance manipulation.',
      location: 'withdrawal_handler',
      recommendation: 'Use atomic balance checks before withdrawal. Implement withdrawal limits and delays. Add fraud detection for unusual patterns. Use multi-confirmation for large withdrawals.'
    });
  }
  
  return findings;
}

// SOL867: Loopscale Admin Wallet Takeover
export function checkLoopscaleAdminTakeover(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || input.content || '';
  
  // Check for admin wallet security patterns
  const hasAdminWallet = /admin.*wallet|operator.*address|authority.*pubkey/i.test(content);
  const hasHighValueOps = /liquidate|withdraw|transfer.*large|emergency/i.test(content);
  const hasMissingKeyRotation = !/(rotate.*key|key.*rotation|update.*admin)/i.test(content);
  const hasMissingMonitoring = !/(monitor|alert|anomaly|threshold)/i.test(content);
  
  if (hasAdminWallet && hasHighValueOps && hasMissingKeyRotation && hasMissingMonitoring) {
    findings.push({
      id: 'SOL867',
      title: 'Loopscale-Style Admin Wallet Takeover Risk ($5.8M)',
      severity: 'critical',
      description: 'Admin wallet without proper security controls creates takeover risk. Loopscale lost $5.8M just 2 weeks after launch when admin wallet was compromised.',
      location: 'admin_wallet_security',
      recommendation: 'Use hardware security modules for admin keys. Implement key rotation policies. Add real-time monitoring for admin actions. Use multi-sig with geographically distributed signers.'
    });
  }
  
  return findings;
}

// SOL868: Saga DAO Insider Attack
export function checkSagaDAOInsiderAttack(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || input.content || '';
  
  // Check for DAO membership/access patterns
  const hasDAOMembership = /dao.*member|council|leadership|team.*access/i.test(content);
  const hasFundAccess = /treasury|vault|pool|fund/i.test(content);
  const hasMissingAccessControl = !/(permission.*level|role.*check|access.*list)/i.test(content);
  
  if (hasDAOMembership && hasFundAccess && hasMissingAccessControl) {
    findings.push({
      id: 'SOL868',
      title: 'Saga DAO-Style Insider Attack Risk ($1.5M)',
      severity: 'high',
      description: 'DAO member access without granular permissions creates insider attack risk. Saga DAO lost $1.5M through internal breach by leadership members.',
      location: 'dao_access_control',
      recommendation: 'Implement role-based access control. Use principle of least privilege. Add audit trails for all member actions. Implement vesting and lockup for member allocations.'
    });
  }
  
  return findings;
}

// Export all pattern checkers
export const batchedPatterns32 = {
  checkAudiusStyleGovernanceAttack,
  checkOptiFiStyleProgramClose,
  checkMangoStyleOracleManipulation,
  checkSlopeStyleKeyExposure,
  checkSupplyChainDependencyAttack,
  checkInsiderExploitationRisk,
  checkBotCompromiseRisk,
  checkDEXXStyleCentralizedKeys,
  checkThunderStyleDatabaseInjection,
  checkRaydiumStylePoolDrain,
  checkCypherStyleInsiderTheft,
  checkSolareumStyleRugPull,
  checkSynthetifyStyleDAOHeist,
  checkNoOnesStyleWithdrawalExploit,
  checkLoopscaleAdminTakeover,
  checkSagaDAOInsiderAttack
};

export default batchedPatterns32;
