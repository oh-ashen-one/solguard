/**
 * Batch 68: January 2026 Emerging Threats & Security Patterns
 * Based on latest exploits and vulnerability disclosures
 * Patterns: SOL3051-SOL3100
 */

import type { PatternInput, Finding } from './index.js';

/**
 * Creates a finding with consistent structure
 */
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
 * SOL3051: Owner Permission Phishing Attack
 * Based on Jan 7, 2026 attack - bypasses transaction simulations
 */
function checkOwnerPermissionPhishing(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;

  // Check for SetAuthority without proper warnings/confirmations
  if (input.rust.content.includes('SetAuthority') && 
      !input.rust.content.includes('owner_change_confirmation') &&
      !input.rust.content.includes('transfer_ownership_warning')) {
    findings.push(createFinding(
      'SOL3051',
      'Owner Permission Phishing Vulnerability',
      'critical',
      'SetAuthority operations without explicit user confirmation can be exploited in phishing attacks that bypass transaction simulations.',
      { file: input.path },
      'Add explicit ownership transfer confirmations and warnings before SetAuthority operations'
    ));
  }

  return findings;
}

/**
 * SOL3052: Silent Account Control Transfer
 * Based on Solana "Owner" permission field manipulation
 */
function checkSilentAccountTransfer(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;

  if (input.rust.content.includes('owner') && 
      input.rust.content.includes('transfer') &&
      !input.rust.content.includes('emit_ownership_event') &&
      !input.rust.content.includes('log_owner_change')) {
    findings.push(createFinding(
      'SOL3052',
      'Silent Account Control Transfer',
      'critical',
      'Account ownership transfers without logging or events can be exploited silently in phishing attacks.',
      { file: input.path },
      'Emit events and logs for all ownership transfers to ensure visibility'
    ));
  }

  return findings;
}

/**
 * SOL3053: Analytics Library Key Harvesting
 * Based on Trust Wallet Chrome Extension breach (Dec 2025) - posthog-js
 */
function checkAnalyticsKeyHarvesting(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;

  // Check for analytics with key access
  if ((input.rust.content.includes('analytics') || 
       input.rust.content.includes('telemetry') ||
       input.rust.content.includes('tracking')) &&
      (input.rust.content.includes('private_key') ||
       input.rust.content.includes('seed_phrase') ||
       input.rust.content.includes('keypair'))) {
    findings.push(createFinding(
      'SOL3053',
      'Analytics Library Key Harvesting Risk',
      'critical',
      'Analytics/telemetry code has access to key material. Compromised analytics libraries (like posthog-js) can exfiltrate wallet credentials.',
      { file: input.path },
      'Isolate analytics code from key material. Never allow analytics libraries access to sensitive cryptographic data.'
    ));
  }

  return findings;
}

/**
 * SOL3054: Third-Party Library Credential Exposure
 * Trust Wallet breach pattern - open source libraries harvesting wallet info
 */
function checkThirdPartyCredentialExposure(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;

  if ((input.rust.content.includes('extern crate') || 
       input.rust.content.includes('use ')) &&
      (input.rust.content.includes('wallet') ||
       input.rust.content.includes('keypair')) &&
      !input.rust.content.includes('audit') &&
      !input.rust.content.includes('trusted')) {
    findings.push(createFinding(
      'SOL3054',
      'Third-Party Library Credential Exposure',
      'high',
      'External libraries with wallet access can be supply chain attack vectors. Trust Wallet lost $7M via malicious library injection.',
      { file: input.path },
      'Audit all third-party dependencies that access wallet/key functionality. Use lockfiles and verify checksums.'
    ));
  }

  return findings;
}

/**
 * SOL3055: Simulation Bypass via Owner Field
 * Jan 2026 phishing attack bypassed traditional transaction simulations
 */
function checkSimulationBypassOwner(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;

  if (input.rust.content.includes('simulate') &&
      !input.rust.content.includes('owner_field_check') &&
      !input.rust.content.includes('authority_simulation')) {
    findings.push(createFinding(
      'SOL3055',
      'Transaction Simulation Bypass via Owner Field',
      'high',
      'Owner permission changes may not appear in standard transaction simulations, enabling phishing attacks.',
      { file: input.path },
      'Implement specialized simulation for authority/ownership changes that explicitly displays permission modifications'
    ));
  }

  return findings;
}

/**
 * SOL3056: Hot Wallet Key Isolation Failure
 * Pattern from Upbit $36M breach (Nov 2025)
 */
function checkHotWalletKeyIsolation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;

  if (input.rust.content.includes('hot_wallet') &&
      !input.rust.content.includes('hsm') &&
      !input.rust.content.includes('key_isolation') &&
      !input.rust.content.includes('hardware_security')) {
    findings.push(createFinding(
      'SOL3056',
      'Hot Wallet Key Isolation Failure',
      'critical',
      'Hot wallet keys without HSM or hardware isolation are vulnerable to server-side compromises. Upbit lost $36M in similar scenario.',
      { file: input.path },
      'Use HSM (Hardware Security Modules) for hot wallet key storage with strict access controls'
    ));
  }

  return findings;
}

/**
 * SOL3057: Exchange Deposit Address Validation
 * Upbit breach pattern - deposit address validation gaps
 */
function checkDepositAddressValidation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;

  if (input.rust.content.includes('deposit') &&
      input.rust.content.includes('address') &&
      !input.rust.content.includes('whitelist') &&
      !input.rust.content.includes('address_validation')) {
    findings.push(createFinding(
      'SOL3057',
      'Exchange Deposit Address Validation Missing',
      'high',
      'Deposit operations without address whitelisting or validation can lead to fund redirection attacks.',
      { file: input.path },
      'Implement deposit address whitelisting and multi-signature approval for new addresses'
    ));
  }

  return findings;
}

/**
 * SOL3058: Wallet Drain via Chrome Extension
 * Trust Wallet pattern - malicious code in browser extension
 */
function checkChromeExtensionSecurity(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;

  if ((input.rust.content.includes('extension') || 
       input.rust.content.includes('browser')) &&
      input.rust.content.includes('wallet') &&
      !input.rust.content.includes('content_security_policy') &&
      !input.rust.content.includes('script_isolation')) {
    findings.push(createFinding(
      'SOL3058',
      'Browser Extension Wallet Security Risk',
      'high',
      'Browser extension wallets are vulnerable to malicious code injection. Trust Wallet breach drained $7M via extension compromise.',
      { file: input.path },
      'Implement strict CSP, script isolation, and code signing for browser extension components'
    ));
  }

  return findings;
}

/**
 * SOL3059: Anza/Firedancer Consensus Vulnerability Pattern
 * Based on Dec 2025 critical vulnerabilities disclosed via GitHub
 */
function checkConsensusVulnerabilityPattern(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;

  if (input.rust.content.includes('consensus') &&
      (input.rust.content.includes('block') || input.rust.content.includes('slot')) &&
      !input.rust.content.includes('validator_set_check') &&
      !input.rust.content.includes('finality_confirmation')) {
    findings.push(createFinding(
      'SOL3059',
      'Consensus Layer Vulnerability Pattern',
      'critical',
      'Consensus operations without proper validator set and finality checks can lead to network stalling attacks.',
      { file: input.path },
      'Ensure consensus operations include validator set verification and finality confirmation mechanisms'
    ));
  }

  return findings;
}

/**
 * SOL3060: Network Stalling Attack Vector
 * Dec 2025 Solana vulnerability that could stall the network
 */
function checkNetworkStallingVector(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;

  if (input.rust.content.includes('network') &&
      input.rust.content.includes('propagate') &&
      !input.rust.content.includes('rate_limit') &&
      !input.rust.content.includes('ddos_protection')) {
    findings.push(createFinding(
      'SOL3060',
      'Network Stalling Attack Vector',
      'high',
      'Network propagation without rate limiting can be exploited to stall block production.',
      { file: input.path },
      'Implement rate limiting and DDoS protection for network propagation paths'
    ));
  }

  return findings;
}

/**
 * SOL3061: Transaction Fee Manipulation via Priority
 * MEV and priority fee gaming patterns
 */
function checkTransactionFeeManipulation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;

  if (input.rust.content.includes('priority_fee') &&
      !input.rust.content.includes('fee_cap') &&
      !input.rust.content.includes('max_priority')) {
    findings.push(createFinding(
      'SOL3061',
      'Transaction Fee Manipulation Risk',
      'medium',
      'Priority fee handling without caps can lead to fee manipulation and transaction ordering attacks.',
      { file: input.path },
      'Implement priority fee caps and fair ordering mechanisms'
    ));
  }

  return findings;
}

/**
 * SOL3062: Wallet Provider Integration Security
 * OKX and Phantom warning patterns from Jan 2026
 */
function checkWalletProviderIntegration(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;

  if ((input.rust.content.includes('phantom') || 
       input.rust.content.includes('okx') ||
       input.rust.content.includes('wallet_adapter')) &&
      !input.rust.content.includes('version_check') &&
      !input.rust.content.includes('signature_validation')) {
    findings.push(createFinding(
      'SOL3062',
      'Wallet Provider Integration Security',
      'medium',
      'Wallet provider integrations should verify versions and signatures to prevent phishing attacks.',
      { file: input.path },
      'Validate wallet provider versions and implement signature verification for critical operations'
    ));
  }

  return findings;
}

/**
 * SOL3063: Multi-Chain Bridge Theft via Tornado Cash
 * Pattern from multiple 2025 hacks bridging to ETH/BSC and mixing
 */
function checkBridgeFundLaundering(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;

  if (input.rust.content.includes('bridge') &&
      !input.rust.content.includes('monitoring') &&
      !input.rust.content.includes('rate_limit_bridge')) {
    findings.push(createFinding(
      'SOL3063',
      'Bridge Fund Exfiltration Risk',
      'high',
      'Bridge operations without monitoring or rate limits enable attackers to quickly move stolen funds cross-chain.',
      { file: input.path },
      'Implement bridge operation monitoring, rate limits, and pause mechanisms for suspicious activity'
    ));
  }

  return findings;
}

/**
 * SOL3064: Rapid Incident Response Pattern
 * Modern exploits are detected in minutes (Thunder Terminal: 9 min)
 */
function checkIncidentResponseCapability(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;

  if (input.rust.content.includes('admin') &&
      !input.rust.content.includes('pause') &&
      !input.rust.content.includes('emergency_stop') &&
      !input.rust.content.includes('circuit_breaker')) {
    findings.push(createFinding(
      'SOL3064',
      'Missing Rapid Incident Response Capability',
      'medium',
      'Protocols without pause mechanisms cannot respond quickly to exploits. Modern attacks require sub-10-minute response.',
      { file: input.path },
      'Implement emergency pause/circuit breaker mechanisms controllable by multisig or guardian'
    ));
  }

  return findings;
}

/**
 * SOL3065: Community Vigilance Alert Pattern
 * CertiK and ZachXBT style external alert integration
 */
function checkExternalAlertIntegration(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;

  if (input.rust.content.includes('oracle') || input.rust.content.includes('price')) {
    // This is more of an info pattern - encourage monitoring
    findings.push(createFinding(
      'SOL3065',
      'External Security Alert Integration Recommended',
      'info',
      'Consider integrating external security alerts (CertiK, SlowMist) for early warning of oracle manipulation or exploits.',
      { file: input.path },
      'Subscribe to security monitoring services and implement automated pause on external alerts'
    ));
  }

  return findings;
}

/**
 * SOL3066: Token Mixer Detection
 * Pattern for detecting attempts to obscure fund flows
 */
function checkTokenMixerUsage(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;

  if ((input.rust.content.includes('tornado') || 
       input.rust.content.includes('mixer') ||
       input.rust.content.includes('tumbler')) &&
      !input.rust.content.includes('compliance')) {
    findings.push(createFinding(
      'SOL3066',
      'Token Mixer Integration Risk',
      'high',
      'Integration with mixer services can facilitate money laundering and may violate compliance requirements.',
      { file: input.path },
      'Implement compliance checks and avoid direct integration with mixer services'
    ));
  }

  return findings;
}

/**
 * SOL3067: SlowMist Phishing Pattern Detection
 * Based on $3M+ phishing incidents analyzed by SlowMist
 */
function checkSlowMistPhishingPatterns(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;

  // Check for common phishing vectors
  if (input.rust.content.includes('approve') && 
      input.rust.content.includes('unlimited') &&
      !input.rust.content.includes('approval_limit')) {
    findings.push(createFinding(
      'SOL3067',
      'Unlimited Token Approval Phishing Risk',
      'high',
      'Unlimited token approvals are a primary phishing vector. SlowMist documented $3M+ in losses from approval drain attacks.',
      { file: input.path },
      'Limit token approvals to specific amounts and implement approval expiry mechanisms'
    ));
  }

  return findings;
}

/**
 * SOL3068: SetAuthority Phishing Attack
 * Specific pattern from Dec 2025 SlowMist analysis
 */
function checkSetAuthorityPhishing(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;

  if (input.rust.content.includes('set_authority') || 
      input.rust.content.includes('SetAuthority')) {
    // Check for proper safeguards
    if (!input.rust.content.includes('two_step') &&
        !input.rust.content.includes('timelock') &&
        !input.rust.content.includes('confirmation_required')) {
      findings.push(createFinding(
        'SOL3068',
        'SetAuthority Phishing Attack Vector',
        'critical',
        'SetAuthority without two-step confirmation or timelock can be exploited in phishing attacks for immediate account takeover.',
        { file: input.path },
        'Implement two-step authority transfer with timelock and explicit user confirmation'
      ));
    }
  }

  return findings;
}

/**
 * SOL3069: Memo-Based Phishing Attack
 * Fake airdrop links and scam messages in transaction memos
 */
function checkMemoPhishing(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;

  if (input.rust.content.includes('memo') &&
      !input.rust.content.includes('memo_sanitize') &&
      !input.rust.content.includes('url_filter')) {
    findings.push(createFinding(
      'SOL3069',
      'Memo-Based Phishing Vector',
      'medium',
      'Transaction memos containing URLs can be used for phishing. Fake airdrop scams commonly use memo links.',
      { file: input.path },
      'Sanitize memo content and warn users about URLs in transaction memos'
    ));
  }

  return findings;
}

/**
 * SOL3070: Insurance Fund Depletion Attack
 * DeFi protocols need robust insurance fund protection
 */
function checkInsuranceFundProtection(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;

  if (input.rust.content.includes('insurance') && 
      input.rust.content.includes('fund')) {
    if (!input.rust.content.includes('insurance_cap') &&
        !input.rust.content.includes('insurance_min')) {
      findings.push(createFinding(
        'SOL3070',
        'Insurance Fund Depletion Risk',
        'high',
        'Insurance funds without caps and minimums can be drained through repeated claims or manipulation.',
        { file: input.path },
        'Implement insurance fund caps, minimums, and claim rate limits'
      ));
    }
  }

  return findings;
}

/**
 * SOL3071: White Hat Bounty Coordination
 * Pattern from successful recoveries (Loopscale $5.8M, Crema $7.2M)
 */
function checkWhiteHatCoordination(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;

  if (input.rust.content.includes('admin') || input.rust.content.includes('authority')) {
    if (!input.rust.content.includes('contact') &&
        !input.rust.content.includes('security_team')) {
      findings.push(createFinding(
        'SOL3071',
        'White Hat Contact Information Missing',
        'info',
        'Protocols should publish security contact information for white hat coordination. Loopscale recovered $5.8M through negotiation.',
        { file: input.path },
        'Add security.txt or on-chain contact for responsible disclosure'
      ));
    }
  }

  return findings;
}

/**
 * SOL3072: Full Reimbursement Pattern
 * Wormhole ($326M), Pump.fun ($1.9M), Banana Gun ($1.4M) full recovery
 */
function checkReimbursementCapability(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;

  if (input.rust.content.includes('treasury') || input.rust.content.includes('vault')) {
    if (!input.rust.content.includes('emergency_fund') &&
        !input.rust.content.includes('backup_treasury')) {
      findings.push(createFinding(
        'SOL3072',
        'Reimbursement Capability Assessment',
        'info',
        'Protocols with emergency funds can fully reimburse users after exploits (Wormhole: $326M, Pump.fun: $1.9M).',
        { file: input.path },
        'Maintain emergency funds or insurance coverage for potential exploit reimbursement'
      ));
    }
  }

  return findings;
}

/**
 * SOL3073: Insider Threat Detection
 * Pump.fun employee, Cypher insider theft patterns
 */
function checkInsiderThreatControls(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;

  if (input.rust.content.includes('admin') || input.rust.content.includes('operator')) {
    if (!input.rust.content.includes('multi_sig') &&
        !input.rust.content.includes('timelock') &&
        !input.rust.content.includes('approval_required')) {
      findings.push(createFinding(
        'SOL3073',
        'Insider Threat Control Missing',
        'high',
        'Admin operations without multisig or timelock enable insider theft. Pump.fun lost $1.9M to employee exploit.',
        { file: input.path },
        'Require multisig and timelock for all privileged operations'
      ));
    }
  }

  return findings;
}

/**
 * SOL3074: Partial Recovery Documentation
 * Raydium pattern - 100% RAY pools, 90% non-RAY pools
 */
function checkPartialRecoveryMechanism(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;

  if (input.rust.content.includes('recovery') || input.rust.content.includes('compensation')) {
    if (!input.rust.content.includes('priority') &&
        !input.rust.content.includes('pro_rata')) {
      findings.push(createFinding(
        'SOL3074',
        'Partial Recovery Priority Undefined',
        'low',
        'Define recovery priorities for partial reimbursement scenarios (e.g., Raydium: 100% native pools, 90% others).',
        { file: input.path },
        'Document recovery priorities and pro-rata distribution mechanisms in advance'
      ));
    }
  }

  return findings;
}

/**
 * SOL3075: Real-Time Monitoring Integration
 * Modern protocols need sub-minute detection
 */
function checkRealTimeMonitoring(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust?.content) return findings;

  if (input.rust.content.includes('transfer') || input.rust.content.includes('withdraw')) {
    if (!input.rust.content.includes('monitor') &&
        !input.rust.content.includes('alert') &&
        !input.rust.content.includes('anomaly')) {
      findings.push(createFinding(
        'SOL3075',
        'Real-Time Monitoring Missing',
        'medium',
        'Protocols should implement real-time monitoring for rapid exploit detection. Response times have improved from hours to minutes.',
        { file: input.path },
        'Integrate real-time anomaly detection and alerting for critical operations'
      ));
    }
  }

  return findings;
}

// Export all patterns from this batch
export function checkBatch68Patterns(input: PatternInput): Finding[] {
  const allFindings: Finding[] = [];
  
  allFindings.push(...checkOwnerPermissionPhishing(input));
  allFindings.push(...checkSilentAccountTransfer(input));
  allFindings.push(...checkAnalyticsKeyHarvesting(input));
  allFindings.push(...checkThirdPartyCredentialExposure(input));
  allFindings.push(...checkSimulationBypassOwner(input));
  allFindings.push(...checkHotWalletKeyIsolation(input));
  allFindings.push(...checkDepositAddressValidation(input));
  allFindings.push(...checkChromeExtensionSecurity(input));
  allFindings.push(...checkConsensusVulnerabilityPattern(input));
  allFindings.push(...checkNetworkStallingVector(input));
  allFindings.push(...checkTransactionFeeManipulation(input));
  allFindings.push(...checkWalletProviderIntegration(input));
  allFindings.push(...checkBridgeFundLaundering(input));
  allFindings.push(...checkIncidentResponseCapability(input));
  allFindings.push(...checkExternalAlertIntegration(input));
  allFindings.push(...checkTokenMixerUsage(input));
  allFindings.push(...checkSlowMistPhishingPatterns(input));
  allFindings.push(...checkSetAuthorityPhishing(input));
  allFindings.push(...checkMemoPhishing(input));
  allFindings.push(...checkInsuranceFundProtection(input));
  allFindings.push(...checkWhiteHatCoordination(input));
  allFindings.push(...checkReimbursementCapability(input));
  allFindings.push(...checkInsiderThreatControls(input));
  allFindings.push(...checkPartialRecoveryMechanism(input));
  allFindings.push(...checkRealTimeMonitoring(input));

  return allFindings;
}

// Pattern list for registry
export const batch68Patterns = [
  { id: 'SOL3051', name: 'Owner Permission Phishing Attack', severity: 'critical' as const },
  { id: 'SOL3052', name: 'Silent Account Control Transfer', severity: 'critical' as const },
  { id: 'SOL3053', name: 'Analytics Library Key Harvesting', severity: 'critical' as const },
  { id: 'SOL3054', name: 'Third-Party Library Credential Exposure', severity: 'high' as const },
  { id: 'SOL3055', name: 'Transaction Simulation Bypass via Owner Field', severity: 'high' as const },
  { id: 'SOL3056', name: 'Hot Wallet Key Isolation Failure', severity: 'critical' as const },
  { id: 'SOL3057', name: 'Exchange Deposit Address Validation Missing', severity: 'high' as const },
  { id: 'SOL3058', name: 'Browser Extension Wallet Security Risk', severity: 'high' as const },
  { id: 'SOL3059', name: 'Consensus Layer Vulnerability Pattern', severity: 'critical' as const },
  { id: 'SOL3060', name: 'Network Stalling Attack Vector', severity: 'high' as const },
  { id: 'SOL3061', name: 'Transaction Fee Manipulation Risk', severity: 'medium' as const },
  { id: 'SOL3062', name: 'Wallet Provider Integration Security', severity: 'medium' as const },
  { id: 'SOL3063', name: 'Bridge Fund Exfiltration Risk', severity: 'high' as const },
  { id: 'SOL3064', name: 'Missing Rapid Incident Response Capability', severity: 'medium' as const },
  { id: 'SOL3065', name: 'External Security Alert Integration Recommended', severity: 'info' as const },
  { id: 'SOL3066', name: 'Token Mixer Integration Risk', severity: 'high' as const },
  { id: 'SOL3067', name: 'Unlimited Token Approval Phishing Risk', severity: 'high' as const },
  { id: 'SOL3068', name: 'SetAuthority Phishing Attack Vector', severity: 'critical' as const },
  { id: 'SOL3069', name: 'Memo-Based Phishing Vector', severity: 'medium' as const },
  { id: 'SOL3070', name: 'Insurance Fund Depletion Risk', severity: 'high' as const },
  { id: 'SOL3071', name: 'White Hat Contact Information Missing', severity: 'info' as const },
  { id: 'SOL3072', name: 'Reimbursement Capability Assessment', severity: 'info' as const },
  { id: 'SOL3073', name: 'Insider Threat Control Missing', severity: 'high' as const },
  { id: 'SOL3074', name: 'Partial Recovery Priority Undefined', severity: 'low' as const },
  { id: 'SOL3075', name: 'Real-Time Monitoring Missing', severity: 'medium' as const },
];
