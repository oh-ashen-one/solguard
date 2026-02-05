import type { Finding } from '../commands/audit.js';
import type { ParsedIdl } from '../parsers/idl.js';
import type { ParsedRust } from '../parsers/rust.js';

type PatternInput = { idl: ParsedIdl | null; rust: ParsedRust | null };

/**
 * SOL501-SOL520: Executive Compromise & Social Engineering Patterns
 * Based on 2024-2025 exploits targeting team members, not just code.
 */

// SOL501: Privileged Key Management
export function checkPrivilegedKeyManagement(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (input.rust?.sourceCode) {
    const code = input.rust.sourceCode;
    // Check for hardcoded admin keys or weak key derivation
    if (/admin_key\s*=\s*Pubkey::new|authority\s*=\s*\[/.test(code)) {
      findings.push({
        id: 'SOL501',
        severity: 'critical',
        title: 'Hardcoded Privileged Key',
        description: 'Admin/authority keys should not be hardcoded. Use configurable PDAs or multisig.',
        location: 'Key declaration',
        recommendation: 'Use PDA-derived authorities or on-chain configurable multisig for privileged operations.',
      });
    }
  }
  return findings;
}

// SOL502: Single Point of Failure Authority
export function checkSinglePointAuthority(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (input.rust?.sourceCode) {
    const code = input.rust.sourceCode;
    if (/signer_is_authority|is_admin/.test(code) && !/multisig|threshold/.test(code)) {
      findings.push({
        id: 'SOL502',
        severity: 'high',
        title: 'Single Point of Failure Authority',
        description: 'Critical operations rely on a single key without multisig protection.',
        location: 'Authority check',
        recommendation: 'Implement multisig or threshold signatures for critical operations.',
      });
    }
  }
  return findings;
}

// SOL503: Missing Key Rotation Mechanism
export function checkKeyRotationMechanism(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (input.rust?.sourceCode) {
    const code = input.rust.sourceCode;
    if (/authority|admin|owner/.test(code) && !/rotate|transfer_authority|update_admin/.test(code)) {
      findings.push({
        id: 'SOL503',
        severity: 'medium',
        title: 'Missing Key Rotation Mechanism',
        description: 'No mechanism to rotate authority keys in case of compromise.',
        location: 'Authority management',
        recommendation: 'Implement authority rotation with timelock and proper access controls.',
      });
    }
  }
  return findings;
}

// SOL504: Insecure Upgrade Authority Pattern
export function checkInsecureUpgradeAuthority(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (input.rust?.sourceCode) {
    const code = input.rust.sourceCode;
    if (/upgrade_authority|BpfLoaderUpgradeable/.test(code) && !/timelock|multisig|governance/.test(code)) {
      findings.push({
        id: 'SOL504',
        severity: 'critical',
        title: 'Insecure Upgrade Authority',
        description: 'Program upgrade authority lacks timelock or multisig protection.',
        location: 'Upgrade authority',
        recommendation: 'Use timelock + multisig for upgrade authority, or make program immutable.',
      });
    }
  }
  return findings;
}

// SOL505: Hot Wallet Concentration Risk
export function checkHotWalletConcentration(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (input.rust?.sourceCode) {
    const code = input.rust.sourceCode;
    if (/treasury|vault|pool/.test(code) && !/cold_wallet|withdrawal_limit|rate_limit/.test(code)) {
      findings.push({
        id: 'SOL505',
        severity: 'high',
        title: 'Hot Wallet Concentration Risk',
        description: 'Large value in hot wallet without withdrawal limits or cold storage.',
        location: 'Treasury/vault logic',
        recommendation: 'Implement withdrawal limits, rate limiting, and cold wallet segregation.',
      });
    }
  }
  return findings;
}

// SOL506: Missing Emergency Pause
export function checkMissingEmergencyPause(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (input.rust?.sourceCode) {
    const code = input.rust.sourceCode;
    if (/pub fn (deposit|withdraw|swap|transfer)/.test(code) && !/paused|is_paused|emergency_stop/.test(code)) {
      findings.push({
        id: 'SOL506',
        severity: 'high',
        title: 'Missing Emergency Pause Mechanism',
        description: 'Critical functions lack emergency pause capability for incident response.',
        location: 'Core functions',
        recommendation: 'Add pausable pattern with admin controls for emergency situations.',
      });
    }
  }
  return findings;
}

// SOL507: Insufficient Event Logging
export function checkInsufficientEventLogging(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (input.rust?.sourceCode) {
    const code = input.rust.sourceCode;
    if (/pub fn (transfer|withdraw|mint)/.test(code) && !/emit!|msg!|log/.test(code)) {
      findings.push({
        id: 'SOL507',
        severity: 'medium',
        title: 'Insufficient Event Logging',
        description: 'Critical operations lack event emission for monitoring and forensics.',
        location: 'Transaction handlers',
        recommendation: 'Emit events for all state-changing operations with relevant parameters.',
      });
    }
  }
  return findings;
}

// SOL508: Social Engineering Attack Surface
export function checkSocialEngineeringAttackSurface(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (input.rust?.sourceCode) {
    const code = input.rust.sourceCode;
    if (/airdrop|claim|redeem/.test(code) && !/verify_signature|merkle_proof|whitelist/.test(code)) {
      findings.push({
        id: 'SOL508',
        severity: 'high',
        title: 'Social Engineering Attack Surface',
        description: 'Claim/airdrop functions may be exploited via social engineering without proper verification.',
        location: 'Claim functions',
        recommendation: 'Implement signature verification, merkle proofs, or whitelist checks.',
      });
    }
  }
  return findings;
}

// SOL509: Phishing-Vulnerable Approval Pattern
export function checkPhishingVulnerableApproval(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (input.rust?.sourceCode) {
    const code = input.rust.sourceCode;
    if (/approve|delegate|set_authority/.test(code) && !/expiration|max_amount|revoke/.test(code)) {
      findings.push({
        id: 'SOL509',
        severity: 'high',
        title: 'Phishing-Vulnerable Approval Pattern',
        description: 'Unlimited approvals without expiration increase phishing risk.',
        location: 'Approval logic',
        recommendation: 'Add expiration timestamps, amount limits, and easy revocation for approvals.',
      });
    }
  }
  return findings;
}

// SOL510: Domain Spoofing Vulnerability
export function checkDomainSpoofingVulnerability(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (input.rust?.sourceCode) {
    const code = input.rust.sourceCode;
    if (/website|url|domain|link/.test(code) && !/verify_domain|trusted_domains/.test(code)) {
      findings.push({
        id: 'SOL510',
        severity: 'medium',
        title: 'Domain Spoofing Vulnerability',
        description: 'External links/domains not verified, enabling frontend spoofing attacks.',
        location: 'Domain references',
        recommendation: 'Validate domains against trusted list, use checksums for off-chain data.',
      });
    }
  }
  return findings;
}

// SOL511: Missing Rate Limiting
export function checkMissingRateLimiting(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (input.rust?.sourceCode) {
    const code = input.rust.sourceCode;
    if (/pub fn (swap|trade|mint|claim)/.test(code) && !/rate_limit|cooldown|last_action/.test(code)) {
      findings.push({
        id: 'SOL511',
        severity: 'medium',
        title: 'Missing Rate Limiting',
        description: 'High-frequency operations lack rate limiting, enabling bot abuse.',
        location: 'Core operations',
        recommendation: 'Implement per-user rate limiting with cooldown periods.',
      });
    }
  }
  return findings;
}

// SOL512: Unprotected Config Update
export function checkUnprotectedConfigUpdate(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (input.rust?.sourceCode) {
    const code = input.rust.sourceCode;
    if (/update_config|set_config|configure/.test(code) && !/timelock|governance|multisig/.test(code)) {
      findings.push({
        id: 'SOL512',
        severity: 'high',
        title: 'Unprotected Configuration Update',
        description: 'Configuration changes can be made instantly without timelock.',
        location: 'Config update functions',
        recommendation: 'Add timelock delay for configuration changes to allow user response.',
      });
    }
  }
  return findings;
}

// SOL513: Improper Access Control Hierarchy
export function checkImproperAccessControlHierarchy(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (input.rust?.sourceCode) {
    const code = input.rust.sourceCode;
    if (/admin|operator|manager/.test(code) && !/role|permission|access_level/.test(code)) {
      findings.push({
        id: 'SOL513',
        severity: 'medium',
        title: 'Improper Access Control Hierarchy',
        description: 'Flat access control without proper role hierarchy.',
        location: 'Access control',
        recommendation: 'Implement role-based access control with proper permission levels.',
      });
    }
  }
  return findings;
}

// SOL514: Unverified External Call Result
export function checkUnverifiedExternalCallResult(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (input.rust?.sourceCode) {
    const code = input.rust.sourceCode;
    if (/invoke|invoke_signed|cpi/.test(code) && !/check_|verify_|assert_|\.is_ok\(\)/.test(code)) {
      findings.push({
        id: 'SOL514',
        severity: 'high',
        title: 'Unverified External Call Result',
        description: 'CPI call results not properly verified, may miss failures.',
        location: 'CPI calls',
        recommendation: 'Always check return values and verify expected state after CPI calls.',
      });
    }
  }
  return findings;
}

// SOL515: Missing Withdrawal Delay
export function checkMissingWithdrawalDelay(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (input.rust?.sourceCode) {
    const code = input.rust.sourceCode;
    if (/withdraw|unstake|exit/.test(code) && !/delay|timelock|pending|cooldown/.test(code)) {
      findings.push({
        id: 'SOL515',
        severity: 'medium',
        title: 'Missing Withdrawal Delay',
        description: 'Large withdrawals can be executed instantly without delay.',
        location: 'Withdrawal logic',
        recommendation: 'Implement withdrawal delay for amounts above threshold.',
      });
    }
  }
  return findings;
}

// SOL516: Insecure Random Number Generation
export function checkInsecureRandomNumberGeneration(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (input.rust?.sourceCode) {
    const code = input.rust.sourceCode;
    if (/random|rand|lottery|raffle/.test(code) && !/vrf|switchboard|pyth/.test(code)) {
      findings.push({
        id: 'SOL516',
        severity: 'critical',
        title: 'Insecure Random Number Generation',
        description: 'On-chain randomness without VRF is predictable and exploitable.',
        location: 'Randomness source',
        recommendation: 'Use Switchboard VRF, Pyth Entropy, or other verifiable randomness.',
      });
    }
  }
  return findings;
}

// SOL517: Cross-Program State Inconsistency
export function checkCrossProgramStateInconsistency(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (input.rust?.sourceCode) {
    const code = input.rust.sourceCode;
    if (/invoke_signed.*invoke_signed|cpi.*cpi/.test(code) && !/atomic|check_state/.test(code)) {
      findings.push({
        id: 'SOL517',
        severity: 'high',
        title: 'Cross-Program State Inconsistency',
        description: 'Multiple CPI calls may leave state inconsistent if one fails.',
        location: 'Multi-CPI sequences',
        recommendation: 'Verify state consistency after CPI sequences, implement rollback logic.',
      });
    }
  }
  return findings;
}

// SOL518: Unprotected Initialization
export function checkUnprotectedInitialization(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (input.rust?.sourceCode) {
    const code = input.rust.sourceCode;
    if (/pub fn initialize|init\s*\(/.test(code) && !/is_initialized|initialized/.test(code)) {
      findings.push({
        id: 'SOL518',
        severity: 'critical',
        title: 'Unprotected Initialization',
        description: 'Initialize function can be called multiple times or by unauthorized parties.',
        location: 'Initialize function',
        recommendation: 'Add initialization flag check and proper authority validation.',
      });
    }
  }
  return findings;
}

// SOL519: Missing Sanity Checks on Inputs
export function checkMissingSanityChecks(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (input.rust?.sourceCode) {
    const code = input.rust.sourceCode;
    if (/amount|value|price|rate/.test(code) && !/require!.*>|assert!.*>|check.*zero/.test(code)) {
      findings.push({
        id: 'SOL519',
        severity: 'medium',
        title: 'Missing Sanity Checks on Inputs',
        description: 'Numeric inputs not validated for reasonable bounds.',
        location: 'Input handling',
        recommendation: 'Add bounds checking for all numeric inputs (min/max values).',
      });
    }
  }
  return findings;
}

// SOL520: Timestamp Dependency Without Bounds
export function checkTimestampDependencyWithoutBounds(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (input.rust?.sourceCode) {
    const code = input.rust.sourceCode;
    if (/clock\.unix_timestamp|get_clock/.test(code) && !/max_drift|tolerance|bound/.test(code)) {
      findings.push({
        id: 'SOL520',
        severity: 'medium',
        title: 'Timestamp Dependency Without Bounds',
        description: 'Timestamp-dependent logic without drift tolerance.',
        location: 'Time-based logic',
        recommendation: 'Add reasonable bounds/tolerance for timestamp comparisons.',
      });
    }
  }
  return findings;
}

// Functions are exported inline
