/**
 * SolShield Security Patterns - Batch 8 (SOL261-SOL275)
 * Real-world exploits from 2024-2025 research
 */

import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

// SOL261: Private Key Logging (Slope-style wallet leak)
export function checkPrivateKeyLogging(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  // Check for logging of sensitive key material
  const patterns = [
    /log!?\s*\([^)]*(?:private|secret|seed|mnemonic|keypair)[^)]*\)/gi,
    /println!?\s*\([^)]*(?:private|secret|seed|mnemonic|keypair)[^)]*\)/gi,
    /msg!?\s*\([^)]*(?:private|secret|seed|mnemonic|keypair)[^)]*\)/gi,
    /trace!?\s*\([^)]*(?:private|secret|seed|mnemonic|keypair)[^)]*\)/gi,
    /debug!?\s*\([^)]*(?:private|secret|seed|mnemonic|keypair)[^)]*\)/gi,
    /info!?\s*\([^)]*(?:private|secret|seed|mnemonic|keypair)[^)]*\)/gi,
    /\.log\s*\([^)]*(?:private|secret|seed|mnemonic)[^)]*\)/gi,
    /console\s*\.\s*log/gi,
    /sentry|bugsnag|crashlytics/gi,
  ];
  
  for (const pattern of patterns) {
    if (pattern.test(content)) {
      findings.push({
        id: 'SOL261',
        severity: 'critical',
        title: 'Private Key Logging Detected',
        description: 'Code may log sensitive key material (private keys, seeds, mnemonics). This caused the $8M Slope wallet exploit where seed phrases were sent to centralized logging servers.',
        location: input.path,
        recommendation: 'Never log private keys, seeds, or mnemonics. Remove all logging of sensitive cryptographic material. Use secure key storage practices.',
      });
      break;
    }
  }
  
  return findings;
}

// SOL262: Centralized Logging of Sensitive Data
export function checkCentralizedLogging(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  // Check for external logging services with wallet data
  const patterns = [
    /sentry::capture|sentry_sdk/gi,
    /bugsnag|rollbar|logrocket/gi,
    /datadog|newrelic|splunk/gi,
    /firebase.*crashlytics/gi,
    /amplitude|mixpanel.*wallet/gi,
  ];
  
  for (const pattern of patterns) {
    if (pattern.test(content)) {
      findings.push({
        id: 'SOL262',
        severity: 'high',
        title: 'Centralized Logging Service Detected',
        description: 'External logging services may capture sensitive wallet data. The Slope wallet hack occurred because seed phrases were sent to a centralized logging server.',
        location: input.path,
        recommendation: 'Audit all data sent to external logging services. Ensure no sensitive wallet data (keys, seeds, balances) is transmitted.',
      });
      break;
    }
  }
  
  return findings;
}

// SOL263: TWAP Oracle Manipulation
export function checkTwapOracleManipulation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  // Check for TWAP implementations without sufficient protections
  if (/twap|time.?weighted|average.?price/gi.test(content)) {
    // Check for short TWAP windows
    if (/twap.*(?:60|120|300|600)\s*(?:seconds|secs)/gi.test(content) || 
        /window.*(?:1|2|5|10)\s*(?:min|minute)/gi.test(content)) {
      findings.push({
        id: 'SOL263',
        severity: 'high',
        title: 'Short TWAP Window Detected',
        description: 'TWAP oracle with short time window (< 30 minutes) is vulnerable to manipulation. Attackers can manipulate prices over short periods using flash loans.',
        location: input.path,
        recommendation: 'Use longer TWAP windows (at least 30 minutes to 1 hour). Implement additional price deviation checks and circuit breakers.',
      });
    }
    
    // Check for missing manipulation protections
    if (!/max.*deviation|price.*bound|circuit.*breaker/gi.test(content)) {
      findings.push({
        id: 'SOL263',
        severity: 'medium',
        title: 'TWAP Without Price Bounds',
        description: 'TWAP oracle implementation lacks price deviation checks or circuit breakers.',
        location: input.path,
        recommendation: 'Add maximum price deviation checks and circuit breakers to prevent manipulation during volatile periods.',
      });
    }
  }
  
  return findings;
}

// SOL264: Leveraged Position Manipulation (Mango-style)
export function checkLeveragedPositionManipulation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  // Check for leveraged position systems
  if (/leverage|margin|perpetual|perp|collateral.*borrow/gi.test(content)) {
    // Check for missing self-trading protections
    if (!/self.*trade|same.*account.*check|duplicate.*position/gi.test(content)) {
      findings.push({
        id: 'SOL264',
        severity: 'critical',
        title: 'Missing Self-Trading Protection',
        description: 'Leveraged trading system may allow self-trading to manipulate oracle prices. This was the root cause of the $116M Mango Markets exploit.',
        location: input.path,
        recommendation: 'Implement checks to prevent self-trading and cross-account manipulation. Add position size limits and price impact calculations.',
      });
    }
    
    // Check for low liquidity token risks
    if (!/liquidity.*check|min.*liquidity|volume.*requirement/gi.test(content)) {
      findings.push({
        id: 'SOL264',
        severity: 'high',
        title: 'Low Liquidity Token Risk',
        description: 'No liquidity checks for collateral tokens. Low liquidity tokens can be easily manipulated for leveraged borrowing.',
        location: input.path,
        recommendation: 'Only allow high-liquidity tokens as collateral. Implement minimum liquidity and volume requirements.',
      });
    }
  }
  
  return findings;
}

// SOL265: Flash Loan Oracle Attack
export function checkFlashLoanOracleAttack(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  // Check for oracle usage with potential flash loan vulnerability
  if (/oracle|price.*feed|get.*price/gi.test(content)) {
    // Check for same-block price usage
    if (!/block.*number|slot.*check|stale.*price|price.*age/gi.test(content)) {
      findings.push({
        id: 'SOL265',
        severity: 'critical',
        title: 'Flash Loan Oracle Attack Vector',
        description: 'Oracle price used without staleness or same-transaction checks. Attacker can manipulate price via flash loan, use manipulated price, and repay loan in same transaction.',
        location: input.path,
        recommendation: 'Implement minimum price age requirements. Use TWAP oracles. Add same-transaction manipulation detection.',
      });
    }
  }
  
  return findings;
}

// SOL266: Bonding Curve Flash Loan Attack (Nirvana-style)
export function checkBondingCurveFlashLoan(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  // Check for bonding curve implementations
  if (/bonding.*curve|price.*curve|mint.*curve/gi.test(content)) {
    // Check for flash loan protections
    if (!/flash.*loan.*guard|same.*block.*mint|cooldown|time.*lock/gi.test(content)) {
      findings.push({
        id: 'SOL266',
        severity: 'critical',
        title: 'Bonding Curve Flash Loan Vulnerability',
        description: 'Bonding curve without flash loan protection. Attackers can use flash loans to buy tokens at low price, pump the curve, and sell at inflated price. This caused the $3.5M Nirvana Finance exploit.',
        location: input.path,
        recommendation: 'Add flash loan guards (same-block minting restrictions). Implement time delays between buy and sell operations.',
      });
    }
  }
  
  return findings;
}

// SOL267: Governance Timelock Bypass (Audius-style)
export function checkGovernanceTimelockBypass(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  // Check for governance systems
  if (/governance|proposal|vote|dao/gi.test(content)) {
    // Check for proper timelock implementation
    if (!/timelock|delay.*execution|execution.*delay|min.*delay/gi.test(content)) {
      findings.push({
        id: 'SOL267',
        severity: 'critical',
        title: 'Missing Governance Timelock',
        description: 'Governance system without execution timelock. Attackers can execute malicious proposals immediately after passing. This enabled the $6.1M Audius exploit.',
        location: input.path,
        recommendation: 'Implement mandatory timelocks (24-48 hours minimum) between proposal passing and execution. Add emergency veto mechanisms.',
      });
    }
    
    // Check for proposal validation
    if (!/validate.*proposal|proposal.*check|whitelist.*action/gi.test(content)) {
      findings.push({
        id: 'SOL267',
        severity: 'high',
        title: 'Missing Proposal Validation',
        description: 'Governance proposals not validated for malicious content. Attackers can inject harmful code or reconfigure permissions.',
        location: input.path,
        recommendation: 'Validate proposal contents against allowed actions. Implement action whitelists for governance.',
      });
    }
  }
  
  return findings;
}

// SOL268: Third-Party Pool Dependency (UXD/Tulip-style)
export function checkThirdPartyPoolDependency(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  // Check for external protocol dependencies
  if (/deposit.*external|external.*pool|third.*party|lending.*pool/gi.test(content)) {
    // Check for diversification
    if (!/diversif|multiple.*pool|fallback.*pool/gi.test(content)) {
      findings.push({
        id: 'SOL268',
        severity: 'high',
        title: 'Single Third-Party Pool Dependency',
        description: 'Protocol depends on single external pool/protocol. If that protocol is exploited, funds are at risk. UXD and Tulip lost access to funds during the Mango exploit.',
        location: input.path,
        recommendation: 'Diversify across multiple lending pools. Implement fallback mechanisms and position limits per external protocol.',
      });
    }
    
    // Check for monitoring
    if (!/monitor.*external|health.*check|pool.*status/gi.test(content)) {
      findings.push({
        id: 'SOL268',
        severity: 'medium',
        title: 'No External Pool Monitoring',
        description: 'No monitoring of third-party pool health. Protocol may not detect when external pools are compromised.',
        location: input.path,
        recommendation: 'Implement health monitoring for all external pool dependencies. Add automatic withdrawal triggers on anomalies.',
      });
    }
  }
  
  return findings;
}

// SOL269: MongoDB/NoSQL Injection (Thunder Terminal-style)
export function checkNoSqlInjection(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  // Check for database operations (even in Rust programs that might call external APIs)
  const patterns = [
    /mongodb|mongoose|nosql/gi,
    /db\s*\.\s*(?:find|update|insert|delete)/gi,
    /\$where|\$regex|\$gt|\$lt/gi,
    /json.*query|query.*json/gi,
  ];
  
  for (const pattern of patterns) {
    if (pattern.test(content)) {
      // Check for parameterization
      if (!/parameteriz|sanitiz|escape|prepared/gi.test(content)) {
        findings.push({
          id: 'SOL269',
          severity: 'critical',
          title: 'Potential NoSQL Injection Vector',
          description: 'Database queries without apparent parameterization or sanitization. Thunder Terminal lost $240K due to MongoDB session token theft via injection.',
          location: input.path,
          recommendation: 'Use parameterized queries. Sanitize all user inputs. Implement strict input validation.',
        });
        break;
      }
    }
  }
  
  return findings;
}

// SOL270: Session Token Security
export function checkSessionTokenSecurity(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  // Check for session management
  if (/session|token|jwt|auth.*token/gi.test(content)) {
    // Check for secure token generation
    if (!/crypto.*random|secure.*random|getrandom|rand::rngs::OsRng/gi.test(content)) {
      findings.push({
        id: 'SOL270',
        severity: 'high',
        title: 'Weak Session Token Generation',
        description: 'Session tokens may not be using cryptographically secure random generation.',
        location: input.path,
        recommendation: 'Use cryptographically secure random number generators for all session tokens.',
      });
    }
    
    // Check for token expiration
    if (!/expir|ttl|max.*age|valid.*until/gi.test(content)) {
      findings.push({
        id: 'SOL270',
        severity: 'medium',
        title: 'Missing Session Token Expiration',
        description: 'Session tokens without expiration are vulnerable to theft and replay attacks.',
        location: input.path,
        recommendation: 'Implement token expiration with reasonable TTL. Add token refresh mechanisms.',
      });
    }
  }
  
  return findings;
}

// SOL271: Employee/Insider Access Control
export function checkInsiderAccessControl(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  // Check for admin/privileged functions
  if (/admin|operator|privileged|internal.*only/gi.test(content)) {
    // Check for multisig requirement
    if (!/multisig|multi.*sig|threshold.*sign|m.*of.*n/gi.test(content)) {
      findings.push({
        id: 'SOL271',
        severity: 'critical',
        title: 'Single-Key Admin Access',
        description: 'Privileged functions controlled by single key. The Pump.fun exploit was executed by an employee with privileged access. Use multisig for all admin functions.',
        location: input.path,
        recommendation: 'Require multisig (2-of-3 minimum) for all admin and privileged operations. Implement time delays for sensitive actions.',
      });
    }
    
    // Check for audit logging
    if (!/audit.*log|action.*log|admin.*event/gi.test(content)) {
      findings.push({
        id: 'SOL271',
        severity: 'medium',
        title: 'Missing Admin Action Logging',
        description: 'Administrative actions not logged. This prevents detection of insider threats.',
        location: input.path,
        recommendation: 'Log all administrative actions with timestamps and actor identification.',
      });
    }
  }
  
  return findings;
}

// SOL272: Wormhole-style Guardian Validation
export function checkGuardianValidationComprehensive(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  // Check for bridge/guardian patterns
  if (/guardian|validator.*set|bridge.*signer|relayer/gi.test(content)) {
    // Check for signature verification
    if (!/verify.*signature|check.*sig|validate.*guardian/gi.test(content)) {
      findings.push({
        id: 'SOL272',
        severity: 'critical',
        title: 'Missing Guardian Signature Verification',
        description: 'Bridge guardian signatures not properly verified. The $326M Wormhole exploit bypassed guardian validation through signature verification flaws.',
        location: input.path,
        recommendation: 'Implement robust signature verification with proper input validation. Verify signer set membership before accepting messages.',
      });
    }
    
    // Check for replay protection
    if (!/nonce|sequence|used.*message|replay.*protect/gi.test(content)) {
      findings.push({
        id: 'SOL272',
        severity: 'critical',
        title: 'Missing Bridge Replay Protection',
        description: 'Bridge messages may be replayed. Each message must have unique nonce or sequence number.',
        location: input.path,
        recommendation: 'Implement strict replay protection with message nonces. Track used messages to prevent double-spending.',
      });
    }
  }
  
  return findings;
}

// SOL273: Trading Bot Security (Banana Gun-style)
export function checkTradingBotSecurity(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  // Check for bot/automation patterns
  if (/bot|automat|sniper|trading.*agent/gi.test(content)) {
    // Check for key isolation
    if (!/isolated.*key|separate.*wallet|hot.*wallet.*limit/gi.test(content)) {
      findings.push({
        id: 'SOL273',
        severity: 'critical',
        title: 'Bot Key Isolation Missing',
        description: 'Trading bot may not have proper key isolation. The Banana Gun exploit drained user wallets due to key management issues.',
        location: input.path,
        recommendation: 'Isolate bot keys from main wallets. Implement withdrawal limits. Use separate keys for each user.',
      });
    }
  }
  
  return findings;
}

// SOL274: DEXX-style Private Key Management
export function checkPrivateKeyManagement(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  // Check for key management patterns
  if (/private.*key|secret.*key|keypair|wallet.*key/gi.test(content)) {
    // Check for key storage
    if (/store.*key|save.*key|persist.*key/gi.test(content)) {
      if (!/encrypt|sealed|hardware.*security|hsm/gi.test(content)) {
        findings.push({
          id: 'SOL274',
          severity: 'critical',
          title: 'Insecure Private Key Storage',
          description: 'Private keys stored without encryption. The $30M DEXX exploit occurred due to private key leakage from insecure storage.',
          location: input.path,
          recommendation: 'Never store unencrypted private keys. Use hardware security modules (HSM) or secure enclaves. Implement key derivation with user secrets.',
        });
      }
    }
    
    // Check for key transmission
    if (/send.*key|transmit.*key|network.*key|api.*key/gi.test(content)) {
      findings.push({
        id: 'SOL274',
        severity: 'critical',
        title: 'Private Key Network Transmission',
        description: 'Private keys may be transmitted over network. Keys should never leave the secure enclave.',
        location: input.path,
        recommendation: 'Never transmit private keys over any network. Sign transactions locally and only send signed transactions.',
      });
    }
  }
  
  return findings;
}

// SOL275: NPM/Dependency Hijacking (Web3.js-style)
export function checkNpmDependencyHijacking(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  if (!input.rust) return findings;
  const content = input.rust.content;
  
  // Check for dependency patterns (even in Rust with external calls)
  if (/extern\s+crate|use\s+\w+::|import|require/gi.test(content)) {
    // Check for known vulnerable patterns
    const vulnerablePatterns = [
      /solana.*web3.*js/gi,
      /unpinned.*version/gi,
      /\*\s*$|>=\s*\d|>\s*\d/gm, // Version ranges
    ];
    
    for (const pattern of vulnerablePatterns) {
      if (pattern.test(content)) {
        findings.push({
          id: 'SOL275',
          severity: 'high',
          title: 'Dependency Version Not Pinned',
          description: 'Dependencies with unpinned versions are vulnerable to supply chain attacks. The @solana/web3.js supply chain attack in 2024 compromised versions 1.95.6 and 1.95.7.',
          location: input.path,
          recommendation: 'Pin all dependency versions exactly. Use lockfiles. Verify package checksums. Audit dependencies regularly.',
        });
        break;
      }
    }
  }
  
  return findings;
}
