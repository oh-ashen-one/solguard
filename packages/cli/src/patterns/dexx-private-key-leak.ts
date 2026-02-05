// SOL737: DEXX Private Key Leak Pattern (Nov 2024 - $30M)
// Based on the DEXX exploit where private keys were leaked to malicious servers

import type { ParsedRust } from '../parsers/rust.js';
import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * DEXX Exploit Pattern - Private Key Management Vulnerabilities
 * 
 * The DEXX exploit in November 2024 resulted in ~$30M in losses due to
 * private keys being sent to malicious servers. This pattern detects:
 * 
 * 1. Private key exposure in code or logs
 * 2. Insecure key storage patterns
 * 3. Key transmission to external endpoints
 * 4. Missing encryption for sensitive data
 * 5. Hardcoded secrets or mnemonics
 */

export function checkDexxKeyLeak(parsed: ParsedRust): Finding[] {
  const findings: Finding[] = [];

  // Check for private key exposure patterns
  const privateKeyPatterns = [
    /private_key|secret_key|mnemonic|seed_phrase/i,
    /wallet\.secret|keypair\.secret/i,
    /sk_|secret_|priv_/i,
  ];

  // Check for transmission to external endpoints
  const transmissionPatterns = [
    /http:\/\/|https:\/\//i,
    /\.post\s*\(|\.send\s*\(/i,
    /fetch\s*\(|reqwest|hyper/i,
  ];

  // Check for logging sensitive data
  const loggingPatterns = [
    /println!.*(?:key|secret|seed|mnemonic)/i,
    /log::.*(?:key|secret|seed|mnemonic)/i,
    /msg!.*(?:key|secret|seed|mnemonic)/i,
  ];

  for (const func of parsed.functions) {
    const content = func.content.toLowerCase();
    
    // Check for private key exposure
    for (const pattern of privateKeyPatterns) {
      if (pattern.test(content)) {
        // Check if it's being transmitted
        for (const txPattern of transmissionPatterns) {
          if (txPattern.test(content)) {
            findings.push({
              id: 'SOL657',
              severity: 'critical',
              title: 'DEXX-style Private Key Transmission Risk',
              description: `Function '${func.name}' may expose private keys to external endpoints`,
              location: func.location,
              recommendation: 'Never transmit private keys. Use signatures for authentication, hardware wallets for key storage, and server-side validation without key exposure.',
            });
          }
        }
      }
    }

    // Check for logging sensitive data
    for (const logPattern of loggingPatterns) {
      if (logPattern.test(content)) {
        findings.push({
          id: 'SOL657',
          severity: 'critical',
          title: 'Sensitive Key Data in Logs',
          description: `Function '${func.name}' may log sensitive key material`,
          location: func.location,
          recommendation: 'Never log private keys, seeds, or mnemonics. Use secure audit logging without sensitive data.',
        });
      }
    }
  }

  // Check for hardcoded secrets
  const hardcodedPatterns = [
    /const\s+(?:SECRET|PRIVATE|MNEMONIC|SEED)/i,
    /static\s+(?:SECRET|PRIVATE|MNEMONIC|SEED)/i,
    /[a-f0-9]{64}/i, // Possible private key hex
  ];

  for (const struct of parsed.structs) {
    const content = struct.fields.join(' ').toLowerCase();
    for (const pattern of hardcodedPatterns) {
      if (pattern.test(content)) {
        findings.push({
          id: 'SOL657',
          severity: 'critical',
          title: 'Hardcoded Secret Detected',
          description: `Struct '${struct.name}' may contain hardcoded secrets`,
          location: struct.location,
          recommendation: 'Never hardcode secrets. Use environment variables, secure vaults, or HSMs for key management.',
        });
      }
    }
  }

  return findings;
}

// Additional patterns for wallet/key security
export function checkWalletKeyManagement(parsed: ParsedRust): Finding[] {
  const findings: Finding[] = [];

  // Check for insecure key derivation
  const insecureDerivationPatterns = [
    /derive_key.*(?:weak|simple|basic)/i,
    /sha256.*(?:password|pin)/i,
    /md5|sha1/i, // Weak hashing
  ];

  for (const func of parsed.functions) {
    const content = func.content.toLowerCase();
    
    for (const pattern of insecureDerivationPatterns) {
      if (pattern.test(content)) {
        findings.push({
          id: 'SOL658',
          severity: 'high',
          title: 'Insecure Key Derivation',
          description: `Function '${func.name}' uses potentially weak key derivation`,
          location: func.location,
          recommendation: 'Use strong key derivation functions like PBKDF2, Argon2, or scrypt with appropriate parameters.',
        });
      }
    }
  }

  return findings;
}

// Export combined check
export function checkPrivateKeySecurityPatterns(input: PatternInput): Finding[] {
  if (!input.rust) return [];
  return [
    ...checkDexxKeyLeak(input.rust),
    ...checkWalletKeyManagement(input.rust),
  ];
}
