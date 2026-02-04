import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL137: Private Key Exposure
 * Detects patterns that could lead to private key leakage
 * Real-world: Slope Wallet ($8M), DEXX ($38M)
 */
export function checkPrivateKeyExposure(input: PatternInput): Finding[] {
  const findings: Finding[] = [];

  if (input.rust?.content) {
    const content = input.rust.content;
    const lines = content.split('\n');

    // Check for secret key handling patterns
    const keyPatterns = [
      /secret_key|private_key|priv_key/i,
      /seed_phrase|mnemonic/i,
      /keypair.*from/i,
      /signing_key|SigningKey/i,
    ];

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];

      // Check for logging of sensitive data
      if (line.match(/msg!|log|print|debug/i) && keyPatterns.some(p => p.test(line))) {
        findings.push({
          id: 'SOL137',
          title: 'Potential Key Logging',
          severity: 'critical',
          description: 'Never log private keys, seed phrases, or sensitive key material.',
          location: { file: input.path, line: i + 1 },
          suggestion: 'Remove all logging of sensitive key material. Use msg!("Signature verified") instead of logging keys.',
          cwe: 'CWE-532',
        });
      }

      // Check for hardcoded keys
      if (line.match(/\[(\s*\d+\s*,\s*){31}\d+\s*\]/) && !line.includes('//')) {
        findings.push({
          id: 'SOL137',
          title: 'Hardcoded Key Material',
          severity: 'critical',
          description: 'Detected potential hardcoded 32-byte key material.',
          location: { file: input.path, line: i + 1 },
          suggestion: 'Never hardcode private keys. Use PDAs or derive keys from program-owned seeds.',
          cwe: 'CWE-798',
        });
      }
    }

    // Check for insecure key derivation
    if (content.includes('Keypair::from_seed') && !content.includes('HMAC') && !content.includes('hkdf')) {
      findings.push({
        id: 'SOL137',
        title: 'Weak Key Derivation',
        severity: 'high',
        description: 'Key derivation should use secure KDFs like HKDF, not raw seeds.',
        location: { file: input.path, line: 1 },
        suggestion: 'Use secure key derivation: HKDF-SHA256 with proper salt and info parameters.',
        cwe: 'CWE-328',
      });
    }

    // Check for transmission of key material
    if (content.includes('serialize') && keyPatterns.some(p => p.test(content))) {
      findings.push({
        id: 'SOL137',
        title: 'Key Material Serialization',
        severity: 'critical',
        description: 'Private key material should never be serialized for transmission or storage.',
        location: { file: input.path, line: 1 },
        suggestion: 'Never serialize private keys. Use signature-based authentication instead.',
        cwe: 'CWE-312',
      });
    }
  }

  return findings;
}
