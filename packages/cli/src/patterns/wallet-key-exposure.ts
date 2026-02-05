import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL182: Wallet Private Key Exposure
 * 
 * Detects patterns that could lead to private key exposure in
 * mobile wallets and browser extensions.
 * 
 * Real-world exploit: Slope Wallet - $8M stolen when private keys
 * were logged to centralized servers.
 */
export function checkWalletKeyExposure(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const { rust, path } = input;

  if (!rust) return findings;

  const dangerousPatterns = [
    { pattern: /log.*private.*key/i, severity: 'critical' as const, desc: 'Logging private keys' },
    { pattern: /log.*secret/i, severity: 'critical' as const, desc: 'Logging secrets' },
    { pattern: /log.*seed.*phrase/i, severity: 'critical' as const, desc: 'Logging seed phrases' },
    { pattern: /log.*mnemonic/i, severity: 'critical' as const, desc: 'Logging mnemonics' },
    { pattern: /send.*private.*key/i, severity: 'critical' as const, desc: 'Sending private keys' },
    { pattern: /telemetry.*key/i, severity: 'critical' as const, desc: 'Telemetry with keys' },
    { pattern: /analytics.*wallet/i, severity: 'high' as const, desc: 'Analytics with wallet data' },
    { pattern: /plaintext.*key/i, severity: 'critical' as const, desc: 'Plaintext key storage' },
    { pattern: /localStorage.*key/i, severity: 'high' as const, desc: 'Local storage key access' },
    { pattern: /serialize.*keypair/i, severity: 'high' as const, desc: 'Serializing keypairs' },
    { pattern: /export.*private/i, severity: 'high' as const, desc: 'Exporting private data' },
    { pattern: /console\.log.*key/i, severity: 'critical' as const, desc: 'Console logging keys' },
  ];

  const lines = rust.content.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    for (const { pattern, severity, desc } of dangerousPatterns) {
      if (pattern.test(line)) {
        findings.push({
          id: 'SOL182',
          severity,
          title: 'Private Key Exposure Risk',
          description: `${desc} - private keys should never be logged, transmitted, or stored in plaintext.`,
          location: { file: path, line: i + 1 },
          recommendation: 'Never log or transmit private keys. Use hardware security modules or secure enclaves for key operations.',
        });
      }
    }
  }

  return findings;
}
