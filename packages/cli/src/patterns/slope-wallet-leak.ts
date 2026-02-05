import type { Finding } from '../commands/audit.js';
import type { ParsedIdl } from '../parsers/idl.js';
import type { ParsedRust } from '../parsers/rust.js';

/**
 * SOL240: Slope Wallet-style Key Leakage
 * Detects patterns that could leak private keys/seed phrases
 * Reference: Slope Mobile Wallet hack (August 2022) - $8M stolen via key logging
 */
export function checkSlopeWalletLeak(idl: ParsedIdl | null, rust: ParsedRust | null): Finding[] {
  const findings: Finding[] = [];

  if (rust) {
    for (const fn of rust.functions) {
      const content = fn.body;
      const contentLower = content.toLowerCase();

      // Check for key logging/printing
      if (contentLower.includes('private') || contentLower.includes('secret') || contentLower.includes('keypair')) {
        if (contentLower.includes('println') || contentLower.includes('print!') || 
            contentLower.includes('log::') || contentLower.includes('debug!') ||
            contentLower.includes('info!') || contentLower.includes('trace!')) {
          findings.push({
            id: 'SOL240',
            severity: 'critical',
            title: 'Private Key Logging',
            description: 'Private key material may be logged. Slope wallet leaked keys through Sentry logging.',
            location: `Function: ${fn.name}`,
            recommendation: 'NEVER log private keys, seed phrases, or any secret material. Use secure memory handling.',
          });
        }
      }

      // Check for key serialization to strings
      if (contentLower.includes('keypair') || contentLower.includes('secret_key')) {
        if (contentLower.includes('to_string') || contentLower.includes('format!') || 
            contentLower.includes('display') || contentLower.includes('to_base58')) {
          if (!contentLower.includes('pubkey')) {
            findings.push({
              id: 'SOL240',
              severity: 'high',
              title: 'Secret Key Serialization',
              description: 'Secret key being converted to string format. This creates a copy that may persist in memory or logs.',
              location: `Function: ${fn.name}`,
              recommendation: 'Keep secrets in their native format. Use zeroize crate to clear memory after use.',
            });
          }
        }
      }

      // Check for telemetry with key data
      if (contentLower.includes('sentry') || contentLower.includes('analytics') || 
          contentLower.includes('telemetry') || contentLower.includes('tracking')) {
        if (contentLower.includes('wallet') || contentLower.includes('account') || 
            contentLower.includes('user')) {
          findings.push({
            id: 'SOL240',
            severity: 'critical',
            title: 'Telemetry Near Wallet Operations',
            description: 'Telemetry/analytics near wallet operations. Slope accidentally sent seed phrases to Sentry.',
            location: `Function: ${fn.name}`,
            recommendation: 'Audit all telemetry calls. Never include wallet data. Use allowlist for telemetry fields.',
          });
        }
      }

      // Check for seed phrase handling
      if (contentLower.includes('mnemonic') || contentLower.includes('seed_phrase') || 
          contentLower.includes('bip39') || contentLower.includes('recovery')) {
        if (!contentLower.includes('zeroize') && !contentLower.includes('secure_') && 
            !contentLower.includes('encrypt')) {
          findings.push({
            id: 'SOL240',
            severity: 'high',
            title: 'Seed Phrase Without Secure Handling',
            description: 'Seed phrase handled without explicit security measures. Use zeroize to clear memory.',
            location: `Function: ${fn.name}`,
            recommendation: 'Use #[zeroize(drop)] on structs containing secrets. Clear memory immediately after use.',
          });
        }
      }

      // Check for clipboard operations with keys
      if (contentLower.includes('clipboard') || contentLower.includes('copy') || 
          contentLower.includes('paste')) {
        if (contentLower.includes('key') || contentLower.includes('secret') || 
            contentLower.includes('seed')) {
          findings.push({
            id: 'SOL240',
            severity: 'high',
            title: 'Secret in Clipboard',
            description: 'Secrets may be copied to clipboard. Clipboard contents can be accessed by other applications.',
            location: `Function: ${fn.name}`,
            recommendation: 'Warn users about clipboard risks. Auto-clear clipboard after short timeout.',
          });
        }
      }

      // Check for network transmission of keys
      if (contentLower.includes('http') || contentLower.includes('fetch') || 
          contentLower.includes('reqwest') || contentLower.includes('send')) {
        if (contentLower.includes('key') || contentLower.includes('secret') || 
            contentLower.includes('keypair')) {
          findings.push({
            id: 'SOL240',
            severity: 'critical',
            title: 'Secret Key Network Transmission',
            description: 'Private key may be transmitted over network. Keys should NEVER leave the device.',
            location: `Function: ${fn.name}`,
            recommendation: 'Sign transactions locally. Never transmit private keys. Use hardware wallets.',
          });
        }
      }

      // Check for file storage of keys
      if (contentLower.includes('write') || contentLower.includes('save') || 
          contentLower.includes('store') || contentLower.includes('file')) {
        if (contentLower.includes('keypair') || contentLower.includes('secret') || 
            contentLower.includes('private')) {
          if (!contentLower.includes('encrypt') && !contentLower.includes('cipher') && 
              !contentLower.includes('aes') && !contentLower.includes('sealed')) {
            findings.push({
              id: 'SOL240',
              severity: 'critical',
              title: 'Unencrypted Key Storage',
              description: 'Private key may be stored without encryption. Keys at rest must be encrypted.',
              location: `Function: ${fn.name}`,
              recommendation: 'Encrypt all stored keys with user-derived key. Use OS keychain when available.',
            });
          }
        }
      }

      // Check for debug builds with secrets
      if (content.includes('#[cfg(debug_assertions)]') || content.includes('debug_assert')) {
        if (contentLower.includes('key') || contentLower.includes('secret')) {
          findings.push({
            id: 'SOL240',
            severity: 'medium',
            title: 'Debug Build Key Handling',
            description: 'Secret handling differs in debug builds. Debug builds may have less secure key handling.',
            location: `Function: ${fn.name}`,
            recommendation: 'Ensure security measures are consistent between debug and release builds.',
          });
        }
      }
    }
  }

  return findings;
}
