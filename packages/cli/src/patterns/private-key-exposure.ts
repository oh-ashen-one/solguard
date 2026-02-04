import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL137: Private Key Exposure (Slope Wallet - $8M, DEXX - $30M)
 * 
 * Detects patterns that could lead to private key exposure or
 * improper key management.
 */
export function checkPrivateKeyExposure(input: PatternInput): Finding[] {
  const findings: Finding[] = [];

  if (!input.rust || !input.rust.files) return findings;

  for (const file of input.rust.files) {
    const lines = file.lines;
    const content = file.content;

    lines.forEach((line, index) => {
      const lineNum = index + 1;
      const lineLower = line.toLowerCase();

      // Pattern 1: Keypair/private key in code
      if (lineLower.includes('keypair') || lineLower.includes('private_key') || 
          lineLower.includes('secret_key') || lineLower.includes('secretkey')) {
        findings.push({
          id: `SOL137-${findings.length + 1}`,
          pattern: 'Private Key Exposure Risk',
          severity: 'critical',
          title: 'Private key handling in code',
          description: 'Code references private keys or keypairs. On-chain programs should never handle private keys directly (Slope/DEXX exploits).',
          location: { file: file.path, line: lineNum },
          suggestion: 'Use PDAs for program-owned accounts. Never store or process private keys.',
        });
      }

      // Pattern 2: Logging that could expose sensitive data
      if ((lineLower.includes('msg!') || lineLower.includes('println!') || 
           lineLower.includes('log::') || lineLower.includes('debug!')) &&
          (lineLower.includes('key') || lineLower.includes('secret') || 
           lineLower.includes('authority') || lineLower.includes('signer'))) {
        findings.push({
          id: `SOL137-${findings.length + 1}`,
          pattern: 'Private Key Exposure Risk',
          severity: 'high',
          title: 'Potentially sensitive data in logs',
          description: 'Logging statement may expose sensitive key material. Logs are public on Solana.',
          location: { file: file.path, line: lineNum },
          suggestion: 'Never log keys, secrets, or full account data. Log only identifiers if needed.',
        });
      }

      // Pattern 3: Seed phrase / mnemonic handling
      if (lineLower.includes('mnemonic') || lineLower.includes('seed_phrase') ||
          lineLower.includes('bip39') || lineLower.includes('word_list')) {
        findings.push({
          id: `SOL137-${findings.length + 1}`,
          pattern: 'Private Key Exposure Risk',
          severity: 'critical',
          title: 'Seed phrase/mnemonic in code',
          description: 'Code handles seed phrases or mnemonics. This should never be in on-chain code.',
          location: { file: file.path, line: lineNum },
          suggestion: 'Remove all seed phrase handling from on-chain code.',
        });
      }

      // Pattern 4: Signature creation (could indicate key usage)
      if (lineLower.includes('sign_message') || lineLower.includes('ed25519_sign') ||
          lineLower.includes('signature::new')) {
        if (!lineLower.includes('verify') && !lineLower.includes('check')) {
          findings.push({
            id: `SOL137-${findings.length + 1}`,
            pattern: 'Private Key Exposure Risk',
            severity: 'high',
            title: 'Signature creation detected',
            description: 'Code creates signatures which requires private key access. Programs should use invoke_signed, not manual signing.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Use invoke_signed for CPI with program-derived seeds instead of manual signing.',
          });
        }
      }

      // Pattern 5: Unsafe deserialization of account data that could be keys
      if (lineLower.includes('try_from_slice') || lineLower.includes('deserialize')) {
        const fnEnd = Math.min(lines.length, index + 5);
        const fnBody = lines.slice(index, fnEnd).join('\n').toLowerCase();
        
        if (fnBody.includes('[u8; 64]') || fnBody.includes('[u8; 32]')) {
          findings.push({
            id: `SOL137-${findings.length + 1}`,
            pattern: 'Private Key Exposure Risk',
            severity: 'medium',
            title: 'Deserialization of key-sized byte array',
            description: 'Deserializing 32 or 64 byte arrays could be handling keys. Verify this is not key material.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Document what this data represents. Ensure it is not private key material.',
          });
        }
      }
    });
  }

  return findings;
}
