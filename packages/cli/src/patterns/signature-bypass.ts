import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL142: Signature Verification Bypass (Wormhole - $326M enhanced)
 * 
 * Advanced detection for signature verification bypasses including
 * guardian/validator signature spoofing and verification flaws.
 */
export function checkSignatureBypass(input: PatternInput): Finding[] {
  const findings: Finding[] = [];

  if (!input.rust || !input.rust.files) return findings;

  for (const file of input.rust.files) {
    const lines = file.lines;
    const content = file.content;

    lines.forEach((line, index) => {
      const lineNum = index + 1;
      const lineLower = line.toLowerCase();

      // Pattern 1: Signature verification with external sysvar
      if (lineLower.includes('signature') && lineLower.includes('verify')) {
        const fnEnd = Math.min(lines.length, index + 20);
        const fnBody = lines.slice(index, fnEnd).join('\n').toLowerCase();
        
        if (fnBody.includes('sysvar') || fnBody.includes('instruction_sysvar')) {
          if (!fnBody.includes('sysvar::instructions::id') && !fnBody.includes('check_id')) {
            findings.push({
              id: `SOL142-${findings.length + 1}`,
              pattern: 'Signature Verification Bypass',
              severity: 'critical',
              title: 'Sysvar used without ID verification',
              description: 'Instruction sysvar used for signature verification without verifying it is the real sysvar. Attacker can pass fake sysvar (Wormhole exploit).',
              location: { file: file.path, line: lineNum },
              suggestion: 'Always verify: require_keys_eq!(sysvar_account.key(), sysvar::instructions::ID)',
            });
          }
        }
      }

      // Pattern 2: Guardian/validator set manipulation
      if (lineLower.includes('guardian') || lineLower.includes('validator_set') ||
          lineLower.includes('signer_set')) {
        const fnEnd = Math.min(lines.length, index + 25);
        const fnBody = lines.slice(index, fnEnd).join('\n').toLowerCase();
        
        if (fnBody.includes('update') || fnBody.includes('set') || fnBody.includes('add')) {
          if (!fnBody.includes('quorum') && !fnBody.includes('threshold') && !fnBody.includes('supermajority')) {
            findings.push({
              id: `SOL142-${findings.length + 1}`,
              pattern: 'Signature Verification Bypass',
              severity: 'critical',
              title: 'Guardian/validator set update without quorum',
              description: 'Signer set can be updated without supermajority agreement. Could allow hostile takeover.',
              location: { file: file.path, line: lineNum },
              suggestion: 'Require 2/3+ of current guardians to approve set changes.',
            });
          }
        }
      }

      // Pattern 3: Ed25519 verification without proper checks
      if (lineLower.includes('ed25519') && (lineLower.includes('verify') || lineLower.includes('check'))) {
        const fnEnd = Math.min(lines.length, index + 15);
        const fnBody = lines.slice(index, fnEnd).join('\n').toLowerCase();
        
        if (!fnBody.includes('message') || !fnBody.includes('pubkey')) {
          findings.push({
            id: `SOL142-${findings.length + 1}`,
            pattern: 'Signature Verification Bypass',
            severity: 'high',
            title: 'Incomplete Ed25519 verification',
            description: 'Ed25519 verification may not properly bind signature to message and pubkey.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Verify complete tuple: ed25519_verify(signature, message, pubkey)',
          });
        }
      }

      // Pattern 4: Secp256k1 recovery issues
      if (lineLower.includes('secp256k1') || lineLower.includes('recover')) {
        findings.push({
          id: `SOL142-${findings.length + 1}`,
          pattern: 'Signature Verification Bypass',
          severity: 'high',
          title: 'Secp256k1 signature recovery used',
          description: 'Signature recovery can have edge cases. Ensure recovery_id is validated and result checked.',
          location: { file: file.path, line: lineNum },
          suggestion: 'Validate recovery: verify recovered pubkey matches expected signer.',
        });
      }

      // Pattern 5: Multi-sig with insufficient checks
      if (lineLower.includes('multisig') || lineLower.includes('multi_sig') ||
          (lineLower.includes('threshold') && lineLower.includes('sign'))) {
        const fnEnd = Math.min(lines.length, index + 20);
        const fnBody = lines.slice(index, fnEnd).join('\n').toLowerCase();
        
        if (!fnBody.includes('unique') && !fnBody.includes('duplicate') && !fnBody.includes('distinct')) {
          findings.push({
            id: `SOL142-${findings.length + 1}`,
            pattern: 'Signature Verification Bypass',
            severity: 'critical',
            title: 'Multi-sig without duplicate signer check',
            description: 'Multi-sig may not check for duplicate signatures. Same signer could be counted multiple times.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Verify unique signers: ensure no pubkey appears twice in signature list.',
          });
        }
      }
    });
  }

  return findings;
}
