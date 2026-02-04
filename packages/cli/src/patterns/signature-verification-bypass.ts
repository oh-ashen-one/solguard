import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL142: Signature Verification Bypass
 * Detects vulnerabilities in signature verification
 * Real-world: Wormhole ($326M exploit)
 */
export function checkSignatureVerificationBypass(input: PatternInput): Finding[] {
  const findings: Finding[] = [];

  if (input.rust?.content) {
    const content = input.rust.content;
    const lines = content.split('\n');

    // Check for signature-related patterns
    const sigPatterns = [
      /verify.*signature|signature.*verify/i,
      /ed25519|secp256k1/i,
      /SignatureSet|guardian.*signature/i,
      /check_signature|validate_signature/i,
    ];

    const hasSignature = sigPatterns.some(p => p.test(content));

    if (hasSignature) {
      // Check for signature account validation (Wormhole attack vector)
      if (content.includes('SignatureSet') || content.includes('signature_set')) {
        if (!content.includes('signature_set.is_initialized') && !content.includes('is_verified')) {
          findings.push({
            id: 'SOL142',
            title: 'Unvalidated Signature Set',
            severity: 'critical',
            description: 'Signature sets must be validated as properly initialized and verified before use.',
            location: { file: input.path, line: 1 },
            suggestion: 'Validate signature set: require!(signature_set.is_verified && signature_set.guardian_set_index == expected_index)',
            cwe: 'CWE-347',
          });
        }
      }

      // Check for deprecated verification (Wormhole used deprecated secp256k1 instruction)
      if (content.includes('Secp256k1') && !content.includes('new_secp256k1') && !content.includes('Ed25519')) {
        findings.push({
          id: 'SOL142',
          title: 'Legacy Signature Verification',
          severity: 'high',
          description: 'Use the latest signature verification methods. Legacy methods may have known vulnerabilities.',
          location: { file: input.path, line: 1 },
          suggestion: 'Use current verification: prefer Ed25519Program::verify or updated secp256k1 verification.',
          cwe: 'CWE-327',
        });
      }

      // Check for proper guardian/verifier threshold
      if (content.includes('guardian') || content.includes('verifier')) {
        if (!content.includes('threshold') && !content.includes('quorum')) {
          findings.push({
            id: 'SOL142',
            title: 'Missing Guardian Threshold',
            severity: 'critical',
            description: 'Multi-signature verification must enforce threshold requirements.',
            location: { file: input.path, line: 1 },
            suggestion: 'Enforce threshold: require!(valid_signatures >= (total_guardians * 2 / 3) + 1, InsufficientSignatures)',
            cwe: 'CWE-287',
          });
        }
      }

      // Check for signature malleability
      if (content.includes('signature') && !content.includes('canonicalize') && !content.includes('normalize')) {
        for (let i = 0; i < lines.length; i++) {
          if (lines[i].match(/verify|check.*sig/i)) {
            findings.push({
              id: 'SOL142',
              title: 'Signature Malleability Risk',
              severity: 'high',
              description: 'Signatures should be canonicalized to prevent malleability attacks.',
              location: { file: input.path, line: i + 1 },
              suggestion: 'Normalize signatures: ensure s-value is in lower half of curve order.',
              cwe: 'CWE-347',
            });
            break;
          }
        }
      }

      // Check for message hash verification
      if (content.includes('verify') && !content.includes('hash') && !content.includes('message')) {
        findings.push({
          id: 'SOL142',
          title: 'Missing Message Hash Verification',
          severity: 'critical',
          description: 'Signature verification must include the message hash that was signed.',
          location: { file: input.path, line: 1 },
          suggestion: 'Include message: let message_hash = hash(&message_data); verify(signature, pubkey, message_hash)',
          cwe: 'CWE-347',
        });
      }
    }
  }

  return findings;
}
