import type { Finding } from '../commands/audit.js';
import type { ParsedIdl } from '../parsers/idl.js';
import type { ParsedRust } from '../parsers/rust.js';

/**
 * SOL242: Wormhole-style Guardian/Validator Bypass
 * Detects signature verification and guardian validation issues
 * Reference: Wormhole Bridge Exploit (February 2022) - $326M stolen via signature verification bypass
 */
export function checkWormholeGuardian(idl: ParsedIdl | null, rust: ParsedRust | null): Finding[] {
  const findings: Finding[] = [];

  if (rust) {
    for (const fn of rust.functions) {
      const content = fn.body.toLowerCase();

      // Check for signature verification patterns
      if (content.includes('verify_signature') || content.includes('signature_verify') ||
          content.includes('ed25519') || content.includes('secp256k1')) {
        
        // Check for missing signer count verification
        if (!content.includes('guardian_count') && !content.includes('num_signers') &&
            !content.includes('threshold') && content.includes('guardian')) {
          findings.push({
            id: 'SOL242',
            severity: 'critical',
            title: 'Guardian Signature Without Threshold Check',
            description: 'Guardian signatures verified without checking required threshold. Wormhole was exploited by forging a single signature.',
            location: `Function: ${fn.name}`,
            recommendation: 'Always verify: num_valid_signatures >= required_threshold. Validate guardian set is current.',
          });
        }

        // Check for signature set account validation
        if (content.includes('signature_set') || content.includes('sig_set')) {
          if (!content.includes('owner') || !content.includes('program_id')) {
            findings.push({
              id: 'SOL242',
              severity: 'critical',
              title: 'Signature Set Without Owner Check',
              description: 'Signature set account used without verifying ownership. Attackers can create fake signature sets.',
              location: `Function: ${fn.name}`,
              recommendation: 'Verify signature set account is owned by your program. Check it was created by verify instruction.',
            });
          }
        }
      }

      // Check for VAA (Verified Action Approval) patterns
      if (content.includes('vaa') || content.includes('verified_action') || content.includes('message_hash')) {
        if (!content.includes('guardian_set_index') && !content.includes('set_index')) {
          findings.push({
            id: 'SOL242',
            severity: 'high',
            title: 'VAA Without Guardian Set Verification',
            description: 'Message verified without checking guardian set version. Old guardian sets should not be valid.',
            location: `Function: ${fn.name}`,
            recommendation: 'Verify VAA is signed by current guardian set. Reject signatures from expired sets.',
          });
        }
        
        if (!content.includes('timestamp') && !content.includes('expiry')) {
          findings.push({
            id: 'SOL242',
            severity: 'medium',
            title: 'VAA Without Timestamp Check',
            description: 'Verified messages should have timestamp to prevent replay of old messages.',
            location: `Function: ${fn.name}`,
            recommendation: 'Check message timestamp is within acceptable window. Prevent replay of expired messages.',
          });
        }
      }

      // Check for cross-chain message validation
      if (content.includes('cross_chain') || content.includes('bridge') || content.includes('foreign_chain')) {
        if (!content.includes('emitter') || !content.includes('chain_id')) {
          findings.push({
            id: 'SOL242',
            severity: 'high',
            title: 'Cross-chain Message Without Emitter Verification',
            description: 'Cross-chain message processed without verifying emitter address and chain ID.',
            location: `Function: ${fn.name}`,
            recommendation: 'Verify message emitter matches registered contract address for source chain.',
          });
        }
      }

      // Check for secp256k1 instruction usage
      if (content.includes('ed25519_program') || content.includes('secp256k1_program')) {
        if (!content.includes('instruction_sysvar') && !content.includes('instructions_sysvar')) {
          findings.push({
            id: 'SOL242',
            severity: 'high',
            title: 'Signature Verification Without Instruction Introspection',
            description: 'Using native signature programs requires instruction introspection to verify the signature was actually checked.',
            location: `Function: ${fn.name}`,
            recommendation: 'Use instruction sysvar to verify signature verification instruction preceded this instruction.',
          });
        }
      }

      // Check for deprecated/vulnerable verification patterns
      if (content.includes('verify_signatures') || content.includes('post_signatures')) {
        // Wormhole-specific: Check for deprecated instruction patterns
        if (content.includes('complete_') || content.includes('redeem_')) {
          if (!content.includes('guardian_set.creation_time') && !content.includes('expiration_time')) {
            findings.push({
              id: 'SOL242',
              severity: 'medium',
              title: 'Missing Guardian Set Expiration Check',
              description: 'Guardian set expiration not checked. Compromised old guardian keys could still be valid.',
              location: `Function: ${fn.name}`,
              recommendation: 'Check guardian_set.expiration_time against current timestamp before accepting signatures.',
            });
          }
        }
      }

      // Check for solana_program::verify patterns
      if (content.includes('invoke') && content.includes('ed25519')) {
        if (!content.includes('data_offset') || !content.includes('signature_offset')) {
          findings.push({
            id: 'SOL242',
            severity: 'high',
            title: 'Ed25519 Invocation Missing Offset Verification',
            description: 'Ed25519 program invoked without proper data offset handling. Attackers may manipulate offsets.',
            location: `Function: ${fn.name}`,
            recommendation: 'Carefully validate all offsets in Ed25519SignatureOffsets struct. Ensure bounds checking.',
          });
        }
      }
    }
  }

  if (idl) {
    // Check for bridge/validator instructions
    for (const instruction of idl.instructions) {
      const name = instruction.name.toLowerCase();
      
      // Check signature-related instructions
      if (name.includes('verify') || name.includes('redeem') || name.includes('complete')) {
        const hasGuardianSet = instruction.accounts.some(acc => 
          acc.name.toLowerCase().includes('guardian') ||
          acc.name.toLowerCase().includes('validator')
        );
        
        const hasSignatureSet = instruction.accounts.some(acc => 
          acc.name.toLowerCase().includes('signature')
        );

        if (hasGuardianSet || hasSignatureSet) {
          findings.push({
            id: 'SOL242',
            severity: 'info',
            title: 'Bridge Verification Instruction',
            description: `${instruction.name} handles signature verification. Ensure thorough guardian/signature validation.`,
            location: `Instruction: ${instruction.name}`,
            recommendation: 'Audit all signature verification paths. Test with forged signatures.',
          });
        }
      }
    }
  }

  return findings;
}
