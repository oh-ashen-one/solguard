import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL308: Cross-Chain Delegation Verification
 * Detects vulnerabilities in cross-chain message delegation
 * Real-world: Wormhole $326M exploit - delegated signature verification bypass
 */
export function checkCrossChainDelegation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];

  if (input.rust?.content) {
    const content = input.rust.content;
    const lines = content.split('\n');

    // Detect cross-chain/bridge patterns
    const isBridge = /bridge|wormhole|guardian|vaa|cross_chain|message_passing|relay/i.test(content);

    if (isBridge) {
      // Check for signature verification delegation
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];

        // Delegated verification pattern
        if (line.includes('verify') && (line.includes('signature') || line.includes('secp256k1'))) {
          const contextLines = lines.slice(i, Math.min(i + 15, lines.length)).join('\n');
          
          // Check if verification is properly chained
          if (contextLines.includes('instruction_sysvar') || contextLines.includes('get_instruction')) {
            if (!contextLines.includes('check_program_id') && !contextLines.includes('program_id ==')) {
              findings.push({
                id: 'SOL308',
                title: 'Delegated Verification Without Program Check',
                severity: 'critical',
                description: 'Signature verification via sysvar must verify the calling program.',
                location: { file: input.path, line: i + 1 },
                suggestion: 'Verify program ID: require!(ix.program_id == secp256k1_program::ID, InvalidVerifier)',
                cwe: 'CWE-347',
              });
              break;
            }
          }
        }

        // Guardian set validation
        if (line.includes('guardian') || line.includes('validator_set')) {
          const contextLines = lines.slice(i, Math.min(i + 10, lines.length)).join('\n');
          if (!contextLines.includes('expir') && !contextLines.includes('valid_until')) {
            findings.push({
              id: 'SOL308',
              title: 'No Guardian Set Expiry',
              severity: 'high',
              description: 'Guardian/validator sets should have expiration to prevent stale key usage.',
              location: { file: input.path, line: i + 1 },
              suggestion: 'Add expiry: require!(guardian_set.expiration_time > clock.unix_timestamp, ExpiredGuardians)',
              cwe: 'CWE-672',
            });
            break;
          }
        }
      }

      // Check for VAA/message validation
      if (content.includes('vaa') || content.includes('message')) {
        // Check for replay protection
        if (!content.includes('processed') && !content.includes('used') && !content.includes('claimed')) {
          findings.push({
            id: 'SOL308',
            title: 'No Message Replay Protection',
            severity: 'critical',
            description: 'Cross-chain messages must track processed state to prevent replay.',
            location: { file: input.path, line: 1 },
            suggestion: 'Track processed: claimed_vaas.set(vaa_hash, true)?; require!(!claimed_vaas.get(vaa_hash), AlreadyProcessed)',
            cwe: 'CWE-294',
          });
        }

        // Check for chain ID validation
        if (!content.includes('chain_id') && !content.includes('source_chain')) {
          findings.push({
            id: 'SOL308',
            title: 'Missing Source Chain Validation',
            severity: 'high',
            description: 'Cross-chain messages must validate source chain to prevent cross-chain replay.',
            location: { file: input.path, line: 1 },
            suggestion: 'Validate chain: require!(vaa.emitter_chain == expected_chain_id, InvalidSourceChain)',
            cwe: 'CWE-346',
          });
        }

        // Check for emitter validation
        if (!content.includes('emitter') && !content.includes('sender_address')) {
          findings.push({
            id: 'SOL308',
            title: 'Missing Emitter Validation',
            severity: 'critical',
            description: 'Cross-chain messages must validate the emitter/sender address.',
            location: { file: input.path, line: 1 },
            suggestion: 'Validate emitter: require!(vaa.emitter_address == registered_emitters[vaa.emitter_chain])',
            cwe: 'CWE-346',
          });
        }
      }

      // Check for quorum validation
      if (content.includes('signature') && content.includes('guardian')) {
        if (!content.includes('quorum') && !content.includes('threshold') && !content.includes('2/3')) {
          findings.push({
            id: 'SOL308',
            title: 'No Quorum Validation',
            severity: 'critical',
            description: 'Guardian signatures must meet quorum threshold (typically 2/3+1).',
            location: { file: input.path, line: 1 },
            suggestion: 'Check quorum: require!(valid_signatures >= (guardian_set.len() * 2 / 3) + 1, InsufficientSignatures)',
            cwe: 'CWE-345',
          });
        }
      }

      // Check for signature ordering
      if (content.includes('signatures') && content.includes('verify')) {
        if (!content.includes('sort') && !content.includes('ordered') && !content.includes('ascending')) {
          findings.push({
            id: 'SOL308',
            title: 'Unordered Signature Validation',
            severity: 'medium',
            description: 'Signatures should be validated in ascending guardian index order to prevent duplicates.',
            location: { file: input.path, line: 1 },
            suggestion: 'Require ordering: require!(sig.guardian_index > last_index, SignaturesNotOrdered)',
            cwe: 'CWE-290',
          });
        }
      }

      // Check for finality validation
      if (!content.includes('finalized') && !content.includes('confirmed') && !content.includes('commitment')) {
        findings.push({
          id: 'SOL308',
          title: 'No Finality Check',
          severity: 'high',
          description: 'Cross-chain operations should verify source chain finality to prevent reorg attacks.',
          location: { file: input.path, line: 1 },
          suggestion: 'Check finality: require!(vaa.consistency_level >= ConsistencyLevel::Finalized)',
          cwe: 'CWE-362',
        });
      }
    }
  }

  return findings;
}
