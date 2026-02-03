import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL096: Cross-Chain Bridge Security
 * Detects issues in cross-chain/bridging implementations
 */
export function checkCrossChain(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rust = input.rust;

  if (!rust || !rust.content) return findings;

  const hasCrossChain = rust.content.includes('bridge') ||
                        rust.content.includes('cross_chain') ||
                        rust.content.includes('relay') ||
                        rust.content.includes('wormhole');

  if (!hasCrossChain) return findings;

  // Check for message verification
  if (!rust.content.includes('verify') && !rust.content.includes('signature')) {
    findings.push({
      id: 'SOL096',
      severity: 'critical',
      title: 'Bridge Without Message Verification',
      description: 'Cross-chain message without cryptographic verification',
      location: input.path,
      recommendation: 'Verify message signatures from guardian/relayer set',
    });
  }

  // Check for replay protection
  if (!rust.content.includes('nonce') && !rust.content.includes('sequence') && 
      !rust.content.includes('processed')) {
    findings.push({
      id: 'SOL096',
      severity: 'critical',
      title: 'Bridge Without Replay Protection',
      description: 'Cross-chain message may be replayed multiple times',
      location: input.path,
      recommendation: 'Track processed message IDs/nonces to prevent replay',
    });
  }

  // Check for chain ID validation
  if (!rust.content.includes('chain_id') && !rust.content.includes('source_chain')) {
    findings.push({
      id: 'SOL096',
      severity: 'high',
      title: 'Missing Chain ID Validation',
      description: 'Cross-chain message without source chain verification',
      location: input.path,
      recommendation: 'Validate source chain ID matches expected value',
    });
  }

  return findings;
}
