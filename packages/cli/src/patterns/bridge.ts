import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL046: Bridge/Cross-Chain Vulnerabilities
 * Issues with bridge and cross-chain messaging.
 */
export function checkBridge(input: PatternInput): Finding[] {
  const findings: Finding[] = [];

  if (!input.rust || !input.rust.files) return findings;

  for (const file of input.rust.files) {
    const lines = file.lines;
    const content = file.content;

    if (!content.includes('bridge') && !content.includes('wormhole') && 
        !content.includes('message') && !content.includes('relay')) {
      continue;
    }

    lines.forEach((line, index) => {
      const lineNum = index + 1;

      // Pattern 1: Message replay without nonce
      if (line.includes('process_message') || line.includes('receive_message')) {
        const fnEnd = Math.min(lines.length, index + 25);
        const fnBody = lines.slice(index, fnEnd).join('\n');

        if (!fnBody.includes('nonce') && !fnBody.includes('sequence') && 
            !fnBody.includes('processed')) {
          findings.push({
            id: `SOL046-${findings.length + 1}`,
            pattern: 'Bridge Vulnerability',
            severity: 'critical',
            title: 'Cross-chain message without replay protection',
            description: 'Message can be replayed. Attacker could execute same message multiple times.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Track processed message hashes/nonces to prevent replay.',
          });
        }
      }

      // Pattern 2: Missing source chain validation
      if (line.includes('chain_id') || line.includes('source_chain')) {
        const contextStart = Math.max(0, index - 5);
        const context = lines.slice(contextStart, index + 5).join('\n');

        if (!context.includes('whitelist') && !context.includes('allowed') &&
            !context.includes('== ')) {
          findings.push({
            id: `SOL046-${findings.length + 1}`,
            pattern: 'Bridge Vulnerability',
            severity: 'high',
            title: 'Source chain not validated',
            description: 'Messages accepted from any chain. Should whitelist trusted chains.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Validate source chain: require!(ALLOWED_CHAINS.contains(&source))',
          });
        }
      }

      // Pattern 3: Token minting on message
      if ((line.includes('mint') || line.includes('unlock')) && 
          content.includes('message')) {
        const contextStart = Math.max(0, index - 15);
        const context = lines.slice(contextStart, index + 5).join('\n');

        if (!context.includes('verify') && !context.includes('signature') &&
            !context.includes('proof')) {
          findings.push({
            id: `SOL046-${findings.length + 1}`,
            pattern: 'Bridge Vulnerability',
            severity: 'critical',
            title: 'Token mint/unlock without message verification',
            description: 'Minting tokens based on unverified cross-chain message.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Verify message signature/proof from trusted guardians.',
          });
        }
      }
    });
  }

  return findings;
}
