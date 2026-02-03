import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL049: Compression/cNFT Vulnerabilities
 * Issues with state compression and compressed NFTs.
 */
export function checkCompression(input: PatternInput): Finding[] {
  const findings: Finding[] = [];

  if (!input.rust || !input.rust.files) return findings;

  for (const file of input.rust.files) {
    const lines = file.lines;
    const content = file.content;

    if (!content.includes('compression') && !content.includes('concurrent_merkle') && 
        !content.includes('bubblegum') && !content.includes('cNFT')) {
      continue;
    }

    lines.forEach((line, index) => {
      const lineNum = index + 1;

      // Pattern 1: Merkle tree without canopy
      if (line.includes('ConcurrentMerkleTree') || line.includes('merkle_tree')) {
        const contextEnd = Math.min(lines.length, index + 10);
        const context = lines.slice(index, contextEnd).join('\n');

        if (!context.includes('canopy') && !context.includes('Canopy')) {
          findings.push({
            id: `SOL049-${findings.length + 1}`,
            pattern: 'Compression Vulnerability',
            severity: 'medium',
            title: 'Merkle tree without canopy consideration',
            description: 'Canopy depth affects proof size and cost. Large trees need sufficient canopy.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Set appropriate canopy depth to reduce proof costs.',
          });
        }
      }

      // Pattern 2: cNFT transfer without creator verification
      if (line.includes('transfer') && content.includes('bubblegum')) {
        const contextStart = Math.max(0, index - 15);
        const context = lines.slice(contextStart, index + 10).join('\n');

        if (!context.includes('creator') && !context.includes('collection')) {
          findings.push({
            id: `SOL049-${findings.length + 1}`,
            pattern: 'Compression Vulnerability',
            severity: 'medium',
            title: 'cNFT operation without creator/collection check',
            description: 'cNFT operations should verify collection or creator for access control.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Validate cNFT belongs to expected collection.',
          });
        }
      }

      // Pattern 3: Proof verification bypass
      if (line.includes('proof') && content.includes('merkle')) {
        const contextStart = Math.max(0, index - 5);
        const context = lines.slice(contextStart, index + 5).join('\n');

        if (context.includes('skip') || context.includes('bypass') || 
            context.includes('unchecked')) {
          findings.push({
            id: `SOL049-${findings.length + 1}`,
            pattern: 'Compression Vulnerability',
            severity: 'critical',
            title: 'Merkle proof verification bypassed',
            description: 'Proof verification appears to be skipped. Anyone could claim assets.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Always verify merkle proofs. Never skip verification.',
          });
        }
      }
    });
  }

  return findings;
}
