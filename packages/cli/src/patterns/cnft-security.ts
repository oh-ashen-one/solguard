import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL136: Compressed NFT (cNFT) Security
 * Detects vulnerabilities specific to Metaplex Bubblegum compressed NFTs
 * 
 * cNFTs use merkle trees and have unique security considerations:
 * - Proof validation
 * - Tree authority
 * - Concurrent merkle tree updates
 */
export function checkCnftSecurity(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rust = input.rust;
  if (!rust) return findings;

  const content = rust.content;
  const lines = content.split('\n');

  lines.forEach((line, i) => {
    // Check for merkle proof validation
    if (/verify.*proof|merkle.*proof|proof.*path/i.test(line)) {
      const nearbyContent = lines.slice(Math.max(0, i - 10), Math.min(lines.length, i + 10)).join('\n');
      
      if (!/root.*match|verify.*root|check.*root/i.test(nearbyContent)) {
        findings.push({
          id: 'SOL136',
          name: 'cNFT Proof Root Not Verified',
          severity: 'critical',
          message: 'Merkle proof verified without checking against tree root',
          location: `${input.path}:${i + 1}`,
          snippet: line.trim(),
          fix: 'Always verify proof against current merkle tree root',
        });
      }
    }

    // Check for tree authority validation
    if (/tree_authority|merkle_tree.*authority|bubblegum/i.test(line)) {
      const nearbyContent = lines.slice(Math.max(0, i - 10), Math.min(lines.length, i + 10)).join('\n');
      
      if (!/tree_creator|check.*authority|verify.*tree/i.test(nearbyContent)) {
        findings.push({
          id: 'SOL136',
          name: 'cNFT Tree Authority Not Validated',
          severity: 'high',
          message: 'Tree authority not validated - operations may affect wrong tree',
          location: `${input.path}:${i + 1}`,
          snippet: line.trim(),
          fix: 'Verify tree authority matches expected merkle tree account',
        });
      }
    }

    // Check for concurrent merkle tree race conditions
    if (/concurrent.*merkle|append|replace_leaf/i.test(line)) {
      const nearbyContent = lines.slice(Math.max(0, i - 15), Math.min(lines.length, i + 15)).join('\n');
      
      if (!/changelog|sequence|nonce|index/i.test(nearbyContent)) {
        findings.push({
          id: 'SOL136',
          name: 'cNFT Concurrent Update Risk',
          severity: 'high',
          message: 'Concurrent merkle tree update without sequence tracking can cause proof invalidation',
          location: `${input.path}:${i + 1}`,
          snippet: line.trim(),
          fix: 'Track changelog buffer for concurrent updates or use canopy',
        });
      }
    }

    // Check for leaf schema validation
    if (/leaf.*schema|hash.*leaf|create.*leaf/i.test(line)) {
      if (!/owner|delegate|collection/i.test(line)) {
        findings.push({
          id: 'SOL136',
          name: 'cNFT Leaf Schema Incomplete',
          severity: 'medium',
          message: 'cNFT leaf may be missing required fields (owner, delegate, collection)',
          location: `${input.path}:${i + 1}`,
          snippet: line.trim(),
          fix: 'Include all required fields in leaf hash: owner, delegate, collection',
        });
      }
    }

    // Check for canopy depth
    if (/canopy|canopy_depth|proof_length/i.test(line)) {
      findings.push({
        id: 'SOL136',
        name: 'cNFT Canopy Configuration',
        severity: 'low',
        message: 'Canopy depth affects proof size and transaction cost - verify appropriate for use case',
        location: `${input.path}:${i + 1}`,
        snippet: line.trim(),
        fix: 'Balance canopy depth between rent cost and proof size requirements',
      });
    }
  });

  return findings;
}
