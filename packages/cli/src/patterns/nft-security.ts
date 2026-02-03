import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL042: NFT Security Issues
 * Vulnerabilities specific to NFT programs.
 */
export function checkNftSecurity(input: PatternInput): Finding[] {
  const findings: Finding[] = [];

  if (!input.rust || !input.rust.files) return findings;

  for (const file of input.rust.files) {
    const lines = file.lines;
    const content = file.content;

    if (!content.includes('nft') && !content.includes('NFT') && 
        !content.includes('metadata') && !content.includes('Metadata')) {
      continue;
    }

    lines.forEach((line, index) => {
      const lineNum = index + 1;

      // Pattern 1: Metadata validation missing
      if (line.includes('Metadata') || line.includes('metadata')) {
        const contextStart = Math.max(0, index - 5);
        const context = lines.slice(contextStart, index + 5).join('\n');

        if (context.includes('AccountInfo') && !context.includes('mpl_token_metadata') &&
            !context.includes('owner')) {
          findings.push({
            id: `SOL042-${findings.length + 1}`,
            pattern: 'NFT Security Issue',
            severity: 'high',
            title: 'Metadata account not validated',
            description: 'Metadata account passed without verifying owner is Token Metadata program.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Verify: metadata.owner == &mpl_token_metadata::ID',
          });
        }
      }

      // Pattern 2: Edition check missing for 1/1 operations
      if (line.includes('master_edition') || line.includes('MasterEdition')) {
        const contextStart = Math.max(0, index - 10);
        const context = lines.slice(contextStart, index + 5).join('\n');

        if (!context.includes('max_supply') && !context.includes('supply')) {
          findings.push({
            id: `SOL042-${findings.length + 1}`,
            pattern: 'NFT Security Issue',
            severity: 'medium',
            title: 'Master edition without supply check',
            description: 'Operating on master edition without checking max_supply/supply.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Check edition.max_supply and edition.supply for edition limit enforcement.',
          });
        }
      }

      // Pattern 3: Collection verification bypass
      if (line.includes('collection') && !line.includes('verified')) {
        const contextEnd = Math.min(lines.length, index + 10);
        const context = lines.slice(index, contextEnd).join('\n');

        if (context.includes('==') || context.includes('require')) {
          if (!context.includes('verified')) {
            findings.push({
              id: `SOL042-${findings.length + 1}`,
              pattern: 'NFT Security Issue',
              severity: 'high',
              title: 'Collection check without verified flag',
              description: 'Checking collection key but not verified status. Unverified NFTs can fake collection.',
              location: { file: file.path, line: lineNum },
              suggestion: 'Always check: metadata.collection.verified == true',
            });
          }
        }
      }

      // Pattern 4: Creator royalty bypass
      if (line.includes('creator') || line.includes('royalt')) {
        const contextStart = Math.max(0, index - 5);
        const context = lines.slice(contextStart, index + 5).join('\n');

        if (context.includes('fee') || context.includes('sale')) {
          if (!context.includes('seller_fee_basis_points') && !context.includes('royalty')) {
            findings.push({
              id: `SOL042-${findings.length + 1}`,
              pattern: 'NFT Security Issue',
              severity: 'medium',
              title: 'Sale without royalty enforcement',
              description: 'NFT sale logic may not enforce creator royalties.',
              location: { file: file.path, line: lineNum },
              suggestion: 'Enforce royalties: pay seller_fee_basis_points to verified creators.',
            });
          }
        }
      }
    });
  }

  return findings;
}
