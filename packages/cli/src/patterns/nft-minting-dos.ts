import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL189: NFT Minting DoS Prevention
 * 
 * Detects vulnerabilities in NFT minting that can lead to
 * denial of service or unfair distribution.
 * 
 * Real-world exploit: Candy Machine NFT Minting Outage - 
 * Network congestion from bot minting caused 4-hour outage.
 */
export function checkNftMintingDos(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const { rust, idl, path } = input;

  if (idl) {
    const mintInstructions = idl.instructions.filter(ix =>
      ix.name.toLowerCase().includes('mint') ||
      ix.name.toLowerCase().includes('candy') ||
      ix.name.toLowerCase().includes('nft')
    );

    for (const ix of mintInstructions) {
      // Check for rate limiting or bot protection
      const hasProtection = ix.accounts?.some(acc =>
        acc.name.toLowerCase().includes('whitelist') ||
        acc.name.toLowerCase().includes('allowlist') ||
        acc.name.toLowerCase().includes('rate_limit') ||
        acc.name.toLowerCase().includes('bot_tax')
      );

      if (!hasProtection) {
        findings.push({
          id: 'SOL189',
          severity: 'medium',
          title: 'NFT Mint Without Bot Protection',
          description: `Instruction "${ix.name}" lacks apparent bot protection or rate limiting.`,
          location: { file: path, line: 1 },
          recommendation: 'Implement bot tax, whitelist/allowlist phases, or Merkle proof verification.',
        });
      }
    }
  }

  if (!rust) return findings;

  const vulnerablePatterns = [
    { pattern: /mint_nft.*public/i, desc: 'Public NFT mint' },
    { pattern: /candy_machine.*mint/i, desc: 'Candy machine mint' },
    { pattern: /remaining.*supply/i, desc: 'Supply check without rate limit' },
  ];

  const lines = rust.content.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    for (const { pattern, desc } of vulnerablePatterns) {
      if (pattern.test(line)) {
        const context = lines.slice(Math.max(0, i - 20), Math.min(lines.length, i + 20)).join('\n');
        
        const hasProtection = 
          context.includes('bot_tax') ||
          context.includes('whitelist') ||
          context.includes('allowlist') ||
          context.includes('merkle') ||
          context.includes('rate_limit') ||
          context.includes('per_wallet_limit');

        if (!hasProtection) {
          findings.push({
            id: 'SOL189',
            severity: 'medium',
            title: 'NFT Minting DoS Risk',
            description: `${desc} - vulnerable to bot attacks and network congestion.`,
            location: { file: path, line: i + 1 },
            recommendation: 'Add bot tax, per-wallet limits, whitelist phases, or Merkle proof verification.',
          });
        }
      }
    }
  }

  return findings;
}
