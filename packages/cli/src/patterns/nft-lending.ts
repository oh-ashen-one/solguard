import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL149: NFT Lending Security
 * Detects vulnerabilities in NFT-collateralized lending (Sharky, Citrus style)
 * 
 * NFT lending risks:
 * - Floor price manipulation
 * - Trait-based valuation attacks
 * - Liquidation timing
 */
export function checkNftLending(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rust = input.rust;
  if (!rust) return findings;

  const content = rust.content;
  const lines = content.split('\n');

  lines.forEach((line, i) => {
    // Check for NFT collateral valuation
    if (/nft.*value|floor.*price|collateral.*worth/i.test(line)) {
      const nearbyContent = lines.slice(Math.max(0, i - 20), Math.min(lines.length, i + 20)).join('\n');
      
      // Check for TWAP floor
      if (!/twap|time.*weighted|average.*floor/i.test(nearbyContent)) {
        findings.push({
          id: 'SOL149',
          name: 'NFT Spot Floor Price',
          severity: 'critical',
          message: 'Spot floor price can be manipulated for instant over-borrowing',
          location: `${input.path}:${i + 1}`,
          snippet: line.trim(),
          fix: 'Use TWAP floor price (e.g., 7-day average) for LTV calculation',
        });
      }

      // Check for collection validation
      if (!/verified.*collection|check.*collection|collection.*id/i.test(nearbyContent)) {
        findings.push({
          id: 'SOL149',
          name: 'NFT Collection Not Verified',
          severity: 'critical',
          message: 'Fake NFTs from unverified collections accepted as collateral',
          location: `${input.path}:${i + 1}`,
          snippet: line.trim(),
          fix: 'Verify NFT belongs to whitelisted verified collection',
        });
      }

      // Check for trait premium handling
      if (!/trait|attribute|rarity/i.test(nearbyContent) && /premium|bonus|extra/i.test(nearbyContent)) {
        findings.push({
          id: 'SOL149',
          name: 'Trait Premium Manipulation',
          severity: 'high',
          message: 'Trait-based premiums can be gamed with wash trading',
          location: `${input.path}:${i + 1}`,
          snippet: line.trim(),
          fix: 'Use conservative floor-only pricing or well-established trait oracles',
        });
      }
    }

    // Check for loan creation
    if (/create.*loan|borrow.*against.*nft|collateralize.*nft/i.test(line)) {
      const nearbyContent = lines.slice(Math.max(0, i - 15), Math.min(lines.length, i + 15)).join('\n');
      
      // Check LTV limits
      if (!/ltv|loan.*to.*value|max.*borrow/i.test(nearbyContent)) {
        findings.push({
          id: 'SOL149',
          name: 'NFT LTV Not Limited',
          severity: 'high',
          message: 'Unlimited LTV allows over-leveraged positions',
          location: `${input.path}:${i + 1}`,
          snippet: line.trim(),
          fix: 'Cap LTV at conservative level (e.g., 30-50% of floor)',
        });
      }

      // Check for NFT escrow
      if (!/escrow|custody|transfer.*to.*program/i.test(nearbyContent)) {
        findings.push({
          id: 'SOL149',
          name: 'NFT Not Escrowed',
          severity: 'critical',
          message: 'NFT collateral not transferred to escrow - borrower can sell',
          location: `${input.path}:${i + 1}`,
          snippet: line.trim(),
          fix: 'Transfer NFT to program-controlled escrow PDA',
        });
      }
    }

    // Check for liquidation
    if (/liquidat.*nft|seize.*collateral|foreclose/i.test(line)) {
      const nearbyContent = lines.slice(Math.max(0, i - 15), Math.min(lines.length, i + 15)).join('\n');
      
      // Check for grace period
      if (!/grace|buffer|cure.*period/i.test(nearbyContent)) {
        findings.push({
          id: 'SOL149',
          name: 'NFT No Grace Period',
          severity: 'medium',
          message: 'Instant liquidation without grace period can catch borrowers off guard',
          location: `${input.path}:${i + 1}`,
          snippet: line.trim(),
          fix: 'Add grace period (e.g., 24h) for borrowers to add collateral',
        });
      }

      // Check for auction mechanism
      if (!/auction|bid|dutch|english/i.test(nearbyContent)) {
        findings.push({
          id: 'SOL149',
          name: 'NFT Liquidation No Auction',
          severity: 'medium',
          message: 'Direct liquidation may undervalue rare NFTs',
          location: `${input.path}:${i + 1}`,
          snippet: line.trim(),
          fix: 'Consider auction mechanism for liquidated NFTs',
        });
      }
    }
  });

  return findings;
}
