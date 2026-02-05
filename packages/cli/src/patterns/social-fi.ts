import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL150: SocialFi Security
 * Detects vulnerabilities in social finance protocols (friend.tech style)
 * 
 * SocialFi risks:
 * - Key/share price manipulation
 * - Front-running on influencer buys
 * - Exit scam mechanics
 */
export function checkSocialFi(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rust = input.rust;
  if (!rust) return findings;

  const content = rust.content;
  const lines = content.split('\n');

  lines.forEach((line, i) => {
    // Check for social token/key trading
    if (/buy.*key|sell.*key|trade.*share|social.*token/i.test(line)) {
      const nearbyContent = lines.slice(Math.max(0, i - 20), Math.min(lines.length, i + 20)).join('\n');
      
      // Check for front-running protection
      if (!/commit.*reveal|private|encrypted|batch/i.test(nearbyContent)) {
        findings.push({
          id: 'SOL150',
          name: 'SocialFi Front-Running',
          severity: 'critical',
          message: 'Key purchases can be front-run when influencer announces',
          location: `${input.path}:${i + 1}`,
          snippet: line.trim(),
          fix: 'Use commit-reveal or batch auctions to prevent front-running',
        });
      }

      // Check for slippage/price protection
      if (!/max.*price|slippage|limit.*price/i.test(nearbyContent)) {
        findings.push({
          id: 'SOL150',
          name: 'SocialFi No Price Limit',
          severity: 'high',
          message: 'Buy without price limit can execute at manipulated price',
          location: `${input.path}:${i + 1}`,
          snippet: line.trim(),
          fix: 'Add max_price parameter to prevent sandwich attacks',
        });
      }

      // Check for trading fees
      if (!/fee|protocol.*cut|creator.*share/i.test(nearbyContent)) {
        findings.push({
          id: 'SOL150',
          name: 'SocialFi Fee Structure Missing',
          severity: 'medium',
          message: 'Fee structure not visible in code - verify fee caps',
          location: `${input.path}:${i + 1}`,
          snippet: line.trim(),
          fix: 'Make fee structure explicit and cap total fees (e.g., <20%)',
        });
      }
    }

    // Check for bonding curve
    if (/price.*supply|bonding|curve.*price/i.test(line)) {
      const nearbyContent = lines.slice(Math.max(0, i - 15), Math.min(lines.length, i + 15)).join('\n');
      
      // Check for curve manipulation
      if (!/min.*supply|initial.*price|floor/i.test(nearbyContent)) {
        findings.push({
          id: 'SOL150',
          name: 'SocialFi Curve No Floor',
          severity: 'high',
          message: 'Bonding curve without floor allows dump to zero',
          location: `${input.path}:${i + 1}`,
          snippet: line.trim(),
          fix: 'Set minimum supply or price floor to prevent total crashes',
        });
      }
    }

    // Check for creator controls
    if (/creator.*withdraw|claim.*fee|subject.*fee/i.test(line)) {
      const nearbyContent = lines.slice(Math.max(0, i - 10), Math.min(lines.length, i + 10)).join('\n');
      
      // Check for creator rug protection
      if (!/lock|vesting|time.*release/i.test(nearbyContent)) {
        findings.push({
          id: 'SOL150',
          name: 'Creator Instant Withdraw',
          severity: 'high',
          message: 'Creator can withdraw fees instantly and abandon project',
          location: `${input.path}:${i + 1}`,
          snippet: line.trim(),
          fix: 'Consider vesting creator fees over time to align incentives',
        });
      }
    }

    // Check for holder benefits
    if (/holder.*access|key.*holder|gated/i.test(line)) {
      findings.push({
        id: 'SOL150',
        name: 'SocialFi Access Control',
        severity: 'info',
        message: 'Token-gated access present - verify off-chain enforcement',
        location: `${input.path}:${i + 1}`,
        snippet: line.trim(),
        fix: 'Ensure off-chain access checks token ownership in real-time',
      });
    }

    // Check for exit liquidity
    if (/sell.*all|exit|dump.*key/i.test(line)) {
      const nearbyContent = lines.slice(Math.max(0, i - 10), Math.min(lines.length, i + 10)).join('\n');
      
      if (!/liquidity|reserve|can.*sell/i.test(nearbyContent)) {
        findings.push({
          id: 'SOL150',
          name: 'SocialFi Exit Liquidity Risk',
          severity: 'high',
          message: 'Users may not be able to exit if no buyers exist',
          location: `${input.path}:${i + 1}`,
          snippet: line.trim(),
          fix: 'Document liquidity risks clearly to users',
        });
      }
    }
  });

  return findings;
}
