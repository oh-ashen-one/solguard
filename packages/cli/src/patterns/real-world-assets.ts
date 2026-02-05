import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL147: Real World Asset (RWA) Security
 * Detects vulnerabilities in tokenized real-world assets
 * 
 * RWA risks:
 * - Off-chain custody
 * - Compliance/KYC requirements
 * - Redemption guarantees
 */
export function checkRealWorldAssets(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rust = input.rust;
  if (!rust) return findings;

  const content = rust.content;
  const lines = content.split('\n');

  lines.forEach((line, i) => {
    // Check for RWA token minting
    if (/mint.*rwa|create.*asset.*token|tokenize/i.test(line)) {
      const nearbyContent = lines.slice(Math.max(0, i - 20), Math.min(lines.length, i + 20)).join('\n');
      
      // Check for proof of reserves
      if (!/proof.*reserve|attestation|audit.*reserve/i.test(nearbyContent)) {
        findings.push({
          id: 'SOL147',
          name: 'RWA No Proof of Reserves',
          severity: 'critical',
          message: 'RWA tokens without proof of reserves can be unbacked',
          location: `${input.path}:${i + 1}`,
          snippet: line.trim(),
          fix: 'Implement on-chain proof of reserves or oracle attestation',
        });
      }

      // Check for custodian validation
      if (!/custodian|custody.*proof|third.*party/i.test(nearbyContent)) {
        findings.push({
          id: 'SOL147',
          name: 'Custodian Not Validated',
          severity: 'high',
          message: 'RWA custody not validated on-chain',
          location: `${input.path}:${i + 1}`,
          snippet: line.trim(),
          fix: 'Validate custodian attestation before minting',
        });
      }
    }

    // Check for redemption
    if (/redeem|burn.*rwa|withdraw.*asset/i.test(line)) {
      const nearbyContent = lines.slice(Math.max(0, i - 15), Math.min(lines.length, i + 15)).join('\n');
      
      // Check for redemption delay
      if (!/processing.*time|settle.*period|t\+/i.test(nearbyContent)) {
        findings.push({
          id: 'SOL147',
          name: 'RWA Instant Redemption Claimed',
          severity: 'medium',
          message: 'Real-world assets cannot settle instantly - manage expectations',
          location: `${input.path}:${i + 1}`,
          snippet: line.trim(),
          fix: 'Document redemption timeline (T+1 to T+30 depending on asset)',
        });
      }

      // Check for minimum redemption
      if (!/min.*redeem|minimum.*amount|threshold/i.test(nearbyContent)) {
        findings.push({
          id: 'SOL147',
          name: 'RWA Dust Redemption',
          severity: 'low',
          message: 'Small redemptions may be uneconomical to process',
          location: `${input.path}:${i + 1}`,
          snippet: line.trim(),
          fix: 'Set minimum redemption amount to cover processing costs',
        });
      }
    }

    // Check for KYC/compliance
    if (/kyc|whitelist|accredited|compliance/i.test(line)) {
      const nearbyContent = lines.slice(Math.max(0, i - 10), Math.min(lines.length, i + 10)).join('\n');
      
      // Check for transfer restrictions
      if (!/transfer.*check|can.*receive|verify.*recipient/i.test(nearbyContent)) {
        findings.push({
          id: 'SOL147',
          name: 'RWA Transfer Not Restricted',
          severity: 'high',
          message: 'RWA tokens may require transfer restrictions for compliance',
          location: `${input.path}:${i + 1}`,
          snippet: line.trim(),
          fix: 'Implement transfer hook to verify recipient is whitelisted',
        });
      }
    }

    // Check for oracle/price feed
    if (/rwa.*price|asset.*value|nav/i.test(line)) {
      const nearbyContent = lines.slice(Math.max(0, i - 10), Math.min(lines.length, i + 10)).join('\n');
      
      if (!/oracle|external.*feed|third.*party.*price/i.test(nearbyContent)) {
        findings.push({
          id: 'SOL147',
          name: 'RWA Self-Reported Value',
          severity: 'high',
          message: 'RWA value self-reported without external validation',
          location: `${input.path}:${i + 1}`,
          snippet: line.trim(),
          fix: 'Use independent price oracle or third-party NAV calculation',
        });
      }
    }
  });

  return findings;
}
