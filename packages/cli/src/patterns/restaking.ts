import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL142: Restaking Security
 * Detects vulnerabilities in restaking protocols (EigenLayer-style on Solana)
 * 
 * Restaking risks:
 * - Slashing conditions
 * - AVS (Actively Validated Services) trust
 * - Withdrawal delays
 */
export function checkRestaking(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rust = input.rust;
  if (!rust) return findings;

  const content = rust.content;
  const lines = content.split('\n');

  lines.forEach((line, i) => {
    // Check for restaking/delegation
    if (/restake|delegate.*avs|operator.*delegation/i.test(line)) {
      const nearbyContent = lines.slice(Math.max(0, i - 20), Math.min(lines.length, i + 20)).join('\n');
      
      // Check for slashing documentation
      if (!/slash.*condition|penalty|slashing.*logic/i.test(nearbyContent)) {
        findings.push({
          id: 'SOL142',
          name: 'Slashing Conditions Unclear',
          severity: 'high',
          message: 'Restaking without clear slashing conditions exposes users to unknown risks',
          location: `${input.path}:${i + 1}`,
          snippet: line.trim(),
          fix: 'Document all slashing conditions and maximum penalty percentages',
        });
      }

      // Check for operator selection
      if (!/operator.*whitelist|trusted.*operator|verify.*operator/i.test(nearbyContent)) {
        findings.push({
          id: 'SOL142',
          name: 'Operator Trust Not Validated',
          severity: 'critical',
          message: 'Delegation to any operator without validation is risky',
          location: `${input.path}:${i + 1}`,
          snippet: line.trim(),
          fix: 'Implement operator whitelist or minimum stake requirements',
        });
      }
    }

    // Check for AVS registration
    if (/register.*avs|avs.*registration|add.*service/i.test(line)) {
      const nearbyContent = lines.slice(Math.max(0, i - 15), Math.min(lines.length, i + 15)).join('\n');
      
      // Check for AVS validation
      if (!/verify.*avs|avs.*whitelist|trusted.*avs/i.test(nearbyContent)) {
        findings.push({
          id: 'SOL142',
          name: 'AVS Not Validated',
          severity: 'critical',
          message: 'Registration to unvalidated AVS can result in slashing for invalid reasons',
          location: `${input.path}:${i + 1}`,
          snippet: line.trim(),
          fix: 'Only allow registration to whitelisted/audited AVS programs',
        });
      }

      // Check for max AVS limit
      if (!/max.*avs|avs.*limit|service.*cap/i.test(nearbyContent)) {
        findings.push({
          id: 'SOL142',
          name: 'Unlimited AVS Registration',
          severity: 'medium',
          message: 'No limit on AVS registrations compounds slashing risk',
          location: `${input.path}:${i + 1}`,
          snippet: line.trim(),
          fix: 'Limit number of simultaneous AVS registrations per stake',
        });
      }
    }

    // Check for withdrawal/undelegation
    if (/undelegate|withdraw.*stake|exit.*avs/i.test(line)) {
      const nearbyContent = lines.slice(Math.max(0, i - 15), Math.min(lines.length, i + 15)).join('\n');
      
      // Check for withdrawal delay
      if (!/cooldown|delay|escrow.*period|unbonding/i.test(nearbyContent)) {
        findings.push({
          id: 'SOL142',
          name: 'No Withdrawal Delay',
          severity: 'high',
          message: 'Instant withdrawal prevents fraud proofs and slashing execution',
          location: `${input.path}:${i + 1}`,
          snippet: line.trim(),
          fix: 'Implement withdrawal delay (e.g., 7 days) for fraud proof window',
        });
      }

      // Check for pending slashing
      if (!/pending.*slash|check.*slash|slash.*queue/i.test(nearbyContent)) {
        findings.push({
          id: 'SOL142',
          name: 'Withdrawal Without Slash Check',
          severity: 'critical',
          message: 'Withdrawal without checking pending slashing can allow escape',
          location: `${input.path}:${i + 1}`,
          snippet: line.trim(),
          fix: 'Block withdrawals while slashing is pending',
        });
      }
    }

    // Check for slashing execution
    if (/execute.*slash|apply.*penalty|slash.*funds/i.test(line)) {
      const nearbyContent = lines.slice(Math.max(0, i - 10), Math.min(lines.length, i + 10)).join('\n');
      
      if (!/proof|evidence|verify.*fault/i.test(nearbyContent)) {
        findings.push({
          id: 'SOL142',
          name: 'Slashing Without Proof',
          severity: 'critical',
          message: 'Slashing executed without cryptographic proof of misbehavior',
          location: `${input.path}:${i + 1}`,
          snippet: line.trim(),
          fix: 'Require verifiable proof of misbehavior before slashing',
        });
      }
    }
  });

  return findings;
}
