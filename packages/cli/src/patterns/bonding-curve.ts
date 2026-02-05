import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL134: Bonding Curve Security
 * Detects vulnerabilities in bonding curve implementations (pump.fun style)
 * 
 * Common issues:
 * - Curve manipulation through flash liquidity
 * - Graduation threshold gaming
 * - Migration rug pulls
 */
export function checkBondingCurve(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rust = input.rust;
  if (!rust) return findings;

  const content = rust.content;
  const lines = content.split('\n');

  lines.forEach((line, i) => {
    // Check for bonding curve price calculation
    if (/bonding.*curve|price.*curve|calculate.*price.*supply/i.test(line)) {
      // Check for flash manipulation protection
      const nearbyContent = lines.slice(Math.max(0, i - 15), Math.min(lines.length, i + 15)).join('\n');
      
      if (!/cooldown|rate_limit|block_timestamp|min_hold_time/i.test(nearbyContent)) {
        findings.push({
          id: 'SOL134',
          name: 'Bonding Curve Flash Manipulation',
          severity: 'critical',
          message: 'Bonding curve without rate limiting is vulnerable to flash loan attacks',
          location: `${input.path}:${i + 1}`,
          snippet: line.trim(),
          fix: 'Add cooldown period between buy/sell or implement rate limiting',
        });
      }
    }

    // Check for graduation/migration thresholds
    if (/graduation|migrate.*pool|threshold.*reached/i.test(line)) {
      const nearbyContent = lines.slice(Math.max(0, i - 10), Math.min(lines.length, i + 10)).join('\n');
      
      // Check for manipulation resistance
      if (!/lock|time_lock|admin_only|multisig/i.test(nearbyContent)) {
        findings.push({
          id: 'SOL134',
          name: 'Graduation Manipulation Risk',
          severity: 'high',
          message: 'Graduation threshold can be gamed without proper safeguards',
          location: `${input.path}:${i + 1}`,
          snippet: line.trim(),
          fix: 'Add time locks and admin controls around graduation process',
        });
      }
    }

    // Check for virtual reserves manipulation
    if (/virtual.*reserve|virtual.*liquidity|initial.*reserve/i.test(line)) {
      findings.push({
        id: 'SOL134',
        name: 'Virtual Reserve Configuration',
        severity: 'medium',
        message: 'Virtual reserves affect initial price - ensure values are appropriate',
        location: `${input.path}:${i + 1}`,
        snippet: line.trim(),
        fix: 'Document virtual reserve rationale and consider bounds checking',
      });
    }

    // Check for curve constant changes
    if (/set.*curve|update.*constant|change.*formula/i.test(line)) {
      if (!/admin|authority|multisig/i.test(line)) {
        findings.push({
          id: 'SOL134',
          name: 'Unauthorized Curve Modification',
          severity: 'critical',
          message: 'Curve parameters can be modified without proper authorization',
          location: `${input.path}:${i + 1}`,
          snippet: line.trim(),
          fix: 'Restrict curve parameter changes to authorized admin only',
        });
      }
    }
  });

  return findings;
}
