import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL146: Yield Aggregator Security
 * Detects vulnerabilities in yield optimization vaults (Kamino, Tulip style)
 * 
 * Yield aggregator risks:
 * - Strategy manipulation
 * - Harvest timing attacks
 * - Vault share inflation
 */
export function checkYieldAggregator(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rust = input.rust;
  if (!rust) return findings;

  const content = rust.content;
  const lines = content.split('\n');

  lines.forEach((line, i) => {
    // Check for vault deposit
    if (/deposit.*vault|add.*to.*vault|mint.*share/i.test(line)) {
      const nearbyContent = lines.slice(Math.max(0, i - 20), Math.min(lines.length, i + 20)).join('\n');
      
      // Check for share inflation attack protection
      if (!/total_supply.*>.*0|first.*deposit|initial.*share/i.test(nearbyContent)) {
        findings.push({
          id: 'SOL146',
          name: 'Vault Share Inflation Attack',
          severity: 'critical',
          message: 'First depositor can inflate share price to steal from later depositors',
          location: `${input.path}:${i + 1}`,
          snippet: line.trim(),
          fix: 'Burn initial shares or require minimum initial deposit',
        });
      }

      // Check for deposit cap
      if (!/max.*deposit|cap|limit.*tvl/i.test(nearbyContent)) {
        findings.push({
          id: 'SOL146',
          name: 'No Deposit Cap',
          severity: 'low',
          message: 'Unlimited deposits can exceed strategy capacity',
          location: `${input.path}:${i + 1}`,
          snippet: line.trim(),
          fix: 'Implement deposit caps based on strategy capacity',
        });
      }
    }

    // Check for harvest/compound
    if (/harvest|compound|reinvest|claim.*reward/i.test(line)) {
      const nearbyContent = lines.slice(Math.max(0, i - 15), Math.min(lines.length, i + 15)).join('\n');
      
      // Check for harvest timing manipulation
      if (!/min.*interval|cooldown|rate_limit/i.test(nearbyContent)) {
        findings.push({
          id: 'SOL146',
          name: 'Harvest Timing Manipulation',
          severity: 'high',
          message: 'Attacker can time deposit/harvest/withdraw to extract value',
          location: `${input.path}:${i + 1}`,
          snippet: line.trim(),
          fix: 'Add minimum time between harvest or pro-rate new deposits',
        });
      }

      // Check for sandwich protection
      if (!/slippage|min.*out|deadline/i.test(nearbyContent)) {
        findings.push({
          id: 'SOL146',
          name: 'Harvest Sandwich Risk',
          severity: 'high',
          message: 'Harvest swap can be sandwiched for MEV extraction',
          location: `${input.path}:${i + 1}`,
          snippet: line.trim(),
          fix: 'Use private transactions or commit-reveal for harvests',
        });
      }
    }

    // Check for strategy allocation
    if (/allocate.*strategy|rebalance|adjust.*weight/i.test(line)) {
      const nearbyContent = lines.slice(Math.max(0, i - 10), Math.min(lines.length, i + 10)).join('\n');
      
      if (!/admin|authority|timelock/i.test(nearbyContent)) {
        findings.push({
          id: 'SOL146',
          name: 'Strategy Change Without Governance',
          severity: 'high',
          message: 'Anyone can change strategy allocation',
          location: `${input.path}:${i + 1}`,
          snippet: line.trim(),
          fix: 'Restrict strategy changes to admin with timelock',
        });
      }
    }

    // Check for underlying protocol risks
    if (/underlying|base.*protocol|farm.*address/i.test(line)) {
      findings.push({
        id: 'SOL146',
        name: 'Underlying Protocol Risk',
        severity: 'medium',
        message: 'Vault inherits risks from underlying protocol',
        location: `${input.path}:${i + 1}`,
        snippet: line.trim(),
        fix: 'Document underlying protocol risks and emergency withdrawal path',
      });
    }
  });

  return findings;
}
