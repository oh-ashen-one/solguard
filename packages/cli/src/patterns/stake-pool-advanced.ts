import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL137: Advanced Stake Pool Security
 * Detects vulnerabilities in liquid staking protocols (Marinade, Jito, Sanctum style)
 * 
 * Risks include:
 * - Validator set manipulation
 * - Withdrawal queue attacks
 * - LST depeg scenarios
 */
export function checkStakePoolAdvanced(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rust = input.rust;
  if (!rust) return findings;

  const content = rust.content;
  const lines = content.split('\n');

  lines.forEach((line, i) => {
    // Check for validator selection
    if (/select.*validator|choose.*validator|validator.*score/i.test(line)) {
      const nearbyContent = lines.slice(Math.max(0, i - 15), Math.min(lines.length, i + 15)).join('\n');
      
      if (!/commission|performance|uptime|stake.*concentration/i.test(nearbyContent)) {
        findings.push({
          id: 'SOL137',
          name: 'Validator Selection Criteria Missing',
          severity: 'high',
          message: 'Validator selection without performance/commission checks can harm stakers',
          location: `${input.path}:${i + 1}`,
          snippet: line.trim(),
          fix: 'Include commission rate, uptime, and stake concentration in validator selection',
        });
      }
    }

    // Check for LST exchange rate manipulation
    if (/exchange_rate|lst.*rate|token.*sol.*ratio/i.test(line)) {
      const nearbyContent = lines.slice(Math.max(0, i - 10), Math.min(lines.length, i + 10)).join('\n');
      
      if (!/epoch|time_lock|rate_limit/i.test(nearbyContent)) {
        findings.push({
          id: 'SOL137',
          name: 'LST Rate Manipulation Risk',
          severity: 'critical',
          message: 'LST exchange rate without rate limiting can be manipulated',
          location: `${input.path}:${i + 1}`,
          snippet: line.trim(),
          fix: 'Limit exchange rate changes per epoch and add circuit breakers',
        });
      }
    }

    // Check for withdrawal queue handling
    if (/withdrawal.*queue|unstake.*queue|pending.*withdrawal/i.test(line)) {
      const nearbyContent = lines.slice(Math.max(0, i - 15), Math.min(lines.length, i + 15)).join('\n');
      
      if (!/fifo|priority|cooldown|epoch.*boundary/i.test(nearbyContent)) {
        findings.push({
          id: 'SOL137',
          name: 'Withdrawal Queue Fairness',
          severity: 'medium',
          message: 'Withdrawal queue without clear ordering can be gamed',
          location: `${input.path}:${i + 1}`,
          snippet: line.trim(),
          fix: 'Implement FIFO ordering or priority-based queue with clear rules',
        });
      }
    }

    // Check for stake account splitting
    if (/split.*stake|stake.*split|partial.*unstake/i.test(line)) {
      if (!/minimum.*stake|min_delegation|rent_exempt/i.test(content)) {
        findings.push({
          id: 'SOL137',
          name: 'Stake Split Dust Attack',
          severity: 'medium',
          message: 'Stake splitting without minimum can create dust accounts',
          location: `${input.path}:${i + 1}`,
          snippet: line.trim(),
          fix: 'Enforce minimum stake amount after split (at least rent + min_delegation)',
        });
      }
    }

    // Check for epoch transition handling
    if (/epoch.*transition|new.*epoch|epoch.*change/i.test(line)) {
      const nearbyContent = lines.slice(Math.max(0, i - 10), Math.min(lines.length, i + 10)).join('\n');
      
      if (!/update.*rate|recalculate|sync/i.test(nearbyContent)) {
        findings.push({
          id: 'SOL137',
          name: 'Epoch Transition Not Handled',
          severity: 'high',
          message: 'Epoch transitions require rate/state updates to prevent arbitrage',
          location: `${input.path}:${i + 1}`,
          snippet: line.trim(),
          fix: 'Implement epoch transition handler to update rates and sync state',
        });
      }
    }
  });

  return findings;
}
