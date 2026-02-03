import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL080: Timestamp Manipulation
 * Detects vulnerabilities in timestamp/time-based logic
 */
export function checkTimestampManipulation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rust = input.rust;

  if (!rust || !rust.content) return findings;

  const hasTimestamp = rust.content.includes('unix_timestamp') ||
                       rust.content.includes('timestamp') ||
                       rust.content.includes('Clock') ||
                       rust.content.includes('time');

  if (!hasTimestamp) return findings;

  // Check for timestamp in critical conditions
  const timestampCondition = /(?:unix_timestamp|timestamp)[\s\S]*?(?:==|<|>|<=|>=)/;
  if (timestampCondition.test(rust.content)) {
    // Check for tight timestamp windows
    const tightWindow = /(?:unix_timestamp|timestamp)[\s\S]*?[<>]=?\s*\d{1,3}(?!\d)/;
    if (tightWindow.test(rust.content)) {
      findings.push({
        id: 'SOL080',
        severity: 'high',
        title: 'Tight Timestamp Window',
        description: 'Time condition with very small window - vulnerable to manipulation',
        location: input.path,
        recommendation: 'Use larger time windows (>= 10 seconds) to account for clock drift',
      });
    }
  }

  // Check for timestamp equality checks
  const timestampEquality = /(?:unix_timestamp|timestamp)\s*==\s*\d+/;
  if (timestampEquality.test(rust.content)) {
    findings.push({
      id: 'SOL080',
      severity: 'high',
      title: 'Exact Timestamp Comparison',
      description: 'Comparing timestamp for exact equality will almost never succeed',
      location: input.path,
      recommendation: 'Use range comparisons (>= and <=) instead of exact equality',
    });
  }

  // Check for deadline without grace period
  if (rust.content.includes('deadline') || rust.content.includes('expir')) {
    if (!rust.content.includes('grace') && !rust.content.includes('buffer')) {
      const strictDeadline = /(?:deadline|expir\w+)[\s\S]*?(?:>=|<=|<|>)/;
      if (strictDeadline.test(rust.content)) {
        findings.push({
          id: 'SOL080',
          severity: 'medium',
          title: 'Deadline Without Grace Period',
          description: 'Time deadline without grace period for network delays',
          location: input.path,
          recommendation: 'Add grace period to deadlines to handle network/validator delays',
        });
      }
    }
  }

  // Check for timestamp for ordering/priority
  if (rust.content.includes('timestamp') && 
      (rust.content.includes('first') || rust.content.includes('priority') || rust.content.includes('order'))) {
    findings.push({
      id: 'SOL080',
      severity: 'medium',
      title: 'Timestamp-Based Ordering',
      description: 'Using timestamp for ordering - validators control block timestamp',
      location: input.path,
      recommendation: 'Use slot numbers or sequential counters for ordering instead',
    });
  }

  // Check for auction/bid time logic
  if (rust.content.includes('auction') || rust.content.includes('bid')) {
    if (rust.content.includes('timestamp') || rust.content.includes('Clock')) {
      if (!rust.content.includes('slot')) {
        findings.push({
          id: 'SOL080',
          severity: 'high',
          title: 'Auction Using Timestamp',
          description: 'Auction timing based on timestamp - validator can manipulate',
          location: input.path,
          recommendation: 'Use slot numbers for auction timing to prevent manipulation',
        });
      }
    }
  }

  // Check for vesting/unlock schedules
  if (rust.content.includes('vest') || rust.content.includes('unlock') || rust.content.includes('cliff')) {
    if (!rust.content.includes('slot') && rust.content.includes('timestamp')) {
      findings.push({
        id: 'SOL080',
        severity: 'medium',
        title: 'Vesting Using Timestamp',
        description: 'Vesting schedule uses timestamp which can vary slightly',
        location: input.path,
        recommendation: 'Consider using slot-based vesting or add tolerance windows',
      });
    }
  }

  // Check for randomness from timestamp
  if (rust.content.includes('timestamp') && 
      (rust.content.includes('random') || rust.content.includes('seed') || rust.content.includes('%'))) {
    findings.push({
      id: 'SOL080',
      severity: 'critical',
      title: 'Timestamp Used for Randomness',
      description: 'Timestamp is predictable and should not be used for randomness',
      location: input.path,
      recommendation: 'Use VRF (Switchboard, Pyth) for verifiable randomness',
    });
  }

  return findings;
}
