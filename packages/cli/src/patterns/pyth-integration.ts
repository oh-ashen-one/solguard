import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL139: Pyth Oracle Integration Security
 * Detects vulnerabilities specific to Pyth Network price feeds
 * 
 * Pyth-specific risks:
 * - Confidence interval handling
 * - Price feed status checks
 * - Expo (exponent) handling
 */
export function checkPythIntegration(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rust = input.rust;
  if (!rust) return findings;

  const content = rust.content;
  const lines = content.split('\n');

  lines.forEach((line, i) => {
    // Check for Pyth price usage
    if (/pyth|price_feed|PriceFeed|get_price/i.test(line)) {
      const nearbyContent = lines.slice(Math.max(0, i - 20), Math.min(lines.length, i + 20)).join('\n');
      
      // Check for confidence interval
      if (!/confidence|conf|price_conf/i.test(nearbyContent)) {
        findings.push({
          id: 'SOL139',
          name: 'Pyth Confidence Interval Ignored',
          severity: 'high',
          message: 'Pyth price used without checking confidence interval can lead to bad trades',
          location: `${input.path}:${i + 1}`,
          snippet: line.trim(),
          fix: 'Reject prices where confidence/price ratio exceeds threshold (e.g., 1%)',
        });
      }

      // Check for price status
      if (!/status|trading|unknown|halted/i.test(nearbyContent)) {
        findings.push({
          id: 'SOL139',
          name: 'Pyth Price Status Not Checked',
          severity: 'critical',
          message: 'Pyth price used without checking status - may be stale or halted',
          location: `${input.path}:${i + 1}`,
          snippet: line.trim(),
          fix: 'Verify price.status == PriceStatus::Trading before use',
        });
      }

      // Check for timestamp/staleness
      if (!/publish_time|timestamp|stale|max_age/i.test(nearbyContent)) {
        findings.push({
          id: 'SOL139',
          name: 'Pyth Price Staleness Not Checked',
          severity: 'critical',
          message: 'Pyth price used without staleness check can be outdated',
          location: `${input.path}:${i + 1}`,
          snippet: line.trim(),
          fix: 'Check publish_time is within acceptable age (e.g., < 30 seconds)',
        });
      }

      // Check for expo handling
      if (!/expo|exponent|scale.*price|price.*10/i.test(nearbyContent)) {
        findings.push({
          id: 'SOL139',
          name: 'Pyth Exponent Not Handled',
          severity: 'high',
          message: 'Pyth prices have variable exponents - must scale correctly',
          location: `${input.path}:${i + 1}`,
          snippet: line.trim(),
          fix: 'Apply price.expo to scale price correctly: price * 10^expo',
        });
      }
    }

    // Check for Pyth account validation
    if (/pyth.*account|price.*account.*info/i.test(line)) {
      const nearbyContent = lines.slice(Math.max(0, i - 10), Math.min(lines.length, i + 10)).join('\n');
      
      if (!/pyth.*program|verify.*owner|PYTH_PROGRAM_ID/i.test(nearbyContent)) {
        findings.push({
          id: 'SOL139',
          name: 'Pyth Account Owner Not Verified',
          severity: 'critical',
          message: 'Price account not verified to be owned by Pyth program',
          location: `${input.path}:${i + 1}`,
          snippet: line.trim(),
          fix: 'Verify account owner == PYTH_PROGRAM_ID before reading price',
        });
      }
    }

    // Check for price feed ID validation
    if (/price.*feed.*id|feed_id/i.test(line)) {
      if (!/expected.*feed|known.*feed|allowed.*feed/i.test(content)) {
        findings.push({
          id: 'SOL139',
          name: 'Pyth Feed ID Not Validated',
          severity: 'high',
          message: 'Any price feed accepted - attacker could pass wrong asset price',
          location: `${input.path}:${i + 1}`,
          snippet: line.trim(),
          fix: 'Validate feed_id matches expected asset (e.g., SOL/USD feed)',
        });
      }
    }
  });

  return findings;
}
