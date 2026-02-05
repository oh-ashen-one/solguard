import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL135: DEX Aggregator Security
 * Detects vulnerabilities when integrating with Jupiter and other aggregators
 * 
 * Risks include:
 * - Route manipulation
 * - Intermediate token attacks
 * - Excessive slippage
 */
export function checkDexAggregator(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rust = input.rust;
  if (!rust) return findings;

  const content = rust.content;
  const lines = content.split('\n');

  lines.forEach((line, i) => {
    // Check for Jupiter/aggregator integration
    if (/jupiter|jup_ag|route.*swap|aggregator/i.test(line)) {
      const nearbyContent = lines.slice(Math.max(0, i - 20), Math.min(lines.length, i + 20)).join('\n');
      
      // Check for slippage validation
      if (!/slippage|min_out|minimum_amount_out/i.test(nearbyContent)) {
        findings.push({
          id: 'SOL135',
          name: 'Aggregator Missing Slippage',
          severity: 'critical',
          message: 'DEX aggregator call without slippage protection can result in total loss',
          location: `${input.path}:${i + 1}`,
          snippet: line.trim(),
          fix: 'Always set min_out_amount based on expected price with slippage tolerance',
        });
      }

      // Check for route validation
      if (!/validate.*route|check.*route|verify.*path/i.test(nearbyContent)) {
        findings.push({
          id: 'SOL135',
          name: 'Aggregator Route Not Validated',
          severity: 'high',
          message: 'Swap route not validated - malicious routes can drain funds',
          location: `${input.path}:${i + 1}`,
          snippet: line.trim(),
          fix: 'Validate that route starts/ends with expected tokens',
        });
      }
    }

    // Check for intermediate token handling
    if (/intermediate.*token|hop|multi.*hop/i.test(line)) {
      findings.push({
        id: 'SOL135',
        name: 'Intermediate Token Risk',
        severity: 'medium',
        message: 'Multi-hop swaps expose to intermediate token risks',
        location: `${input.path}:${i + 1}`,
        snippet: line.trim(),
        fix: 'Consider limiting hops or validating intermediate tokens',
      });
    }

    // Check for quote freshness
    if (/get_quote|fetch_quote|quote_response/i.test(line)) {
      const nearbyContent = lines.slice(Math.max(0, i - 10), Math.min(lines.length, i + 10)).join('\n');
      if (!/timestamp|expires|valid_until|ttl/i.test(nearbyContent)) {
        findings.push({
          id: 'SOL135',
          name: 'Quote Freshness Not Checked',
          severity: 'high',
          message: 'Stale quotes can result in unfavorable execution',
          location: `${input.path}:${i + 1}`,
          snippet: line.trim(),
          fix: 'Check quote timestamp and reject if older than acceptable threshold',
        });
      }
    }

    // Check for referral fee manipulation
    if (/referral.*fee|platform.*fee|protocol.*fee/i.test(line)) {
      if (!/max.*fee|cap.*fee|<=|< /i.test(line)) {
        findings.push({
          id: 'SOL135',
          name: 'Uncapped Protocol Fee',
          severity: 'high',
          message: 'Protocol fees without caps can be set to drain user funds',
          location: `${input.path}:${i + 1}`,
          snippet: line.trim(),
          fix: 'Add maximum fee cap (e.g., <= 1%) to prevent fee manipulation',
        });
      }
    }
  });

  return findings;
}
