import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL140: Permissionless Cranking Security
 * Detects vulnerabilities in crank/keeper patterns
 * 
 * Many Solana protocols use permissionless cranks for:
 * - Liquidations
 * - Order matching
 * - Interest accrual
 * - Queue processing
 */
export function checkPermissionlessCranking(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rust = input.rust;
  if (!rust) return findings;

  const content = rust.content;
  const lines = content.split('\n');

  lines.forEach((line, i) => {
    // Check for crank/keeper functions
    if (/crank|keeper|process.*queue|execute.*order/i.test(line)) {
      const nearbyContent = lines.slice(Math.max(0, i - 20), Math.min(lines.length, i + 20)).join('\n');
      
      // Check for incentive alignment
      if (!/reward|fee|incentive|tip/i.test(nearbyContent)) {
        findings.push({
          id: 'SOL140',
          name: 'Crank Without Incentive',
          severity: 'medium',
          message: 'Permissionless crank without rewards may not be called when needed',
          location: `${input.path}:${i + 1}`,
          snippet: line.trim(),
          fix: 'Add crank rewards to incentivize keepers during high gas periods',
        });
      }

      // Check for gas griefing protection
      if (!/compute_limit|max.*iterations|batch_size/i.test(nearbyContent)) {
        findings.push({
          id: 'SOL140',
          name: 'Crank Gas Griefing',
          severity: 'high',
          message: 'Unbounded crank can be griefed with expensive operations',
          location: `${input.path}:${i + 1}`,
          snippet: line.trim(),
          fix: 'Limit iterations per crank call to prevent compute exhaustion',
        });
      }

      // Check for MEV extraction
      if (!/commit.*reveal|sealed|private/i.test(nearbyContent)) {
        findings.push({
          id: 'SOL140',
          name: 'Crank MEV Exposure',
          severity: 'medium',
          message: 'Permissionless crank exposes execution order to MEV extraction',
          location: `${input.path}:${i + 1}`,
          snippet: line.trim(),
          fix: 'Consider commit-reveal or priority ordering to reduce MEV',
        });
      }
    }

    // Check for liquidation cranks
    if (/liquidat.*crank|trigger.*liquidation|execute.*liquidation/i.test(line)) {
      const nearbyContent = lines.slice(Math.max(0, i - 15), Math.min(lines.length, i + 15)).join('\n');
      
      // Check for liquidation incentive
      if (!/liquidation.*bonus|incentive|penalty/i.test(nearbyContent)) {
        findings.push({
          id: 'SOL140',
          name: 'Liquidation Incentive Missing',
          severity: 'high',
          message: 'Liquidation without bonus may not happen during market stress',
          location: `${input.path}:${i + 1}`,
          snippet: line.trim(),
          fix: 'Add liquidation bonus (e.g., 5-10%) to ensure timely liquidations',
        });
      }

      // Check for partial liquidation
      if (!/partial|close_factor|max_liquidation/i.test(nearbyContent)) {
        findings.push({
          id: 'SOL140',
          name: 'Full Liquidation Only',
          severity: 'medium',
          message: 'Only allowing full liquidation may exceed liquidator capacity',
          location: `${input.path}:${i + 1}`,
          snippet: line.trim(),
          fix: 'Allow partial liquidations with close factor for large positions',
        });
      }
    }

    // Check for order matching
    if (/match.*order|fill.*order|execute.*trade/i.test(line)) {
      const nearbyContent = lines.slice(Math.max(0, i - 10), Math.min(lines.length, i + 10)).join('\n');
      
      if (!/price.*time|fifo|priority/i.test(nearbyContent)) {
        findings.push({
          id: 'SOL140',
          name: 'Order Matching Fairness',
          severity: 'medium',
          message: 'Order matching without clear priority rules can be manipulated',
          location: `${input.path}:${i + 1}`,
          snippet: line.trim(),
          fix: 'Implement price-time priority for fair order matching',
        });
      }
    }
  });

  return findings;
}
