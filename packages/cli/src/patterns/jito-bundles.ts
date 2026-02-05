import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL131: Jito Bundle Security
 * Detects vulnerabilities related to Jito bundles and MEV protection
 * 
 * Bundles can:
 * - Execute atomically (all-or-nothing)
 * - Front-run or sandwich user transactions
 * - Manipulate state within a single slot
 */
export function checkJitoBundles(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rust = input.rust;
  if (!rust) return findings;

  const content = rust.content;
  const lines = content.split('\n');

  // Check for price-sensitive operations without MEV protection
  const priceSensitivePatterns = [
    /swap|exchange|trade/i,
    /deposit.*amount|withdraw.*amount/i,
    /liquidat/i,
    /borrow|repay/i,
  ];

  const mevProtectionPatterns = [
    /min_amount_out|minimum_out/i,
    /slippage|max_slippage/i,
    /deadline|expires?_at/i,
    /commitment_slot|require.*slot/i,
  ];

  let hasPriceSensitiveOp = false;
  let hasMevProtection = false;

  lines.forEach((line, i) => {
    // Check for price-sensitive operations
    for (const pattern of priceSensitivePatterns) {
      if (pattern.test(line)) {
        hasPriceSensitiveOp = true;
        
        // Check if this function has MEV protection nearby (within 20 lines)
        const nearbyLines = lines.slice(Math.max(0, i - 10), Math.min(lines.length, i + 10)).join('\n');
        for (const protectionPattern of mevProtectionPatterns) {
          if (protectionPattern.test(nearbyLines)) {
            hasMevProtection = true;
          }
        }

        if (!hasMevProtection) {
          findings.push({
            id: 'SOL131',
            name: 'Missing MEV Protection',
            severity: 'high',
            message: 'Price-sensitive operation without slippage/deadline protection is vulnerable to Jito bundle attacks',
            location: `${input.path}:${i + 1}`,
            snippet: line.trim(),
            fix: 'Add min_amount_out, deadline, or slot commitment checks to prevent sandwich attacks',
          });
        }
      }
    }

    // Check for same-slot state dependency
    if (/get_price|fetch_price|load_price/i.test(line) && !/twap|time_weighted/i.test(line)) {
      findings.push({
        id: 'SOL131',
        name: 'Same-Slot Price Dependency',
        severity: 'medium',
        message: 'Spot price fetch can be manipulated within same slot by bundle attackers',
        location: `${input.path}:${i + 1}`,
        snippet: line.trim(),
        fix: 'Use TWAP oracle or require price commitment from previous slot',
      });
    }
  });

  return findings;
}
