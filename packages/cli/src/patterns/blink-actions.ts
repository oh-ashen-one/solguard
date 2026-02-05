import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL132: Solana Blink/Actions Security
 * Detects vulnerabilities in Solana Actions (blinks) implementations
 * 
 * Actions are URLs that return signable transactions. Risks include:
 * - Malicious transaction crafting
 * - Missing origin validation
 * - Excessive permissions requested
 */
export function checkBlinkActions(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rust = input.rust;
  if (!rust) return findings;

  const content = rust.content;
  const lines = content.split('\n');

  lines.forEach((line, i) => {
    // Check for actions.json endpoint patterns
    if (/actions\.json|solana-action/i.test(line)) {
      // Check for missing origin validation
      if (!/origin|cors|allowed_origin/i.test(content)) {
        findings.push({
          id: 'SOL132',
          name: 'Blink Missing Origin Validation',
          severity: 'high',
          message: 'Solana Action endpoint without origin validation can be embedded maliciously',
          location: `${input.path}:${i + 1}`,
          snippet: line.trim(),
          fix: 'Validate request origin against allowlist before returning transaction',
        });
      }
    }

    // Check for transaction building without fee payer validation
    if (/build.*transaction|create.*transaction/i.test(line)) {
      const nearbyContent = lines.slice(Math.max(0, i - 5), Math.min(lines.length, i + 5)).join('\n');
      if (!/fee_payer|payer.*verify|check.*payer/i.test(nearbyContent)) {
        findings.push({
          id: 'SOL132',
          name: 'Action Fee Payer Risk',
          severity: 'medium',
          message: 'Transaction built without explicit fee payer validation',
          location: `${input.path}:${i + 1}`,
          snippet: line.trim(),
          fix: 'Explicitly set and validate fee_payer to prevent unexpected costs',
        });
      }
    }

    // Check for excessive permissions in actions
    if (/set_compute_unit_limit|request_heap_frame/i.test(line)) {
      findings.push({
        id: 'SOL132',
        name: 'Action Excessive Resources',
        severity: 'low',
        message: 'Action requests elevated compute/memory - ensure this is necessary',
        location: `${input.path}:${i + 1}`,
        snippet: line.trim(),
        fix: 'Only request elevated resources when genuinely needed',
      });
    }
  });

  return findings;
}
