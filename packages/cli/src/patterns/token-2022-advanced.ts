import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL133: Advanced Token-2022 Extension Security
 * Detects vulnerabilities specific to Token-2022 extensions
 * 
 * Extensions include: transfer fees, interest-bearing, permanent delegate,
 * non-transferable, confidential transfers, transfer hooks, metadata
 */
export function checkToken2022Advanced(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rust = input.rust;
  if (!rust) return findings;

  const content = rust.content;
  const lines = content.split('\n');

  lines.forEach((line, i) => {
    // Check for permanent delegate risks
    if (/permanent_delegate|PermanentDelegate/i.test(line)) {
      findings.push({
        id: 'SOL133',
        name: 'Permanent Delegate Risk',
        severity: 'critical',
        message: 'Permanent delegate can transfer tokens without owner consent - use with extreme caution',
        location: `${input.path}:${i + 1}`,
        snippet: line.trim(),
        fix: 'Verify permanent delegate is set to a trusted, audited program only',
      });
    }

    // Check for transfer hook validation
    if (/transfer_hook|TransferHook/i.test(line)) {
      const nearbyContent = lines.slice(Math.max(0, i - 10), Math.min(lines.length, i + 10)).join('\n');
      if (!/validate.*hook|verify.*program|check.*hook_program/i.test(nearbyContent)) {
        findings.push({
          id: 'SOL133',
          name: 'Transfer Hook Validation Missing',
          severity: 'high',
          message: 'Transfer hook program not validated - malicious hooks can block or manipulate transfers',
          location: `${input.path}:${i + 1}`,
          snippet: line.trim(),
          fix: 'Validate transfer_hook_program_id against known safe programs',
        });
      }
    }

    // Check for confidential transfer risks
    if (/confidential_transfer|ConfidentialTransfer/i.test(line)) {
      findings.push({
        id: 'SOL133',
        name: 'Confidential Transfer Complexity',
        severity: 'medium',
        message: 'Confidential transfers require careful ZK proof handling',
        location: `${input.path}:${i + 1}`,
        snippet: line.trim(),
        fix: 'Ensure proper proof validation and consider audit for ZK components',
      });
    }

    // Check for non-transferable token bypass
    if (/non_transferable|NonTransferable/i.test(line)) {
      if (/burn|close_account/i.test(content)) {
        findings.push({
          id: 'SOL133',
          name: 'Non-Transferable Token Bypass',
          severity: 'high',
          message: 'Non-transferable tokens can still be burned or account closed - verify intended behavior',
          location: `${input.path}:${i + 1}`,
          snippet: line.trim(),
          fix: 'Consider if burn/close should also be restricted for soulbound tokens',
        });
      }
    }

    // Check for interest-bearing calculation risks
    if (/interest_bearing|InterestBearing|calculate_interest/i.test(line)) {
      if (!/checked_|saturating_/i.test(line)) {
        findings.push({
          id: 'SOL133',
          name: 'Interest Calculation Overflow',
          severity: 'high',
          message: 'Interest calculations can overflow with large amounts or time periods',
          location: `${input.path}:${i + 1}`,
          snippet: line.trim(),
          fix: 'Use checked_mul/checked_add for interest calculations',
        });
      }
    }

    // Check for transfer fee collection
    if (/transfer_fee|TransferFee|withheld_amount/i.test(line)) {
      const nearbyContent = lines.slice(Math.max(0, i - 10), Math.min(lines.length, i + 10)).join('\n');
      if (!/harvest|withdraw.*fee|collect.*fee/i.test(nearbyContent)) {
        findings.push({
          id: 'SOL133',
          name: 'Transfer Fee Collection Missing',
          severity: 'low',
          message: 'Transfer fees accumulate in token accounts - ensure fee collection mechanism exists',
          location: `${input.path}:${i + 1}`,
          snippet: line.trim(),
          fix: 'Implement fee harvesting to collect withheld transfer fees',
        });
      }
    }
  });

  return findings;
}
