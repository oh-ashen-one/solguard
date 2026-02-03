import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL092: Token Extensions Security
 * Detects issues with SPL Token-2022 extensions
 */
export function checkTokenExtensions(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rust = input.rust;

  if (!rust || !rust.content) return findings;

  const hasToken2022 = rust.content.includes('Token2022') ||
                       rust.content.includes('token_2022') ||
                       rust.content.includes('ExtensionType');

  if (!hasToken2022) return findings;

  // Check for transfer hook handling
  if (rust.content.includes('TransferHook') || rust.content.includes('transfer_hook')) {
    if (!rust.content.includes('execute_cpi')) {
      findings.push({
        id: 'SOL092',
        severity: 'high',
        title: 'Transfer Hook CPI Missing',
        description: 'Transfer hook defined but CPI execution may be missing',
        location: input.path,
        recommendation: 'Ensure transfer hook executes via execute_cpi instruction',
      });
    }
  }

  // Check for confidential transfer handling
  if (rust.content.includes('ConfidentialTransfer')) {
    findings.push({
      id: 'SOL092',
      severity: 'medium',
      title: 'Confidential Transfer Extension',
      description: 'Using confidential transfers - ensure proper ZK proof validation',
      location: input.path,
      recommendation: 'Validate all ZK proofs in confidential transfer flow',
    });
  }

  // Check for permanent delegate risks
  if (rust.content.includes('PermanentDelegate')) {
    findings.push({
      id: 'SOL092',
      severity: 'high',
      title: 'Permanent Delegate Extension',
      description: 'Permanent delegate can transfer tokens without owner consent',
      location: input.path,
      recommendation: 'Ensure users understand permanent delegate implications',
    });
  }

  // Check for non-transferable tokens
  if (rust.content.includes('NonTransferable')) {
    if (rust.content.includes('transfer')) {
      findings.push({
        id: 'SOL092',
        severity: 'medium',
        title: 'Transfer Logic on Non-Transferable Token',
        description: 'Non-transferable token has transfer logic - will fail at runtime',
        location: input.path,
        recommendation: 'Remove transfer logic for non-transferable tokens',
      });
    }
  }

  // Check for interest-bearing token handling
  if (rust.content.includes('InterestBearing')) {
    if (!rust.content.includes('amount_to_ui_amount')) {
      findings.push({
        id: 'SOL092',
        severity: 'medium',
        title: 'Interest-Bearing Without UI Amount',
        description: 'Interest-bearing token without UI amount conversion',
        location: input.path,
        recommendation: 'Use amount_to_ui_amount for display values',
      });
    }
  }

  return findings;
}
