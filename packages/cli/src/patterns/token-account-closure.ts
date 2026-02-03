import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL123: Token Account Closure
 * Detects issues with closing token accounts
 */
export function checkTokenAccountClosure(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rust = input.rust;

  if (!rust || !rust.content) return findings;

  if (!rust.content.includes('CloseAccount') && !rust.content.includes('close_account')) {
    return findings;
  }

  // Check for closing non-empty token account
  if (rust.content.includes('close') && rust.content.includes('token')) {
    if (!rust.content.includes('amount') && !rust.content.includes('== 0')) {
      findings.push({
        id: 'SOL123',
        severity: 'high',
        title: 'Token Account Close Without Balance Check',
        description: 'Closing token account without verifying zero balance',
        location: input.path,
        recommendation: 'Ensure token_account.amount == 0 before closing',
      });
    }
  }

  // Check for close authority validation
  if (!rust.content.includes('close_authority') && rust.content.includes('CloseAccount')) {
    findings.push({
      id: 'SOL123',
      severity: 'medium',
      title: 'No Close Authority Check',
      description: 'Closing token account without close_authority validation',
      location: input.path,
      recommendation: 'Verify close_authority if set on token account',
    });
  }

  return findings;
}
