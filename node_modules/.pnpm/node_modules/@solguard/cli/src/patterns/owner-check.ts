import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';
import { getMutableAccountsWithoutOwnerCheck } from '../parsers/idl.js';
import { findMissingOwnerChecks } from '../parsers/rust.js';

export function checkMissingOwner(input: PatternInput): Finding[] {
  const findings: Finding[] = [];

  // Check IDL for mutable accounts without PDA (potential owner issues)
  if (input.idl) {
    const issues = getMutableAccountsWithoutOwnerCheck(input.idl);
    for (const issue of issues) {
      findings.push({
        id: `SOL001-${findings.length + 1}`,
        pattern: 'Missing Owner Check',
        severity: 'critical',
        title: `Mutable account '${issue.account}' may lack owner verification`,
        description: `In instruction '${issue.instruction}', the account '${issue.account}' is mutable but may not have proper owner verification. An attacker could pass a fake account owned by a different program.`,
        location: {
          file: 'IDL',
          line: undefined,
        },
        suggestion: `Add owner constraint: #[account(owner = expected_program_id)]`,
      });
    }
  }

  // Check Rust source for missing owner constraints
  if (input.rust) {
    const issues = findMissingOwnerChecks(input.rust);
    for (const issue of issues) {
      findings.push({
        id: `SOL001-${findings.length + 1}`,
        pattern: 'Missing Owner Check',
        severity: 'critical',
        title: `Account '${issue.account}' may lack owner constraint`,
        description: `The account '${issue.account}' is declared as Account<'info, T> but may not have an owner constraint. Without this, an attacker could pass an account owned by a malicious program with matching data layout.`,
        location: {
          file: issue.file,
          line: issue.line,
        },
        suggestion: `Add owner constraint to the account:\n#[account(owner = crate::ID)]\npub ${issue.account}: Account<'info, YourType>,`,
      });
    }
  }

  return findings;
}
