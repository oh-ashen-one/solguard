import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';
import { getAccountsWithoutSigner } from '../parsers/idl.js';
import { findMissingSignerChecks } from '../parsers/rust.js';

export function checkMissingSigner(input: PatternInput): Finding[] {
  const findings: Finding[] = [];

  // Check IDL for instructions without any signer
  if (input.idl) {
    const issues = getAccountsWithoutSigner(input.idl);
    for (const issue of issues) {
      findings.push({
        id: `SOL002-${findings.length + 1}`,
        pattern: 'Missing Signer Check',
        severity: 'critical',
        title: `Instruction '${issue.instruction}' has no signer requirement`,
        description: `The instruction '${issue.instruction}' doesn't require any account to sign the transaction. This means anyone can call this instruction, which may allow unauthorized actions.`,
        location: {
          file: 'IDL',
          line: undefined,
        },
        suggestion: `Add a signer account:\npub authority: Signer<'info>,`,
      });
    }
  }

  // Check Rust source for authority accounts using AccountInfo instead of Signer
  if (input.rust) {
    const issues = findMissingSignerChecks(input.rust);
    for (const issue of issues) {
      findings.push({
        id: `SOL002-${findings.length + 1}`,
        pattern: 'Missing Signer Check',
        severity: 'critical',
        title: `Authority account '${issue.account}' is not a Signer`,
        description: `The account '${issue.account}' appears to be an authority/admin account but is declared as AccountInfo instead of Signer. This means anyone could pass any account as the authority without proving ownership.`,
        location: {
          file: issue.file,
          line: issue.line,
        },
        code: `pub ${issue.account}: AccountInfo<'info>`,
        suggestion: `Change to Signer:\npub ${issue.account}: Signer<'info>,`,
      });
    }
  }

  return findings;
}
