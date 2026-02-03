import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL125: Program as Signer
 * Detects issues when program acts as signer via PDA
 */
export function checkProgramSigner(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const rust = input.rust;

  if (!rust || !rust.content) return findings;

  if (!rust.content.includes('invoke_signed')) return findings;

  // Check for signer seeds derivation
  if (rust.content.includes('invoke_signed') && !rust.content.includes('find_program_address')) {
    findings.push({
      id: 'SOL125',
      severity: 'medium',
      title: 'Signer Seeds Without PDA Derivation',
      description: 'Using invoke_signed without find_program_address in same scope',
      location: input.path,
      recommendation: 'Derive PDA and use its bump for invoke_signed',
    });
  }

  // Check for multiple signers
  const signerArrays = (rust.content.match(/&\[&\[/g) || []).length;
  if (signerArrays > 1) {
    findings.push({
      id: 'SOL125',
      severity: 'low',
      title: 'Multiple PDA Signers',
      description: 'Multiple signer seed arrays - ensure all PDAs are valid',
      location: input.path,
      recommendation: 'Verify each PDA signer is correctly derived',
    });
  }

  return findings;
}
