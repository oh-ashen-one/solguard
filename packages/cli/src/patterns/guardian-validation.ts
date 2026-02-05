import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL181: Guardian/Validator Signature Validation
 * 
 * Detects insufficient guardian or validator signature verification
 * in cross-chain bridges and multi-sig systems.
 * 
 * Real-world exploit: Wormhole - $326M stolen due to signature
 * verification flaw allowing forged guardian signatures.
 */
export function checkGuardianValidation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const { rust, idl, path } = input;

  if (idl) {
    const bridgeInstructions = idl.instructions.filter(ix =>
      ix.name.toLowerCase().includes('bridge') ||
      ix.name.toLowerCase().includes('transfer') ||
      ix.name.toLowerCase().includes('relay') ||
      ix.name.toLowerCase().includes('message') ||
      ix.name.toLowerCase().includes('vaa')
    );

    for (const ix of bridgeInstructions) {
      const hasGuardianAccount = ix.accounts?.some(acc =>
        acc.name.toLowerCase().includes('guardian') ||
        acc.name.toLowerCase().includes('validator') ||
        acc.name.toLowerCase().includes('signature')
      );

      if (!hasGuardianAccount) {
        findings.push({
          id: 'SOL181',
          severity: 'critical',
          title: 'Bridge Operation Without Guardian Verification',
          description: `Instruction "${ix.name}" may process cross-chain messages without guardian signature verification.`,
          location: { file: path, line: 1 },
          recommendation: 'Implement multi-guardian signature verification with threshold requirements.',
        });
      }
    }
  }

  if (!rust) return findings;

  const vulnerablePatterns = [
    { pattern: /verify_signature.*deprecated/i, desc: 'Deprecated signature verification' },
    { pattern: /guardian.*count.*<\s*threshold/i, desc: 'Guardian count below threshold' },
    { pattern: /skip.*signature.*check/i, desc: 'Skipped signature check' },
    { pattern: /signature_set.*unchecked/i, desc: 'Unchecked signature set' },
    { pattern: /verify_signatures.*\?\s*;/, desc: 'Ignored signature verification result' },
  ];

  const lines = rust.content.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    for (const { pattern, desc } of vulnerablePatterns) {
      if (pattern.test(line)) {
        findings.push({
          id: 'SOL181',
          severity: 'critical',
          title: 'Guardian Signature Validation Issue',
          description: `${desc}. Attackers may forge messages without proper guardian verification.`,
          location: { file: path, line: i + 1 },
          recommendation: 'Always verify guardian signatures, enforce threshold requirements, and validate signature freshness.',
        });
      }
    }
  }

  // Check for signature verification without proper account validation
  const content = rust.content;
  if (content.includes('verify_signatures') && !content.includes('check_program_account')) {
    findings.push({
      id: 'SOL181',
      severity: 'critical',
      title: 'Signature Verification Without Account Validation',
      description: 'Signature verification found without validating the signature account ownership.',
      location: { file: path, line: 1 },
      recommendation: 'Validate that signature accounts are owned by the correct program and properly initialized.',
    });
  }

  return findings;
}
