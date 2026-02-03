import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL060: Initialization Frontrunning
 * Vulnerabilities where initialization can be frontrun.
 */
export function checkInitializationFrontrun(input: PatternInput): Finding[] {
  const findings: Finding[] = [];

  if (!input.rust || !input.rust.files) return findings;

  for (const file of input.rust.files) {
    const lines = file.lines;

    lines.forEach((line, index) => {
      const lineNum = index + 1;

      // Pattern 1: Initialize without deployer check
      if (line.includes('pub fn initialize') || line.includes('pub fn init')) {
        const fnEnd = Math.min(lines.length, index + 30);
        const fnBody = lines.slice(index, fnEnd).join('\n');

        // Check if there's any access control
        if (!fnBody.includes('deployer') && !fnBody.includes('upgrade_authority') &&
            !fnBody.includes('admin') && !fnBody.includes('authority') &&
            !fnBody.includes('only_') && !fnBody.includes('require!')) {
          findings.push({
            id: `SOL060-${findings.length + 1}`,
            pattern: 'Initialization Frontrunning',
            severity: 'critical',
            title: 'Initialize callable by anyone',
            description: 'No access control on initialize. Attacker can frontrun and become admin.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Restrict to deployer or use deterministic initialization.',
          });
        }
      }

      // Pattern 2: Init sets critical params from args
      if (line.includes('init') && (line.includes('args.admin') || line.includes('args.authority'))) {
        findings.push({
          id: `SOL060-${findings.length + 1}`,
          pattern: 'Initialization Frontrunning',
          severity: 'high',
          title: 'Admin set from init arguments',
          description: 'Admin comes from args. Frontrunner can set themselves as admin.',
          location: { file: file.path, line: lineNum },
          suggestion: 'Use deployer as initial admin, or verify against expected value.',
        });
      }

      // Pattern 3: PDA init without proper seeds
      if (line.includes('init') && line.includes('seeds')) {
        const contextStart = Math.max(0, index - 5);
        const context = lines.slice(contextStart, index + 5).join('\n');

        // Check if seeds are predictable
        if (!context.includes('.key()') && !context.includes('signer')) {
          findings.push({
            id: `SOL060-${findings.length + 1}`,
            pattern: 'Initialization Frontrunning',
            severity: 'medium',
            title: 'PDA init with predictable seeds',
            description: 'PDA seeds are predictable. Could be initialized by anyone first.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Include unique seed component like initializer pubkey.',
          });
        }
      }
    });
  }

  return findings;
}
