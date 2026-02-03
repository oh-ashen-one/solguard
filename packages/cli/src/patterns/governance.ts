import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL041: Governance Vulnerabilities
 * Issues with on-chain governance mechanisms.
 */
export function checkGovernance(input: PatternInput): Finding[] {
  const findings: Finding[] = [];

  if (!input.rust || !input.rust.files) return findings;

  for (const file of input.rust.files) {
    const lines = file.lines;
    const content = file.content;

    if (!content.includes('vote') && !content.includes('proposal') && !content.includes('governance')) {
      continue;
    }

    lines.forEach((line, index) => {
      const lineNum = index + 1;

      // Pattern 1: Vote without delegation check
      if (line.includes('pub fn vote') || line.includes('fn cast_vote')) {
        const fnEnd = Math.min(lines.length, index + 30);
        const fnBody = lines.slice(index, fnEnd).join('\n');

        if (!fnBody.includes('delegate') && !fnBody.includes('voting_power')) {
          findings.push({
            id: `SOL041-${findings.length + 1}`,
            pattern: 'Governance Vulnerability',
            severity: 'medium',
            title: 'Vote function without delegation handling',
            description: 'Voting without checking delegated voting power.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Check for delegated votes and prevent double-voting.',
          });
        }
      }

      // Pattern 2: Proposal execution without quorum
      if (line.includes('execute_proposal') || line.includes('execute')) {
        const contextStart = Math.max(0, index - 10);
        const context = lines.slice(contextStart, index + 10).join('\n');

        if (!context.includes('quorum') && !context.includes('threshold') && 
            context.includes('proposal')) {
          findings.push({
            id: `SOL041-${findings.length + 1}`,
            pattern: 'Governance Vulnerability',
            severity: 'high',
            title: 'Proposal execution without quorum check',
            description: 'Proposals can be executed without minimum vote threshold.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Require quorum: require!(votes >= quorum_threshold)',
          });
        }
      }

      // Pattern 3: Flash loan governance attack
      if (line.includes('vote') && content.includes('token')) {
        const contextStart = Math.max(0, index - 20);
        const context = lines.slice(contextStart, index + 5).join('\n');

        if (!context.includes('snapshot') && !context.includes('checkpoint') &&
            !context.includes('lock')) {
          findings.push({
            id: `SOL041-${findings.length + 1}`,
            pattern: 'Governance Vulnerability',
            severity: 'critical',
            title: 'Governance may be vulnerable to flash loan attack',
            description: 'Token-based voting without snapshot. Attacker can flash loan tokens to vote.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Use voting snapshots or require tokens to be locked before voting.',
          });
        }
      }
    });
  }

  return findings;
}
