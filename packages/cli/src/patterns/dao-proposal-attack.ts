import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL186: DAO Proposal Attack
 * 
 * Detects vulnerabilities in DAO governance that allow malicious
 * proposals to slip through unnoticed.
 * 
 * Real-world exploit: Synthetify DAO - $230K lost when attacker
 * proposed malicious upgrade that went unnoticed.
 */
export function checkDaoProposalAttack(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const { rust, idl, path } = input;

  if (idl) {
    const govInstructions = idl.instructions.filter(ix =>
      ix.name.toLowerCase().includes('proposal') ||
      ix.name.toLowerCase().includes('vote') ||
      ix.name.toLowerCase().includes('execute') ||
      ix.name.toLowerCase().includes('queue')
    );

    for (const ix of govInstructions) {
      // Check for timelock in execute
      if (ix.name.toLowerCase().includes('execute')) {
        const hasTimelock = ix.accounts?.some(acc =>
          acc.name.toLowerCase().includes('timelock') ||
          acc.name.toLowerCase().includes('delay')
        );

        if (!hasTimelock) {
          findings.push({
            id: 'SOL186',
            severity: 'critical',
            title: 'Proposal Execution Without Timelock',
            description: `Instruction "${ix.name}" can execute proposals without apparent timelock delay.`,
            location: { file: path, line: 1 },
            recommendation: 'Implement mandatory timelock period between proposal approval and execution.',
          });
        }
      }

      // Check for quorum requirements
      if (ix.name.toLowerCase().includes('vote')) {
        const hasQuorum = ix.accounts?.some(acc =>
          acc.name.toLowerCase().includes('quorum') ||
          acc.name.toLowerCase().includes('threshold')
        );

        if (!hasQuorum) {
          findings.push({
            id: 'SOL186',
            severity: 'high',
            title: 'Voting Without Quorum Check',
            description: `Instruction "${ix.name}" may not enforce quorum requirements.`,
            location: { file: path, line: 1 },
            recommendation: 'Enforce minimum quorum and approval threshold for all governance votes.',
          });
        }
      }
    }
  }

  if (!rust) return findings;

  const vulnerablePatterns = [
    { pattern: /execute_proposal.*immediate/i, desc: 'Immediate proposal execution' },
    { pattern: /skip.*timelock/i, desc: 'Skipped timelock' },
    { pattern: /quorum.*=.*0/i, desc: 'Zero quorum' },
    { pattern: /min_votes.*=.*1/i, desc: 'Single vote threshold' },
    { pattern: /emergency.*execute/i, desc: 'Emergency execution bypass' },
  ];

  const lines = rust.content.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    for (const { pattern, desc } of vulnerablePatterns) {
      if (pattern.test(line)) {
        findings.push({
          id: 'SOL186',
          severity: 'critical',
          title: 'DAO Governance Vulnerability',
          description: `${desc} - malicious proposals may be executed without proper oversight.`,
          location: { file: path, line: i + 1 },
          recommendation: 'Require meaningful timelock periods, quorum thresholds, and multi-day voting periods.',
        });
      }
    }
  }

  return findings;
}
