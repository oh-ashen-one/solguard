import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL132: Governance Proposal Injection (Audius Exploit - $6.1M)
 * 
 * Detects vulnerabilities where governance proposals can be injected
 * or executed without proper validation, allowing unauthorized 
 * treasury access or parameter changes.
 */
export function checkGovernanceInjection(input: PatternInput): Finding[] {
  const findings: Finding[] = [];

  if (!input.rust || !input.rust.files) return findings;

  for (const file of input.rust.files) {
    const lines = file.lines;
    const content = file.content;

    lines.forEach((line, index) => {
      const lineNum = index + 1;
      const lineLower = line.toLowerCase();

      // Pattern 1: Proposal execution without proper state checks
      if (lineLower.includes('execute_proposal') || lineLower.includes('execute_vote') || 
          lineLower.includes('proposal.execute')) {
        const fnEnd = Math.min(lines.length, index + 20);
        const fnBody = lines.slice(index, fnEnd).join('\n').toLowerCase();
        
        if (!fnBody.includes('quorum') && !fnBody.includes('threshold') && !fnBody.includes('voting_period')) {
          findings.push({
            id: `SOL132-${findings.length + 1}`,
            pattern: 'Governance Proposal Injection',
            severity: 'critical',
            title: 'Proposal execution without quorum/threshold check',
            description: 'Governance proposal can be executed without verifying quorum or voting threshold. Attacker can push malicious proposals (Audius exploit).',
            location: { file: file.path, line: lineNum },
            suggestion: 'Always verify: require!(proposal.votes >= config.quorum && proposal.end_time < clock.unix_timestamp)',
          });
        }
      }

      // Pattern 2: Proposal creation without proper authorization
      if (lineLower.includes('create_proposal') || lineLower.includes('new_proposal')) {
        const fnEnd = Math.min(lines.length, index + 15);
        const fnBody = lines.slice(index, fnEnd).join('\n');
        
        if (!fnBody.includes('has_one') && !fnBody.includes('Signer') && !fnBody.includes('authority')) {
          findings.push({
            id: `SOL132-${findings.length + 1}`,
            pattern: 'Governance Proposal Injection',
            severity: 'critical',
            title: 'Proposal creation without proper authorization',
            description: 'Anyone can create governance proposals without authorization. Could allow proposal spam or injection attacks.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Require minimum token holdings or specific role to create proposals.',
          });
        }
      }

      // Pattern 3: Treasury operations in governance without timelock
      if ((lineLower.includes('treasury') || lineLower.includes('vault')) && 
          (lineLower.includes('transfer') || lineLower.includes('withdraw'))) {
        const fileContent = content.toLowerCase();
        if (!fileContent.includes('timelock') && !fileContent.includes('delay') && !fileContent.includes('grace_period')) {
          findings.push({
            id: `SOL132-${findings.length + 1}`,
            pattern: 'Governance Proposal Injection',
            severity: 'high',
            title: 'Treasury operation without timelock',
            description: 'Treasury funds can be moved without timelock delay. Malicious proposals could drain funds immediately.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Add timelock: require!(clock.unix_timestamp >= proposal.execute_after)',
          });
        }
      }

      // Pattern 4: Governance config update without multi-step
      if ((lineLower.includes('update_config') || lineLower.includes('set_config')) && 
          lineLower.includes('governance')) {
        findings.push({
          id: `SOL132-${findings.length + 1}`,
          pattern: 'Governance Proposal Injection',
          severity: 'high',
          title: 'Governance config update may lack safeguards',
          description: 'Governance configuration can be updated. Ensure proper multi-sig or proposal voting is required.',
          location: { file: file.path, line: lineNum },
          suggestion: 'Use 2-step config updates: propose -> wait -> execute, with multisig approval.',
        });
      }
    });
  }

  return findings;
}
