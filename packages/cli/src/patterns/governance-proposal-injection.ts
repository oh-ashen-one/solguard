import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL132: Governance Proposal Injection
 * Detects vulnerabilities in DAO governance where proposals can be injected or manipulated
 * Real-world: Audius ($6.1M exploit)
 */
export function checkGovernanceProposalInjection(input: PatternInput): Finding[] {
  const findings: Finding[] = [];

  if (input.rust?.content) {
    const content = input.rust.content;
    const lines = content.split('\n');

    // Check for governance/proposal handling
    const governancePatterns = [
      /proposal|governance|vote|ballot/i,
      /execute_proposal|process_proposal/i,
      /create_proposal|submit_proposal/i,
    ];

    const hasGovernance = governancePatterns.some(p => p.test(content));

    if (hasGovernance) {
      // Check for missing proposal state validation
      if (!content.includes('ProposalState::') && !content.includes('proposal_state')) {
        findings.push({
          id: 'SOL132',
          title: 'Missing Proposal State Validation',
          severity: 'critical',
          description: 'Governance proposals must validate state transitions to prevent execution of non-approved proposals.',
          location: { file: input.path, line: 1 },
          suggestion: 'Implement strict state machine: Draft -> Active -> Succeeded -> Queued -> Executed. Validate state before any operation.',
          cwe: 'CWE-284',
        });
      }

      // Check for proposal execution without timelock
      if (content.includes('execute') && !content.includes('timelock') && !content.includes('delay')) {
        for (let i = 0; i < lines.length; i++) {
          if (lines[i].match(/execute.*proposal/i)) {
            findings.push({
              id: 'SOL132',
              title: 'Proposal Execution Without Timelock',
              severity: 'high',
              description: 'Proposals should have a timelock delay between approval and execution to allow community review.',
              location: { file: input.path, line: i + 1 },
              suggestion: 'Add timelock: require!(Clock::get()?.unix_timestamp > proposal.execution_time, TooEarly)',
              cwe: 'CWE-362',
            });
            break;
          }
        }
      }

      // Check for vote weight manipulation
      if (content.includes('vote') && !content.includes('snapshot') && !content.includes('checkpoint')) {
        findings.push({
          id: 'SOL132',
          title: 'Vote Weight Manipulation Risk',
          severity: 'high',
          description: 'Voting power should be snapshotted at proposal creation to prevent flash loan vote manipulation.',
          location: { file: input.path, line: 1 },
          suggestion: 'Use vote weight snapshots: let voting_power = get_voting_power_at(user, proposal.snapshot_slot)',
          cwe: 'CWE-362',
        });
      }
    }
  }

  return findings;
}
