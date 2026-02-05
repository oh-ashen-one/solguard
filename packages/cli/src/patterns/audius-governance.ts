import type { Finding } from '../commands/audit.js';
import type { ParsedIdl } from '../parsers/idl.js';
import type { ParsedRust } from '../parsers/rust.js';

/**
 * SOL246: Audius-style Governance Exploit
 * Detects governance mechanism vulnerabilities
 * Reference: Audius Governance Exploit (July 2022) - $6.1M stolen via malicious proposal execution
 */
export function checkAudiusGovernance(idl: ParsedIdl | null, rust: ParsedRust | null): Finding[] {
  const findings: Finding[] = [];

  if (rust) {
    for (const fn of rust.functions) {
      const content = fn.body.toLowerCase();

      // Check for proposal creation without validation
      if (content.includes('proposal') || content.includes('governance')) {
        // Check for unrestricted proposal targets
        if (content.includes('create_proposal') || content.includes('submit_proposal')) {
          if (!content.includes('whitelist') && !content.includes('allowed_') && 
              !content.includes('valid_target')) {
            findings.push({
              id: 'SOL246',
              severity: 'critical',
              title: 'Unrestricted Proposal Targets',
              description: 'Governance allows arbitrary proposal targets. Audius was exploited via malicious proposal.',
              location: `Function: ${fn.name}`,
              recommendation: 'Whitelist allowed proposal targets. Validate all proposal instructions before execution.',
            });
          }
        }

        // Check for timelock
        if (content.includes('execute') || content.includes('process_proposal')) {
          if (!content.includes('timelock') && !content.includes('delay') && !content.includes('voting_period')) {
            findings.push({
              id: 'SOL246',
              severity: 'high',
              title: 'Governance Without Timelock',
              description: 'Proposal execution without mandatory timelock. Malicious proposals could execute immediately.',
              location: `Function: ${fn.name}`,
              recommendation: 'Enforce minimum timelock (24-48h) between proposal passing and execution.',
            });
          }
        }

        // Check for quorum requirements
        if (!content.includes('quorum') && !content.includes('min_votes') && 
            !content.includes('threshold')) {
          findings.push({
            id: 'SOL246',
            severity: 'high',
            title: 'Governance Without Quorum',
            description: 'No quorum requirement detected. Proposals could pass with minimal participation.',
            location: `Function: ${fn.name}`,
            recommendation: 'Require minimum quorum (e.g., 10% of total voting power) for proposal validity.',
          });
        }

        // Check for vote delegation issues
        if (content.includes('delegate') || content.includes('delegation')) {
          if (!content.includes('undelegate') || !content.includes('revoke')) {
            findings.push({
              id: 'SOL246',
              severity: 'medium',
              title: 'Vote Delegation Without Revocation',
              description: 'Delegation exists but revocation mechanism unclear. Users should be able to undelegate.',
              location: `Function: ${fn.name}`,
              recommendation: 'Implement clear delegation revocation. Allow instant undelegation.',
            });
          }
        }
      }

      // Check for flash loan governance attack
      if (content.includes('vote') || content.includes('voting_power')) {
        if (!content.includes('snapshot') && !content.includes('checkpoint') && 
            !content.includes('block_number')) {
          findings.push({
            id: 'SOL246',
            severity: 'critical',
            title: 'Voting Power Without Snapshot',
            description: 'Voting power calculated without historical snapshot. Flash loans can manipulate votes.',
            location: `Function: ${fn.name}`,
            recommendation: 'Snapshot voting power at proposal creation. Use historical balance for vote weight.',
          });
        }
      }

      // Check for proposal instruction validation
      if (content.includes('instruction') && content.includes('proposal')) {
        if (!content.includes('validate') && !content.includes('verify') && 
            !content.includes('check_instruction')) {
          findings.push({
            id: 'SOL246',
            severity: 'high',
            title: 'Unvalidated Proposal Instructions',
            description: 'Proposal instructions not validated before execution. Malicious CPIs could drain treasury.',
            location: `Function: ${fn.name}`,
            recommendation: 'Validate all proposal instructions. Whitelist allowed programs and instruction types.',
          });
        }
      }

      // Check for guardian/veto power
      if (content.includes('governance') && !content.includes('guardian') && 
          !content.includes('veto') && !content.includes('emergency_council')) {
        findings.push({
          id: 'SOL246',
          severity: 'medium',
          title: 'Governance Without Emergency Override',
          description: 'No emergency override mechanism. Malicious proposals have no defense once passed.',
          location: `Function: ${fn.name}`,
          recommendation: 'Implement guardian/council with veto power for emergency situations.',
        });
      }

      // Check for reentrancy in governance
      if (content.includes('execute_proposal') || content.includes('process_governance')) {
        if (!content.includes('reentrancy') && !content.includes('locked') && 
            !content.includes('executing')) {
          findings.push({
            id: 'SOL246',
            severity: 'high',
            title: 'Governance Execution Without Reentrancy Guard',
            description: 'Proposal execution may be reentrant. Malicious proposals could exploit reentrancy.',
            location: `Function: ${fn.name}`,
            recommendation: 'Add reentrancy guard. Mark proposal as executing before any CPIs.',
          });
        }
      }

      // Check for treasury access via governance
      if (content.includes('treasury') && content.includes('governance')) {
        if (!content.includes('max_') && !content.includes('limit') && !content.includes('cap')) {
          findings.push({
            id: 'SOL246',
            severity: 'high',
            title: 'Unlimited Treasury Access Via Governance',
            description: 'Governance can access unlimited treasury funds. Single malicious proposal could drain all.',
            location: `Function: ${fn.name}`,
            recommendation: 'Limit per-proposal treasury access. Require multiple proposals for large amounts.',
          });
        }
      }

      // Check for voting period duration
      if (content.includes('voting_period') || content.includes('vote_duration')) {
        // Check if it's configurable without governance
        if (content.includes('set_voting_period') && !content.includes('governance_only')) {
          findings.push({
            id: 'SOL246',
            severity: 'medium',
            title: 'Voting Period Modifiable',
            description: 'Voting period can be changed. Malicious actor could shorten period to rush proposals.',
            location: `Function: ${fn.name}`,
            recommendation: 'Make voting period immutable or changeable only through governance with long timelock.',
          });
        }
      }
    }
  }

  if (idl) {
    // Check for governance instructions
    for (const instruction of idl.instructions) {
      const name = instruction.name.toLowerCase();
      
      if (name.includes('propose') || name.includes('vote') || name.includes('execute')) {
        // Check for required accounts that indicate safeguards
        const hasTimelock = instruction.accounts.some(acc => 
          acc.name.toLowerCase().includes('timelock')
        );
        
        const hasGuardian = instruction.accounts.some(acc => 
          acc.name.toLowerCase().includes('guardian') ||
          acc.name.toLowerCase().includes('veto')
        );

        if (name.includes('execute') && !hasTimelock) {
          findings.push({
            id: 'SOL246',
            severity: 'high',
            title: 'Execute Without Timelock Account',
            description: `${instruction.name} lacks timelock validation. May allow immediate execution.`,
            location: `Instruction: ${instruction.name}`,
            recommendation: 'Add timelock account requirement. Validate time has passed since proposal passed.',
          });
        }
      }
    }
  }

  return findings;
}
