import type { Finding } from '../commands/audit.js';
import type { ParsedIdl } from '../parsers/idl.js';
import type { ParsedRust } from '../parsers/rust.js';

/**
 * SOL248: Synthetify DAO-style Hidden Proposal Attack
 * Detects DAO vulnerabilities where malicious proposals go unnoticed
 * Reference: Synthetify DAO attack (October 2023) - $230K lost via unnoticed attack proposal
 */
export function checkSynthetifyDao(idl: ParsedIdl | null, rust: ParsedRust | null): Finding[] {
  const findings: Finding[] = [];

  if (rust) {
    for (const fn of rust.functions) {
      const content = fn.body.toLowerCase();

      // Check for proposal notification mechanism
      if (content.includes('proposal') || content.includes('governance')) {
        if (!content.includes('event') && !content.includes('emit') && !content.includes('notify')) {
          findings.push({
            id: 'SOL248',
            severity: 'high',
            title: 'DAO Proposal Without Event Emission',
            description: 'Proposals created without emitting events. Malicious proposals can go unnoticed (Synthetify attack).',
            location: `Function: ${fn.name}`,
            recommendation: 'Emit events for all proposal state changes. Set up off-chain monitoring and alerts.',
          });
        }

        // Check for proposal visibility
        if (content.includes('create') && !content.includes('index') && !content.includes('list')) {
          findings.push({
            id: 'SOL248',
            severity: 'medium',
            title: 'Proposals May Be Hard to Discover',
            description: 'No proposal indexing mechanism detected. Proposals may be hidden in obscure accounts.',
            location: `Function: ${fn.name}`,
            recommendation: 'Maintain on-chain proposal index. Build frontend that lists all active proposals.',
          });
        }
      }

      // Check for monitoring and alerting hooks
      if (content.includes('dao') || content.includes('governance')) {
        if (!content.includes('monitor') && !content.includes('webhook') && 
            !content.includes('notification')) {
          findings.push({
            id: 'SOL248',
            severity: 'medium',
            title: 'No Proposal Monitoring Infrastructure',
            description: 'No monitoring hooks for proposal tracking. Set up alerts for new proposals.',
            location: `Function: ${fn.name}`,
            recommendation: 'Integrate with monitoring services (Dialect, Notifi). Alert token holders of new proposals.',
          });
        }
      }

      // Check for proposal deadline handling
      if (content.includes('proposal') && content.includes('deadline')) {
        if (!content.includes('extend') && !content.includes('delay_if')) {
          findings.push({
            id: 'SOL248',
            severity: 'medium',
            title: 'Fixed Proposal Deadline',
            description: 'Proposal deadline cannot be extended. Late-discovered malicious proposals have no defense.',
            location: `Function: ${fn.name}`,
            recommendation: 'Allow deadline extension if significant opposition appears late. Add guardian veto power.',
          });
        }
      }

      // Check for minimum voting period
      if (content.includes('voting') || content.includes('vote_period')) {
        if (!content.includes('min') && !content.includes('minimum')) {
          findings.push({
            id: 'SOL248',
            severity: 'high',
            title: 'No Minimum Voting Period',
            description: 'No minimum voting period enforced. Proposals could pass before community notices.',
            location: `Function: ${fn.name}`,
            recommendation: 'Enforce minimum 3-7 day voting period. Longer for high-value proposals.',
          });
        }
      }

      // Check for proposal title/description requirements
      if (content.includes('create_proposal') || content.includes('submit_proposal')) {
        if (!content.includes('title') && !content.includes('description') && 
            !content.includes('metadata')) {
          findings.push({
            id: 'SOL248',
            severity: 'medium',
            title: 'Proposal Without Required Metadata',
            description: 'Proposals can be created without title/description. Hard for community to evaluate.',
            location: `Function: ${fn.name}`,
            recommendation: 'Require non-empty title and description. Store proposal metadata on-chain or IPFS.',
          });
        }
      }

      // Check for proposal cancellation
      if (content.includes('proposal') && !content.includes('cancel')) {
        findings.push({
          id: 'SOL248',
          severity: 'medium',
          title: 'No Proposal Cancellation Mechanism',
          description: 'Proposals cannot be cancelled. Proposer has no way to retract malicious or erroneous proposals.',
          location: `Function: ${fn.name}`,
          recommendation: 'Allow proposer to cancel before voting ends. Consider guardian cancellation power.',
        });
      }

      // Check for anti-spam measures
      if (content.includes('create_proposal')) {
        if (!content.includes('deposit') && !content.includes('fee') && 
            !content.includes('stake')) {
          findings.push({
            id: 'SOL248',
            severity: 'low',
            title: 'No Proposal Spam Prevention',
            description: 'No deposit/fee for proposal creation. Attackers can spam proposals to cause confusion.',
            location: `Function: ${fn.name}`,
            recommendation: 'Require refundable deposit for proposals. Forfeit deposit for failed/malicious proposals.',
          });
        }
      }

      // Check for proposal simulation
      if (content.includes('execute') && content.includes('proposal')) {
        if (!content.includes('simulate') && !content.includes('preview')) {
          findings.push({
            id: 'SOL248',
            severity: 'medium',
            title: 'No Proposal Execution Preview',
            description: 'Proposal effects not simulatable before execution. Unexpected effects may occur.',
            location: `Function: ${fn.name}`,
            recommendation: 'Provide simulation endpoint to preview proposal effects before voting.',
          });
        }
      }
    }
  }

  if (idl) {
    // Check for DAO instructions
    for (const instruction of idl.instructions) {
      const name = instruction.name.toLowerCase();
      
      if (name.includes('propose') || name.includes('create_proposal')) {
        // Check for metadata requirement
        const hasMetadata = instruction.args.some(arg => 
          arg.name.toLowerCase().includes('title') ||
          arg.name.toLowerCase().includes('description') ||
          arg.name.toLowerCase().includes('metadata') ||
          arg.name.toLowerCase().includes('ipfs')
        );

        if (!hasMetadata) {
          findings.push({
            id: 'SOL248',
            severity: 'medium',
            title: 'Create Proposal Without Metadata Args',
            description: `${instruction.name} lacks metadata arguments. Proposals may be opaque.`,
            location: `Instruction: ${instruction.name}`,
            recommendation: 'Add required title and description arguments for proposal transparency.',
          });
        }

        // Check for deposit account
        const hasDeposit = instruction.accounts.some(acc => 
          acc.name.toLowerCase().includes('deposit') ||
          acc.name.toLowerCase().includes('fee') ||
          acc.name.toLowerCase().includes('stake')
        );

        if (!hasDeposit) {
          findings.push({
            id: 'SOL248',
            severity: 'low',
            title: 'Proposal Creation Without Deposit',
            description: `${instruction.name} requires no deposit. Spam proposals possible.`,
            location: `Instruction: ${instruction.name}`,
            recommendation: 'Add deposit account requirement to prevent proposal spam.',
          });
        }
      }
    }
  }

  return findings;
}
