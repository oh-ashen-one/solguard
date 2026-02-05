/**
 * Batch 31: Access Control & Authorization Patterns
 * Based on Sec3 2025 Report - Access Control (19% of severe findings)
 * Added: Feb 5, 2026 6:00 AM CST
 */

import type { PatternInput } from './index.js';
import type { Finding } from '../commands/audit.js';

// SOL837: Missing Operator Role Validation
export function checkOperatorRoleValidation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';
  
  if (content.includes('operator') || content.includes('keeper')) {
    if (!content.includes('is_operator') && !content.includes('has_role') &&
        !content.includes('operator_authority')) {
      findings.push({
        id: 'SOL837',
        severity: 'high',
        title: 'Missing Operator Role Validation',
        description: 'Operator/keeper operations should validate the caller has operator role',
        location: input.path,
        recommendation: 'Implement operator role validation before privileged operations',
      });
    }
  }
  return findings;
}

// SOL838: Missing Governance Timelock
export function checkGovernanceTimelock(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';
  
  if (content.includes('governance') || content.includes('admin_action')) {
    if (!content.includes('timelock') && !content.includes('delay') &&
        !content.includes('execute_after')) {
      findings.push({
        id: 'SOL838',
        severity: 'high',
        title: 'Missing Governance Timelock',
        description: 'Governance actions should have timelock delays to allow users to react',
        location: input.path,
        recommendation: 'Implement timelock for critical governance actions',
      });
    }
  }
  return findings;
}

// SOL839: Missing Two-Step Ownership Transfer
export function checkTwoStepOwnershipTransfer(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';
  
  if (content.includes('transfer_ownership') || content.includes('set_authority')) {
    if (!content.includes('pending_owner') && !content.includes('accept_ownership') &&
        !content.includes('two_step')) {
      findings.push({
        id: 'SOL839',
        severity: 'medium',
        title: 'Missing Two-Step Ownership Transfer',
        description: 'Ownership transfers should use two-step process to prevent accidental loss of control',
        location: input.path,
        recommendation: 'Implement two-step ownership transfer with pending owner acceptance',
      });
    }
  }
  return findings;
}

// SOL840: Missing Guardian/Emergency Admin
export function checkEmergencyAdmin(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';
  
  if (content.includes('pause') || content.includes('emergency')) {
    if (!content.includes('guardian') && !content.includes('emergency_admin') &&
        !content.includes('multisig')) {
      findings.push({
        id: 'SOL840',
        severity: 'medium',
        title: 'Missing Guardian/Emergency Admin Role',
        description: 'Emergency functions should be controlled by a separate guardian role with multisig',
        location: input.path,
        recommendation: 'Implement guardian role with multisig for emergency functions',
      });
    }
  }
  return findings;
}

// SOL841: Missing Function Access Modifier
export function checkFunctionAccessModifier(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';
  
  // Check for public functions without access control
  if (content.includes('pub fn') && content.includes('process_')) {
    if (!content.includes('require!') && !content.includes('constraint') &&
        !content.includes('authority') && !content.includes('signer')) {
      findings.push({
        id: 'SOL841',
        severity: 'high',
        title: 'Missing Function Access Control',
        description: 'Public instruction handlers should have explicit access control checks',
        location: input.path,
        recommendation: 'Add access control modifiers to public instruction handlers',
      });
    }
  }
  return findings;
}

// SOL842: Missing Upgrade Authority Renunciation Option
export function checkUpgradeAuthorityRenunciation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';
  
  if (content.includes('upgrade_authority') || content.includes('program_data')) {
    if (!content.includes('set_upgrade_authority') && !content.includes('renounce') &&
        !content.includes('None')) {
      findings.push({
        id: 'SOL842',
        severity: 'medium',
        title: 'Missing Upgrade Authority Management',
        description: 'Programs should provide mechanism to renounce upgrade authority for immutability',
        location: input.path,
        recommendation: 'Implement upgrade authority management including renunciation option',
      });
    }
  }
  return findings;
}

// SOL843: Missing Rate Limiting
export function checkMissingRateLimiting(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';
  
  if (content.includes('mint') || content.includes('withdraw') || 
      content.includes('claim')) {
    if (!content.includes('rate_limit') && !content.includes('cooldown') &&
        !content.includes('max_per_epoch') && !content.includes('daily_limit')) {
      findings.push({
        id: 'SOL843',
        severity: 'medium',
        title: 'Missing Rate Limiting',
        description: 'Sensitive operations should have rate limiting to prevent abuse',
        location: input.path,
        recommendation: 'Implement rate limiting for minting, withdrawals, and claims',
      });
    }
  }
  return findings;
}

// SOL844: Missing CPI Caller Validation
export function checkCpiCallerValidation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';
  
  if (content.includes('cpi::') || content.includes('CpiContext')) {
    if (!content.includes('caller_program') && !content.includes('invoke_signed') &&
        !content.includes('program_id')) {
      findings.push({
        id: 'SOL844',
        severity: 'high',
        title: 'Missing CPI Caller Validation',
        description: 'CPI handlers should validate the calling program to prevent unauthorized invocations',
        location: input.path,
        recommendation: 'Validate calling program ID for CPI-exposed functions',
      });
    }
  }
  return findings;
}

// SOL845: Missing PDA Authority Derivation Validation
export function checkPdaAuthorityDerivation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';
  
  if (content.includes('authority') && content.includes('seeds')) {
    if (!content.includes('find_program_address') && !content.includes('create_program_address') &&
        content.includes('authority.key')) {
      findings.push({
        id: 'SOL845',
        severity: 'critical',
        title: 'Missing PDA Authority Derivation Validation',
        description: 'Authority PDAs should be derived and validated rather than accepted as input',
        location: input.path,
        recommendation: 'Derive authority PDA using find_program_address and validate',
      });
    }
  }
  return findings;
}

// SOL846: Missing Whitelist/Allowlist Check
export function checkWhitelistCheck(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';
  
  if (content.includes('token_mint') && (content.includes('deposit') || 
      content.includes('collateral'))) {
    if (!content.includes('whitelist') && !content.includes('allowlist') &&
        !content.includes('supported_mints') && !content.includes('approved_tokens')) {
      findings.push({
        id: 'SOL846',
        severity: 'high',
        title: 'Missing Token Whitelist Check',
        description: 'Accepted token mints should be validated against a whitelist',
        location: input.path,
        recommendation: 'Implement token whitelist validation for deposits and collateral',
      });
    }
  }
  return findings;
}

// SOL847: Missing Delegate Authority Revocation
export function checkDelegateRevocation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';
  
  if (content.includes('delegate') && content.includes('approve')) {
    if (!content.includes('revoke') && !content.includes('remove_delegate')) {
      findings.push({
        id: 'SOL847',
        severity: 'medium',
        title: 'Missing Delegate Revocation Mechanism',
        description: 'Delegate authority should be revocable to prevent unauthorized token access',
        location: input.path,
        recommendation: 'Implement delegate revocation function',
      });
    }
  }
  return findings;
}

// SOL848: Missing Config Update Authorization
export function checkConfigUpdateAuth(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';
  
  if (content.includes('update_config') || content.includes('set_parameter')) {
    if (!content.includes('admin') && !content.includes('authority') &&
        !content.includes('governance')) {
      findings.push({
        id: 'SOL848',
        severity: 'critical',
        title: 'Missing Config Update Authorization',
        description: 'Configuration updates must be restricted to authorized administrators',
        location: input.path,
        recommendation: 'Add admin/authority check for configuration updates',
      });
    }
  }
  return findings;
}

// SOL849: Missing Proposal Threshold Check
export function checkProposalThreshold(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';
  
  if (content.includes('create_proposal') || content.includes('submit_proposal')) {
    if (!content.includes('threshold') && !content.includes('min_tokens') &&
        !content.includes('proposal_token_requirement')) {
      findings.push({
        id: 'SOL849',
        severity: 'medium',
        title: 'Missing Proposal Threshold Check',
        description: 'Governance proposals should require minimum token threshold to prevent spam',
        location: input.path,
        recommendation: 'Implement minimum token threshold for proposal creation',
      });
    }
  }
  return findings;
}

// SOL850: Missing Execution Delay After Approval
export function checkExecutionDelay(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';
  
  if (content.includes('execute_proposal') || content.includes('execute_action')) {
    if (!content.includes('delay') && !content.includes('eta') &&
        !content.includes('execute_after')) {
      findings.push({
        id: 'SOL850',
        severity: 'medium',
        title: 'Missing Execution Delay',
        description: 'Approved proposals should have execution delay for user protection',
        location: input.path,
        recommendation: 'Implement execution delay period after proposal approval',
      });
    }
  }
  return findings;
}

// SOL851: Missing Quorum Validation
export function checkQuorumValidation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';
  
  if (content.includes('vote') && content.includes('proposal')) {
    if (!content.includes('quorum') && !content.includes('min_votes') &&
        !content.includes('participation_threshold')) {
      findings.push({
        id: 'SOL851',
        severity: 'high',
        title: 'Missing Quorum Validation',
        description: 'Governance votes should require minimum quorum for validity',
        location: input.path,
        recommendation: 'Implement quorum requirement for proposal approval',
      });
    }
  }
  return findings;
}

// SOL852: Missing Vote Weight Snapshot
export function checkVoteWeightSnapshot(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';
  
  if (content.includes('voting_power') && content.includes('cast_vote')) {
    if (!content.includes('snapshot') && !content.includes('checkpoint') &&
        !content.includes('at_block') && !content.includes('at_slot')) {
      findings.push({
        id: 'SOL852',
        severity: 'high',
        title: 'Missing Vote Weight Snapshot',
        description: 'Voting power should be snapshotted at proposal creation to prevent flash loan attacks',
        location: input.path,
        recommendation: 'Implement vote weight snapshots at proposal creation time',
      });
    }
  }
  return findings;
}

// Export all batch 31 patterns
export const batchedPatterns31 = {
  checkOperatorRoleValidation,
  checkGovernanceTimelock,
  checkTwoStepOwnershipTransfer,
  checkEmergencyAdmin,
  checkFunctionAccessModifier,
  checkUpgradeAuthorityRenunciation,
  checkMissingRateLimiting,
  checkCpiCallerValidation,
  checkPdaAuthorityDerivation,
  checkWhitelistCheck,
  checkDelegateRevocation,
  checkConfigUpdateAuth,
  checkProposalThreshold,
  checkExecutionDelay,
  checkQuorumValidation,
  checkVoteWeightSnapshot,
};
