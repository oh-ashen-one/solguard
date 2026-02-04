import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL139: Treasury Drain Attack
 * Detects vulnerabilities that could allow treasury draining
 * Real-world: Multiple DAO and protocol treasury attacks
 */
export function checkTreasuryDrain(input: PatternInput): Finding[] {
  const findings: Finding[] = [];

  if (input.rust?.content) {
    const content = input.rust.content;
    const lines = content.split('\n');

    // Check for treasury-related patterns
    const treasuryPatterns = [
      /treasury|vault|pool|reserve/i,
      /protocol_fee|fee_account/i,
      /dao_funds|community_funds/i,
    ];

    const hasTreasury = treasuryPatterns.some(p => p.test(content));

    if (hasTreasury) {
      // Check for withdrawal without proper authorization
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (line.match(/withdraw|transfer_from.*treasury|drain/i)) {
          if (!content.includes('governance') && !content.includes('multisig')) {
            findings.push({
              id: 'SOL139',
              title: 'Treasury Withdrawal Without Governance',
              severity: 'critical',
              description: 'Treasury withdrawals should require governance approval, not single-key authorization.',
              location: { file: input.path, line: i + 1 },
              suggestion: 'Implement governance: require!(proposal.state == ProposalState::Executed, NotApproved)',
              cwe: 'CWE-284',
            });
            break;
          }
        }
      }

      // Check for balance validation before withdrawal
      if (content.includes('withdraw') && !content.includes('balance') && !content.includes('amount <=')) {
        findings.push({
          id: 'SOL139',
          title: 'Missing Treasury Balance Check',
          severity: 'high',
          description: 'Treasury operations should validate sufficient balance before withdrawal.',
          location: { file: input.path, line: 1 },
          suggestion: 'Validate balance: require!(treasury.amount >= withdrawal_amount, InsufficientFunds)',
          cwe: 'CWE-682',
        });
      }

      // Check for treasury PDA validation
      if (!content.includes('find_program_address') || !content.includes('treasury_bump')) {
        findings.push({
          id: 'SOL139',
          title: 'Unvalidated Treasury PDA',
          severity: 'critical',
          description: 'Treasury accounts should be PDAs with validated derivation to prevent substitution.',
          location: { file: input.path, line: 1 },
          suggestion: 'Use validated PDA: let (treasury_pda, bump) = Pubkey::find_program_address(&[b"treasury"], &program_id); require!(treasury.key() == treasury_pda)',
          cwe: 'CWE-345',
        });
      }

      // Check for event emission on treasury operations
      if (!content.includes('emit!') && !content.includes('event')) {
        findings.push({
          id: 'SOL139',
          title: 'No Treasury Operation Events',
          severity: 'medium',
          description: 'Treasury operations should emit events for transparency and monitoring.',
          location: { file: input.path, line: 1 },
          suggestion: 'Emit events: emit!(TreasuryWithdrawal { amount, recipient, timestamp })',
          cwe: 'CWE-778',
        });
      }
    }
  }

  return findings;
}
