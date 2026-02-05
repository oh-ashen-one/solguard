import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL311: Stake Pool Security
 * Comprehensive detection of staking pool vulnerabilities
 * Real-world: Solana Stake Pool audits (Kudelski, Neodyme, Quantstamp)
 */
export function checkStakePoolSecurity(input: PatternInput): Finding[] {
  const findings: Finding[] = [];

  if (input.rust?.content) {
    const content = input.rust.content;
    const lines = content.split('\n');

    // Detect stake pool patterns
    const isStakePool = /stake_pool|staking|validator_list|delegation/i.test(content);

    if (isStakePool) {
      // Check for stake account ownership
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];

        if (line.includes('stake_account') || line.includes('StakeAccount')) {
          const contextLines = lines.slice(i, Math.min(i + 10, lines.length)).join('\n');
          if (!contextLines.includes('stake_program') && !contextLines.includes('owner ==')) {
            findings.push({
              id: 'SOL311',
              title: 'Unverified Stake Account Ownership',
              severity: 'critical',
              description: 'Stake accounts must be verified as owned by stake program.',
              location: { file: input.path, line: i + 1 },
              suggestion: 'Verify ownership: require!(stake_account.owner == stake_program::ID, InvalidStakeAccount)',
              cwe: 'CWE-863',
            });
            break;
          }
        }
      }

      // Check for validator list manipulation
      if (content.includes('validator') && content.includes('list')) {
        if (!content.includes('max_validators') || !content.includes('capacity')) {
          findings.push({
            id: 'SOL311',
            title: 'Unbounded Validator List',
            severity: 'high',
            description: 'Validator lists must have capacity limits to prevent DoS.',
            location: { file: input.path, line: 1 },
            suggestion: 'Add limits: require!(validator_list.len() < MAX_VALIDATORS, ValidatorListFull)',
            cwe: 'CWE-770',
          });
        }

        // Check for validator vote account validation
        if (!content.includes('vote_account') || !content.includes('vote_program')) {
          findings.push({
            id: 'SOL311',
            title: 'Missing Vote Account Validation',
            severity: 'high',
            description: 'Validators must have valid vote accounts to prevent fake validator injection.',
            location: { file: input.path, line: 1 },
            suggestion: 'Validate vote: require!(vote_account.owner == vote_program::ID)',
            cwe: 'CWE-346',
          });
        }
      }

      // Check for epoch boundary handling
      if (content.includes('epoch')) {
        if (!content.includes('epoch_schedule') && !content.includes('slots_per_epoch')) {
          findings.push({
            id: 'SOL311',
            title: 'Missing Epoch Boundary Handling',
            severity: 'medium',
            description: 'Stake operations near epoch boundaries can have unexpected behavior.',
            location: { file: input.path, line: 1 },
            suggestion: 'Check epoch: let slots_until_epoch_end = epoch_schedule.get_slots_in_epoch(epoch) - slot_index',
            cwe: 'CWE-682',
          });
        }
      }

      // Check for withdrawal authority
      if (content.includes('withdraw') && content.includes('stake')) {
        if (!content.includes('withdraw_authority') && !content.includes('withdrawer')) {
          findings.push({
            id: 'SOL311',
            title: 'Missing Withdraw Authority Check',
            severity: 'critical',
            description: 'Stake withdrawals must verify withdraw authority.',
            location: { file: input.path, line: 1 },
            suggestion: 'Verify authority: require!(stake.meta.authorized.withdrawer == pool_withdraw_authority.key())',
            cwe: 'CWE-863',
          });
        }
      }

      // Check for lockup handling
      if (!content.includes('lockup') && content.includes('withdraw')) {
        findings.push({
          id: 'SOL311',
          title: 'Missing Lockup Check',
          severity: 'high',
          description: 'Stake pool must check lockup restrictions before withdrawal.',
          location: { file: input.path, line: 1 },
          suggestion: 'Check lockup: require!(clock.unix_timestamp >= stake.meta.lockup.unix_timestamp, StakeLocked)',
          cwe: 'CWE-284',
        });
      }

      // Check for pool token exchange rate
      if (content.includes('pool_token') || content.includes('share')) {
        if (!content.includes('total_lamports') || !content.includes('pool_token_supply')) {
          findings.push({
            id: 'SOL311',
            title: 'Incorrect Exchange Rate Calculation',
            severity: 'high',
            description: 'Pool token exchange rate must account for total staked lamports.',
            location: { file: input.path, line: 1 },
            suggestion: 'Calculate rate: pool_tokens = (stake_lamports * pool_token_supply) / total_stake_lamports',
            cwe: 'CWE-682',
          });
        }
      }

      // Check for fee calculation
      if (content.includes('fee') && content.includes('stake')) {
        for (let i = 0; i < lines.length; i++) {
          if (lines[i].includes('fee') && !lines.slice(i, i + 5).join('').includes('checked_')) {
            findings.push({
              id: 'SOL311',
              title: 'Unchecked Fee Calculation',
              severity: 'high',
              description: 'Fee calculations must use checked math to prevent overflow.',
              location: { file: input.path, line: i + 1 },
              suggestion: 'Use checked: fee = stake_lamports.checked_mul(fee_numerator)?.checked_div(fee_denominator)?',
              cwe: 'CWE-190',
            });
            break;
          }
        }
      }

      // Check for minimum stake amount
      if (!content.includes('MINIMUM_') && !content.includes('min_stake') && !content.includes('MIN_')) {
        findings.push({
          id: 'SOL311',
          title: 'No Minimum Stake Amount',
          severity: 'medium',
          description: 'Stake pools should enforce minimum amounts to prevent dust attacks.',
          location: { file: input.path, line: 1 },
          suggestion: 'Add minimum: require!(stake_amount >= MINIMUM_STAKE_AMOUNT, StakeTooSmall)',
          cwe: 'CWE-20',
        });
      }

      // Check for transient stake handling
      if (content.includes('transient') || content.includes('activating') || content.includes('deactivating')) {
        if (!content.includes('cooldown') && !content.includes('deactivation_epoch')) {
          findings.push({
            id: 'SOL311',
            title: 'Missing Transient Stake Handling',
            severity: 'high',
            description: 'Transient (activating/deactivating) stake must be tracked separately.',
            location: { file: input.path, line: 1 },
            suggestion: 'Track transient: pool.transient_stake_lamports += stake.delegation.stake',
            cwe: 'CWE-682',
          });
        }
      }
    }
  }

  return findings;
}
