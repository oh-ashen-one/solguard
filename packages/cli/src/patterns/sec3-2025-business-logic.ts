import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SEC3 2025 Report: Business Logic Patterns (38.5% of all vulnerabilities)
 * Based on Sec3's analysis of 163 Solana security audits with 1,669 vulnerabilities
 * Business logic flaws are the #1 category for critical/high findings
 */
export function checkSec32025BusinessLogic(input: PatternInput): Finding[] {
  const findings: Finding[] = [];

  if (input.rust?.content) {
    const content = input.rust.content;
    const lines = content.split('\n');

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const context = lines.slice(Math.max(0, i - 5), Math.min(lines.length, i + 10)).join('\n');

      // BL001: State Transition Validation Missing
      if ((line.includes('state =') || line.includes('status =')) && 
          line.includes('::') &&
          !context.includes('require!') && !context.includes('assert!') &&
          !context.includes('match state')) {
        findings.push({
          id: 'SEC3-BL001',
          title: 'State Transition Without Validation',
          severity: 'high',
          description: 'State changes without validating allowed transitions. Attackers can skip intermediate states.',
          location: { file: input.path, line: i + 1 },
          suggestion: 'Add state machine validation: require!(current_state == AllowedPreviousState, InvalidTransition)',
          cwe: 'CWE-840',
        });
      }

      // BL002: Percentage/Basis Points Logic Errors
      if ((line.includes('/ 100') || line.includes('/ 10000') || line.includes('/ 10_000')) &&
          !line.includes('checked_')) {
        if (!context.includes('saturating') && !context.includes('checked_div')) {
          findings.push({
            id: 'SEC3-BL002',
            title: 'Percentage Calculation Without Safe Math',
            severity: 'medium',
            description: 'Percentage/basis point calculations should use checked math to prevent rounding exploits.',
            location: { file: input.path, line: i + 1 },
            suggestion: 'Use checked_mul then checked_div, or dedicated percentage math library.',
            cwe: 'CWE-682',
          });
        }
      }

      // BL003: Missing Order Validation
      if (line.includes('pub fn process_order') || line.includes('fn execute_order') ||
          line.includes('fn fill_order')) {
        if (!context.includes('expired') && !context.includes('expiry') && !context.includes('deadline')) {
          findings.push({
            id: 'SEC3-BL003',
            title: 'Order Processing Without Expiry Check',
            severity: 'high',
            description: 'Order execution without expiry validation allows stale order exploitation.',
            location: { file: input.path, line: i + 1 },
            suggestion: 'Always check: require!(order.expiry > clock.unix_timestamp, OrderExpired)',
            cwe: 'CWE-613',
          });
        }
      }

      // BL004: Withdrawal Logic Bypass
      if ((line.includes('pub fn withdraw') || line.includes('fn withdraw')) &&
          !line.includes('//')) {
        if (!context.includes('cooldown') && !context.includes('lock_') && 
            !context.includes('timelock') && !context.includes('unlock_time')) {
          findings.push({
            id: 'SEC3-BL004',
            title: 'Withdrawal Without Timelock Check',
            severity: 'medium',
            description: 'Withdrawal function without timelock/cooldown validation.',
            location: { file: input.path, line: i + 1 },
            suggestion: 'Consider adding withdrawal cooldowns: require!(clock.unix_timestamp > user.last_deposit + COOLDOWN)',
            cwe: 'CWE-362',
          });
        }
      }

      // BL005: Reward Calculation Drift
      if ((line.includes('reward') || line.includes('yield')) && 
          (line.includes(' * ') || line.includes(' / '))) {
        if (!context.includes('last_update') && !context.includes('accumulated') &&
            !context.includes('per_share')) {
          findings.push({
            id: 'SEC3-BL005',
            title: 'Reward Calculation Without Time Normalization',
            severity: 'high',
            description: 'Reward calculations should track time since last update to prevent manipulation.',
            location: { file: input.path, line: i + 1 },
            suggestion: 'Track rewards_per_share and last_update_timestamp for correct distribution.',
            cwe: 'CWE-682',
          });
        }
      }

      // BL006: Liquidation Logic Incomplete
      if (line.includes('liquidat') && !line.includes('//')) {
        if (!context.includes('health_factor') && !context.includes('collateral_ratio') &&
            !context.includes('ltv') && !context.includes('margin')) {
          findings.push({
            id: 'SEC3-BL006',
            title: 'Liquidation Without Health Factor',
            severity: 'critical',
            description: 'Liquidation logic without clear health factor calculation is exploitable.',
            location: { file: input.path, line: i + 1 },
            suggestion: 'Always compute health_factor = collateral_value * ltv / debt_value',
            cwe: 'CWE-682',
          });
        }
      }

      // BL007: Fee Bypass Possibility
      if (line.includes('fee') && (line.includes(' = 0') || line.includes('= 0u'))) {
        findings.push({
          id: 'SEC3-BL007',
          title: 'Fee Set to Zero Detected',
          severity: 'medium',
          description: 'Hardcoded zero fee may indicate missing fee logic or potential bypass.',
          location: { file: input.path, line: i + 1 },
          suggestion: 'Ensure fees cannot be bypassed. Consider minimum fee requirements.',
          cwe: 'CWE-20',
        });
      }

      // BL008: Vote Weight Manipulation
      if ((line.includes('vote_weight') || line.includes('voting_power')) &&
          !line.includes('//')) {
        if (!context.includes('snapshot') && !context.includes('checkpoint') &&
            !context.includes('lock_time')) {
          findings.push({
            id: 'SEC3-BL008',
            title: 'Vote Weight Without Snapshot',
            severity: 'high',
            description: 'Voting power calculations without snapshots enable flash loan governance attacks.',
            location: { file: input.path, line: i + 1 },
            suggestion: 'Use snapshot-based voting: vote_weight = get_weight_at_snapshot(proposal.snapshot_slot)',
            cwe: 'CWE-362',
          });
        }
      }

      // BL009: Stake/Unstake Timing Attack
      if ((line.includes('pub fn stake') || line.includes('pub fn unstake')) &&
          !line.includes('//')) {
        if (!context.includes('epoch') && !context.includes('warmup') && 
            !context.includes('cooldown')) {
          findings.push({
            id: 'SEC3-BL009',
            title: 'Staking Without Epoch Boundaries',
            severity: 'medium',
            description: 'Stake/unstake without epoch boundaries allows reward gaming.',
            location: { file: input.path, line: i + 1 },
            suggestion: 'Align staking changes with epoch boundaries or add warmup/cooldown periods.',
            cwe: 'CWE-682',
          });
        }
      }

      // BL010: Position Size Limits Missing
      if ((line.includes('open_position') || line.includes('increase_position')) &&
          !line.includes('//')) {
        if (!context.includes('max_position') && !context.includes('position_limit') &&
            !context.includes('max_size')) {
          findings.push({
            id: 'SEC3-BL010',
            title: 'Position Opening Without Size Limits',
            severity: 'high',
            description: 'Trading positions without size limits can destabilize the protocol.',
            location: { file: input.path, line: i + 1 },
            suggestion: 'Enforce position limits: require!(new_size <= max_position_size, PositionTooLarge)',
            cwe: 'CWE-770',
          });
        }
      }
    }
  }

  return findings;
}
