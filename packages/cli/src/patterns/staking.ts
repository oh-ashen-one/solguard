import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL043: Staking Vulnerabilities
 * Issues with staking and reward distribution.
 */
export function checkStaking(input: PatternInput): Finding[] {
  const findings: Finding[] = [];

  if (!input.rust || !input.rust.files) return findings;

  for (const file of input.rust.files) {
    const lines = file.lines;
    const content = file.content;

    if (!content.includes('stake') && !content.includes('reward') && !content.includes('Stake')) {
      continue;
    }

    lines.forEach((line, index) => {
      const lineNum = index + 1;

      // Pattern 1: Reward calculation without time validation
      if (line.includes('reward') && (line.includes('*') || line.includes('calculate'))) {
        const contextStart = Math.max(0, index - 10);
        const context = lines.slice(contextStart, index + 5).join('\n');

        if (!context.includes('timestamp') && !context.includes('slot') && 
            !context.includes('last_update')) {
          findings.push({
            id: `SOL043-${findings.length + 1}`,
            pattern: 'Staking Vulnerability',
            severity: 'high',
            title: 'Reward calculation without time tracking',
            description: 'Rewards calculated without proper time/slot tracking. Could be exploited.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Track last_reward_time and calculate rewards based on elapsed time.',
          });
        }
      }

      // Pattern 2: Unstake without cooldown
      if (line.includes('unstake') || line.includes('withdraw_stake')) {
        const fnEnd = Math.min(lines.length, index + 20);
        const fnBody = lines.slice(index, fnEnd).join('\n');

        if (!fnBody.includes('cooldown') && !fnBody.includes('lock') && 
            !fnBody.includes('unbonding')) {
          findings.push({
            id: `SOL043-${findings.length + 1}`,
            pattern: 'Staking Vulnerability',
            severity: 'medium',
            title: 'Unstake without cooldown period',
            description: 'Immediate unstaking allows flash-stake attacks for rewards.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Add unbonding period: require!(stake.unbonding_end < current_time)',
          });
        }
      }

      // Pattern 3: Global reward rate manipulation
      if (line.includes('reward_rate') || line.includes('emission')) {
        const contextStart = Math.max(0, index - 10);
        const context = lines.slice(contextStart, index + 5).join('\n');

        if (!context.includes('update_') && !context.includes('accrue') &&
            (context.includes('=') || context.includes('set'))) {
          findings.push({
            id: `SOL043-${findings.length + 1}`,
            pattern: 'Staking Vulnerability',
            severity: 'high',
            title: 'Reward rate change without state update',
            description: 'Changing reward rate without updating accumulated rewards first.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Always accrue pending rewards before changing reward rate.',
          });
        }
      }

      // Pattern 4: Stake amount without minimum
      if (line.includes('stake_amount') || line.includes('amount_to_stake')) {
        const contextEnd = Math.min(lines.length, index + 10);
        const context = lines.slice(index, contextEnd).join('\n');

        if (!context.includes('min') && !context.includes('MIN') && 
            !context.includes('>=')) {
          findings.push({
            id: `SOL043-${findings.length + 1}`,
            pattern: 'Staking Vulnerability',
            severity: 'low',
            title: 'No minimum stake amount',
            description: 'Dust stakes could be used for DoS or gaming reward rounding.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Add minimum: require!(amount >= MIN_STAKE_AMOUNT)',
          });
        }
      }
    });
  }

  return findings;
}
