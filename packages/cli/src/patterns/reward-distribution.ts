import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

export function checkRewardDistribution(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const content = input.rust?.content || '';
  const fileName = input.rust?.filePath || 'unknown';

  // Check for reward calculation without precision handling
  const rewardPatterns = [
    /fn\s+(?:calculate_)?reward/gi,
    /fn\s+distribute/gi,
    /fn\s+claim_reward/gi,
    /reward_per_token/gi,
    /pending_reward/gi,
  ];

  for (const pattern of rewardPatterns) {
    const matches = [...content.matchAll(pattern)];
    for (const match of matches) {
      const contextEnd = Math.min(content.length, match.index! + 1500);
      const functionContext = content.substring(match.index!, contextEnd);
      
      // Check for division before multiplication (precision loss)
      if (functionContext.match(/\s*\/\s*[\w.]+\s*\*\s*/)) {
        const lineNumber = content.substring(0, match.index).split('\n').length;
        findings.push({
          id: 'SOL156',
          title: 'Precision Loss in Reward Calculation',
          severity: 'high',
          description: 'Division performed before multiplication in reward calculation. This causes precision loss and can result in users receiving fewer rewards than entitled.',
          location: { file: fileName, line: lineNumber },
          recommendation: 'Restructure calculation to multiply before dividing. Use u128 or checked_math for intermediate values.',
        });
      }

      // Check for missing accumulated rewards
      if (!functionContext.includes('accumulated') && !functionContext.includes('accrued') && 
          !functionContext.includes('pending') && functionContext.includes('claim')) {
        const lineNumber = content.substring(0, match.index).split('\n').length;
        findings.push({
          id: 'SOL156',
          title: 'Reward Claim Without Accumulation Tracking',
          severity: 'high',
          description: 'Reward claiming without tracking accumulated/pending rewards. Users may be able to claim rewards multiple times.',
          location: { file: fileName, line: lineNumber },
          recommendation: 'Track accumulated rewards per user and update on each claim. Use reward_debt pattern: user_reward = (shares * acc_reward_per_share) - reward_debt',
        });
      }
    }
  }

  // Check for staking reward without time-weighting
  if (content.includes('stake') && content.includes('reward')) {
    const hasTimeWeight = content.includes('duration') || content.includes('time_elapsed') || 
                          content.includes('last_update') || content.includes('stake_timestamp');
    if (!hasTimeWeight) {
      findings.push({
        id: 'SOL156',
        title: 'Staking Rewards Without Time-Weighting',
        severity: 'high',
        description: 'Staking rewards calculated without time-based weighting. Users can stake just before rewards and unstake immediately after.',
        location: { file: fileName, line: 1 },
        recommendation: 'Implement time-weighted rewards using accumulated reward per share pattern with last_update_time.',
      });
    }
  }

  // Check for flash deposit vulnerability in reward systems
  const depositPattern = /fn\s+(?:deposit|stake)\s*\(/gi;
  const depositMatches = [...content.matchAll(depositPattern)];
  for (const match of depositMatches) {
    const contextEnd = Math.min(content.length, match.index! + 1000);
    const functionContext = content.substring(match.index!, contextEnd);
    
    if (!functionContext.includes('cooldown') && !functionContext.includes('lock_period') && 
        !functionContext.includes('min_stake_duration')) {
      const lineNumber = content.substring(0, match.index).split('\n').length;
      findings.push({
        id: 'SOL156',
        title: 'Flash Deposit Vulnerability in Rewards',
        severity: 'high',
        description: 'Deposit/stake function without cooldown or lock period. Attackers can use flash loans to deposit, claim rewards, and withdraw in same transaction.',
        location: { file: fileName, line: lineNumber },
        recommendation: 'Implement minimum staking duration or cooldown period before rewards can be claimed.',
      });
    }
  }

  // Check for reward emission rate manipulation
  if (content.includes('emission_rate') || content.includes('reward_rate')) {
    if (!content.includes('only_admin') && !content.includes('has_one = authority') && 
        !content.includes('constraint = ') && !content.includes('require_keys_eq!')) {
      findings.push({
        id: 'SOL156',
        title: 'Unprotected Reward Rate Modification',
        severity: 'critical',
        description: 'Reward emission rate can potentially be modified without proper access control.',
        location: { file: fileName, line: 1 },
        recommendation: 'Restrict reward rate changes to authorized admin with proper access control.',
      });
    }
  }

  // Check for total supply tracking in reward distribution
  if (content.includes('reward') && content.includes('distribute')) {
    if (!content.includes('total_staked') && !content.includes('total_supply') && 
        !content.includes('total_shares')) {
      findings.push({
        id: 'SOL156',
        title: 'Missing Total Supply Tracking for Rewards',
        severity: 'medium',
        description: 'Reward distribution without tracking total staked/supply. This can lead to incorrect reward calculations.',
        location: { file: fileName, line: 1 },
        recommendation: 'Track total staked amount and use it to calculate proportional rewards.',
      });
    }
  }

  return findings;
}
