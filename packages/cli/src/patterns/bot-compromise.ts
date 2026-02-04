import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL141: Bot/Automation Compromise (Banana Gun - $1.4M)
 * 
 * Detects patterns that could make automated trading bots or
 * automation systems vulnerable to compromise.
 */
export function checkBotCompromise(input: PatternInput): Finding[] {
  const findings: Finding[] = [];

  if (!input.rust || !input.rust.files) return findings;

  for (const file of input.rust.files) {
    const lines = file.lines;
    const content = file.content;

    lines.forEach((line, index) => {
      const lineNum = index + 1;
      const lineLower = line.toLowerCase();

      // Pattern 1: Bot/automation account without proper isolation
      if (lineLower.includes('bot') || lineLower.includes('automation') ||
          lineLower.includes('keeper') || lineLower.includes('crank')) {
        if (line.includes('AccountInfo') && !content.includes('has_one')) {
          findings.push({
            id: `SOL141-${findings.length + 1}`,
            pattern: 'Bot Compromise Vector',
            severity: 'high',
            title: 'Automation account without validation',
            description: 'Bot/keeper account passed without validation. Compromised bot could exploit the protocol.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Validate bot authority: has_one = registered_bot or whitelist check.',
          });
        }
      }

      // Pattern 2: Automated execution without safety bounds
      if ((lineLower.includes('execute') || lineLower.includes('run') || lineLower.includes('process')) &&
          (lineLower.includes('order') || lineLower.includes('trade') || lineLower.includes('swap'))) {
        const fnEnd = Math.min(lines.length, index + 20);
        const fnBody = lines.slice(index, fnEnd).join('\n').toLowerCase();
        
        if (!fnBody.includes('deadline') && !fnBody.includes('expires') && !fnBody.includes('valid_until')) {
          findings.push({
            id: `SOL141-${findings.length + 1}`,
            pattern: 'Bot Compromise Vector',
            severity: 'high',
            title: 'Automated execution without deadline',
            description: 'Orders can be executed anytime. Stale orders could be exploited by compromised bots.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Add deadline: require!(clock.unix_timestamp <= order.deadline, OrderExpired)',
          });
        }
      }

      // Pattern 3: No rate limiting on automated actions
      if (lineLower.includes('auto') || lineLower.includes('batch')) {
        const fileContent = content.toLowerCase();
        
        if (!fileContent.includes('rate_limit') && !fileContent.includes('throttle') &&
            !fileContent.includes('max_per_') && !fileContent.includes('cooldown')) {
          findings.push({
            id: `SOL141-${findings.length + 1}`,
            pattern: 'Bot Compromise Vector',
            severity: 'medium',
            title: 'No rate limiting on automated actions',
            description: 'Automated actions have no rate limit. Compromised bot could spam or drain gas.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Add rate limits per bot: require!(bot.last_action + COOLDOWN <= clock.unix_timestamp)',
          });
        }
      }

      // Pattern 4: Reward/tip for automation without bounds
      if ((lineLower.includes('reward') || lineLower.includes('tip') || lineLower.includes('bounty')) &&
          (lineLower.includes('keeper') || lineLower.includes('bot') || lineLower.includes('relayer'))) {
        const fnEnd = Math.min(lines.length, index + 15);
        const fnBody = lines.slice(index, fnEnd).join('\n').toLowerCase();
        
        if (!fnBody.includes('max') && !fnBody.includes('cap') && !fnBody.includes('limit')) {
          findings.push({
            id: `SOL141-${findings.length + 1}`,
            pattern: 'Bot Compromise Vector',
            severity: 'high',
            title: 'Unbounded automation reward',
            description: 'Keeper/bot reward has no upper bound. Could be manipulated to drain funds.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Cap rewards: reward = min(calculated_reward, MAX_KEEPER_REWARD)',
          });
        }
      }

      // Pattern 5: External bot integration without verification
      if (lineLower.includes('external') && (lineLower.includes('call') || lineLower.includes('invoke'))) {
        findings.push({
          id: `SOL141-${findings.length + 1}`,
          pattern: 'Bot Compromise Vector',
          severity: 'medium',
          title: 'External integration point',
          description: 'External call detected. Ensure external services are properly authenticated.',
          location: { file: file.path, line: lineNum },
          suggestion: 'Verify external calls: use signatures or whitelisted addresses only.',
        });
      }
    });
  }

  return findings;
}
