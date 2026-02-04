import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL138: Insider Threat Vector
 * Detects patterns that increase insider threat risk
 * Real-world: Pump.fun ($1.9M insider attack)
 */
export function checkInsiderThreat(input: PatternInput): Finding[] {
  const findings: Finding[] = [];

  if (input.rust?.content) {
    const content = input.rust.content;
    const lines = content.split('\n');

    // Check for single admin/authority patterns
    if (content.match(/admin|authority|owner/i)) {
      // Check for lack of multisig
      if (!content.includes('multisig') && !content.includes('threshold') && !content.includes('signers')) {
        findings.push({
          id: 'SOL138',
          title: 'Single Point of Authority',
          severity: 'high',
          description: 'Single admin accounts are vulnerable to insider threats. Use multisig governance.',
          location: { file: input.path, line: 1 },
          suggestion: 'Implement multisig: require!(approved_signers >= threshold, NotEnoughApprovals)',
          cwe: 'CWE-284',
        });
      }

      // Check for emergency withdrawal functions
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (line.match(/emergency.*withdraw|admin.*withdraw|force.*withdraw/i)) {
          if (!content.includes('timelock') && !content.includes('delay')) {
            findings.push({
              id: 'SOL138',
              title: 'Emergency Withdrawal Without Timelock',
              severity: 'critical',
              description: 'Emergency withdrawal functions should have timelocks to prevent instant rug pulls.',
              location: { file: input.path, line: i + 1 },
              suggestion: 'Add timelock: require!(Clock::get()?.unix_timestamp > emergency_request_time + DELAY, TooEarly)',
              cwe: 'CWE-362',
            });
            break;
          }
        }
      }
    }

    // Check for unrestricted fund movement
    if (content.includes('transfer') || content.includes('withdraw')) {
      if (!content.includes('daily_limit') && !content.includes('withdrawal_limit') && !content.includes('rate_limit')) {
        findings.push({
          id: 'SOL138',
          title: 'No Withdrawal Limits',
          severity: 'high',
          description: 'Large fund movements should have rate limits or caps to limit insider damage.',
          location: { file: input.path, line: 1 },
          suggestion: 'Implement withdrawal limits: require!(amount <= daily_withdrawal_limit, LimitExceeded)',
          cwe: 'CWE-770',
        });
      }
    }

    // Check for upgrade authority patterns
    if (content.includes('upgrade') || content.includes('set_authority')) {
      if (!content.includes('timelock') && !content.includes('governance')) {
        findings.push({
          id: 'SOL138',
          title: 'Unrestricted Upgrade Authority',
          severity: 'critical',
          description: 'Program upgrades should require multisig approval or timelock delays.',
          location: { file: input.path, line: 1 },
          suggestion: 'Use governance for upgrades: implement timelock and multisig for upgrade authority changes.',
          cwe: 'CWE-284',
        });
      }
    }
  }

  return findings;
}
