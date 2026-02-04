import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL141: Bot/Automation Compromise
 * Detects vulnerabilities in trading bots and automation systems
 * Real-world: Banana Gun ($1.9M), various MEV bot exploits
 */
export function checkBotCompromise(input: PatternInput): Finding[] {
  const findings: Finding[] = [];

  if (input.rust?.content) {
    const content = input.rust.content;
    const lines = content.split('\n');

    // Check for bot/automation patterns
    const botPatterns = [
      /bot|automation|auto_/i,
      /crank|keeper|executor/i,
      /arbitrage|mev|sandwich/i,
      /snipe|front_run/i,
    ];

    const hasBot = botPatterns.some(p => p.test(content));

    if (hasBot) {
      // Check for operator key rotation
      if (content.includes('operator') && !content.includes('rotate') && !content.includes('update_operator')) {
        findings.push({
          id: 'SOL141',
          title: 'No Operator Key Rotation',
          severity: 'high',
          description: 'Bot operator keys should support rotation in case of compromise.',
          location: { file: input.path, line: 1 },
          suggestion: 'Implement key rotation: pub fn rotate_operator(ctx: Context<RotateOperator>, new_operator: Pubkey)',
          cwe: 'CWE-324',
        });
      }

      // Check for fund limits
      if (!content.includes('max_amount') && !content.includes('limit')) {
        findings.push({
          id: 'SOL141',
          title: 'No Transaction Limits',
          severity: 'high',
          description: 'Automated systems should have per-transaction and daily limits.',
          location: { file: input.path, line: 1 },
          suggestion: 'Add limits: require!(amount <= config.max_per_tx && daily_total <= config.daily_limit, LimitExceeded)',
          cwe: 'CWE-770',
        });
      }

      // Check for session/nonce management
      if (!content.includes('nonce') && !content.includes('session')) {
        findings.push({
          id: 'SOL141',
          title: 'No Replay Protection',
          severity: 'critical',
          description: 'Bot transactions need nonce or session tracking to prevent replay attacks.',
          location: { file: input.path, line: 1 },
          suggestion: 'Add nonce: require!(tx_nonce == expected_nonce, InvalidNonce); expected_nonce += 1;',
          cwe: 'CWE-294',
        });
      }

      // Check for whitelist/allowlist
      if (!content.includes('whitelist') && !content.includes('allowlist') && !content.includes('approved_')) {
        findings.push({
          id: 'SOL141',
          title: 'No Target Whitelist',
          severity: 'medium',
          description: 'Bots should only interact with whitelisted protocols/tokens to limit attack surface.',
          location: { file: input.path, line: 1 },
          suggestion: 'Implement allowlist: require!(config.approved_protocols.contains(&target_program), UnapprovedProtocol)',
          cwe: 'CWE-284',
        });
      }

      // Check for emergency stop
      if (!content.includes('pause') && !content.includes('emergency_stop') && !content.includes('halt')) {
        findings.push({
          id: 'SOL141',
          title: 'No Emergency Stop',
          severity: 'high',
          description: 'Automated systems need emergency stop functionality.',
          location: { file: input.path, line: 1 },
          suggestion: 'Add emergency stop: require!(!config.paused, SystemPaused)',
          cwe: 'CWE-754',
        });
      }
    }
  }

  return findings;
}
