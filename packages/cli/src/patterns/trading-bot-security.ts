import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL198: Trading Bot Security
 * 
 * Detects vulnerabilities in trading bot implementations that
 * could lead to fund theft or manipulation.
 * 
 * Real-world exploit: Banana Gun - $1.4M stolen due to bot vulnerabilities
 */
export function checkTradingBotSecurity(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const { rust, path } = input;

  if (!rust) return findings;

  const vulnerablePatterns = [
    { pattern: /auto_sign/i, severity: 'critical' as const, desc: 'Automatic transaction signing' },
    { pattern: /hot_wallet.*key/i, severity: 'critical' as const, desc: 'Hot wallet key exposure' },
    { pattern: /slippage.*100/i, severity: 'high' as const, desc: 'High slippage tolerance' },
    { pattern: /unlimited.*approval/i, severity: 'high' as const, desc: 'Unlimited token approval' },
    { pattern: /bot.*private.*key/i, severity: 'critical' as const, desc: 'Bot with exposed private key' },
    { pattern: /retry.*indefinite/i, severity: 'medium' as const, desc: 'Indefinite retry logic' },
  ];

  const lines = rust.content.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    for (const { pattern, severity, desc } of vulnerablePatterns) {
      if (pattern.test(line)) {
        findings.push({
          id: 'SOL198',
          severity,
          title: 'Trading Bot Security Issue',
          description: `${desc} - trading bots require extra security hardening.`,
          location: { file: path, line: i + 1 },
          recommendation: 'Use hardware wallets, limit approvals, set tight slippage, and implement circuit breakers.',
        });
      }
    }
  }

  return findings;
}
