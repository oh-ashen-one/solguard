import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL138: Insider Threat Patterns (Pump.fun Employee Exploit - $1.9M)
 * 
 * Detects patterns that could enable insider/employee attacks,
 * including overprivileged roles and lack of separation of duties.
 */
export function checkInsiderThreat(input: PatternInput): Finding[] {
  const findings: Finding[] = [];

  if (!input.rust || !input.rust.files) return findings;

  for (const file of input.rust.files) {
    const lines = file.lines;
    const content = file.content;

    lines.forEach((line, index) => {
      const lineNum = index + 1;
      const lineLower = line.toLowerCase();

      // Pattern 1: Single admin with full powers
      if (lineLower.includes('pub admin:') || lineLower.includes('pub authority:')) {
        // Check if this single authority has too many powers
        const criticalOps = ['withdraw', 'transfer', 'mint', 'burn', 'upgrade', 'pause', 'set_fee'];
        const foundOps = criticalOps.filter(op => content.toLowerCase().includes(op));
        
        if (foundOps.length >= 3) {
          findings.push({
            id: `SOL138-${findings.length + 1}`,
            pattern: 'Insider Threat Vector',
            severity: 'high',
            title: 'Single authority with multiple critical powers',
            description: `Single admin can: ${foundOps.join(', ')}. A compromised or malicious insider could abuse these powers (Pump.fun exploit).`,
            location: { file: file.path, line: lineNum },
            suggestion: 'Implement role separation: separate withdrawal, upgrade, and operational authorities.',
          });
        }
      }

      // Pattern 2: Emergency/backdoor functions
      if (lineLower.includes('emergency') || lineLower.includes('backdoor') ||
          lineLower.includes('rescue') || lineLower.includes('recover_funds')) {
        findings.push({
          id: `SOL138-${findings.length + 1}`,
          pattern: 'Insider Threat Vector',
          severity: 'high',
          title: 'Emergency/recovery function detected',
          description: 'Emergency functions can be legitimate but also enable insider theft. Ensure proper safeguards.',
          location: { file: file.path, line: lineNum },
          suggestion: 'Emergency functions should require multisig and have timelocks.',
        });
      }

      // Pattern 3: Direct fund withdrawal by admin
      if ((lineLower.includes('admin') || lineLower.includes('authority')) &&
          (lineLower.includes('withdraw') || lineLower.includes('transfer'))) {
        const fnEnd = Math.min(lines.length, index + 20);
        const fnBody = lines.slice(index, fnEnd).join('\n').toLowerCase();
        
        if (!fnBody.includes('multisig') && !fnBody.includes('timelock') && 
            !fnBody.includes('governance') && !fnBody.includes('threshold')) {
          findings.push({
            id: `SOL138-${findings.length + 1}`,
            pattern: 'Insider Threat Vector',
            severity: 'critical',
            title: 'Admin can withdraw without multisig',
            description: 'Single admin can withdraw funds without additional approval. Insider could drain protocol.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Require multisig (2-of-3 or 3-of-5) for any fund movements.',
          });
        }
      }

      // Pattern 4: No event emission for admin actions
      if (lineLower.includes('admin') && (lineLower.includes('update') || lineLower.includes('set'))) {
        const fnEnd = Math.min(lines.length, index + 30);
        const fnBody = lines.slice(index, fnEnd).join('\n').toLowerCase();
        
        if (!fnBody.includes('emit!') && !fnBody.includes('event') && !fnBody.includes('msg!')) {
          findings.push({
            id: `SOL138-${findings.length + 1}`,
            pattern: 'Insider Threat Vector',
            severity: 'medium',
            title: 'Admin action without event emission',
            description: 'Admin operations should emit events for transparency and monitoring.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Emit events for all admin actions: emit!(AdminActionEvent { ... })',
          });
        }
      }

      // Pattern 5: Authority transfer without timelock
      if (lineLower.includes('transfer_authority') || lineLower.includes('set_admin') ||
          lineLower.includes('new_authority')) {
        const fnEnd = Math.min(lines.length, index + 15);
        const fnBody = lines.slice(index, fnEnd).join('\n').toLowerCase();
        
        if (!fnBody.includes('pending') && !fnBody.includes('accept') && !fnBody.includes('2step')) {
          findings.push({
            id: `SOL138-${findings.length + 1}`,
            pattern: 'Insider Threat Vector',
            severity: 'high',
            title: 'Immediate authority transfer',
            description: 'Authority can be transferred instantly. Malicious admin could transfer to attacker.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Use 2-step transfer: set_pending_admin -> accept_admin with timelock.',
          });
        }
      }
    });
  }

  return findings;
}
