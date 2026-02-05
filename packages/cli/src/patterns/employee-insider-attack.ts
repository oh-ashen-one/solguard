import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL185: Employee/Insider Attack Prevention
 * 
 * Detects code patterns that could allow insider attacks by
 * employees or team members with privileged access.
 * 
 * Real-world exploits: Pump.fun ($1.9M by employee), Cypher ($317K by Hoak)
 */
export function checkEmployeeInsiderAttack(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const { rust, idl, path } = input;

  if (idl) {
    // Check for single-sig admin operations
    const adminOps = idl.instructions.filter(ix =>
      ix.name.toLowerCase().includes('admin') ||
      ix.name.toLowerCase().includes('withdraw') ||
      ix.name.toLowerCase().includes('emergency') ||
      ix.name.toLowerCase().includes('upgrade')
    );

    for (const ix of adminOps) {
      const signerAccounts = ix.accounts?.filter(acc => acc.isSigner) || [];
      
      if (signerAccounts.length < 2) {
        findings.push({
          id: 'SOL185',
          severity: 'high',
          title: 'Single-Signer Admin Operation',
          description: `Instruction "${ix.name}" requires only one signer - vulnerable to insider attacks.`,
          location: { file: path, line: 1 },
          recommendation: 'Implement multi-sig requirements for sensitive operations. Use timelock delays.',
        });
      }
    }
  }

  if (!rust) return findings;

  const vulnerablePatterns = [
    { pattern: /single_admin/, desc: 'Single admin pattern' },
    { pattern: /owner_only/, desc: 'Single owner access' },
    { pattern: /emergency_withdraw.*!.*multisig/i, desc: 'Emergency withdraw without multisig' },
    { pattern: /backdoor/i, desc: 'Potential backdoor' },
    { pattern: /dev_key/i, desc: 'Developer key reference' },
    { pattern: /team_wallet/i, desc: 'Team wallet with special access' },
  ];

  const lines = rust.content.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    for (const { pattern, desc } of vulnerablePatterns) {
      if (pattern.test(line)) {
        findings.push({
          id: 'SOL185',
          severity: 'high',
          title: 'Insider Attack Vector',
          description: `${desc} - single points of control increase insider attack risk.`,
          location: { file: path, line: i + 1 },
          recommendation: 'Implement multi-sig, timelocks, and separation of duties for all privileged operations.',
        });
      }
    }
  }

  // Check for lack of multisig in withdrawal functions
  if (rust.content.includes('withdraw') || rust.content.includes('transfer_from_treasury')) {
    if (!rust.content.includes('multisig') && !rust.content.includes('multi_sig')) {
      findings.push({
        id: 'SOL185',
        severity: 'high',
        title: 'Treasury Operations Without Multi-Sig',
        description: 'Withdrawal or treasury operations found without multi-signature requirements.',
        location: { file: path, line: 1 },
        recommendation: 'Require multiple signatures for any operation that moves funds from protocol treasuries.',
      });
    }
  }

  return findings;
}
