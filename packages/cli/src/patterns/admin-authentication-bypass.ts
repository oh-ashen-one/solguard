import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL179: Admin Authentication Bypass
 * 
 * Detects insecure admin authentication patterns that allow
 * attackers to bypass admin checks.
 * 
 * Real-world exploit: Solend - Attacker bypassed admin checks by
 * creating own lending market, putting $2M at risk.
 */
export function checkAdminAuthenticationBypass(input: PatternInput): Finding[] {
  const findings: Finding[] = [];
  const { rust, idl, path } = input;

  // Check IDL for admin functions
  if (idl) {
    const adminInstructions = idl.instructions.filter(ix =>
      ix.name.toLowerCase().includes('admin') ||
      ix.name.toLowerCase().includes('update') ||
      ix.name.toLowerCase().includes('config') ||
      ix.name.toLowerCase().includes('set') ||
      ix.name.toLowerCase().includes('initialize')
    );

    for (const ix of adminInstructions) {
      // Check for proper admin account constraints
      const adminAccount = ix.accounts?.find(acc =>
        acc.name.toLowerCase().includes('admin') ||
        acc.name.toLowerCase().includes('authority') ||
        acc.name.toLowerCase().includes('owner')
      );

      if (!adminAccount?.isSigner) {
        findings.push({
          id: 'SOL179',
          severity: 'critical',
          title: 'Admin Function Without Signer Check',
          description: `Admin instruction "${ix.name}" may not properly verify admin signer.`,
          location: { file: path, line: 1 },
          recommendation: 'Ensure admin account is a signer and verify against a trusted, immutable authority.',
        });
      }
    }
  }

  if (!rust) return findings;

  const bypassPatterns = [
    { pattern: /admin.*=.*accounts\[/, desc: 'Admin from arbitrary account index' },
    { pattern: /authority.*==.*ctx\.accounts\.market\.authority/, desc: 'Authority check against passed-in market' },
    { pattern: /update.*config.*without.*owner/i, desc: 'Config update without owner verification' },
    { pattern: /if.*admin\.key.*==.*config\.admin/i, desc: 'Admin check may use attacker-controlled config' },
  ];

  const lines = rust.content.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    for (const { pattern, desc } of bypassPatterns) {
      if (pattern.test(line)) {
        // Check if there's proper hardcoded or PDA-derived admin check
        const context = lines.slice(Math.max(0, i - 10), i + 10).join('\n');
        if (!context.includes('ADMIN_PUBKEY') && 
            !context.includes('program_id') &&
            !context.includes('find_program_address')) {
          findings.push({
            id: 'SOL179',
            severity: 'critical',
            title: 'Admin Authentication Bypass Risk',
            description: `${desc}. Attackers may bypass admin checks by controlling the referenced account.`,
            location: { file: path, line: i + 1 },
            recommendation: 'Verify admin against a hardcoded pubkey or program-derived address, not user-supplied accounts.',
          });
        }
      }
    }
  }

  return findings;
}
