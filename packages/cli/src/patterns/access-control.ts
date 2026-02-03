import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL031: Access Control Vulnerabilities
 * Missing or improper role-based access control.
 */
export function checkAccessControl(input: PatternInput): Finding[] {
  const findings: Finding[] = [];

  if (!input.rust || !input.rust.files) return findings;

  for (const file of input.rust.files) {
    const lines = file.lines;
    const content = file.content;

    // Track admin/privileged functions
    const privilegedKeywords = ['admin', 'owner', 'authority', 'operator', 'manager', 'governance'];
    
    lines.forEach((line, index) => {
      const lineNum = index + 1;

      // Pattern 1: Privileged function without access check
      if (line.includes('pub fn')) {
        const fnNameMatch = line.match(/pub fn\s+(\w+)/);
        if (fnNameMatch) {
          const fnName = fnNameMatch[1].toLowerCase();
          const isPrivileged = privilegedKeywords.some(kw => fnName.includes(kw)) ||
                              fnName.includes('set_') || fnName.includes('update_') ||
                              fnName.includes('pause') || fnName.includes('unpause');

          if (isPrivileged) {
            // Check function body for access control
            const fnEnd = Math.min(lines.length, index + 30);
            const fnBody = lines.slice(index, fnEnd).join('\n');

            const hasAccessCheck = fnBody.includes('has_one') || 
                                   fnBody.includes('constraint') ||
                                   fnBody.includes('require!') && fnBody.includes('authority') ||
                                   fnBody.includes('admin') && fnBody.includes('==');

            if (!hasAccessCheck) {
              findings.push({
                id: `SOL031-${findings.length + 1}`,
                pattern: 'Access Control Vulnerability',
                severity: 'critical',
                title: `Privileged function '${fnNameMatch[1]}' may lack access control`,
                description: 'Admin/privileged function without visible access control checks.',
                location: { file: file.path, line: lineNum },
                suggestion: 'Add access control: has_one = admin, or require!(ctx.accounts.authority.key() == admin)',
              });
            }
          }
        }
      }

      // Pattern 2: Role stored but never checked
      if (line.includes('pub admin:') || line.includes('pub authority:') || line.includes('pub owner:')) {
        const roleField = line.match(/pub (\w+):/)?.[1];
        if (roleField && !content.includes(`has_one = ${roleField}`) && 
            !content.includes(`${roleField}.key()`) && !content.includes(`${roleField} ==`)) {
          findings.push({
            id: `SOL031-${findings.length + 1}`,
            pattern: 'Access Control Vulnerability',
            severity: 'high',
            title: `Role field '${roleField}' defined but never verified`,
            description: 'Authority/admin field exists but is never used in access control checks.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Add has_one constraint or explicit key comparison in privileged functions.',
          });
        }
      }

      // Pattern 3: Hardcoded admin (centralization risk)
      if (line.includes('Pubkey::') && (line.includes('admin') || line.includes('authority'))) {
        if (line.match(/Pubkey::new_from_array|Pubkey::from_str/)) {
          findings.push({
            id: `SOL031-${findings.length + 1}`,
            pattern: 'Access Control Vulnerability',
            severity: 'medium',
            title: 'Hardcoded admin pubkey',
            description: 'Admin/authority is hardcoded. Cannot be changed if key is compromised.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Store admin in a config account that can be updated via governance/multisig.',
          });
        }
      }
    });
  }

  return findings;
}
