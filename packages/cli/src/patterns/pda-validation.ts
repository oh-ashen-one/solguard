import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

export function checkPdaValidation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];

  if (!input.rust) return findings;

  for (const file of input.rust.files) {
    // Look for PDA derivation without proper verification
    const lines = file.lines;
    
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      
      // Pattern 1: find_program_address without bump verification
      if (/find_program_address/.test(line) || /Pubkey::find_program_address/.test(line)) {
        // Check if bump is verified in nearby lines
        const context = lines.slice(Math.max(0, i - 5), Math.min(lines.length, i + 10)).join('\n');
        
        if (!/bump\s*==|bump\.eq|assert.*bump|require.*bump/.test(context)) {
          findings.push({
            id: `SOL004-${findings.length + 1}`,
            pattern: 'PDA Validation Gap',
            severity: 'high',
            title: 'PDA derived without bump verification',
            description: `A PDA is derived using find_program_address but the bump may not be verified. An attacker could potentially pass a PDA with a different bump, leading to account confusion.`,
            location: {
              file: file.path,
              line: i + 1,
            },
            code: line.trim(),
            suggestion: `Store and verify the bump:\nlet (pda, bump) = Pubkey::find_program_address(&seeds, &program_id);\nassert!(bump == expected_bump);`,
          });
        }
      }
      
      // Pattern 2: create_program_address without try/error handling
      if (/create_program_address/.test(line) && !/\?|unwrap_or|ok_or/.test(line)) {
        findings.push({
          id: `SOL004-${findings.length + 1}`,
          pattern: 'PDA Validation Gap',
          severity: 'medium',
          title: 'Unhandled PDA creation error',
          description: `create_program_address can fail if the seeds produce an invalid PDA (on-curve point). The error should be handled gracefully.`,
          location: {
            file: file.path,
            line: i + 1,
          },
          code: line.trim(),
          suggestion: `Handle the Result:\nlet pda = Pubkey::create_program_address(&seeds, &program_id)\n    .map_err(|_| ErrorCode::InvalidPda)?;`,
        });
      }
      
      // Pattern 3: Account with seeds but no bump constraint in Anchor
      if (/#\[account\(.*seeds\s*=/.test(line) && !/#\[account\(.*bump/.test(line)) {
        // Look at next few lines too
        const context = lines.slice(i, Math.min(lines.length, i + 3)).join(' ');
        if (!context.includes('bump')) {
          findings.push({
            id: `SOL004-${findings.length + 1}`,
            pattern: 'PDA Validation Gap',
            severity: 'medium',
            title: 'PDA seeds without bump constraint',
            description: `An account has a seeds constraint but no bump constraint. While Anchor will derive the bump, explicitly storing it is more gas-efficient and clearer.`,
            location: {
              file: file.path,
              line: i + 1,
            },
            code: line.trim(),
            suggestion: `Add bump constraint:\n#[account(\n    seeds = [b"prefix", user.key().as_ref()],\n    bump = pda_account.bump,\n)]`,
          });
        }
      }
    }
  }

  return findings;
}
