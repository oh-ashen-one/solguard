import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL021: Sysvar Manipulation Risk
 * Improper use of sysvars (Clock, Rent, etc.) can lead to exploits.
 */
export function checkSysvarManipulation(input: PatternInput): Finding[] {
  const findings: Finding[] = [];

  if (!input.rust || !input.rust.files) return findings;

  for (const file of input.rust.files) {
    const lines = file.lines;
    const content = file.content;

    lines.forEach((line, index) => {
      const lineNum = index + 1;

      // Pattern 1: Using Clock::get() for randomness
      if (line.includes('Clock') && (content.includes('random') || content.includes('seed'))) {
        const contextStart = Math.max(0, index - 5);
        const contextEnd = Math.min(lines.length, index + 5);
        const context = lines.slice(contextStart, contextEnd).join('\n').toLowerCase();
        
        if (context.includes('random') || context.includes('seed') || context.includes('lottery')) {
          findings.push({
            id: `SOL021-${findings.length + 1}`,
            pattern: 'Sysvar Manipulation Risk',
            severity: 'critical',
            title: 'Clock used for randomness',
            description: 'Using Clock sysvar for randomness is predictable. Validators can manipulate timestamps within bounds.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Use a VRF (Verifiable Random Function) like Switchboard VRF for secure randomness.',
          });
        }
      }

      // Pattern 2: Not validating sysvar account
      if ((line.includes('Sysvar') || line.includes('sysvar::')) && 
          !line.includes('from_account_info') && !line.includes('::get()')) {
        if (line.includes('AccountInfo') && !line.includes('check_id')) {
          findings.push({
            id: `SOL021-${findings.length + 1}`,
            pattern: 'Sysvar Manipulation Risk',
            severity: 'high',
            title: 'Sysvar account not validated',
            description: 'Sysvar passed as AccountInfo without validation. Attacker could pass fake sysvar data.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Use Sysvar::from_account_info() with proper validation, or use Sysvar::get() directly.',
          });
        }
      }

      // Pattern 3: Slot-based timing assumptions
      if (line.includes('slot') && (line.includes('==') || line.includes('<') || line.includes('>'))) {
        const contextStart = Math.max(0, index - 3);
        const context = lines.slice(contextStart, index + 1).join('\n').toLowerCase();
        
        if (context.includes('expire') || context.includes('deadline') || context.includes('timeout')) {
          findings.push({
            id: `SOL021-${findings.length + 1}`,
            pattern: 'Sysvar Manipulation Risk',
            severity: 'medium',
            title: 'Slot-based timing may be unreliable',
            description: 'Slot numbers can skip during network issues. Using slots for deadlines may be exploitable.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Consider using Unix timestamps with appropriate tolerance, or multiple confirmations.',
          });
        }
      }
    });
  }

  return findings;
}
