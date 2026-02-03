import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL058: Pause Mechanism Issues
 * Vulnerabilities in emergency pause functionality.
 */
export function checkPauseMechanism(input: PatternInput): Finding[] {
  const findings: Finding[] = [];

  if (!input.rust || !input.rust.files) return findings;

  for (const file of input.rust.files) {
    const lines = file.lines;
    const content = file.content;

    // Check if protocol has pause functionality
    const hasPause = content.includes('pause') || content.includes('Pause');
    
    if (!hasPause) {
      // No pause mechanism at all - might be intentional
      if (content.includes('transfer') || content.includes('swap') || content.includes('withdraw')) {
        findings.push({
          id: `SOL058-${findings.length + 1}`,
          pattern: 'Pause Mechanism Issue',
          severity: 'info',
          title: 'No pause mechanism found',
          description: 'Protocol has no emergency pause. Consider adding for incident response.',
          location: { file: file.path, line: 1 },
          suggestion: 'Add pausable pattern for emergency situations.',
        });
      }
      return findings;
    }

    lines.forEach((line, index) => {
      const lineNum = index + 1;

      // Pattern 1: Pause without unpause
      if (line.includes('pub fn pause')) {
        if (!content.includes('unpause') && !content.includes('resume')) {
          findings.push({
            id: `SOL058-${findings.length + 1}`,
            pattern: 'Pause Mechanism Issue',
            severity: 'high',
            title: 'Pause without unpause function',
            description: 'Can pause but cannot unpause. Protocol could be locked forever.',
            location: { file: file.path, line: lineNum },
            suggestion: 'Add unpause function with appropriate access control.',
          });
        }
      }

      // Pattern 2: Critical function without pause check
      const criticalFns = ['withdraw', 'transfer', 'swap', 'liquidate', 'borrow'];
      for (const fn of criticalFns) {
        if (line.includes(`pub fn ${fn}`)) {
          const fnEnd = Math.min(lines.length, index + 20);
          const fnBody = lines.slice(index, fnEnd).join('\n');

          if (!fnBody.includes('paused') && !fnBody.includes('not_paused') && 
              !fnBody.includes('require!') && !fnBody.includes('Paused')) {
            findings.push({
              id: `SOL058-${findings.length + 1}`,
              pattern: 'Pause Mechanism Issue',
              severity: 'medium',
              title: `Critical function '${fn}' not checking pause state`,
              description: 'Function executes even when protocol is paused.',
              location: { file: file.path, line: lineNum },
              suggestion: 'Add: require!(!config.paused, ErrorCode::Paused)',
            });
          }
        }
      }
    });
  }

  return findings;
}
