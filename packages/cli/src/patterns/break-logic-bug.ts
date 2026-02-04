import type { Finding } from '../commands/audit.js';
import type { PatternInput } from './index.js';

/**
 * SOL145: Break Statement Logic Bug
 * Detects subtle logic bugs involving break/continue/return in loops
 * Real-world: Jet Protocol borrowing vulnerability
 */
export function checkBreakLogicBug(input: PatternInput): Finding[] {
  const findings: Finding[] = [];

  if (input.rust?.content) {
    const content = input.rust.content;
    const lines = content.split('\n');

    let inLoop = false;
    let loopDepth = 0;
    let loopStartLine = 0;

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];

      // Track loop entry
      if (line.match(/\b(for|while|loop)\b/)) {
        if (!inLoop) {
          inLoop = true;
          loopStartLine = i + 1;
        }
        loopDepth++;
      }

      // Track loop exit
      if (inLoop && line.includes('}')) {
        loopDepth--;
        if (loopDepth === 0) {
          inLoop = false;
        }
      }

      // Check for break without full processing
      if (inLoop && line.includes('break')) {
        // Check if break is after error handling
        const contextLines = lines.slice(Math.max(0, i - 5), i + 1).join('\n');
        
        if (!contextLines.includes('Err') && !contextLines.includes('Error') && !contextLines.includes('error!')) {
          findings.push({
            id: 'SOL145',
            title: 'Suspicious Break Statement',
            severity: 'medium',
            description: 'Break statements in loops may skip important processing. Ensure this is intentional.',
            location: { file: input.path, line: i + 1 },
            suggestion: 'Verify break logic: ensure all necessary items are processed before breaking.',
            cwe: 'CWE-670',
          });
        }
      }

      // Check for early return in iteration
      if (inLoop && line.includes('return') && line.includes('Ok')) {
        findings.push({
          id: 'SOL145',
          title: 'Early Return in Loop',
          severity: 'high',
          description: 'Returning Ok() early in a loop may skip processing remaining items.',
          location: { file: input.path, line: i + 1 },
          suggestion: 'Ensure all items are processed: collect results and return after loop completes.',
          cwe: 'CWE-670',
        });
      }

      // Check for continue without logging
      if (inLoop && line.includes('continue')) {
        if (!lines.slice(Math.max(0, i - 2), i + 1).join('\n').includes('msg!')) {
          findings.push({
            id: 'SOL145',
            title: 'Silent Continue Statement',
            severity: 'low',
            description: 'Continue statements should log why iteration was skipped for debugging.',
            location: { file: input.path, line: i + 1 },
            suggestion: 'Add logging: msg!("Skipping item due to: {}", reason); continue;',
            cwe: 'CWE-778',
          });
        }
      }
    }

    // Check for loop with side effects and early exit
    if (content.match(/for|while/) && content.includes('+=') && content.includes('break')) {
      findings.push({
        id: 'SOL145',
        title: 'Loop With Side Effects and Early Exit',
        severity: 'high',
        description: 'Loops that modify state and have early exits may leave state partially updated.',
        location: { file: input.path, line: 1 },
        suggestion: 'Use atomic updates: collect all changes, validate, then apply as a batch.',
        cwe: 'CWE-662',
      });
    }
  }

  return findings;
}
